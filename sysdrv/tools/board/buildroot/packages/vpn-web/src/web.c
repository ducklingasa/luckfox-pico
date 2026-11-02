#define _GNU_SOURCE
#include "web.h"
#include "netlink.h"

#include <ctype.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static jmp_buf failure;
static int response_status = 500;
static const char *error_code = "internal";
static const char *error_message = "Device operation failed. Check device state over SSH.";
static int auth_lock = -1, vpn_lock = -1;
static struct json_object *body;
static char scratch[VPN_FILE_LIMIT + 1], config_text[VPN_FILE_LIMIT + 1];
static struct vpn_device device;
static struct json_object *allocations[16384];
static unsigned char allocation_owned[16384];
static size_t allocation_count;
static char timeout_output[768];
static size_t timeout_length;

static void timed_out(int signal_number)
{
    (void)signal_number;
    if (auth_lock >= 0)
        close(auth_lock);
    if (vpn_lock >= 0)
        close(vpn_lock);
    const char log[] = "vpn-web: operation failed (timeout)\n";
    ssize_t ignored = write(STDERR_FILENO, log, sizeof(log) - 1);
    ignored = write(STDOUT_FILENO, timeout_output, timeout_length);
    (void)ignored;
    _exit(0);
}

static void request_timer(void)
{
    const char text[] = "{\"ok\":false,\"error\":{\"code\":\"timeout\","
        "\"message\":\"Request timed out. Refresh status before retrying.\"}}";
    int length = snprintf(timeout_output, sizeof(timeout_output),
        "Status: 504\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n"
        "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
        "Referrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'self'; "
        "script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'\r\n\r\n%s",
        sizeof(text) - 1, text);
    if (length < 0 || (size_t)length >= sizeof(timeout_output))
        web_internal();
    timeout_length = (size_t)length;
    struct sigaction action = {0};
    action.sa_handler = timed_out;
    if (sigemptyset(&action.sa_mask) || sigaction(SIGALRM, &action, NULL))
        web_internal();
    alarm(5);
}

void web_wipe(void *buffer, size_t size)
{
    volatile unsigned char *p = buffer;
    while (size--)
        *p++ = 0;
}

_Noreturn void web_fail(int status, const char *code, const char *message)
{
    response_status = status;
    error_code = code;
    error_message = message;
    longjmp(failure, 1);
}

_Noreturn void web_internal(void)
{
    web_fail(500, "internal", "Device operation failed. Check device state over SSH.");
}

static struct json_object *checked(struct json_object *value)
{
    if (!value)
        web_internal();
    if (allocation_count == sizeof(allocations) / sizeof(allocations[0])) {
        json_object_put(value);
        web_internal();
    }
    allocations[allocation_count] = value;
    allocation_owned[allocation_count++] = 1;
    return value;
}

static void transfer(struct json_object *value)
{
    if (!value)
        return;
    for (size_t i = allocation_count; i > 0; i--)
        if (allocations[i - 1] == value) {
            allocation_owned[i - 1] = 0;
            return;
        }
    web_internal();
}

static void release_allocations(void)
{
    for (size_t i = 0; i < allocation_count; i++)
        if (allocation_owned[i])
            json_object_put(allocations[i]);
    allocation_count = 0;
}

struct json_object *web_object(void) { return checked(json_object_new_object()); }
struct json_object *web_array(void) { return checked(json_object_new_array()); }
struct json_object *web_string(const char *s) { return checked(json_object_new_string(s)); }
struct json_object *web_uint(uint64_t n) { return checked(json_object_new_uint64(n)); }
struct json_object *web_number(double n)
{
    if (!isfinite(n))
        web_internal();
    return checked(json_object_new_double(n));
}
struct json_object *web_bool(int n) { return checked(json_object_new_boolean(n)); }

void web_add(struct json_object *obj, const char *key, struct json_object *value)
{
    transfer(value);
    if (json_object_object_add(obj, key, value) != 0) {
        json_object_put(value);
        web_internal();
    }
}

void web_append(struct json_object *obj, struct json_object *value)
{
    transfer(value);
    if (json_object_array_add(obj, value) != 0) {
        json_object_put(value);
        web_internal();
    }
}

static void unlock(int *fd)
{
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

static int private_fd(int fd, int directory)
{
    struct stat st;
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) || st.st_uid != VPN_OWNER_UID ||
            (st.st_mode & 07777) != (directory ? 0700 : 0600) ||
            (directory ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode))) {
        close(fd);
        errno = EACCES;
        return -1;
    }
    return fd;
}

static int private_dir(const char *path)
{
    /* Every component is opened relative to an already checked descriptor. */
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    char copy[512];
    if (strlen(path) >= sizeof(copy) || fd < 0)
        web_internal();
    strcpy(copy, path);
    char *save = NULL;
    for (char *part = strtok_r(copy, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
        int next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(fd);
        if (next < 0)
            web_internal();
        fd = next;
    }
    fd = private_fd(fd, 1);
    if (fd < 0)
        web_internal();
    return fd;
}

static int valid_utf8(const unsigned char *p, size_t length)
{
    size_t i = 0;
    while (i < length) {
        uint32_t code = p[i++];
        if (code < 128)
            continue;
        size_t extra;
        uint32_t minimum;
        if (code >= 0xc2 && code <= 0xdf) {
            extra = 1; minimum = 0x80; code &= 0x1f;
        } else if (code >= 0xe0 && code <= 0xef) {
            extra = 2; minimum = 0x800; code &= 0x0f;
        } else if (code >= 0xf0 && code <= 0xf4) {
            extra = 3; minimum = 0x10000; code &= 0x07;
        } else {
            return 0;
        }
        if (extra > length - i)
            return 0;
        while (extra--) {
            if ((p[i] & 0xc0) != 0x80)
                return 0;
            code = (code << 6) | (p[i++] & 0x3f);
        }
        if (code < minimum || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff))
            return 0;
    }
    return 1;
}

static int take_lock(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    fd = private_fd(fd, 0);
    if (fd < 0)
        web_internal();
    if (flock(fd, LOCK_SH | LOCK_NB)) {
        int saved = errno;
        close(fd);
        if (saved == EWOULDBLOCK || saved == EAGAIN)
            web_fail(409, "busy", "Another operation is running. Please retry.");
        web_internal();
    }
    return fd;
}

static int read_fd(int fd, char *buffer, size_t capacity)
{
    size_t used = 0;
    while (used < capacity) {
        ssize_t n = read(fd, buffer + used, capacity - used);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 || (n == 0 && (memchr(buffer, 0, used) ||
                !valid_utf8((const unsigned char *)buffer, used)))) {
            close(fd);
            web_internal();
        }
        if (!n) {
            buffer[used] = 0;
            close(fd);
            return 1;
        }
        used += (size_t)n;
    }
    close(fd);
    web_internal();
}

int web_read(const char *path, char *buffer, size_t capacity, int optional)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        if (optional && (errno == ENOENT || (optional == 2 && errno == EACCES)))
            return 0;
        web_internal();
    }
    return read_fd(fd, buffer, capacity);
}

static double decimal(const char *text)
{
    const char *p = text;
    while (isspace((unsigned char)*p))
        p++;
    if (*p == '+' || *p == '-')
        p++;
    size_t digits = 0;
    while (*p >= '0' && *p <= '9') { p++; digits++; }
    if (*p == '.') {
        p++;
        while (*p >= '0' && *p <= '9') { p++; digits++; }
    }
    if (!digits)
        web_internal();
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-')
            p++;
        const char *start = p;
        while (*p >= '0' && *p <= '9')
            p++;
        if (start == p)
            web_internal();
    }
    while (isspace((unsigned char)*p))
        p++;
    if (*p)
        web_internal();
    char *end;
    errno = 0;
    double value = strtod(text, &end);
    if (end == text || (errno && errno != ERANGE) || !isfinite(value))
        web_internal();
    while (isspace((unsigned char)*end))
        end++;
    if (*end)
        web_internal();
    return value;
}

double web_uptime(void)
{
    char buffer[128];
    web_read(VPN_ROOT "/proc/uptime", buffer, sizeof(buffer), 0);
    char *end = strpbrk(buffer, " \t");
    if (!end)
        web_internal();
    *end = 0;
    double value = decimal(buffer);
    if (value < 0)
        web_internal();
    return value;
}

static int cookie_id(char id[65])
{
    const char *cookies = getenv("HTTP_COOKIE");
    size_t found = 0;
    int valid = 0;
    if (!cookies)
        return 0;
    if (strlen(cookies) > 8192)
        return 0;
    while (*cookies) {
        const char *end = strchr(cookies, ';');
        if (!end)
            end = cookies + strlen(cookies);
        const char *start = cookies;
        while (start < end && isspace((unsigned char)*start))
            start++;
        while (end > start && isspace((unsigned char)end[-1]))
            end--;
        if ((size_t)(end - start) >= 12 && !memcmp(start, "vpn_session=", 12)) {
            found++;
            valid = (end - start == 76);
            if (valid) {
                for (size_t i = 0; i < 64; i++)
                    if (!((start[12 + i] >= '0' && start[12 + i] <= '9') ||
                            (start[12 + i] >= 'a' && start[12 + i] <= 'f')))
                        valid = 0;
                if (valid) {
                    memcpy(id, start + 12, 64);
                    id[64] = 0;
                }
            }
        }
        cookies = strchr(cookies, ';');
        if (!cookies)
            break;
        cookies++;
    }
    return found == 1 && valid;
}

static void authenticate(void)
{
    int run = private_dir(VPN_ROOT "/run/webui");
    auth_lock = private_fd(openat(run, "auth.lock",
            O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600), 0);
    close(run);
    if (auth_lock < 0)
        web_internal();
    if (flock(auth_lock, LOCK_SH | LOCK_NB)) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            web_fail(409, "busy", "Another operation is running. Please retry.");
        web_internal();
    }
    int auth = private_dir(VPN_ROOT "/userdata/webui");
    int fd = openat(auth, "auth.conf", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    int saved = errno;
    close(auth);
    if (fd < 0 && saved == ENOENT)
        web_fail(401, "login", "Please log in.");
    fd = private_fd(fd, 0);
    if (fd < 0)
        web_internal();
    /* Validate the configured verifier without hashing on dashboard reads. */
    read_fd(fd, scratch, 4096);
    for (const unsigned char *p = (const unsigned char *)scratch; *p; p++)
        if (*p > 127)
            web_internal();
    struct json_tokener *tok = json_tokener_new();
    if (!tok)
        web_internal();
    struct json_object *verifier = json_tokener_parse_ex(tok, scratch, (int)strlen(scratch));
    size_t parsed = json_tokener_get_parse_end(tok);
    int parse_ok = json_tokener_get_error(tok) == json_tokener_success;
    json_tokener_free(tok);
    while (isspace((unsigned char)scratch[parsed]))
        parsed++;
    struct json_object *algorithm = NULL, *iterations = NULL, *salt = NULL, *hash = NULL;
    int good = parse_ok && !scratch[parsed] && verifier &&
        json_object_is_type(verifier, json_type_object) &&
        json_object_object_get_ex(verifier, "algorithm", &algorithm) &&
        json_object_is_type(algorithm, json_type_string) &&
        json_object_get_string_len(algorithm) == 13 &&
        !strcmp(json_object_get_string(algorithm), "pbkdf2-sha256") &&
        json_object_object_get_ex(verifier, "iterations", &iterations) &&
        json_object_is_type(iterations, json_type_int) &&
        json_object_get_int64(iterations) == 600000 &&
        json_object_object_get_ex(verifier, "salt", &salt) &&
        json_object_is_type(salt, json_type_string) &&
        json_object_object_get_ex(verifier, "hash", &hash) &&
        json_object_is_type(hash, json_type_string);
    if (good) {
        const char *values[] = {json_object_get_string(salt), json_object_get_string(hash)};
        if (json_object_get_string_len(salt) != 64 || json_object_get_string_len(hash) != 64)
            good = 0;
        for (size_t i = 0; i < 2; i++) {
            if (strlen(values[i]) != 64)
                good = 0;
            for (const char *p = values[i]; *p; p++)
                if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f')))
                    good = 0;
        }
    }
    json_object_put(verifier);
    web_wipe(scratch, sizeof(scratch));
    if (!good)
        web_internal();
    char id[65];
    if (!cookie_id(id))
        web_fail(401, "login", "Please log in.");
    int sessions = private_dir(VPN_ROOT "/run/webui/sessions");
    fd = openat(sessions, id, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    saved = errno;
    close(sessions);
    web_wipe(id, sizeof(id));
    if (fd < 0 && saved == ENOENT)
        web_fail(401, "login", "Please log in.");
    fd = private_fd(fd, 0);
    if (fd < 0)
        web_internal();
    read_fd(fd, scratch, 128);
    double issued = decimal(scratch), now = web_uptime();
    web_wipe(scratch, sizeof(scratch));
    if (issued < 0)
        web_internal();
    if (!(issued <= now && now < issued + 1800))
        web_fail(401, "login", "Please log in.");
    unlock(&auth_lock);
}

/* A single POSIX shlex word, with comments, quoting and concatenated quotes;
 * assignments are data, never evaluated as shell code. */
static int assignment(const char *line, char *word, size_t capacity)
{
    size_t used = 0;
    int quote = 0, started = 0, finished = 0;
    for (const unsigned char *p = (const unsigned char *)line; *p; p++) {
        unsigned char c = *p;
        if (!quote && c == '#')
            break;
        if (!quote && isspace(c)) {
            if (started)
                finished = 1;
            continue;
        }
        if (finished)
            web_internal();
        started = 1;
        if (c == '\'' && quote != '"') {
            quote = quote == '\'' ? 0 : '\'';
            continue;
        }
        if (c == '"' && quote != '\'') {
            quote = quote == '"' ? 0 : '"';
            continue;
        }
        if (c == '\\' && quote != '\'') {
            if (!p[1])
                web_internal();
            if (!quote || p[1] == '"' || p[1] == '\\')
                c = *++p;
        }
        if (used + 1 >= capacity || (c < 32 && c != '\t') || c == 127)
            web_internal();
        word[used++] = (char)c;
    }
    if (quote)
        web_internal();
    word[used] = 0;
    if (started && !strchr(word, '='))
        web_internal();
    return started;
}

static uint64_t integer(const char *text)
{
    if (!*text)
        web_internal();
    for (const char *p = text; *p; p++)
        if (*p < '0' || *p > '9')
            web_internal();
    char *end;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || *end)
        web_internal();
    return (uint64_t)value;
}

static struct json_object *settings(uint16_t *port)
{
    static const char *keys[] = {"pivpnHOST", "pivpnPORT", "pivpnNET", "subnetClass",
        "pivpnDNS1", "pivpnDNS2", "pivpnMTU", "ALLOWED_IPS"};
    struct json_object *values = web_object();
    web_add(body, "settings", values);
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        web_add(values, keys[i], NULL);
    web_read(VPN_ROOT "/etc/pivpn/wireguard/setupVars.conf", scratch, sizeof(scratch), 0);
    char *save = NULL, word[4096];
    for (char *line = strtok_r(scratch, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        if (!assignment(line, word, sizeof(word)))
            continue;
        char *value = strchr(word, '=');
        *value++ = 0;
        for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
            if (!strcmp(word, keys[i]))
                web_add(values, keys[i], web_string(value));
    }
    struct json_object *port_value = NULL;
    if (!json_object_object_get_ex(values, "pivpnPORT", &port_value) || !port_value)
        web_internal();
    uint64_t number = integer(json_object_get_string(port_value));
    if (number > UINT16_MAX)
        web_internal();
    *port = (uint16_t)number;
    return values;
}

static void collect(void)
{
    if (vpn_collect(&device)) {
        if (errno == ETIMEDOUT)
            web_fail(504, "timeout", "The operation timed out; refresh status before retrying.");
        web_fail(500, "command", "The operation failed. Refresh status and check the device over SSH.");
    }
}

static void status_read(void)
{
    vpn_lock = take_lock(VPN_ROOT "/run/pivpn.lock");
    uint16_t configured_port = 0;
    settings(&configured_port);
    struct stat info;
    if (stat(VPN_ROOT "/userdata/wireguard/wg0.conf", &info)) {
        if (errno == ENOENT || errno == ENOTDIR)
            web_fail(503, "not_ready", "WireGuard configuration is unavailable.");
        web_internal();
    }
    if (!S_ISREG(info.st_mode))
        web_fail(503, "not_ready", "WireGuard configuration is unavailable.");
    collect();
    web_wipe(config_text, sizeof(config_text));
    unlock(&vpn_lock);
    web_add(body, "running", web_bool(device.running));
    web_add(body, "interface", web_string("wg0"));
    web_add(body, "address", device.address[0] ? web_string(device.address) : NULL);
    web_add(body, "listen_port", web_uint(device.running ? device.port : configured_port));
    web_add(body, "metrics", web_metrics());
    web_add(body, "leds", web_string(web_leds()));
}

static int valid_name(const char *name)
{
    size_t n = strlen(name);
    if (!n || n > 15 || !isalnum((unsigned char)name[0]))
        return 0;
    for (size_t i = 0; i < n; i++)
        if (!((name[i] >= 'a' && name[i] <= 'z') ||
                (name[i] >= 'A' && name[i] <= 'Z') ||
                (name[i] >= '0' && name[i] <= '9') ||
                (i && strchr("._-", name[i]))))
            return 0;
    return 1;
}

static void key_text(const unsigned char key[32], char output[45])
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t j = 0;
    for (size_t i = 0; i < 32; i += 3) {
        uint32_t n = (uint32_t)key[i] << 16;
        if (i + 1 < 32)
            n |= (uint32_t)key[i + 1] << 8;
        if (i + 2 < 32)
            n |= key[i + 2];
        output[j++] = alphabet[(n >> 18) & 63];
        output[j++] = alphabet[(n >> 12) & 63];
        output[j++] = i + 1 < 32 ? alphabet[(n >> 6) & 63] : '=';
        output[j++] = i + 2 < 32 ? alphabet[n & 63] : '=';
    }
    output[44] = 0;
}

static int valid_key(const char *key)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (strlen(key) != 44 || key[43] != '=')
        return 0;
    for (size_t i = 0; i < 43; i++)
        if (!strchr(alphabet, key[i]))
            return 0;
    const char *last = strchr(alphabet, key[42]);
    return last && (last - alphabet) % 4 == 0;
}

static int marker(const char *name)
{
    char enabled[64], disabled[80];
    snprintf(enabled, sizeof(enabled), "### begin %s ###", name);
    snprintf(disabled, sizeof(disabled), "#[disabled] %s", enabled);
    int on = 0, off = 0;
    const char *p = config_text;
    while (*p) {
        const char *end = strchr(p, '\n');
        if (!end)
            end = p + strlen(p);
        const char *line_end = end;
        if (line_end > p && line_end[-1] == '\r')
            line_end--;
        if ((size_t)(line_end - p) == strlen(enabled) && !memcmp(p, enabled, strlen(enabled)))
            on++;
        if ((size_t)(line_end - p) == strlen(disabled) && !memcmp(p, disabled, strlen(disabled)))
            off++;
        p = *end ? end + 1 : end;
    }
    if (on + off != 1)
        web_internal();
    return on;
}

static void clients_read(void)
{
    vpn_lock = take_lock(VPN_ROOT "/run/pivpn.lock");
    web_read(VPN_ROOT "/userdata/wireguard/wg0.conf", config_text, sizeof(config_text), 0);
    web_read(VPN_ROOT "/userdata/wireguard/configs/clients.txt", scratch, sizeof(scratch), 0);
    if (scratch[0] == '\n' || strstr(scratch, "\n\n"))
        web_internal();
    collect();
    /* Copy live/config state under the VPN lock, then release before JSON work. */
    unlock(&vpn_lock);
    web_add(body, "running", web_bool(device.running));
    web_add(body, "timestamps", web_string("approximate until NTP sync"));
    struct json_object *rows = web_array();
    web_add(body, "clients", rows);
    char *save = NULL;
    size_t count = 0;
    struct timespec stamp;
    if (clock_gettime(CLOCK_REALTIME, &stamp))
        web_internal();
    double now = (double)stamp.tv_sec + (double)stamp.tv_nsec / 1000000000.0;
#ifdef VPN_TEST_CLOCK
    now = VPN_TEST_CLOCK;
#endif
    for (char *line = strtok_r(scratch, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char *parts[5], *row_save = NULL;
        size_t n = 0;
        for (char *p = strtok_r(line, " \t\r\v\f", &row_save); p; p = strtok_r(NULL, " \t\r\v\f", &row_save)) {
            if (n == 5)
                web_internal();
            parts[n++] = p;
        }
        struct in_addr address;
        if (n != 4 || !valid_name(parts[0]) || !valid_key(parts[1]) ||
                inet_pton(AF_INET, parts[3], &address) != 1 || ++count > VPN_MAX_PEERS)
            web_internal();
        uint64_t created = integer(parts[2]);
        int enabled = marker(parts[0]);
        struct vpn_peer *peer = NULL;
        for (size_t i = 0; i < device.count; i++) {
            char pub[45];
            key_text(device.peers[i].key, pub);
            if (!strcmp(parts[1], pub)) {
                peer = &device.peers[i];
                break;
            }
        }
        struct json_object *row = web_object();
        web_append(rows, row);
        web_add(row, "name", web_string(parts[0]));
        web_add(row, "ip", web_string(parts[3]));
        web_add(row, "created", web_uint(created));
        web_add(row, "enabled", web_bool(enabled));
        web_add(row, "handshake", peer && peer->has_handshake ? web_uint(peer->handshake) : NULL);
        web_add(row, "rx", peer && peer->has_rx ? web_uint(peer->rx) : NULL);
        web_add(row, "tx", peer && peer->has_tx ? web_uint(peer->tx) : NULL);
        web_add(row, "endpoint", peer && peer->has_endpoint ? web_string(peer->endpoint) : NULL);
        double age = peer ? now - (double)peer->handshake : -1;
        web_add(row, "recent", web_bool(peer && peer->has_handshake &&
                peer->handshake > 0 && age >= 0 && age <= 180));
    }
    web_wipe(config_text, sizeof(config_text));
    web_wipe(scratch, sizeof(scratch));
}

static void cold(void)
{
    int run = private_dir(VPN_ROOT "/run/webui");
    int fd = private_fd(openat(run, "request.lock",
            O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0600), 0);
    close(run);
    if (fd < 0)
        web_internal();
    for (int attempt = 0; attempt < 5; attempt++) {
        if (!flock(fd, LOCK_EX | LOCK_NB)) {
            char *const args[] = {"/usr/bin/python3", "-I", "-B", VPN_PYTHON_SCRIPT, NULL};
            /* The gate must survive exec and interpreter shutdown. */
            execv(args[0], args);
            close(fd);
            web_internal();
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            close(fd);
            web_internal();
        }
        struct timespec delay = {0, 100000000};
        while (nanosleep(&delay, &delay) && errno == EINTR) {}
    }
    close(fd);
    web_fail(503, "busy", "Another web request is running. Please retry.");
}

static int write_all(const char *text, size_t length, const struct timespec *deadline)
{
    size_t used = 0;
    while (used < length) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now))
            return -1;
        int64_t remaining = ((int64_t)deadline->tv_sec - (int64_t)now.tv_sec) * 1000000000 +
            (int64_t)deadline->tv_nsec - (int64_t)now.tv_nsec;
        if (remaining <= 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        ssize_t written = write(STDOUT_FILENO, text + used, length - used);
        if (written > 0) {
            used += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        if (written >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
            return -1;
        struct pollfd output = {STDOUT_FILENO, POLLOUT, 0};
        int ready = poll(&output, 1, (int)((remaining + 999999) / 1000000));
        if (ready < 0 && errno == EINTR)
            continue;
        if (!ready) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (ready < 0 || output.revents & (POLLERR | POLLHUP | POLLNVAL))
            return -1;
    }
    return 0;
}

static int emit(const char *text)
{
    char header[512];
    size_t length = strlen(text);
    int size = snprintf(header, sizeof(header),
            "Status: %d\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n"
            "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
            "Referrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'self'; "
            "script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'\r\n\r\n",
            response_status, length);
    struct timespec deadline;
    struct sigaction action = {0};
    action.sa_handler = SIG_IGN;
    int flags = fcntl(STDOUT_FILENO, F_GETFL);
    if (size < 0 || (size_t)size >= sizeof(header) || flags < 0 ||
            fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK) ||
            sigemptyset(&action.sa_mask) || sigaction(SIGPIPE, &action, NULL) ||
            clock_gettime(CLOCK_MONOTONIC, &deadline)) {
        fprintf(stderr, "vpn-web: response preparation failed\n");
        return 1;
    }
    deadline.tv_sec += 5;
    if (write_all(header, (size_t)size, &deadline) || write_all(text, length, &deadline)) {
        fprintf(stderr, "vpn-web: response write failed (%s)\n",
                errno == ETIMEDOUT ? "timeout" : "io");
        return 1;
    }
    return 0;
}

static unsigned char hex_value(unsigned char c)
{
    if (c >= '0' && c <= '9')
        return (unsigned char)(c - '0');
    return (unsigned char)(tolower(c) - 'a' + 10);
}

static void reject_query(const char *query)
{
    size_t length = strlen(query);
    if (length > 4096)
        web_fail(413, "too_large", "Request fields exceed the allowed size.");
    for (const char *p = query; *p; p++)
        if (*p == '%' && (!p[1] || !p[2] ||
                !isxdigit((unsigned char)p[1]) || !isxdigit((unsigned char)p[2])))
            web_fail(400, "encoding", "Malformed URL encoding.");
    size_t fields = 0;
    const char *p = query;
    while (*p) {
        const char *end = strchr(p, '&');
        if (!end)
            end = p + strlen(p);
        const char *equal = memchr(p, '=', (size_t)(end - p));
        if (++fields > 8 || !equal || (*end == '&' && !end[1]))
            web_fail(400, "fields", "Malformed request fields.");
        /* parse_qsl validates UTF-8 in every field before checking names. */
        const char *starts[] = {p, equal + 1};
        const char *ends[] = {equal, end};
        for (size_t i = 0; i < 2; i++) {
            unsigned char decoded[4096];
            size_t used = 0;
            for (const char *s = starts[i]; s < ends[i]; s++) {
                unsigned char c = (unsigned char)*s;
                if (c == '%') {
                    c = (unsigned char)((hex_value((unsigned char)s[1]) << 4) |
                            hex_value((unsigned char)s[2]));
                    s += 2;
                } else if (c == '+') {
                    c = ' ';
                }
                decoded[used++] = c;
            }
            if (!valid_utf8(decoded, used))
                web_fail(400, "fields", "Malformed request fields.");
        }
        p = *end ? end + 1 : end;
    }
    web_fail(400, "fields", "Unknown, duplicate, or invalid request field.");
}

int main(void)
{
    umask(077);
    if (!setjmp(failure)) {
        const char *route = getenv("PATH_INFO"), *method = getenv("REQUEST_METHOD");
        if (!route)
            route = "";
        while (*route == '/')
            route++;
        size_t length = strlen(route);
        while (length && route[length - 1] == '/')
            length--;
        int status = length == 6 && !memcmp(route, "status", 6);
        int clients = length == 7 && !memcmp(route, "clients", 7);
        if (!status && !clients)
            cold();
        if (!method || strcmp(method, "GET"))
            web_fail(405, "method", "Unsupported HTTP method.");
        request_timer();
        authenticate();
        const char *query = getenv("QUERY_STRING");
        if (query && *query)
            reject_query(query);
        body = web_object();
        web_add(body, "ok", web_bool(1));
        if (status)
            status_read();
        else
            clients_read();
        size_t size;
        const char *json = json_object_to_json_string_length(body, JSON_C_TO_STRING_PLAIN, &size);
        if (!json || size > VPN_RESPONSE_LIMIT)
            web_internal();
        response_status = 200;
    } else {
        unlock(&auth_lock);
        unlock(&vpn_lock);
        release_allocations();
        body = NULL;
        if (response_status >= 500)
            fprintf(stderr, "vpn-web: operation failed (%s)\n", error_code);
    }
    alarm(0);
    web_wipe(scratch, sizeof(scratch));
    web_wipe(config_text, sizeof(config_text));
    web_wipe(&device, sizeof(device));
    int result;
    if (body) {
        result = emit(json_object_to_json_string_ext(body, JSON_C_TO_STRING_PLAIN));
    } else {
        /* All error categories/messages are fixed literals, not request data. */
        char error[512];
        snprintf(error, sizeof(error), "{\"ok\":false,\"error\":{\"code\":\"%s\",\"message\":\"%s\"}}",
                error_code, error_message);
        result = emit(error);
    }
    release_allocations();
    return result;
}
