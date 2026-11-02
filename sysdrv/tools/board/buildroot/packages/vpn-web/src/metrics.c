#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include "web.h"

#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <unistd.h>

static uint64_t sum(uint64_t a, uint64_t b)
{
    if (b > UINT64_MAX - a)
        web_internal();
    return a + b;
}

static uint64_t product(uint64_t a, uint64_t b)
{
    if (a && b > UINT64_MAX / a)
        web_internal();
    return a * b;
}

static int parse_uint(const char *text, uint64_t *value)
{
    while (isspace((unsigned char)*text))
        text++;
    if (*text < '0' || *text > '9')
        return 0;
    char *end;
    errno = 0;
    unsigned long long number = strtoull(text, &end, 10);
    if (errno)
        return 0;
    while (isspace((unsigned char)*end))
        end++;
    if (*end)
        return 0;
    *value = (uint64_t)number;
    return 1;
}

static uint64_t counter(const char *path)
{
    char buffer[128];
    uint64_t value;
    web_read(path, buffer, sizeof(buffer), 0);
    if (!parse_uint(buffer, &value))
        web_internal();
    return value;
}

static struct json_object *memory(void)
{
    char buffer[16384];
    web_read(VPN_ROOT "/proc/meminfo", buffer, sizeof(buffer), 0);
    const char *source[] = {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"};
    const char *output[] = {"total", "available", "swap_total", "swap_free"};
    uint64_t values[4] = {0};
    int found[4] = {0};
    char *save = NULL;
    for (char *line = strtok_r(buffer, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char *colon = strchr(line, ':');
        if (!colon)
            web_internal();
        *colon++ = 0;
        for (size_t i = 0; i < 4; i++) {
            if (strcmp(line, source[i]))
                continue;
            char *unit = strstr(colon, "kB");
            if (!unit)
                web_internal();
            *unit = 0;
            for (char *p = unit + 2; *p; p++)
                if (!isspace((unsigned char)*p))
                    web_internal();
            if (found[i] || !parse_uint(colon, &values[i]))
                web_internal();
            values[i] = product(values[i], 1024);
            found[i] = 1;
        }
    }
    if (!found[0] || !found[2] || !found[3])
        web_internal();
    struct json_object *result = web_object();
    for (size_t i = 0; i < 4; i++)
        web_add(result, output[i], found[i] ? web_uint(values[i]) : NULL);
    return result;
}

static struct json_object *cpu(void)
{
    char buffer[65536];
    web_read(VPN_ROOT "/proc/stat", buffer, sizeof(buffer), 0);
    char *newline = strchr(buffer, '\n');
    if (newline)
        *newline = 0;
    char *save = NULL;
    char *name = strtok_r(buffer, " \t", &save);
    if (!name || strcmp(name, "cpu"))
        web_internal();
    uint64_t ticks[8] = {0}, total = 0;
    size_t n = 0;
    while (n < 8) {
        char *part = strtok_r(NULL, " \t", &save);
        if (!part)
            break;
        if (!parse_uint(part, &ticks[n]))
            web_internal();
        total = sum(total, ticks[n++]);
    }
    if (n < 5)
        web_internal();
    struct json_object *result = web_object();
    web_add(result, "total", web_uint(total));
    web_add(result, "idle", web_uint(sum(ticks[3], ticks[4])));
    return result;
}

static struct json_object *networks(void)
{
    const char *names[] = {"eth0", "wg0"};
    struct json_object *result = web_object();
    for (size_t i = 0; i < 2; i++) {
        char path[512], buffer[128];
        snprintf(path, sizeof(path), VPN_ROOT "/sys/class/net/%s/statistics/rx_bytes", names[i]);
        if (!web_read(path, buffer, sizeof(buffer), 1)) {
            /* A missing device is optional; a partial statistics tree is not. */
            char directory[512];
            snprintf(directory, sizeof(directory), VPN_ROOT "/sys/class/net/%s/statistics", names[i]);
            if (access(directory, F_OK) == 0 || errno != ENOENT)
                web_internal();
            web_add(result, names[i], NULL);
            continue;
        }
        uint64_t rx;
        if (!parse_uint(buffer, &rx))
            web_internal();
        snprintf(path, sizeof(path), VPN_ROOT "/sys/class/net/%s/statistics/tx_bytes", names[i]);
        struct json_object *entry = web_object();
        web_add(result, names[i], entry);
        web_add(entry, "rx", web_uint(rx));
        web_add(entry, "tx", web_uint(counter(path)));
    }
    return result;
}

static struct json_object *storage(void)
{
    const char *paths[] = {"/", "/userdata"};
    struct json_object *result = web_array();
    for (size_t i = 0; i < 2; i++) {
        char path[512];
        snprintf(path, sizeof(path), "%s%s", VPN_ROOT, paths[i]);
        struct statvfs usage;
        if (statvfs(path, &usage) || usage.f_bfree > usage.f_blocks)
            web_internal();
        struct json_object *entry = web_object();
        web_append(result, entry);
        web_add(entry, "path", web_string(paths[i]));
        web_add(entry, "total", web_uint(product(usage.f_blocks, usage.f_frsize)));
        web_add(entry, "used", web_uint(product(usage.f_blocks - usage.f_bfree, usage.f_frsize)));
        web_add(entry, "free", web_uint(product(usage.f_bavail, usage.f_frsize)));
    }
    return result;
}

static void strip(char *text)
{
    char *start = text;
    while (isspace((unsigned char)*start))
        start++;
    char *end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1]))
        *--end = 0;
    memmove(text, start, (size_t)(end - start) + 1);
}

static struct json_object *temperatures(void)
{
    char zones[128][256];
    size_t count = 0, visited = 0;
    DIR *directory = opendir(VPN_ROOT "/sys/class/thermal");
    if (!directory && errno != ENOENT)
        web_internal();
    if (directory) {
        struct dirent *entry;
        errno = 0;
        while ((entry = readdir(directory))) {
            if (++visited > 1024) {
                closedir(directory);
                web_internal();
            }
            if (strncmp(entry->d_name, "thermal_zone", 12))
                continue;
            size_t length = strlen(entry->d_name);
            if (count == 128 || length >= sizeof(zones[0])) {
                closedir(directory);
                web_internal();
            }
            memcpy(zones[count++], entry->d_name, length + 1);
        }
        int saved = errno;
        closedir(directory);
        if (saved)
            web_internal();
    }
    /* Small insertion sort avoids extra allocations in the optional collector. */
    for (size_t i = 1; i < count; i++) {
        char name[256];
        strcpy(name, zones[i]);
        size_t j = i;
        while (j && strcmp(zones[j - 1], name) > 0) {
            strcpy(zones[j], zones[j - 1]);
            j--;
        }
        strcpy(zones[j], name);
    }
    struct json_object *result = web_array();
    for (size_t i = 0; i < count; i++) {
        char path[512], name[256], temperature[128];
        int length = snprintf(path, sizeof(path), VPN_ROOT "/sys/class/thermal/%.255s/type", zones[i]);
        if (length < 0 || (size_t)length >= sizeof(path))
            web_internal();
        int good = web_read(path, name, sizeof(name), 2);
        length = snprintf(path, sizeof(path), VPN_ROOT "/sys/class/thermal/%.255s/temp", zones[i]);
        if (length < 0 || (size_t)length >= sizeof(path))
            web_internal();
        good = web_read(path, temperature, sizeof(temperature), 2) && good;
        char *end = temperature;
        long value = 0;
        if (good) {
            errno = 0;
            value = strtol(temperature, &end, 10);
            if (errno || end == temperature)
                good = 0;
            while (isspace((unsigned char)*end))
                end++;
            if (*end)
                good = 0;
        }
        struct json_object *entry = web_object();
        web_append(result, entry);
        if (good)
            strip(name);
        web_add(entry, "name", web_string(good ? name : zones[i]));
        web_add(entry, "celsius", good ? web_number((double)value / 1000) : NULL);
    }
    return result;
}

struct json_object *web_metrics(void)
{
    struct json_object *result = web_object();
    web_add(result, "uptime", web_number(web_uptime()));
    double load[3];
    if (getloadavg(load, 3) != 3)
        web_internal();
#ifdef VPN_TEST_CLOCK
    load[0] = 0.1; load[1] = 0.2; load[2] = 0.3;
#endif
    struct json_object *loads = web_array();
    web_add(result, "load", loads);
    for (size_t i = 0; i < 3; i++)
        web_append(loads, web_number(load[i]));
    web_add(result, "cpu", cpu());
    web_add(result, "memory", memory());
    web_add(result, "storage", storage());
    web_add(result, "temperatures", temperatures());
    web_add(result, "networks", networks());
    return result;
}

const char *web_leds(void)
{
    const char *names[] = {"eth_link", "eth_act", "work"};
    int enabled = 0, disabled = 0;
    for (size_t i = 0; i < 3; i++) {
        char path[512], text[1024];
        snprintf(path, sizeof(path), VPN_ROOT "/sys/class/leds/%s/trigger", names[i]);
        if (!web_read(path, text, sizeof(text), 2))
            return "unavailable";
        char *selected = strchr(text, '[');
        char *end = selected ? strchr(selected + 1, ']') : NULL;
        if (!end)
            continue;
        *end = 0;
        selected++;
        if (!strcmp(selected, "none")) {
            snprintf(path, sizeof(path), VPN_ROOT "/sys/class/leds/%s/brightness", names[i]);
            if (!web_read(path, text, sizeof(text), 2))
                return "unavailable";
            strip(text);
            if (!strcmp(text, "0"))
                disabled++;
        } else if (i == 2 && !strcmp(selected, "activity")) {
            enabled++;
        } else if (i < 2 && !strcmp(selected, "netdev")) {
            const char *attrs[] = {"device_name", "link", "rx", "tx"};
            const char *expected[] = {"eth0", i == 0 ? "1" : "0", i == 0 ? "0" : "1", i == 0 ? "0" : "1"};
            int matches = 1;
            for (size_t j = 0; j < 4; j++) {
                snprintf(path, sizeof(path), VPN_ROOT "/sys/class/leds/%s/%s", names[i], attrs[j]);
                if (!web_read(path, text, sizeof(text), 2))
                    return "unavailable";
                strip(text);
                if (strcmp(text, expected[j]))
                    matches = 0;
            }
            if (matches)
                enabled++;
        }
    }
    return enabled == 3 ? "enabled" : disabled == 3 ? "disabled" : "mixed";
}
