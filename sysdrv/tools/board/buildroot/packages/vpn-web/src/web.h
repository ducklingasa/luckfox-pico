#ifndef VPN_WEB_H
#define VPN_WEB_H

#include <json-c/json.h>
#include <stdint.h>

#ifndef VPN_ROOT
#define VPN_ROOT ""
#endif
#ifndef VPN_OWNER_UID
#define VPN_OWNER_UID 0
#endif
#ifndef VPN_PYTHON_SCRIPT
#define VPN_PYTHON_SCRIPT "/opt/vpn-web/webui.py"
#endif

#define VPN_FILE_LIMIT (128 * 1024)
#define VPN_RESPONSE_LIMIT (1024 * 1024)

_Noreturn void web_fail(int status, const char *code, const char *message);
_Noreturn void web_internal(void);
void web_add(struct json_object *obj, const char *key, struct json_object *value);
void web_append(struct json_object *obj, struct json_object *value);
struct json_object *web_object(void);
struct json_object *web_array(void);
struct json_object *web_string(const char *value);
struct json_object *web_uint(uint64_t value);
struct json_object *web_number(double value);
struct json_object *web_bool(int value);
int web_read(const char *path, char *buffer, size_t capacity, int optional);
double web_uptime(void);
struct json_object *web_metrics(void);
const char *web_leds(void);
void web_wipe(void *buffer, size_t size);

#endif
