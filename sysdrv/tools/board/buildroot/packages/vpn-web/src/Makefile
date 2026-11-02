CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2
LDFLAGS ?=
WARNINGS = -std=c11 -Wall -Wextra -Werror -Wformat=2 -Wshadow -Wconversion
HARDENING = -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE

vpn-native: web.c metrics.c netlink.c web.h netlink.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(HARDENING) \
		web.c metrics.c netlink.c $(LDFLAGS) -pie -Wl,-z,relro,-z,now \
		-ljson-c -lm -o $@

clean:
	rm -f vpn-native

.PHONY: clean
