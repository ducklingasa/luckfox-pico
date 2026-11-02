#ifndef VPN_WEB_NETLINK_H
#define VPN_WEB_NETLINK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VPN_MAX_PEERS 1024

struct vpn_peer {
    unsigned char key[32];
    uint64_t handshake, rx, tx;
    bool has_handshake, has_rx, has_tx, has_endpoint;
    char endpoint[80];
};

struct vpn_device {
    bool running;
    uint16_t port;
    char address[32];
    size_t count;
    struct vpn_peer peers[VPN_MAX_PEERS];
};

/* Returns 0 on a complete snapshot, -1 with errno on any collection failure.
 * An absent interface is a successful, empty, non-running snapshot. */
int vpn_collect(struct vpn_device *device);

#endif
