#define _POSIX_C_SOURCE 200809L
#include "netlink.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/genetlink.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/wireguard.h>
#include <net/if.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define RECEIVE_SIZE 65536U
#define MAX_DATAGRAMS 256U
#define MAX_BYTES (8U * 1024U * 1024U)
#define MAX_WORK (4U * 1024U * 1024U)
#define COLLECTION_MS 2000

enum reply_kind { FAMILY_REPLY, DEVICE_REPLY, ADDRESS_REPLY };

struct collection {
    struct vpn_device *device;
    unsigned int ifindex;
    uint16_t family;
    uint32_t sequence, portid;
    enum reply_kind kind;
    bool done, seen, multipart, identified;
    unsigned int datagrams;
    size_t bytes, work;
    int64_t deadline;
};

struct attribute {
    uint16_t type, flags;
    const unsigned char *data;
    size_t length;
};

static int fail(int error)
{
    errno = error;
    return -1;
}

static void clear_memory(void *memory, size_t size)
{
    volatile unsigned char *p = memory;
    while (size--)
        *p++ = 0;
}

static int64_t now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int time_left(const struct collection *c)
{
    int64_t now = now_ms();
    if (now < 0)
        return -1;
    if (now >= c->deadline)
        return fail(ETIMEDOUT);
    return (int)(c->deadline - now);
}

static int charge(struct collection *c)
{
    if (++c->work > MAX_WORK)
        return fail(E2BIG);
    return 0;
}

/* memcpy headers and scalars: netlink's four-byte alignment does not align u64. */
static int next_attr(struct collection *c, const unsigned char **data,
                     size_t *length, struct attribute *a)
{
    struct nlattr h;
    size_t padded;
    if (!*length)
        return 0;
    if (charge(c) < 0)
        return -1;
    if (*length < sizeof(h))
        return fail(EPROTO);
    memcpy(&h, *data, sizeof(h));
    if (h.nla_len < sizeof(h) || h.nla_len > *length)
        return fail(EPROTO);
    padded = ((size_t)h.nla_len + 3U) & ~(size_t)3U;
    if (padded > *length)
        return fail(EPROTO);
    a->type = h.nla_type & (uint16_t)NLA_TYPE_MASK;
    a->flags = h.nla_type & (NLA_F_NESTED | NLA_F_NET_BYTEORDER);
    a->data = *data + sizeof(h);
    a->length = h.nla_len - sizeof(h);
    *data += padded;
    *length -= padded;
    return 1;
}

static int scalar(const struct attribute *a, size_t size)
{
    if (a->flags || a->length != size)
        return fail(EPROTO);
    return 0;
}

static int nested(const struct attribute *a)
{
    if (a->flags & NLA_F_NET_BYTEORDER)
        return fail(EPROTO);
    return 0;
}

static int validate_tree(struct collection *c, const unsigned char *p,
                         size_t length, unsigned int depth)
{
    struct attribute a;
    int r;
    if (depth > 4)
        return fail(EPROTO);
    while ((r = next_attr(c, &p, &length, &a)) > 0)
        if ((a.flags & NLA_F_NESTED) &&
            (nested(&a) < 0 ||
             validate_tree(c, a.data, a.length, depth + 1) < 0))
            return -1;
    return r;
}

static int endpoint(const struct attribute *a, char *out, size_t size)
{
    uint16_t family;
    char address[INET6_ADDRSTRLEN + IF_NAMESIZE + 1];
    int n;
    if (a->flags || a->length < sizeof(family))
        return fail(EPROTO);
    memcpy(&family, a->data, sizeof(family));
    if (family == AF_INET) {
        struct sockaddr_in sin;
        if (a->length != sizeof(sin))
            return fail(EPROTO);
        memcpy(&sin, a->data, sizeof(sin));
        if (!inet_ntop(AF_INET, &sin.sin_addr, address, sizeof(address)))
            return -1;
        n = snprintf(out, size, "%s:%u", address, (unsigned int)ntohs(sin.sin_port));
    } else if (family == AF_INET6) {
        struct sockaddr_in6 sin6;
        char service[6];
        int error;
        if (a->length != sizeof(sin6))
            return fail(EPROTO);
        memcpy(&sin6, a->data, sizeof(sin6));
        /* Match bundled wg's numeric-only libc formatting, including scope
         * omission on uClibc builds that lack numeric scope support. */
        error = getnameinfo((const struct sockaddr *)&sin6, sizeof(sin6),
                            address, sizeof(address), service, sizeof(service),
                            NI_DGRAM | NI_NUMERICHOST | NI_NUMERICSERV);
        if (error)
            return error == EAI_SYSTEM ? -1 :
                   fail(error == EAI_OVERFLOW ? EOVERFLOW :
                        error == EAI_MEMORY ? ENOMEM : EPROTO);
        n = snprintf(out, size, "[%s]:%s", address, service);
    } else {
        return fail(EPROTO);
    }
    if (n < 0 || (size_t)n >= size)
        return fail(EOVERFLOW);
    return 0;
}

static int allowedips(struct collection *c, const struct attribute *container)
{
    const unsigned char *p = container->data;
    size_t length = container->length;
    struct attribute item;
    int r;
    if (nested(container) < 0)
        return -1;
    while ((r = next_attr(c, &p, &length, &item)) > 0) {
        const unsigned char *q = item.data;
        size_t remaining = item.length, ip_size = 0;
        struct attribute a;
        uint16_t family = 0;
        uint8_t prefix = 0;
        unsigned int seen = 0;
        int s;
        if (nested(&item) < 0)
            return -1;
        while ((s = next_attr(c, &q, &remaining, &a)) > 0) {
            if (a.type > WGALLOWEDIP_A_UNSPEC && a.type <= WGALLOWEDIP_A_MAX) {
                unsigned int bit = 1U << a.type;
                if (seen & bit)
                    return fail(EPROTO);
                seen |= bit;
            }
            switch (a.type) {
            case WGALLOWEDIP_A_FAMILY:
                if (scalar(&a, sizeof(family)) < 0)
                    return -1;
                memcpy(&family, a.data, sizeof(family));
                break;
            case WGALLOWEDIP_A_IPADDR:
                if (a.flags || (a.length != 4 && a.length != 16))
                    return fail(EPROTO);
                ip_size = a.length;
                break;
            case WGALLOWEDIP_A_CIDR_MASK:
                if (scalar(&a, sizeof(prefix)) < 0)
                    return -1;
                memcpy(&prefix, a.data, sizeof(prefix));
                break;
            default:
                if ((a.flags & NLA_F_NESTED) &&
                    validate_tree(c, a.data, a.length, 0) < 0)
                    return -1;
            }
        }
        if (s < 0)
            return -1;
        if (seen != ((1U << WGALLOWEDIP_A_FAMILY) |
                     (1U << WGALLOWEDIP_A_IPADDR) |
                     (1U << WGALLOWEDIP_A_CIDR_MASK)) ||
            (family != AF_INET && family != AF_INET6) ||
            ip_size != (family == AF_INET ? 4U : 16U) ||
            prefix > (family == AF_INET ? 32U : 128U))
            return fail(EPROTO);
    }
    return r;
}

static int peer_attrs(struct collection *c, const struct attribute *container)
{
    const unsigned char *p = container->data;
    size_t length = container->length, i;
    struct attribute a;
    struct vpn_peer peer = {0}, *target;
    uint32_t seen = 0;
    bool key = false;
    int r;
    if (nested(container) < 0)
        return -1;
    while ((r = next_attr(c, &p, &length, &a)) > 0) {
        if (a.type > WGPEER_A_UNSPEC && a.type <= WGPEER_A_MAX) {
            uint32_t bit = UINT32_C(1) << a.type;
            if (seen & bit)
                return fail(EPROTO);
            seen |= bit;
        }
        switch (a.type) {
        case WGPEER_A_UNSPEC:
            if (scalar(&a, 0) < 0)
                return -1;
            break;
        case WGPEER_A_PUBLIC_KEY:
            if (scalar(&a, sizeof(peer.key)) < 0)
                return -1;
            memcpy(peer.key, a.data, sizeof(peer.key));
            key = true;
            break;
        case WGPEER_A_LAST_HANDSHAKE_TIME: {
            /* WireGuard UAPI uses two signed 64-bit values on every ABI. */
            int64_t ts[2];
            if (scalar(&a, sizeof(ts)) < 0)
                return -1;
            memcpy(ts, a.data, sizeof(ts));
            if (ts[0] < 0 || ts[1] < 0 || ts[1] >= 1000000000)
                return fail(EPROTO);
            peer.handshake = (uint64_t)ts[0];
            peer.has_handshake = true;
            break;
        }
        case WGPEER_A_RX_BYTES:
        case WGPEER_A_TX_BYTES:
            if (scalar(&a, sizeof(uint64_t)) < 0)
                return -1;
            if (a.type == WGPEER_A_RX_BYTES) {
                memcpy(&peer.rx, a.data, sizeof(peer.rx));
                peer.has_rx = true;
            } else {
                memcpy(&peer.tx, a.data, sizeof(peer.tx));
                peer.has_tx = true;
            }
            break;
        case WGPEER_A_ENDPOINT:
            if (endpoint(&a, peer.endpoint, sizeof(peer.endpoint)) < 0)
                return -1;
            peer.has_endpoint = true;
            break;
        case WGPEER_A_PRESHARED_KEY:
            if (scalar(&a, WG_KEY_LEN) < 0)
                return -1;
            break;
        case WGPEER_A_FLAGS:
        case WGPEER_A_PROTOCOL_VERSION:
            if (scalar(&a, sizeof(uint32_t)) < 0)
                return -1;
            break;
        case WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL:
            if (scalar(&a, sizeof(uint16_t)) < 0)
                return -1;
            break;
        case WGPEER_A_ALLOWEDIPS:
            if (allowedips(c, &a) < 0)
                return -1;
            break;
        default:
            if ((a.flags & NLA_F_NESTED) &&
                validate_tree(c, a.data, a.length, 0) < 0)
                return -1;
        }
    }
    if (r < 0)
        return -1;
    if (!key)
        return fail(EPROTO);
    for (i = 0; i < c->device->count; ++i) {
        if (charge(c) < 0)
            return -1;
        if (!memcmp(c->device->peers[i].key, peer.key, sizeof(peer.key)))
            break;
    }
    if (i == c->device->count) {
        if (i == VPN_MAX_PEERS)
            return fail(E2BIG);
        target = &c->device->peers[c->device->count++];
        memset(target, 0, sizeof(*target));
        memcpy(target->key, peer.key, sizeof(peer.key));
        /* wg show supplies defaults for live peers, unlike absent peer lookups. */
        target->has_handshake = target->has_rx = target->has_tx = target->has_endpoint = true;
        strcpy(target->endpoint, "(none)");
    } else {
        target = &c->device->peers[i];
    }
    if (peer.has_handshake) {
        target->handshake = peer.handshake;
        target->has_handshake = true;
    }
    if (peer.has_rx) {
        target->rx = peer.rx;
        target->has_rx = true;
    }
    if (peer.has_tx) {
        target->tx = peer.tx;
        target->has_tx = true;
    }
    if (peer.has_endpoint) {
        memcpy(target->endpoint, peer.endpoint, sizeof(peer.endpoint));
        target->has_endpoint = true;
    }
    return 0;
}

static int device_attrs(struct collection *c, const unsigned char *p, size_t length)
{
    struct attribute a;
    uint32_t seen = 0;
    int r;
    while ((r = next_attr(c, &p, &length, &a)) > 0) {
        if (a.type > WGDEVICE_A_UNSPEC && a.type <= WGDEVICE_A_MAX) {
            uint32_t bit = UINT32_C(1) << a.type;
            if (seen & bit)
                return fail(EPROTO);
            seen |= bit;
        }
        switch (a.type) {
        case WGDEVICE_A_UNSPEC:
            if (scalar(&a, 0) < 0)
                return -1;
            break;
        case WGDEVICE_A_IFINDEX: {
            uint32_t index;
            if (scalar(&a, sizeof(index)) < 0)
                return -1;
            memcpy(&index, a.data, sizeof(index));
            if (index != c->ifindex)
                return fail(ENODEV);
            c->identified = true;
            break;
        }
        case WGDEVICE_A_IFNAME:
            if (scalar(&a, sizeof("wg0")) < 0 ||
                memcmp(a.data, "wg0", sizeof("wg0")))
                return fail(EPROTO);
            c->identified = true;
            break;
        case WGDEVICE_A_LISTEN_PORT:
            if (scalar(&a, sizeof(c->device->port)) < 0)
                return -1;
            memcpy(&c->device->port, a.data, sizeof(c->device->port));
            break;
        case WGDEVICE_A_PEERS: {
            const unsigned char *q = a.data;
            size_t remaining = a.length;
            struct attribute item;
            int s;
            if (nested(&a) < 0)
                return -1;
            while ((s = next_attr(c, &q, &remaining, &item)) > 0)
                if (peer_attrs(c, &item) < 0)
                    return -1;
            if (s < 0)
                return -1;
            break;
        }
        case WGDEVICE_A_PRIVATE_KEY:
        case WGDEVICE_A_PUBLIC_KEY:
            if (scalar(&a, WG_KEY_LEN) < 0)
                return -1;
            break;
        case WGDEVICE_A_FLAGS:
        case WGDEVICE_A_FWMARK:
            if (scalar(&a, sizeof(uint32_t)) < 0)
                return -1;
            break;
        default:
            if ((a.flags & NLA_F_NESTED) &&
                validate_tree(c, a.data, a.length, 0) < 0)
                return -1;
        }
    }
    return r;
}

static int family_attrs(struct collection *c, const unsigned char *p, size_t length)
{
    struct attribute a;
    bool found = false;
    int r;
    while ((r = next_attr(c, &p, &length, &a)) > 0) {
        if (a.type == CTRL_ATTR_FAMILY_ID) {
            if (found || scalar(&a, sizeof(c->family)) < 0)
                return fail(EPROTO);
            memcpy(&c->family, a.data, sizeof(c->family));
            if (c->family < NLMSG_MIN_TYPE)
                return fail(EPROTO);
            found = true;
        } else if (a.type == CTRL_ATTR_FAMILY_NAME) {
            if (scalar(&a, sizeof(WG_GENL_NAME)) < 0 ||
                memcmp(a.data, WG_GENL_NAME, sizeof(WG_GENL_NAME)))
                return fail(EPROTO);
        } else if ((a.flags & NLA_F_NESTED) &&
                   validate_tree(c, a.data, a.length, 0) < 0) {
            return -1;
        }
    }
    if (r < 0)
        return -1;
    return found ? 0 : fail(EPROTO);
}

static int address_attrs(struct collection *c, const unsigned char *p, size_t length)
{
    struct ifaddrmsg info;
    struct attribute a;
    struct in_addr local = {0}, address = {0};
    bool has_local = false, has_address = false;
    int r;
    if (length < sizeof(info))
        return fail(EPROTO);
    memcpy(&info, p, sizeof(info));
    p += sizeof(info);
    length -= sizeof(info);
    if (info.ifa_family != AF_INET || info.ifa_prefixlen > 32)
        return fail(EPROTO);
    while ((r = next_attr(c, &p, &length, &a)) > 0) {
        if (a.type == IFA_LOCAL || a.type == IFA_ADDRESS) {
            if (scalar(&a, sizeof(local)) < 0)
                return -1;
            if (a.type == IFA_LOCAL) {
                if (has_local)
                    return fail(EPROTO);
                memcpy(&local, a.data, sizeof(local));
                has_local = true;
            } else {
                if (has_address)
                    return fail(EPROTO);
                memcpy(&address, a.data, sizeof(address));
                has_address = true;
            }
        } else if ((a.flags & NLA_F_NESTED) &&
                   validate_tree(c, a.data, a.length, 0) < 0) {
            return -1;
        }
    }
    if (r < 0)
        return -1;
    if (info.ifa_index == c->ifindex && !c->device->address[0] &&
        (has_local || has_address)) {
        char text[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, has_local ? &local : &address, text, sizeof(text)))
            return -1;
        r = snprintf(c->device->address, sizeof(c->device->address), "%s/%u",
                     text, (unsigned int)info.ifa_prefixlen);
        if (r < 0 || (size_t)r >= sizeof(c->device->address))
            return fail(EOVERFLOW);
    }
    return 0;
}

static int parse_datagram(struct collection *c, const unsigned char *p,
                          size_t length, const struct sockaddr_nl *sender,
                          socklen_t sender_length, int flags)
{
    if (flags & (MSG_TRUNC | MSG_CTRUNC))
        return fail(EMSGSIZE);
    if (sender_length != sizeof(*sender) || sender->nl_family != AF_NETLINK ||
        sender->nl_pid || sender->nl_groups)
        return fail(EPROTO);
    if (!length)
        return fail(EPROTO);
    if (++c->datagrams > MAX_DATAGRAMS || length > MAX_BYTES - c->bytes)
        return fail(E2BIG);
    c->bytes += length;
    while (length) {
        struct nlmsghdr h;
        const unsigned char *body;
        size_t size, padded;
        if (charge(c) < 0)
            return -1;
        if (length < sizeof(h))
            return fail(EPROTO);
        memcpy(&h, p, sizeof(h));
        if (h.nlmsg_len < sizeof(h) || h.nlmsg_len > length)
            return fail(EPROTO);
        padded = ((size_t)h.nlmsg_len + 3U) & ~(size_t)3U;
        if (padded > length || c->done || h.nlmsg_seq != c->sequence ||
            h.nlmsg_pid != c->portid)
            return fail(EPROTO);
        if (h.nlmsg_flags & NLM_F_DUMP_INTR)
            return fail(EINTR);
        if (h.nlmsg_flags & NLM_F_DUMP_FILTERED)
            return fail(EPROTO);
        body = p + sizeof(h);
        size = h.nlmsg_len - sizeof(h);
        if (h.nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr error;
            if (size < sizeof(error))
                return fail(EPROTO);
            memcpy(&error, body, sizeof(error));
            if (error.error > 0 || error.error < -4095)
                return fail(EPROTO);
            if (error.error)
                return fail(-error.error);
        } else if (h.nlmsg_type == NLMSG_DONE) {
            int error = 0;
            if (size != 0 && size != sizeof(error))
                return fail(EPROTO);
            if (size)
                memcpy(&error, body, sizeof(error));
            if (error > 0 || error < -4095)
                return fail(EPROTO);
            if (error)
                return fail(-error);
            if ((c->kind != ADDRESS_REPLY && !c->seen) ||
                (c->kind == DEVICE_REPLY && !c->identified) ||
                !(h.nlmsg_flags & NLM_F_MULTI))
                return fail(EPROTO);
            c->done = true;
        } else if (h.nlmsg_type == NLMSG_OVERRUN) {
            return fail(ENOBUFS);
        } else {
            if (c->kind == ADDRESS_REPLY) {
                if (h.nlmsg_type != RTM_NEWADDR || !(h.nlmsg_flags & NLM_F_MULTI))
                    return fail(EPROTO);
                if (address_attrs(c, body, size) < 0)
                    return -1;
            } else {
                struct genlmsghdr gen;
                if (h.nlmsg_type != (c->kind == FAMILY_REPLY ? GENL_ID_CTRL : c->family) ||
                    size < sizeof(gen))
                    return fail(EPROTO);
                memcpy(&gen, body, sizeof(gen));
                if (gen.reserved ||
                    gen.cmd != (c->kind == FAMILY_REPLY ? CTRL_CMD_NEWFAMILY : WG_CMD_GET_DEVICE) ||
                    gen.version != (c->kind == FAMILY_REPLY ? 2 : WG_GENL_VERSION))
                    return fail(EPROTO);
                if (c->kind == FAMILY_REPLY) {
                    if (c->seen)
                        return fail(EPROTO);
                    if (family_attrs(c, body + sizeof(gen), size - sizeof(gen)) < 0)
                        return -1;
                } else {
                    if (!(h.nlmsg_flags & NLM_F_MULTI))
                        return fail(EPROTO);
                    if (device_attrs(c, body + sizeof(gen), size - sizeof(gen)) < 0)
                        return -1;
                }
            }
            c->seen = true;
            c->multipart = (h.nlmsg_flags & NLM_F_MULTI) != 0;
            if (c->kind == FAMILY_REPLY && !c->multipart)
                c->done = true;
        }
        p += padded;
        length -= padded;
    }
    return 0;
}

static int open_netlink(int protocol, uint32_t *portid)
{
    struct sockaddr_nl address = {0};
    socklen_t length = sizeof(address);
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, protocol);
    if (fd < 0)
        return -1;
    address.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        getsockname(fd, (struct sockaddr *)&address, &length) < 0) {
        int error = errno;
        close(fd);
        return fail(error);
    }
    if (length != sizeof(address) || address.nl_family != AF_NETLINK ||
        !address.nl_pid || address.nl_groups) {
        close(fd);
        return fail(EPROTO);
    }
    *portid = address.nl_pid;
    return fd;
}

static int wait_socket(int fd, short events, struct collection *c)
{
    struct pollfd p = {fd, events, 0};
    int remaining = time_left(c), r;
    if (remaining < 0)
        return -1;
    r = poll(&p, 1, remaining);
    if (r < 0)
        return -1;
    if (!r)
        return fail(ETIMEDOUT);
    if (p.revents & (POLLERR | POLLHUP | POLLNVAL))
        return fail(EIO);
    if (!(p.revents & events))
        return fail(EIO);
    return 0;
}

static int exchange(int fd, struct collection *c, unsigned char *buffer,
                    const void *request, size_t request_size)
{
    struct sockaddr_nl kernel = {0};
    ssize_t n;
    kernel.nl_family = AF_NETLINK;
    c->done = c->seen = c->multipart = c->identified = false;
    if (wait_socket(fd, POLLOUT, c) < 0)
        return -1;
    n = sendto(fd, request, request_size, 0, (struct sockaddr *)&kernel, sizeof(kernel));
    if (n < 0)
        return -1;
    if ((size_t)n != request_size)
        return fail(EIO);
    while (!c->done) {
        struct sockaddr_nl sender = {0};
        struct iovec iov = {buffer, RECEIVE_SIZE};
        struct msghdr message = {0};
        int r, error;
        if (wait_socket(fd, POLLIN, c) < 0)
            return -1;
        message.msg_name = &sender;
        message.msg_namelen = sizeof(sender);
        message.msg_iov = &iov;
        message.msg_iovlen = 1;
        n = recvmsg(fd, &message, 0);
        if (n < 0)
            return -1;
        r = parse_datagram(c, buffer, (size_t)n, &sender,
                           message.msg_namelen, message.msg_flags);
        error = errno;
        clear_memory(buffer, RECEIVE_SIZE);
        if (r < 0)
            return fail(error);
        if (time_left(c) < 0)
            return -1;
    }
    return 0;
}

static size_t request_genl(unsigned char *buffer, struct collection *c,
                           uint16_t type, unsigned char command,
                           unsigned char version, uint16_t attr_type,
                           const void *value, size_t size, bool dump)
{
    struct nlmsghdr h = {0};
    struct genlmsghdr gen = {0};
    struct nlattr a;
    size_t length = sizeof(h) + sizeof(gen) + ((sizeof(a) + size + 3U) & ~(size_t)3U);
    memset(buffer, 0, length);
    h.nlmsg_len = (uint32_t)length;
    h.nlmsg_type = type;
    h.nlmsg_flags = NLM_F_REQUEST | (dump ? NLM_F_DUMP : 0);
    h.nlmsg_seq = ++c->sequence;
    h.nlmsg_pid = c->portid;
    gen.cmd = command;
    gen.version = version;
    a.nla_len = (uint16_t)(sizeof(a) + size);
    a.nla_type = attr_type;
    memcpy(buffer, &h, sizeof(h));
    memcpy(buffer + sizeof(h), &gen, sizeof(gen));
    memcpy(buffer + sizeof(h) + sizeof(gen), &a, sizeof(a));
    memcpy(buffer + sizeof(h) + sizeof(gen) + sizeof(a), value, size);
    return length;
}

int vpn_collect(struct vpn_device *device)
{
    struct collection c = {0};
    unsigned char request[128] = {0}, *buffer = NULL;
    int generic = -1, route = -1, error = 0;
    int64_t start;
    size_t length;
    unsigned int index;
    if (!device)
        return fail(EINVAL);
    memset(device, 0, sizeof(*device));
    c.device = device;
    start = now_ms();
    if (start < 0)
        return -1;
    c.deadline = start + COLLECTION_MS;
    errno = 0;
    index = if_nametoindex("wg0");
    if (!index) {
        if (errno == 0 || errno == ENODEV || errno == ENXIO)
            return 0;
        return -1;
    }
    c.ifindex = index;
    buffer = malloc(RECEIVE_SIZE);
    if (!buffer)
        goto failed;
    generic = open_netlink(NETLINK_GENERIC, &c.portid);
    if (generic < 0)
        goto failed;
    c.kind = FAMILY_REPLY;
    length = request_genl(request, &c, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 2,
                          CTRL_ATTR_FAMILY_NAME, WG_GENL_NAME, sizeof(WG_GENL_NAME), false);
    if (exchange(generic, &c, buffer, request, length) < 0)
        goto failed;
    c.kind = DEVICE_REPLY;
    length = request_genl(request, &c, c.family, WG_CMD_GET_DEVICE, WG_GENL_VERSION,
                          WGDEVICE_A_IFINDEX, &c.ifindex, sizeof(c.ifindex), true);
    if (exchange(generic, &c, buffer, request, length) < 0)
        goto failed;
    route = open_netlink(NETLINK_ROUTE, &c.portid);
    if (route < 0)
        goto failed;
    c.kind = ADDRESS_REPLY;
    {
        struct nlmsghdr h = {0};
        struct ifaddrmsg address = {0};
        length = sizeof(h) + sizeof(address);
        memset(request, 0, sizeof(request));
        h.nlmsg_len = (uint32_t)length;
        h.nlmsg_type = RTM_GETADDR;
        h.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        h.nlmsg_seq = ++c.sequence;
        h.nlmsg_pid = c.portid;
        address.ifa_family = AF_INET;
        /* Unfiltered IPv4 dump; select our interface only in the parser. */
        memcpy(request, &h, sizeof(h));
        memcpy(request + sizeof(h), &address, sizeof(address));
    }
    if (exchange(route, &c, buffer, request, length) < 0)
        goto failed;
    /* A route dump can finish after wg0 vanished: never return that snapshot. */
    index = if_nametoindex("wg0");
    if (!index || index != c.ifindex) {
        errno = ENODEV;
        goto failed;
    }
    if (time_left(&c) < 0)
        goto failed;
    device->running = true;
    goto finished;
failed:
    error = errno ? errno : EIO;
    clear_memory(device, sizeof(*device));
finished:
    if (generic >= 0)
        close(generic);
    if (route >= 0)
        close(route);
    if (buffer) {
        clear_memory(buffer, RECEIVE_SIZE);
        free(buffer);
    }
    clear_memory(request, sizeof(request));
    return error ? fail(error) : 0;
}
