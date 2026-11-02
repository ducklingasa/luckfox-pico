#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static unsigned int mock_if_nametoindex(const char *);
static int mock_socket(int, int, int);
static int mock_bind(int, const struct sockaddr *, socklen_t);
static int mock_getsockname(int, struct sockaddr *, socklen_t *);
static int mock_poll(struct pollfd *, nfds_t, int);
static ssize_t mock_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t mock_recvmsg(int, struct msghdr *, int);
static int mock_close(int);

/* Include the private parser, and replace I/O so tests never touch networking. */
#define if_nametoindex mock_if_nametoindex
#define socket mock_socket
#define bind mock_bind
#define getsockname mock_getsockname
#define poll mock_poll
#define sendto mock_sendto
#define recvmsg mock_recvmsg
#define close mock_close
#include "netlink.c"
#undef if_nametoindex
#undef socket
#undef bind
#undef getsockname
#undef poll
#undef sendto
#undef recvmsg
#undef close

struct fixture {
    unsigned char data[RECEIVE_SIZE];
    size_t length, message;
};

static struct vpn_device device;
static struct sockaddr_nl sender = { .nl_family = AF_NETLINK };
static unsigned int interface_calls, socket_calls, close_calls;
static int mock_mode, mock_stage;
static uint32_t mock_sequence;
static unsigned char *last_receive_buffer;
enum { MOCK_OK, MOCK_ABSENT, MOCK_DISAPPEAR, MOCK_TIMEOUT, MOCK_WG_ERROR };

static struct collection context(enum reply_kind kind)
{
    struct collection c = {0};
    memset(&device, 0, sizeof(device));
    c.device = &device;
    c.kind = kind;
    c.ifindex = 7;
    c.family = 30;
    c.portid = 42;
    c.sequence = 19;
    c.deadline = now_ms() + COLLECTION_MS;
    return c;
}

static void bytes(struct fixture *f, const void *data, size_t size)
{
    assert(f->length + size <= sizeof(f->data));
    memcpy(f->data + f->length, data, size);
    f->length += size;
}

static void begin_message(struct fixture *f, struct collection *c,
                          uint16_t type, uint16_t flags)
{
    struct nlmsghdr h = {0};
    f->message = f->length;
    h.nlmsg_type = type;
    h.nlmsg_flags = flags;
    h.nlmsg_seq = c->sequence;
    h.nlmsg_pid = c->portid;
    bytes(f, &h, sizeof(h));
}

static void end_message(struct fixture *f)
{
    uint32_t size = (uint32_t)(f->length - f->message);
    memcpy(f->data + f->message, &size, sizeof(size));
    while (f->length & 3U) {
        unsigned char zero = 0;
        bytes(f, &zero, 1);
    }
}

static size_t begin_attr(struct fixture *f, uint16_t type)
{
    struct nlattr a = { .nla_type = type };
    size_t offset = f->length;
    bytes(f, &a, sizeof(a));
    return offset;
}

static void end_attr(struct fixture *f, size_t offset)
{
    uint16_t size;
    assert(f->length - offset <= UINT16_MAX);
    size = (uint16_t)(f->length - offset);
    memcpy(f->data + offset, &size, sizeof(size));
    while (f->length & 3U) {
        unsigned char zero = 0;
        bytes(f, &zero, 1);
    }
}

static void attr(struct fixture *f, uint16_t type, const void *data, size_t size)
{
    size_t offset = begin_attr(f, type);
    bytes(f, data, size);
    end_attr(f, offset);
}

static void begin_device(struct fixture *f, struct collection *c)
{
    struct genlmsghdr gen = { .cmd = WG_CMD_GET_DEVICE, .version = WG_GENL_VERSION };
    begin_message(f, c, c->family, NLM_F_MULTI);
    bytes(f, &gen, sizeof(gen));
    if (!c->seen)
        attr(f, WGDEVICE_A_IFINDEX, &c->ifindex, sizeof(c->ifindex));
}

static void done(struct fixture *f, struct collection *c, int error)
{
    begin_message(f, c, NLMSG_DONE, NLM_F_MULTI);
    bytes(f, &error, sizeof(error));
    end_message(f);
}

static void key_attr(struct fixture *f, unsigned int id)
{
    unsigned char key[32] = {0};
    memcpy(key, &id, sizeof(id));
    attr(f, WGPEER_A_PUBLIC_KEY, key, sizeof(key));
}

static int parse(struct collection *c, struct fixture *f)
{
    errno = 0;
    return parse_datagram(c, f->data, f->length, &sender, sizeof(sender), 0);
}

static void bad(struct collection *c, struct fixture *f, int error)
{
    assert(parse(c, f) == -1);
    assert(errno == error);
}

static void test_fragments(void)
{
    struct collection c = context(DEVICE_REPLY);
    struct fixture f = {0};
    uint16_t port = 51820;
    uint64_t rx = UINT64_MAX, tx = 0;
    int64_t ts[2] = {0, 0};
    struct sockaddr_in sin = { .sin_family = AF_INET, .sin_port = htons(1234) };
    struct sockaddr_in6 sin6 = { .sin6_family = AF_INET6, .sin6_port = htons(65535) };
    unsigned char secret[32];
    size_t peers, peer;
    memset(secret, 0xa5, sizeof(secret));
    assert(inet_pton(AF_INET, "192.0.2.1", &sin.sin_addr) == 1);
    assert(inet_pton(AF_INET6, "2001:db8::1", &sin6.sin6_addr) == 1);
    begin_device(&f, &c);
    attr(&f, WGDEVICE_A_LISTEN_PORT, &port, sizeof(port));
    attr(&f, WGDEVICE_A_PRIVATE_KEY, secret, sizeof(secret));
    peers = begin_attr(&f, WGDEVICE_A_PEERS | NLA_F_NESTED);
    peer = begin_attr(&f, NLA_F_NESTED);
    key_attr(&f, 1);
    attr(&f, WGPEER_A_PRESHARED_KEY, secret, sizeof(secret));
    attr(&f, WGPEER_A_UNSPEC, secret, 0);
    attr(&f, WGPEER_A_RX_BYTES, &rx, sizeof(rx));
    attr(&f, WGPEER_A_UNSPEC, secret, 0);
    attr(&f, WGPEER_A_ENDPOINT, &sin, sizeof(sin));
    end_attr(&f, peer);
    peer = begin_attr(&f, NLA_F_NESTED);
    key_attr(&f, 2);
    end_attr(&f, peer);
    end_attr(&f, peers);
    end_message(&f);
    assert(parse(&c, &f) == 0 && !c.done);
    assert(device.count == 2);
    assert(device.peers[0].has_tx && device.peers[0].tx == 0);
    assert(device.peers[0].has_handshake && device.peers[0].handshake == 0);
    assert(!strcmp(device.peers[0].endpoint, "192.0.2.1:1234"));
    assert(device.peers[1].has_endpoint && !strcmp(device.peers[1].endpoint, "(none)"));
    assert(device.peers[1].has_handshake && device.peers[1].handshake == 0);
    assert(device.peers[1].has_rx && device.peers[1].rx == 0);
    assert(device.peers[1].has_tx && device.peers[1].tx == 0);

    memset(&f, 0, sizeof(f));
    begin_device(&f, &c);
    peers = begin_attr(&f, WGDEVICE_A_PEERS | NLA_F_NESTED);
    peer = begin_attr(&f, NLA_F_NESTED);
    /* Attribute order is immaterial: the key need not be first. */
    attr(&f, WGPEER_A_TX_BYTES, &tx, sizeof(tx));
    attr(&f, WGPEER_A_LAST_HANDSHAKE_TIME, ts, sizeof(ts));
    key_attr(&f, 1);
    attr(&f, WGPEER_A_ENDPOINT, &sin6, sizeof(sin6));
    end_attr(&f, peer);
    end_attr(&f, peers);
    end_message(&f);
    assert(parse(&c, &f) == 0 && !c.done);

    memset(&f, 0, sizeof(f));
    begin_device(&f, &c);
    peers = begin_attr(&f, WGDEVICE_A_PEERS | NLA_F_NESTED);
    peer = begin_attr(&f, NLA_F_NESTED);
    key_attr(&f, 1); /* A sparse continuation must not reset collected values. */
    end_attr(&f, peer);
    end_attr(&f, peers);
    end_message(&f);
    done(&f, &c, 0);
    assert(parse(&c, &f) == 0 && c.done);
    assert(device.count == 2 && device.port == port);
    assert(device.peers[0].has_rx && device.peers[0].rx == UINT64_MAX);
    assert(device.peers[0].has_tx && device.peers[0].tx == 0);
    assert(device.peers[0].has_handshake && device.peers[0].handshake == 0);
    assert(!strcmp(device.peers[0].endpoint, "[2001:db8::1]:65535"));
    assert(device.peers[1].has_rx && device.peers[1].rx == 0);
    assert(device.peers[1].has_handshake && device.peers[1].handshake == 0);
}

static void test_peer_errors(void)
{
    unsigned int test;
    for (test = 0; test < 11; ++test) {
        struct collection c = context(DEVICE_REPLY);
        struct fixture f = {0};
        uint64_t value = 1;
        int64_t ts[2] = {123, 0};
        size_t peers, peer;
        begin_device(&f, &c);
        peers = begin_attr(&f, WGDEVICE_A_PEERS | NLA_F_NESTED);
        peer = begin_attr(&f, NLA_F_NESTED);
        if (test != 0)
            key_attr(&f, 1);
        switch (test) {
        case 0: attr(&f, WGPEER_A_RX_BYTES, &value, sizeof(value)); break;
        case 1: attr(&f, WGPEER_A_RX_BYTES, &value, sizeof(value) - 1); break;
        case 2: key_attr(&f, 1); break;
        case 3: attr(&f, WGPEER_A_TX_BYTES | NLA_F_NET_BYTEORDER, &value, sizeof(value)); break;
        case 4: ts[0] = -1; attr(&f, WGPEER_A_LAST_HANDSHAKE_TIME, ts, sizeof(ts)); break;
        case 5: ts[1] = 1000000000; attr(&f, WGPEER_A_LAST_HANDSHAKE_TIME, ts, sizeof(ts)); break;
        case 6: attr(&f, WGPEER_A_PUBLIC_KEY + 100, &value, sizeof(value)); break;
        case 7: {
            unsigned char malformed[4] = {3, 0, 1, 0};
            attr(&f, WGPEER_A_ALLOWEDIPS | NLA_F_NESTED, malformed, sizeof(malformed));
            break;
        }
        case 8: attr(&f, WGPEER_A_PRESHARED_KEY, &value, sizeof(value)); break;
        case 9: attr(&f, WGPEER_A_LAST_HANDSHAKE_TIME, ts, sizeof(ts) - 1); break;
        case 10: {
            unsigned char key[33] = {0};
            /* Replace the first key rather than accidentally test only duplicates. */
            f.length = peer + sizeof(struct nlattr);
            attr(&f, WGPEER_A_PUBLIC_KEY, key, sizeof(key));
            break;
        }
        }
        end_attr(&f, peer);
        end_attr(&f, peers);
        end_message(&f);
        if (test == 6)
            assert(parse(&c, &f) == 0); /* Unknown scalar attrs are forward-compatible. */
        else
            bad(&c, &f, EPROTO);
    }
}

static void test_endpoints(void)
{
    unsigned int test;
    for (test = 0; test < 9; ++test) {
        struct collection c = context(DEVICE_REPLY);
        struct fixture f = {0};
        struct sockaddr_in6 sin6 = { .sin6_family = AF_INET6, .sin6_port = htons(9),
                                    .sin6_scope_id = UINT32_MAX };
        size_t peers, peer;
        assert(inet_pton(AF_INET6, "fe80::1", &sin6.sin6_addr) == 1);
        begin_device(&f, &c);
        peers = begin_attr(&f, WGDEVICE_A_PEERS | NLA_F_NESTED);
        peer = begin_attr(&f, NLA_F_NESTED);
        key_attr(&f, 1);
        if (test >= 6) {
            /* Read-only lookup of Linux's loopback zone, no interface changes. */
            sin6.sin6_scope_id = if_nametoindex("lo");
            assert(sin6.sin6_scope_id != 0);
            if (test == 7)
                assert(inet_pton(AF_INET6, "ff02::1", &sin6.sin6_addr) == 1);
            else if (test == 8)
                assert(inet_pton(AF_INET6, "2001:db8::1", &sin6.sin6_addr) == 1);
            attr(&f, WGPEER_A_ENDPOINT, &sin6, sizeof(sin6));
        } else if (test == 0)
            attr(&f, WGPEER_A_ENDPOINT, &sin6, sizeof(sin6));
        else if (test == 1)
            attr(&f, WGPEER_A_ENDPOINT, &sin6, sizeof(sin6) - 1);
        else if (test == 2) {
            sin6.sin6_family = AF_UNIX;
            attr(&f, WGPEER_A_ENDPOINT, &sin6, sizeof(sin6));
        } else if (test == 3)
            attr(&f, WGPEER_A_ENDPOINT, &sin6, 0);
        else if (test == 4) {
            sin6.sin6_family = AF_INET;
            attr(&f, WGPEER_A_ENDPOINT, &sin6, sizeof(sin6));
        } else
            attr(&f, WGPEER_A_ENDPOINT | NLA_F_NESTED, &sin6, sizeof(sin6));
        end_attr(&f, peer);
        end_attr(&f, peers);
        end_message(&f);
        if (!test || test >= 6) {
            /* Independent reference to bundled wg's formatter on this libc.
             * Named, global and unknown scopes intentionally inherit its ABI. */
            char host[4097], service[513], expected[4097 + 513 + 4];
            int n;
            assert(parse(&c, &f) == 0);
            assert(device.peers[0].has_endpoint);
            assert(getnameinfo((const struct sockaddr *)&sin6, sizeof(sin6),
                               host, sizeof(host), service, sizeof(service),
                               NI_DGRAM | NI_NUMERICHOST | NI_NUMERICSERV) == 0);
            n = snprintf(expected, sizeof(expected),
                         strchr(host, ':') ? "[%s]:%s" : "%s:%s", host, service);
            assert(n >= 0 && (size_t)n < sizeof(expected));
            assert(!strcmp(device.peers[0].endpoint, expected));
        } else {
            bad(&c, &f, EPROTO);
        }
    }
}

static void test_allowedips_and_attr_lengths(void)
{
    unsigned int test;
    for (test = 0; test < 6; ++test) {
        struct collection c = context(DEVICE_REPLY);
        struct fixture f = {0};
        uint16_t family = AF_INET;
        uint8_t prefix = test == 3 ? 33 : 24;
        unsigned char address[16] = {192, 0, 2, 1};
        size_t peers, peer, ips, ip;
        begin_device(&f, &c);
        peers = begin_attr(&f, WGDEVICE_A_PEERS | NLA_F_NESTED);
        peer = begin_attr(&f, NLA_F_NESTED);
        key_attr(&f, 1);
        ips = begin_attr(&f, WGPEER_A_ALLOWEDIPS | NLA_F_NESTED);
        ip = begin_attr(&f, NLA_F_NESTED);
        attr(&f, WGALLOWEDIP_A_FAMILY, &family, test == 1 ? 1 : sizeof(family));
        attr(&f, WGALLOWEDIP_A_IPADDR, address, test == 2 ? 16 : 4);
        if (test != 4)
            attr(&f, WGALLOWEDIP_A_CIDR_MASK, &prefix, sizeof(prefix));
        if (test == 5)
            attr(&f, WGALLOWEDIP_A_CIDR_MASK, &prefix, sizeof(prefix));
        end_attr(&f, ip);
        end_attr(&f, ips);
        end_attr(&f, peer);
        end_attr(&f, peers);
        end_message(&f);
        if (!test)
            assert(parse(&c, &f) == 0 && device.count == 1);
        else
            bad(&c, &f, EPROTO);
    }
    for (test = 0; test < 4; ++test) {
        struct collection c = context(DEVICE_REPLY);
        struct fixture f = {0};
        size_t offset;
        uint16_t malformed = test == 0 ? 0 : test == 1 ? 3 : test == 2 ? 1000 : 5;
        begin_device(&f, &c);
        offset = begin_attr(&f, WGDEVICE_A_LISTEN_PORT);
        end_attr(&f, offset);
        end_message(&f);
        memcpy(f.data + offset, &malformed, sizeof(malformed));
        bad(&c, &f, EPROTO);
    }
    {
        struct collection c = context(DEVICE_REPLY);
        struct fixture f = {0};
        struct genlmsghdr gen = { .cmd = WG_CMD_GET_DEVICE, .version = WG_GENL_VERSION };
        begin_message(&f, &c, c.family, NLM_F_MULTI);
        bytes(&f, &gen, sizeof(gen));
        end_message(&f);
        done(&f, &c, 0);
        bad(&c, &f, EPROTO); /* No matching device identity in the entire dump. */
    }
}

static void test_message_errors(void)
{
    unsigned int test;
    for (test = 0; test < 17; ++test) {
        struct collection c = context(DEVICE_REPLY);
        struct fixture f = {0};
        struct nlmsghdr h;
        int error = EPROTO;
        begin_device(&f, &c);
        end_message(&f);
        memcpy(&h, f.data, sizeof(h));
        switch (test) {
        case 0: h.nlmsg_len = 15; break;
        case 1: h.nlmsg_len = 100; break;
        case 2: h.nlmsg_seq++; break;
        case 3: h.nlmsg_pid = 0; break;
        case 4: h.nlmsg_flags |= NLM_F_DUMP_INTR; error = EINTR; break;
        case 5: h.nlmsg_flags = 0; break;
        case 6: h.nlmsg_type = NLMSG_NOOP; break;
        case 7: h.nlmsg_type = NLMSG_OVERRUN; error = ENOBUFS; break;
        case 8: c.done = true; break;
        case 9: h.nlmsg_flags |= NLM_F_DUMP_FILTERED; break;
        case 10: f.length--; break;
        case 11: c.datagrams = MAX_DATAGRAMS; error = E2BIG; break;
        case 12: c.bytes = MAX_BYTES; error = E2BIG; break;
        case 13: c.work = MAX_WORK; error = E2BIG; break;
        case 14: f.data[sizeof(h) + 2] = 1; break;
        case 15: f.data[sizeof(h)] = WG_CMD_SET_DEVICE; break;
        case 16: f.data[sizeof(h) + 1] = 99; break;
        }
        memcpy(f.data, &h, sizeof(h));
        bad(&c, &f, error);
    }
    {
        struct collection c = context(DEVICE_REPLY);
        struct fixture f = {0};
        struct sockaddr_nl user = sender;
        begin_device(&f, &c);
        end_message(&f);
        user.nl_pid = 123;
        assert(parse_datagram(&c, f.data, f.length, &user, sizeof(user), 0) < 0);
        assert(errno == EPROTO);
        assert(parse_datagram(&c, f.data, f.length, &sender, sizeof(sender) - 1, 0) < 0);
        assert(errno == EPROTO);
        assert(parse_datagram(&c, f.data, f.length, &sender, sizeof(sender), MSG_TRUNC) < 0);
        assert(errno == EMSGSIZE);
        assert(parse_datagram(&c, f.data, f.length, &sender, sizeof(sender), MSG_CTRUNC) < 0);
        assert(errno == EMSGSIZE);
        assert(parse_datagram(&c, f.data, 0, &sender, sizeof(sender), 0) < 0);
        assert(errno == EPROTO);
    }
}

static void test_done_and_kernel_errors(void)
{
    unsigned int test;
    for (test = 0; test < 8; ++test) {
        struct collection c = context(DEVICE_REPLY);
        struct fixture f = {0};
        struct nlmsgerr e = {0};
        int expected = EPROTO;
        if (test < 4) {
            begin_message(&f, &c, NLMSG_ERROR, 0);
            e.error = test == 0 ? -ENODEV : test == 1 ? 1 : test == 2 ? -5000 : 0;
            bytes(&f, &e, test == 3 ? sizeof(e) - 1 : sizeof(e));
            end_message(&f);
            if (!test)
                expected = ENODEV;
        } else {
            if (test != 4) {
                begin_device(&f, &c);
                end_message(&f);
            }
            done(&f, &c, test == 5 ? -EIO : test == 6 ? 1 : 0);
            if (test == 5)
                expected = EIO;
            if (test == 7) {
                assert(parse(&c, &f) == 0 && c.done);
                continue;
            }
        }
        bad(&c, &f, expected);
    }
    {
        struct collection c = context(DEVICE_REPLY);
        struct fixture f = {0};
        struct nlmsgerr ack = {0};
        begin_message(&f, &c, NLMSG_ERROR, 0);
        bytes(&f, &ack, sizeof(ack));
        end_message(&f);
        assert(parse(&c, &f) == 0 && !c.done);
        c.deadline = now_ms();
        assert(time_left(&c) < 0 && errno == ETIMEDOUT);
    }
}

static void test_kernel_sender_requester_pid(void)
{
    struct collection c = context(ADDRESS_REPLY);
    struct fixture f = {0};
    c.portid = UINT32_C(123456789);
    done(&f, &c, 0);
    assert(sender.nl_pid == 0);
    assert(parse(&c, &f) == 0 && c.done);

    c = context(ADDRESS_REPLY);
    /* A kernel sender is not sufficient if the response targets another port. */
    bad(&c, &f, EPROTO);
}

static void test_max_peers(void)
{
    struct collection c = context(DEVICE_REPLY);
    unsigned int batch;
    for (batch = 0; batch < VPN_MAX_PEERS / 64 + 1; ++batch) {
        struct fixture f = {0};
        size_t peers;
        unsigned int i, count = batch == VPN_MAX_PEERS / 64 ? 1 : 64;
        begin_device(&f, &c);
        peers = begin_attr(&f, WGDEVICE_A_PEERS | NLA_F_NESTED);
        for (i = 0; i < count; ++i) {
            size_t peer = begin_attr(&f, NLA_F_NESTED);
            key_attr(&f, batch * 64 + i);
            end_attr(&f, peer);
        }
        end_attr(&f, peers);
        end_message(&f);
        if (batch == VPN_MAX_PEERS / 64)
            bad(&c, &f, E2BIG);
        else
            assert(parse(&c, &f) == 0);
    }
    assert(device.count == VPN_MAX_PEERS);
    {
        struct fixture f = {0};
        size_t peers, peer;
        begin_device(&f, &c);
        peers = begin_attr(&f, WGDEVICE_A_PEERS | NLA_F_NESTED);
        peer = begin_attr(&f, NLA_F_NESTED);
        key_attr(&f, 0);
        end_attr(&f, peer);
        end_attr(&f, peers);
        end_message(&f);
        done(&f, &c, 0);
        assert(parse(&c, &f) == 0 && c.done);
        assert(device.count == VPN_MAX_PEERS);
    }
}

static void add_address(struct fixture *f, struct collection *c, unsigned int index,
                        const char *ip, const char *local)
{
    struct ifaddrmsg info = { .ifa_family = AF_INET, .ifa_prefixlen = 24 };
    struct in_addr address;
    info.ifa_index = index;
    begin_message(f, c, RTM_NEWADDR, NLM_F_MULTI);
    bytes(f, &info, sizeof(info));
    assert(inet_pton(AF_INET, ip, &address) == 1);
    attr(f, IFA_ADDRESS, &address, sizeof(address));
    if (local) {
        assert(inet_pton(AF_INET, local, &address) == 1);
        attr(f, IFA_LOCAL, &address, sizeof(address));
    }
    end_message(f);
}

static void test_addresses_and_family(void)
{
    struct collection c = context(ADDRESS_REPLY);
    struct fixture f = {0};
    uint16_t family = 30;
    struct genlmsghdr gen = { .cmd = CTRL_CMD_NEWFAMILY, .version = 2 };
    add_address(&f, &c, 8, "192.0.2.1", NULL);
    add_address(&f, &c, 7, "192.0.2.2", "192.0.2.3");
    add_address(&f, &c, 7, "192.0.2.4", NULL);
    done(&f, &c, 0);
    assert(parse(&c, &f) == 0 && c.done);
    assert(!strcmp(device.address, "192.0.2.3/24"));
    c = context(ADDRESS_REPLY);
    memset(&f, 0, sizeof(f));
    done(&f, &c, 0);
    assert(parse(&c, &f) == 0 && !device.address[0]);
    c = context(ADDRESS_REPLY);
    memset(&f, 0, sizeof(f));
    add_address(&f, &c, 7, "192.0.2.1", NULL);
    f.data[sizeof(struct nlmsghdr) + 1] = 33;
    bad(&c, &f, EPROTO);
    c = context(FAMILY_REPLY);
    memset(&f, 0, sizeof(f));
    begin_message(&f, &c, GENL_ID_CTRL, 0);
    bytes(&f, &gen, sizeof(gen));
    attr(&f, CTRL_ATTR_FAMILY_ID, &family, sizeof(family));
    attr(&f, CTRL_ATTR_FAMILY_NAME, WG_GENL_NAME, sizeof(WG_GENL_NAME));
    end_message(&f);
    assert(parse(&c, &f) == 0 && c.done && c.family == 30);
    c = context(FAMILY_REPLY);
    memset(&f, 0, sizeof(f));
    begin_message(&f, &c, GENL_ID_CTRL, 0);
    bytes(&f, &gen, sizeof(gen));
    end_message(&f);
    bad(&c, &f, EPROTO);
}

static unsigned int mock_if_nametoindex(const char *name)
{
    assert(!strcmp(name, "wg0"));
    ++interface_calls;
    if (mock_mode == MOCK_ABSENT || (mock_mode == MOCK_DISAPPEAR && interface_calls > 1)) {
        errno = ENODEV;
        return 0;
    }
    return 7;
}

static int mock_socket(int domain, int type, int protocol)
{
    assert(domain == AF_NETLINK && (type & SOCK_NONBLOCK));
    assert(protocol == NETLINK_GENERIC || protocol == NETLINK_ROUTE);
    ++socket_calls;
    return protocol == NETLINK_GENERIC ? 10 : 11;
}

static int mock_bind(int fd, const struct sockaddr *address, socklen_t size)
{
    (void)fd;
    assert(size == sizeof(struct sockaddr_nl));
    assert(address->sa_family == AF_NETLINK);
    return 0;
}

static int mock_getsockname(int fd, struct sockaddr *address, socklen_t *size)
{
    struct sockaddr_nl local = { .nl_family = AF_NETLINK, .nl_pid = 42 };
    (void)fd;
    assert(*size == sizeof(local));
    memcpy(address, &local, sizeof(local));
    return 0;
}

static int mock_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    assert(count == 1 && timeout > 0 && timeout <= COLLECTION_MS);
    if (mock_mode == MOCK_TIMEOUT)
        return 0;
    fds->revents = fds->events;
    return 1;
}

static ssize_t mock_sendto(int fd, const void *data, size_t size, int flags,
                           const struct sockaddr *address, socklen_t address_size)
{
    struct nlmsghdr h;
    (void)fd;
    assert(flags == 0 && address_size == sizeof(struct sockaddr_nl));
    assert(address->sa_family == AF_NETLINK);
    memcpy(&h, data, sizeof(h));
    mock_sequence = h.nlmsg_seq;
    mock_stage = h.nlmsg_type == GENL_ID_CTRL ? 0 : h.nlmsg_type == RTM_GETADDR ? 2 : 1;
    return (ssize_t)size;
}

static ssize_t mock_recvmsg(int fd, struct msghdr *message, int flags)
{
    struct collection c = {0};
    struct fixture f = {0};
    (void)fd;
    assert(flags == 0);
    c.sequence = mock_sequence;
    c.portid = 42;
    c.family = 30;
    c.ifindex = 7;
    if (mock_stage == 0) {
        struct genlmsghdr gen = { .cmd = CTRL_CMD_NEWFAMILY, .version = 2 };
        uint16_t family = 30;
        begin_message(&f, &c, GENL_ID_CTRL, 0);
        bytes(&f, &gen, sizeof(gen));
        attr(&f, CTRL_ATTR_FAMILY_ID, &family, sizeof(family));
        end_message(&f);
    } else if (mock_stage == 1 && mock_mode == MOCK_WG_ERROR) {
        struct nlmsgerr error = { .error = -ENODEV };
        begin_message(&f, &c, NLMSG_ERROR, 0);
        bytes(&f, &error, sizeof(error));
        end_message(&f);
    } else if (mock_stage == 1) {
        size_t peers, peer;
        begin_device(&f, &c);
        peers = begin_attr(&f, WGDEVICE_A_PEERS | NLA_F_NESTED);
        peer = begin_attr(&f, NLA_F_NESTED);
        key_attr(&f, 1);
        end_attr(&f, peer);
        end_attr(&f, peers);
        end_message(&f);
        done(&f, &c, 0);
    } else {
        add_address(&f, &c, 7, "192.0.2.1", NULL);
        done(&f, &c, 0);
    }
    assert(message->msg_iov[0].iov_len >= f.length);
    memcpy(message->msg_iov[0].iov_base, f.data, f.length);
    last_receive_buffer = message->msg_iov[0].iov_base;
    memcpy(message->msg_name, &sender, sizeof(sender));
    message->msg_namelen = sizeof(sender);
    message->msg_flags = 0;
    return (ssize_t)f.length;
}

static int mock_close(int fd)
{
    size_t i;
    assert(fd == 10 || fd == 11);
    if (last_receive_buffer)
        for (i = 0; i < RECEIVE_SIZE; ++i)
            assert(last_receive_buffer[i] == 0);
    ++close_calls;
    return 0;
}

static void test_collect(void)
{
    int mode;
    assert(vpn_collect(NULL) < 0 && errno == EINVAL);
    for (mode = MOCK_OK; mode <= MOCK_WG_ERROR; ++mode) {
        int r;
        const unsigned char *p = (const unsigned char *)&device;
        size_t i;
        mock_mode = mode;
        interface_calls = socket_calls = close_calls = 0;
        last_receive_buffer = NULL;
        memset(&device, 0xff, sizeof(device));
        r = vpn_collect(&device);
        assert(close_calls == socket_calls);
        if (mode == MOCK_OK) {
            assert(r == 0 && device.running && device.count == 1);
            assert(!strcmp(device.address, "192.0.2.1/24"));
            assert(device.peers[0].has_handshake && device.peers[0].handshake == 0);
            assert(device.peers[0].has_rx && device.peers[0].rx == 0);
            assert(device.peers[0].has_tx && device.peers[0].tx == 0);
            assert(device.peers[0].has_endpoint && !strcmp(device.peers[0].endpoint, "(none)"));
        } else {
            assert(r == (mode == MOCK_ABSENT ? 0 : -1));
            if (mode == MOCK_TIMEOUT)
                assert(errno == ETIMEDOUT);
            else if (mode != MOCK_ABSENT)
                assert(errno == ENODEV);
            if (mode == MOCK_ABSENT)
                assert(socket_calls == 0);
            for (i = 0; i < sizeof(device); ++i)
                assert(p[i] == 0);
        }
    }
    {
        unsigned char memory[32];
        size_t i;
        memset(memory, 0xa5, sizeof(memory));
        clear_memory(memory, sizeof(memory));
        for (i = 0; i < sizeof(memory); ++i)
            assert(memory[i] == 0);
    }
}

int main(void)
{
    test_fragments();
    test_peer_errors();
    test_endpoints();
    test_allowedips_and_attr_lengths();
    test_message_errors();
    test_done_and_kernel_errors();
    test_kernel_sender_requester_pid();
    test_max_peers();
    test_addresses_and_family();
    test_collect();
    puts("netlink parser and bounded collector tests passed");
    return 0;
}
