/*
 * ipxbox - Userspace IPX adapter for DOSBox
 *
 * Copyright (c) 2014 Vitaly Sinilin
 */

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "ipx.h"
#include "log.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define DEFAULT_UDP_PORT 213
#define IPX_BUF_SZ 65536
#define UDP_BUF_SZ 65536
#define MAC_ADDR_SZ 6

#define FRAME_TYPES_TABLE \
    X(FRAME_802_3,       "802.3",      ETH_P_802_3 ) \
    X(FRAME_802_2,       "802.2",      ETH_P_802_2, 0xE0, 0xE0, 0x03 ) \
    X(FRAME_802_2_SNAP,  "802.2SNAP",  ETH_P_802_2, 0xAA, 0xAA, 0x03, 0, 0, 0, 0x81, 0x37 ) \
    X(FRAME_ETHERNET_II, "EthernetII", ETH_P_IPX )

static const struct
{
    const char *name;
    int proto;
    const char *hdr;
    size_t hdr_sz;
} g_frame_types[] =
{
#define X(_id, _name, _proto, ...) \
    { .name = _name, \
      .proto = _proto, \
      .hdr = (const char []){ __VA_ARGS__ }, \
      .hdr_sz = sizeof((const char []){ __VA_ARGS__}) },
    FRAME_TYPES_TABLE
#undef X
};

enum frame_type_id
{
#define X(id, name, proto, ...) id,
    FRAME_TYPES_TABLE
#undef X
};

static int g_ipx_sock;
static int g_udp_sock;
static int g_udp_port = DEFAULT_UDP_PORT;
static unsigned int g_ipx_ifindex;
static int g_is_client_registered;
static int g_frame_type = FRAME_802_2_SNAP;

static const char *g_extra_hdr;
static size_t g_extra_hdr_sz;

static union ipx_node g_my_node;
static union ipx_node g_client_node;
static struct sockaddr_in g_client_addr;

static void forward_packet_to_udp(const char *buf, size_t sz)
{
    if (sz != sendto(g_udp_sock, buf, sz, 0,
                     (const struct sockaddr *)&g_client_addr,
                     sizeof(g_client_addr)))
    {
        warn_errno("Unable to send IPX->UDP packet");
    }
}

static void forward_packet_to_ipx(const char *buf, size_t sz)
{
    struct sockaddr_ll dst_addr =
    {
        .sll_family = AF_PACKET,
        .sll_ifindex = g_ipx_ifindex,
        .sll_protocol = htons(g_frame_type),
        .sll_halen = MAC_ADDR_SZ
    };
    struct iovec iov[] =
    {
        { (void *)g_extra_hdr, g_extra_hdr_sz },
        { (void *)buf,         sz             },
    };
    struct msghdr msg =
    {
        .msg_name = &dst_addr,
        .msg_namelen = sizeof(dst_addr),
        .msg_iov = iov,
        .msg_iovlen = ARRAY_SIZE(iov),
    };
    struct ipx_hdr *hdr = (struct ipx_hdr *)buf;

    memcpy(&dst_addr.sll_addr, &hdr->dst_addr.node, MAC_ADDR_SZ);

    if ((sz + g_extra_hdr_sz) != sendmsg(g_ipx_sock, &msg, 0))
    {
        warn_errno("Unable to send UDP->IPX packet");
    }
}

static void recv_ipx_packet(void)
{
    struct sockaddr_ll src_addr;
    socklen_t src_addr_len = sizeof(src_addr);
    char buf[IPX_BUF_SZ];
    ssize_t ret = recvfrom(g_ipx_sock, buf, sizeof(buf), 0,
                           (struct sockaddr *)&src_addr,
                           &src_addr_len);

    if (-1 != ret)
    {
        if (ret >= g_extra_hdr_sz + sizeof(struct ipx_hdr))
        {
            if (g_extra_hdr_sz == 0 || !memcmp(buf, g_extra_hdr, g_extra_hdr_sz))
            {
                struct ipx_hdr *hdr = (struct ipx_hdr *)(buf + g_extra_hdr_sz);
                size_t sz = ret - g_extra_hdr_sz;

                if (0xFFFF == hdr->chksum)
                {
                    debug("Received IPX packet of size %d from "
                          "%02X:%02X:%02X:%02X:%02X:%02X",
                          ret,
                          src_addr.sll_addr[0],
                          src_addr.sll_addr[1],
                          src_addr.sll_addr[2],
                          src_addr.sll_addr[3],
                          src_addr.sll_addr[4],
                          src_addr.sll_addr[5]);

                    if (g_is_client_registered)
                    {
                        forward_packet_to_udp((char *)hdr, sz);
                    }
                    else
                    {
                        warn("Ignore IPX packet since client is not "
                             "registered so far");
                    }
                }
            }
        }
    }
    else
    {
        warn_errno("Unable to read from IPX socket");
    }
}

static int is_dosbox_registration_request(const struct ipx_hdr *hdr)
{
    const char nullnode[IPX_NODE_SZ] = { 0 };

    return hdr->transport_control == 0
           && hdr->pkt_len == htons(30)
           && hdr->src_addr.net == 0
           && hdr->dst_addr.net == 0
           && hdr->src_addr.sock == htons(2)
           && hdr->dst_addr.sock == htons(2)
           && !memcmp(&hdr->src_addr.node, nullnode, sizeof(nullnode))
           && !memcmp(&hdr->dst_addr.node, nullnode, sizeof(nullnode));
}

static void send_dosbox_registration_response(void)
{
    struct ipx_hdr hdr =
    {
        .chksum = 0xFFFF,
        .pkt_len = htons(30),
        .transport_control = 0,
        .pkt_type = 2,
        .dst_addr = { .node = g_client_node, .sock = htons(2) },
        .src_addr = { .node = g_my_node,     .sock = htons(2) }
    };

    if (sizeof(hdr) != sendto(g_udp_sock, &hdr, sizeof(hdr), 0,
                              (struct sockaddr *)&g_client_addr,
                              sizeof(g_client_addr)))
    {
        warn_errno("Unable to send registration response");
    }
}

static void recv_udp_packet(void)
{
    struct sockaddr_in src_addr;
    socklen_t src_addr_len = sizeof(src_addr);
    char buf[UDP_BUF_SZ];
    struct ipx_hdr *hdr = (struct ipx_hdr *)buf;
    ssize_t ret = recvfrom(g_udp_sock, buf, sizeof(buf), 0,
                           (struct sockaddr *)&src_addr, &src_addr_len);

    if (-1 != ret)
    {
        debug("Received UDP packet of size %u from %s:%u",
              ret, inet_ntoa(src_addr.sin_addr), src_addr.sin_port);

        if (ret >= sizeof(struct ipx_hdr))
        {
            if (is_dosbox_registration_request(hdr))
            {
                info("Received registration request from %s:%u",
                     inet_ntoa(src_addr.sin_addr), src_addr.sin_port);
                g_client_addr = src_addr;
                g_is_client_registered = 1;
                send_dosbox_registration_response();
            }
            else
            {
                forward_packet_to_ipx(buf, ret);
            }
        }
    }
    else
    {
        warn_errno("Unable to read from UDP socket");
    }
}

static void init_client_node(int fd, const char *ifname)
{
    struct ifreq req;

    memset(&req, '\0', sizeof(req));
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name) - 1);

    if (0 != ioctl(fd, SIOCGIFHWADDR, &req))
    {
        crit_errno("Unable to obtain MAC address of %s", ifname);
    }

    memcpy(&g_client_node, req.ifr_hwaddr.sa_data, MAC_ADDR_SZ);
}

static unsigned int get_if_index(const char *ifname)
{
    unsigned int ifindex = if_nametoindex(ifname);

    if (0 == ifindex)
    {
        crit_errno("Unable to obtain index of interface %s", ifname);
    }

    return ifindex;
}

static void setup_frame_type(void)
{
    g_extra_hdr = g_frame_types[g_frame_type].hdr;
    g_extra_hdr_sz = g_frame_types[g_frame_type].hdr_sz;
}

static enum frame_type_id parse_frame_type(const char *str)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(g_frame_types); i++)
    {
        if (!strcmp(g_frame_types[i].name, str))
        {
            return i;
        }
    }

    warn("Unknown frame type %s, supported types are:", str);

    for (i = 0; i < ARRAY_SIZE(g_frame_types); i++)
    {
        warn("  %s", g_frame_types[i].name);
    }

    exit(EXIT_FAILURE);
    return FRAME_802_2_SNAP;
}

static int get_ipx_udp_port(void)
{
    struct servent *se = getservbyname("ipx", "udp");
    endservent();

    if (se)
    {
        return ntohs(se->s_port);
    }
    else
    {
        warn("Unable to determine IPX over UDP port, use %i", DEFAULT_UDP_PORT);
        return DEFAULT_UDP_PORT;
    }
}

int main(int argc, char **argv)
{
    if (argc != 2 && argc != 3)
    {
        crit("usage: ipxbox <ipxif> [frame_type]");
    }

    if (argc == 3)
    {
        g_frame_type = parse_frame_type(argv[2]);
    }

    setup_frame_type();

    g_ipx_sock = socket(AF_PACKET, SOCK_DGRAM,
                        htons(g_frame_types[g_frame_type].proto));

    if (-1 == g_ipx_sock)
    {
        crit_errno("Unable to open IPX socket");
    }

    g_udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (-1 == g_udp_sock)
    {
        crit_errno("Unable to open UDP socket");
    }

    g_udp_port = get_ipx_udp_port();

    struct sockaddr_in udp_addr =
    {
        .sin_family = AF_INET,
        .sin_port = htons(g_udp_port),
        .sin_addr = htonl(0x7F000001) /* 127.0.0.1 */
    };

    if (0 != bind(g_udp_sock, (struct sockaddr *)&udp_addr, sizeof(udp_addr)))
    {
        crit_errno("Unable to bind UDP socket");
    }

    g_my_node.map.port = g_udp_port;
    g_ipx_ifindex = get_if_index(argv[1]);
    init_client_node(g_ipx_sock, argv[1]);

    int nfds = g_ipx_sock > g_udp_sock ? g_ipx_sock + 1 : g_udp_sock + 1;

    for (;;)
    {
        fd_set sock_set;
        FD_ZERO(&sock_set);
        FD_SET(g_ipx_sock, &sock_set);
        FD_SET(g_udp_sock, &sock_set);
        int count = select(nfds, &sock_set, NULL, NULL, NULL);
        if (count > 0)
        {
            if (FD_ISSET(g_ipx_sock, &sock_set))
            {
                recv_ipx_packet();
            }
            if (FD_ISSET(g_udp_sock, &sock_set))
            {
                recv_udp_packet();
            }
        }
        else if (-1 == count)
        {
            warn_errno("select() error");
        }
    }

    exit(EXIT_SUCCESS);
}
