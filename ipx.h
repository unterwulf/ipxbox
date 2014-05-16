/*
 * ipxbox - Userspace IPX adapter for DOSBox
 *
 * Copyright (c) 2014 Vitaly Sinilin
 */

#ifndef IPX_H
#define IPX_H

#include <stdint.h>

#define IPX_HDR_SZ        30
#define IPX_NODE_SZ       6
#define IPX_PKT_TYPE_ECHO 0x02
#define IPX_SOCK_ECHO     0x0002

union ipx_node
{
    uint8_t octets[IPX_NODE_SZ];
    struct __attribute__ ((__packed__))
    {
        uint32_t ip_addr;
        uint16_t port;
    } map;
} __attribute__ ((__packed__));

struct ipx_addr
{
    uint32_t        net;
    union ipx_node  node;
    uint16_t        sock;
} __attribute__ ((__packed__));

struct ipx_hdr
{
    uint16_t        chksum;
    uint16_t        pkt_len; // including the IPX header
    uint8_t         transport_control;
    uint8_t         pkt_type;
    struct ipx_addr dst_addr;
    struct ipx_addr src_addr;
} __attribute__ ((__packed__));

#endif
