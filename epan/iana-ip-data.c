/*
 * This file was generated by running ./tools/make-iana-ip.py.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "iana-ip.h"

_U_ static const struct ws_iana_ip_special_block __ipv4_special_block[] = {
    { 4, { .ipv4 = { 0x00000000, 0xff000000 } }, "\"This network\"", 1, 0, 0, 0, 1 },
    { 4, { .ipv4 = { 0x00000000, 0xffffffff } }, "\"This host on this network\"", 1, 0, 0, 0, 1 },
    { 4, { .ipv4 = { 0x0a000000, 0xff000000 } }, "Private-Use", 1, 1, 1, 0, 0 },
    { 4, { .ipv4 = { 0x64400000, 0xffc00000 } }, "Shared Address Space", 1, 1, 1, 0, 0 },
    { 4, { .ipv4 = { 0x7f000000, 0xff000000 } }, "Loopback", -1, -1, -1, -1, 1 },
    { 4, { .ipv4 = { 0xa9fe0000, 0xffff0000 } }, "Link Local", 1, 1, 0, 0, 1 },
    { 4, { .ipv4 = { 0xac100000, 0xfff00000 } }, "Private-Use", 1, 1, 1, 0, 0 },
    { 4, { .ipv4 = { 0xc0000000, 0xffffff00 } }, "IETF Protocol Assignments", 0, 0, 0, 0, 0 },
    { 4, { .ipv4 = { 0xc0000000, 0xfffffff8 } }, "IPv4 Service Continuity Prefix", 1, 1, 1, 0, 0 },
    { 4, { .ipv4 = { 0xc0000008, 0xffffffff } }, "IPv4 dummy address", 1, 0, 0, 0, 0 },
    { 4, { .ipv4 = { 0xc0000009, 0xffffffff } }, "Port Control Protocol Anycast", 1, 1, 1, 1, 0 },
    { 4, { .ipv4 = { 0xc000000a, 0xffffffff } }, "Traversal Using Relays around NAT Anycast", 1, 1, 1, 1, 0 },
    { 4, { .ipv4 = { 0xc00000aa, 0xffffffff } }, "NAT64/DNS64 Discovery", 0, 0, 0, 0, 1 },
    { 4, { .ipv4 = { 0xc00000ab, 0xffffffff } }, "NAT64/DNS64 Discovery", 0, 0, 0, 0, 1 },
    { 4, { .ipv4 = { 0xc0000200, 0xffffff00 } }, "Documentation (TEST-NET-1)", 0, 0, 0, 0, 0 },
    { 4, { .ipv4 = { 0xc01fc400, 0xffffff00 } }, "AS112-v4", 1, 1, 1, 1, 0 },
    { 4, { .ipv4 = { 0xc034c100, 0xffffff00 } }, "AMT", 1, 1, 1, 1, 0 },
    { 4, { .ipv4 = { 0xc0586302, 0xffffffff } }, "6a44-relay anycast address", 1, 1, 1, 0, 0 },
    { 4, { .ipv4 = { 0xc0a80000, 0xffff0000 } }, "Private-Use", 1, 1, 1, 0, 0 },
    { 4, { .ipv4 = { 0xc0af3000, 0xffffff00 } }, "Direct Delegation AS112 Service", 1, 1, 1, 1, 0 },
    { 4, { .ipv4 = { 0xc6120000, 0xfffe0000 } }, "Benchmarking", 1, 1, 1, 0, 0 },
    { 4, { .ipv4 = { 0xc6336400, 0xffffff00 } }, "Documentation (TEST-NET-2)", 0, 0, 0, 0, 0 },
    { 4, { .ipv4 = { 0xcb007100, 0xffffff00 } }, "Documentation (TEST-NET-3)", 0, 0, 0, 0, 0 },
    { 4, { .ipv4 = { 0xf0000000, 0xf0000000 } }, "Reserved", 0, 0, 0, 0, 1 },
    { 4, { .ipv4 = { 0xffffffff, 0xffffffff } }, "Limited Broadcast", 0, 1, 0, 0, 1 },
};

// GCC bug?
DIAG_OFF(missing-braces)
_U_ static const struct ws_iana_ip_special_block __ipv6_special_block[] = {
    { 6, { .ipv6 = { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 128 } },
            "Unspecified Address", 1, 0, 0, 0, 1 },
    { 6, { .ipv6 = { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }, 128 } },
            "Loopback Address", 0, 0, 0, 0, 1 },
    { 6, { .ipv6 = { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }, 96 } },
            "IPv4-mapped Address", 0, 0, 0, 0, 1 },
    { 6, { .ipv6 = { { 0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 96 } },
            "IPv4-IPv6 Translat.", 1, 1, 1, 1, 0 },
    { 6, { .ipv6 = { { 0x00, 0x64, 0xff, 0x9b, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 48 } },
            "IPv4-IPv6 Translat.", 1, 1, 1, 0, 0 },
    { 6, { .ipv6 = { { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 64 } },
            "Discard-Only Address Block", 1, 1, 1, 0, 0 },
    { 6, { .ipv6 = { { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 64 } },
            "Dummy IPv6 Prefix", 1, 0, 0, 0, 0 },
    { 6, { .ipv6 = { { 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 23 } },
            "IETF Protocol Assignments", -1, -1, -1, -1, 0 },
    { 6, { .ipv6 = { { 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 32 } },
            "TEREDO", 1, 1, 1, -1, 0 },
    { 6, { .ipv6 = { { 0x20, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }, 128 } },
            "Port Control Protocol Anycast", 1, 1, 1, 1, 0 },
    { 6, { .ipv6 = { { 0x20, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 }, 128 } },
            "Traversal Using Relays around NAT Anycast", 1, 1, 1, 1, 0 },
    { 6, { .ipv6 = { { 0x20, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, 128 } },
            "DNS-SD Service Registration Protocol Anycast", 1, 1, 1, 1, 0 },
    { 6, { .ipv6 = { { 0x20, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 48 } },
            "Benchmarking", 1, 1, 1, 0, 0 },
    { 6, { .ipv6 = { { 0x20, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 32 } },
            "AMT", 1, 1, 1, 1, 0 },
    { 6, { .ipv6 = { { 0x20, 0x01, 0x00, 0x04, 0x01, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 48 } },
            "AS112-v6", 1, 1, 1, 1, 0 },
    { 6, { .ipv6 = { { 0x20, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 28 } },
            "ORCHIDv2", 1, 1, 1, 1, 0 },
    { 6, { .ipv6 = { { 0x20, 0x01, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 28 } },
            "Drone Remote ID Protocol Entity Tags (DETs) Prefix", 1, 1, 1, 1, 0 },
    { 6, { .ipv6 = { { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 32 } },
            "Documentation", 0, 0, 0, 0, 0 },
    { 6, { .ipv6 = { { 0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16 } },
            "6to4", 1, 1, 1, -1, 0 },
    { 6, { .ipv6 = { { 0x26, 0x20, 0x00, 0x4f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 48 } },
            "Direct Delegation AS112 Service", 1, 1, 1, 1, 0 },
    { 6, { .ipv6 = { { 0x3f, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 20 } },
            "Documentation", 0, 0, 0, 0, 0 },
    { 6, { .ipv6 = { { 0x5f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16 } },
            "Segment Routing (SRv6) SIDs", 1, 1, 1, 0, 0 },
    { 6, { .ipv6 = { { 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 7 } },
            "Unique-Local", 1, 1, 1, -1, 0 },
    { 6, { .ipv6 = { { 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 10 } },
            "Link-Local Unicast", 1, 1, 0, 0, 1 },
};
DIAG_ON(missing-braces)
