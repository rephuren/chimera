#include <arpa/inet.h>
#include <string.h>

#include "chimera.h"

static uint16_t be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }

static int decode_ipv4(const uint8_t *p, size_t len, decoded_t *o);
static int decode_ipv6(const uint8_t *p, size_t len, decoded_t *o);

static int decode_l4(uint8_t proto, const uint8_t *p, size_t len, decoded_t *o) {
    o->proto = proto;
    if (proto == 6) {
        if (len < 20) return -2;
        size_t off = (size_t)(p[12] >> 4) * 4;
        if (off < 20 || off > len) return -2;
        o->sport = be16(p);
        o->dport = be16(p + 2);
        o->tcp_flags = p[13];
        o->payload = p + off;
        o->payload_len = len - off;
    } else if (proto == 17) {
        if (len < 8) return -2;
        o->sport = be16(p);
        o->dport = be16(p + 2);
        o->payload = p + 8;
        o->payload_len = len - 8;
    }
    return 0;
}

static int decode_ipv4(const uint8_t *p, size_t len, decoded_t *o) {
    if (len < 20) return -2;
    size_t ihl = (size_t)(p[0] & 0x0f) * 4;
    if (ihl < 20 || ihl > len) return -2;
    size_t total = be16(p + 2);
    if (total < ihl) return -2;
    if (total > len) total = len; /* snap-truncated capture */
    o->ip_version = 4;
    inet_ntop(AF_INET, p + 12, o->src, sizeof o->src);
    inet_ntop(AF_INET, p + 16, o->dst, sizeof o->dst);
    o->ip_len = total;
    o->proto = p[9];
    uint16_t frag = be16(p + 6);
    if ((frag & 0x1fff) != 0) return 0; /* not the first fragment: no L4 header here */
    return decode_l4(p[9], p + ihl, total - ihl, o);
}

static int decode_ipv6(const uint8_t *p, size_t len, decoded_t *o) {
    if (len < 40) return -2;
    size_t plen = be16(p + 4);
    size_t avail = len - 40;
    if (plen > avail) plen = avail;
    o->ip_version = 6;
    inet_ntop(AF_INET6, p + 8, o->src, sizeof o->src);
    inet_ntop(AF_INET6, p + 24, o->dst, sizeof o->dst);
    o->ip_len = 40 + plen;
    uint8_t next = p[6];
    const uint8_t *q = p + 40;
    size_t rem = plen;
    for (int hops = 0; hops < 8; hops++) { /* extension headers: hop-by-hop, routing, destination options, fragment */
        if (next == 0 || next == 43 || next == 60) {
            if (rem < 8) return -2;
            size_t hl = ((size_t)q[1] + 1) * 8;
            if (hl > rem) return -2;
            next = q[0]; q += hl; rem -= hl;
        } else if (next == 44) {
            if (rem < 8) return -2;
            if ((be16(q + 2) & 0xfff8) != 0) { o->proto = q[0]; return 0; }
            next = q[0]; q += 8; rem -= 8;
        } else {
            break;
        }
    }
    return decode_l4(next, q, rem, o);
}

int decode_packet(const uint8_t *p, size_t len, uint32_t linktype, decoded_t *out) {
    memset(out, 0, sizeof *out);
    uint16_t etype = 0;
    switch (linktype) {
    case LINK_ETHERNET:
        if (len < 14) return -2;
        etype = be16(p + 12);
        p += 14; len -= 14;
        for (int tags = 0; tags < 2 && (etype == 0x8100 || etype == 0x88a8); tags++) {
            if (len < 4) return -2;
            etype = be16(p + 2);
            p += 4; len -= 4;
        }
        break;
    case LINK_LINUX_SLL:
        if (len < 16) return -2;
        etype = be16(p + 14);
        p += 16; len -= 16;
        break;
    case LINK_NULL:
        if (len < 4) return -2;
        p += 4; len -= 4;
        if (len == 0) return -2;
        etype = (p[0] >> 4) == 4 ? 0x0800 : (p[0] >> 4) == 6 ? 0x86dd : 0;
        break;
    case LINK_RAW:
        if (len == 0) return -2;
        etype = (p[0] >> 4) == 4 ? 0x0800 : (p[0] >> 4) == 6 ? 0x86dd : 0;
        break;
    default:
        return -1;
    }
    if (etype == 0x0800) return decode_ipv4(p, len, out);
    if (etype == 0x86dd) return decode_ipv6(p, len, out);
    return -1;
}
