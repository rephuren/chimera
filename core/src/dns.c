#include <arpa/inet.h>
#include <string.h>

#include "chimera.h"

static uint16_t be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

/* Reads a possibly compressed name starting at *pos; advances *pos past the name as it appears at that position. */
static int read_name(const uint8_t *msg, size_t len, size_t *pos, char *out, size_t outsz) {
    size_t p = *pos, o = 0;
    int jumped = 0, hops = 0;
    size_t resume = 0;
    for (;;) {
        if (p >= len) return -1;
        uint8_t c = msg[p];
        if ((c & 0xc0) == 0xc0) { /* compression pointer */
            if (p + 1 >= len) return -1;
            size_t target = (size_t)(c & 0x3f) << 8 | msg[p + 1];
            if (!jumped) resume = p + 2;
            jumped = 1;
            if (++hops > 16 || target >= len) return -1; /* loop or forward junk */
            p = target;
            continue;
        }
        if (c & 0xc0) return -1; /* reserved label types */
        if (c == 0) { p++; break; }
        if (p + 1 + c > len) return -1;
        if (o && o + 1 < outsz) out[o++] = '.';
        for (size_t i = 0; i < c; i++) {
            uint8_t ch = msg[p + 1 + i];
            if (o + 1 < outsz) out[o++] = (ch >= 0x21 && ch <= 0x7e) ? (char)ch : '?'; /* keep output printable */
        }
        p += 1 + c;
    }
    if (o >= outsz) o = outsz - 1;
    out[o] = '\0';
    *pos = jumped ? resume : p;
    return 0;
}

int dns_parse(const uint8_t *p, size_t len, dns_msg_t *out) {
    memset(out, 0, sizeof *out);
    if (len < 12) return -1;
    uint16_t flags = be16(p + 2), qd = be16(p + 4), an = be16(p + 6);
    out->is_response = (flags & 0x8000) != 0;
    out->rcode = flags & 0x0f;
    if (qd < 1) return -1;
    size_t pos = 12;
    if (read_name(p, len, &pos, out->qname, sizeof out->qname) < 0) return -1;
    if (pos + 4 > len) return -1;
    out->qtype = be16(p + pos);
    pos += 4;
    for (uint16_t i = 1; i < qd; i++) { /* skip further questions */
        char tmp[256];
        if (read_name(p, len, &pos, tmp, sizeof tmp) < 0 || pos + 4 > len) return 0;
        pos += 4;
    }
    for (uint16_t i = 0; i < an && out->n_answers < DNS_MAX_ANSWERS; i++) {
        char name[256];
        if (read_name(p, len, &pos, name, sizeof name) < 0 || pos + 10 > len) return 0; /* partial answers are kept */
        uint16_t type = be16(p + pos), rdlen = be16(p + pos + 8);
        uint32_t ttl = be32(p + pos + 4);
        pos += 10;
        if (pos + rdlen > len) return 0;
        int k = out->n_answers;
        out->answers[k].type = type;
        out->answers[k].ttl = ttl;
        if (type == 1 && rdlen == 4) inet_ntop(AF_INET, p + pos, out->answers[k].data, sizeof out->answers[k].data);
        else if (type == 28 && rdlen == 16) inet_ntop(AF_INET6, p + pos, out->answers[k].data, sizeof out->answers[k].data);
        else if (type == 5) { size_t q = pos; if (read_name(p, len, &q, out->answers[k].data, sizeof out->answers[k].data) < 0) out->answers[k].data[0] = '\0'; }
        out->n_answers++;
        pos += rdlen;
    }
    return 0;
}
