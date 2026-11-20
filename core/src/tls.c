#include <string.h>

#include "chimera.h"

static uint16_t be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }

int tls_parse_client_hello(const uint8_t *p, size_t len, tls_hello_t *out) {
    memset(out, 0, sizeof *out);
    if (len < 5 || p[0] != 0x16 || p[1] != 0x03) return -1; /* not a TLS handshake record */
    size_t reclen = be16(p + 3);
    size_t end = 5 + reclen;
    if (end > len) end = len; /* the record may continue in a later segment: use what we have */
    size_t pos = 5;
    if (pos + 4 > end || p[pos] != 0x01) return -1; /* not a ClientHello */
    pos += 4;                                        /* handshake type + 3-byte length */
    if (pos + 2 + 32 > end) return -2;
    out->version = be16(p + pos);
    pos += 2 + 32;
    if (pos + 1 > end) return -2;
    pos += 1 + p[pos];                               /* session id */
    if (pos + 2 > end) return -2;
    pos += 2 + be16(p + pos);                        /* cipher suites */
    if (pos + 1 > end) return -2;
    pos += 1 + p[pos];                               /* compression methods */
    if (pos + 2 > end) return -2;
    size_t ext_end = pos + 2 + be16(p + pos);
    pos += 2;
    if (ext_end > end) ext_end = end;
    while (pos + 4 <= ext_end) {
        uint16_t type = be16(p + pos), elen = be16(p + pos + 2);
        pos += 4;
        if (pos + elen > ext_end) return out->sni[0] ? 0 : -2;
        if (type == 0 && elen >= 5) { /* server_name */
            size_t q = pos + 2;       /* skip list length */
            if (p[q] == 0) {
                size_t nl = be16(p + q + 1);
                q += 3;
                if (q + nl <= pos + elen && nl < sizeof out->sni) {
                    for (size_t i = 0; i < nl; i++) {
                        uint8_t ch = p[q + i];
                        out->sni[i] = (ch >= 0x21 && ch <= 0x7e) ? (char)ch : '?';
                    }
                    out->sni[nl] = '\0';
                }
            }
        }
        pos += elen;
    }
    return 0;
}
