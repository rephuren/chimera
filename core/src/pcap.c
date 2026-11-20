#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chimera.h"

#define MAX_CAPLEN (256u * 1024u) /* a forged header must not make us allocate gigabytes */

struct pcap_reader {
    FILE *fp;
    int swap;
    int nano;
    uint32_t linktype;
    uint8_t *buf;
};

static uint32_t rd32(const uint8_t *p, int swap) {
    uint32_t v = (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
    if (swap) v = (v >> 24) | ((v >> 8) & 0xff00u) | ((v << 8) & 0xff0000u) | (v << 24);
    return v;
}

pcap_reader_t *pr_open(const char *path, int *err) {
    int dummy;
    if (!err) err = &dummy;
    FILE *fp = fopen(path, "rb");
    if (!fp) { *err = PR_ERR_IO; return NULL; }
    uint8_t hdr[24];
    if (fread(hdr, 1, sizeof hdr, fp) != sizeof hdr) { fclose(fp); *err = PR_ERR_FORMAT; return NULL; }
    uint32_t magic = rd32(hdr, 0);
    int swap, nano;
    switch (magic) {
    case 0xa1b2c3d4u: swap = 0; nano = 0; break;
    case 0xa1b23c4du: swap = 0; nano = 1; break;
    case 0xd4c3b2a1u: swap = 1; nano = 0; break;
    case 0x4d3cb2a1u: swap = 1; nano = 1; break;
    default: fclose(fp); *err = PR_ERR_MAGIC; return NULL;
    }
    pcap_reader_t *r = calloc(1, sizeof *r);
    uint8_t *buf = malloc(MAX_CAPLEN);
    if (!r || !buf) { free(r); free(buf); fclose(fp); *err = PR_ERR_IO; return NULL; }
    r->fp = fp; r->swap = swap; r->nano = nano; r->buf = buf;
    r->linktype = rd32(hdr + 20, swap);
    *err = PR_OK;
    return r;
}

uint32_t pr_linktype(const pcap_reader_t *r) { return r->linktype; }

int pr_next(pcap_reader_t *r, pkt_hdr_t *h, const uint8_t **data) {
    uint8_t ph[16];
    size_t n = fread(ph, 1, sizeof ph, r->fp);
    if (n == 0) return 0;
    if (n != sizeof ph) return PR_ERR_FORMAT; /* truncated record header */
    h->ts_sec = rd32(ph, r->swap);
    uint32_t sub = rd32(ph + 4, r->swap);
    h->ts_nsec = r->nano ? sub : sub * 1000u;
    h->caplen = rd32(ph + 8, r->swap);
    h->origlen = rd32(ph + 12, r->swap);
    if (h->caplen > MAX_CAPLEN) return PR_ERR_FORMAT;
    if (fread(r->buf, 1, h->caplen, r->fp) != h->caplen) return PR_ERR_FORMAT;
    *data = r->buf;
    return 1;
}

void pr_close(pcap_reader_t *r) {
    if (!r) return;
    fclose(r->fp);
    free(r->buf);
    free(r);
}
