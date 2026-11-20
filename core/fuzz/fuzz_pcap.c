/* The input is a whole pcap file. It is read packet by packet and then ingested into an in-memory database. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "chimera.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static char path[64];
    if (!path[0]) snprintf(path, sizeof path, "/tmp/chimera-fuzz-%d.pcap", (int)getpid());
    FILE *f = fopen(path, "wb");
    if (!f) return 0;
    if (size && fwrite(data, 1, size, f) != size) {
        fclose(f);
        return 0;
    }
    fclose(f);

    int err = 0;
    pcap_reader_t *r = pr_open(path, &err);
    if (r) {
        pkt_hdr_t h;
        const uint8_t *p;
        int n;
        while ((n = pr_next(r, &h, &p)) > 0) {
            if (h.caplen > 0) (void)p[h.caplen - 1]; /* the packet must really be readable up to caplen */
        }
        pr_close(r);
    }
    store_t *s = store_open(":memory:");
    if (s) {
        read_stats_t st;
        (void)ingest_pcap(path, s, &st);
        store_close(s);
    }
    return 0;
}
