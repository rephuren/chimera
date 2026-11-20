#include <stdio.h>
#include <string.h>

#include "chimera.h"

static void usage(void) {
    fprintf(stderr, "usage: chimera-core read FILE.pcap --db OUT.db\n");
}

int main(int argc, char **argv) {
    if (argc != 5 || strcmp(argv[1], "read") != 0 || strcmp(argv[3], "--db") != 0) {
        usage();
        return 2;
    }
    store_t *s = store_open(argv[4]);
    if (!s) { fprintf(stderr, "error: cannot open database %s\n", argv[4]); return 1; }
    read_stats_t st;
    int rc = ingest_pcap(argv[2], s, &st);
    store_close(s);
    printf("packets %lu · decoded %lu · skipped %lu · dns %lu · tls hellos %lu\n", st.packets, st.decoded, st.skipped, st.dns, st.tls);
    if (rc != 0) {
        fprintf(stderr, "error: %s\n", rc == PR_ERR_MAGIC ? "not a classic pcap file (pcapng is not supported)" : rc == PR_ERR_FORMAT ? "damaged or truncated pcap (data before the damage was kept)" : "i/o error");
        return 1;
    }
    return 0;
}
