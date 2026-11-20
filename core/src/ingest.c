#include "chimera.h"

int ingest_pcap(const char *pcap_path, store_t *s, read_stats_t *stats) {
    read_stats_t local = {0};
    if (!stats) stats = &local;
    *stats = (read_stats_t){0};
    int err = 0;
    pcap_reader_t *r = pr_open(pcap_path, &err);
    if (!r) return err ? err : PR_ERR_IO;
    uint32_t link = pr_linktype(r);
    if (store_begin(s) < 0) { pr_close(r); return PR_ERR_IO; }
    pkt_hdr_t h;
    const uint8_t *data;
    int rc, result = 0;
    while ((rc = pr_next(r, &h, &data)) > 0) {
        stats->packets++;
        decoded_t d;
        if (decode_packet(data, h.caplen, link, &d) < 0) { stats->skipped++; continue; }
        stats->decoded++;
        if (store_flow(s, &h, &d) < 0) { result = PR_ERR_IO; break; }
        if (d.proto == 17 && (d.sport == 53 || d.dport == 53) && d.payload) {
            dns_msg_t m;
            if (dns_parse(d.payload, d.payload_len, &m) == 0) {
                stats->dns++;
                if (store_dns(s, &h, &d, &m) < 0) { result = PR_ERR_IO; break; }
            }
        } else if (d.proto == 6 && d.payload && d.payload_len > 0) {
            tls_hello_t t;
            if (tls_parse_client_hello(d.payload, d.payload_len, &t) == 0) {
                stats->tls++;
                if (store_tls(s, &h, &d, &t) < 0) { result = PR_ERR_IO; break; }
            }
        }
    }
    if (rc < 0 && result == 0) result = rc; /* a damaged file keeps everything read before the damage */
    store_commit(s);
    pr_close(r);
    return result;
}
