/* chimera core: pcap reader, packet decoders and SQLite store. Every parser is bounds-checked: input is untrusted. */
#ifndef CHIMERA_H
#define CHIMERA_H

#include <stddef.h>
#include <stdint.h>

#define LINK_NULL 0
#define LINK_ETHERNET 1
#define LINK_RAW 101
#define LINK_LINUX_SLL 113

/* ---- pcap file reader (classic pcap only; pcapng is not supported) ---- */
typedef struct pcap_reader pcap_reader_t;
typedef struct {
    uint32_t ts_sec;
    uint32_t ts_nsec;
    uint32_t caplen;
    uint32_t origlen;
} pkt_hdr_t;

enum { PR_OK = 0, PR_ERR_IO = -1, PR_ERR_MAGIC = -2, PR_ERR_FORMAT = -3 };

pcap_reader_t *pr_open(const char *path, int *err);
uint32_t pr_linktype(const pcap_reader_t *r);
/* returns 1 with a packet, 0 at end of file, negative on error. data stays valid until the next call. */
int pr_next(pcap_reader_t *r, pkt_hdr_t *h, const uint8_t **data);
void pr_close(pcap_reader_t *r);

/* ---- L2/L3/L4 decoding ---- */
typedef struct {
    int ip_version;      /* 4, 6, or 0 when not IP */
    char src[46], dst[46];
    uint8_t proto;       /* IANA protocol number: 6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6 */
    uint16_t sport, dport;
    uint8_t tcp_flags;
    const uint8_t *payload;
    size_t payload_len;
    size_t ip_len;       /* length of the IP packet as seen on the wire (for byte counters) */
} decoded_t;

/* 0 on success (fields up to the deepest decodable layer are set), negative when the frame is not IP or is malformed. */
int decode_packet(const uint8_t *p, size_t len, uint32_t linktype, decoded_t *out);

/* ---- DNS ---- */
#define DNS_MAX_ANSWERS 8
typedef struct {
    int is_response;
    uint8_t rcode;
    char qname[256];
    uint16_t qtype;
    int n_answers;
    struct {
        uint16_t type;
        uint32_t ttl;
        char data[256]; /* A/AAAA address text, CNAME target; empty for other types */
    } answers[DNS_MAX_ANSWERS];
} dns_msg_t;

int dns_parse(const uint8_t *p, size_t len, dns_msg_t *out);

/* ---- TLS ClientHello ---- */
typedef struct {
    uint16_t version;  /* legacy_version from the hello */
    char sni[256];     /* empty when the extension is absent */
} tls_hello_t;

/* Only a hello fully contained in the first record of the buffer is parsed (no TCP reassembly). */
int tls_parse_client_hello(const uint8_t *p, size_t len, tls_hello_t *out);

/* ---- SQLite store ---- */
typedef struct store store_t;
store_t *store_open(const char *path);
int store_begin(store_t *s);
int store_commit(store_t *s);
int store_flow(store_t *s, const pkt_hdr_t *h, const decoded_t *d);
int store_dns(store_t *s, const pkt_hdr_t *h, const decoded_t *d, const dns_msg_t *m);
int store_tls(store_t *s, const pkt_hdr_t *h, const decoded_t *d, const tls_hello_t *t);
void store_close(store_t *s);

/* ---- read a whole pcap into a store; returns 0 or a negative error ---- */
typedef struct {
    unsigned long packets, decoded, skipped, dns, tls;
} read_stats_t;
int ingest_pcap(const char *pcap_path, store_t *s, read_stats_t *stats);

#endif
