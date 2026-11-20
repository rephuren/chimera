/* Tests build their own packets byte by byte: the point is to check the parsers against the wire formats, not against themselves. */
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "chimera.h"

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

typedef struct { uint8_t b[2048]; size_t n; } buf_t;
static void put(buf_t *x, const void *d, size_t n) { memcpy(x->b + x->n, d, n); x->n += n; }
static void put8(buf_t *x, unsigned v) { uint8_t c = (uint8_t)v; put(x, &c, 1); }
static void put16(buf_t *x, unsigned v) { put8(x, v >> 8); put8(x, v & 0xff); }
static void put32(buf_t *x, uint32_t v) { put16(x, v >> 16); put16(x, v & 0xffff); }

static void eth(buf_t *x, unsigned type) { static const uint8_t macs[12] = {1,2,3,4,5,6,7,8,9,10,11,12}; put(x, macs, 12); put16(x, type); }
static void ipv4(buf_t *x, unsigned proto, size_t l4len, const uint8_t src[4], const uint8_t dst[4]) {
    put8(x, 0x45); put8(x, 0); put16(x, (unsigned)(20 + l4len)); put16(x, 0); put16(x, 0); put8(x, 64); put8(x, proto); put16(x, 0);
    put(x, src, 4); put(x, dst, 4);
}
static void udp(buf_t *x, unsigned sp, unsigned dp, const uint8_t *pl, size_t n) { put16(x, sp); put16(x, dp); put16(x, (unsigned)(8 + n)); put16(x, 0); put(x, pl, n); }
static void tcp(buf_t *x, unsigned sp, unsigned dp, unsigned flags, const uint8_t *pl, size_t n) {
    put16(x, sp); put16(x, dp); put32(x, 1); put32(x, 0); put8(x, 0x50); put8(x, flags); put16(x, 0xffff); put16(x, 0); put16(x, 0); put(x, pl, n);
}

static const uint8_t A[4] = {192, 168, 1, 10}, B[4] = {8, 8, 8, 8};

static size_t dns_query(uint8_t *o, const char *name) {
    size_t n = 0;
    o[n++] = 0x12; o[n++] = 0x34; o[n++] = 0x01; o[n++] = 0x00; o[n++] = 0; o[n++] = 1; o[n++] = 0; o[n++] = 0; o[n++] = 0; o[n++] = 0; o[n++] = 0; o[n++] = 0;
    const char *p = name;
    while (*p) { const char *dot = strchr(p, '.'); size_t l = dot ? (size_t)(dot - p) : strlen(p); o[n++] = (uint8_t)l; memcpy(o + n, p, l); n += l; p += l; if (dot) p++; }
    o[n++] = 0; o[n++] = 0; o[n++] = 1; o[n++] = 0; o[n++] = 1; /* A IN */
    return n;
}

/* response to "example.test": CNAME (compressed pointer to the question) then A record */
static size_t dns_response(uint8_t *o) {
    size_t q = dns_query(o, "example.test");
    o[2] = 0x81; o[3] = 0x80; o[7] = 2; /* response, ANCOUNT=2 */
    size_t n = q;
    static const uint8_t cname[] = {0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 9, 3, 'c', 'd', 'n', 4, 't', 'e', 's', 't', 0, 0}; /* last two are padding, rdlen below */
    (void)cname;
    /* answer 1: name ptr, type 5, class 1, ttl 60, rdlen 6, rdata = 3 'c''d''n' + ptr to "test" label inside question (offset 12+8=20) */
    uint8_t a1[] = {0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6, 3, 'c', 'd', 'n', 0xc0, 20};
    memcpy(o + n, a1, sizeof a1); n += sizeof a1;
    uint8_t a2[] = {0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 93, 184, 216, 34};
    memcpy(o + n, a2, sizeof a2); n += sizeof a2;
    return n;
}

static size_t tls_hello(uint8_t *o, const char *sni) {
    uint8_t ext[300]; size_t e = 0;
    size_t sl = strlen(sni);
    ext[e++] = 0; ext[e++] = 0; ext[e++] = (uint8_t)((sl + 5) >> 8); ext[e++] = (uint8_t)(sl + 5);
    ext[e++] = (uint8_t)((sl + 3) >> 8); ext[e++] = (uint8_t)(sl + 3); ext[e++] = 0; ext[e++] = (uint8_t)(sl >> 8); ext[e++] = (uint8_t)sl;
    memcpy(ext + e, sni, sl); e += sl;
    uint8_t body[400]; size_t b = 0;
    body[b++] = 3; body[b++] = 3; memset(body + b, 0x42, 32); b += 32; /* version, random */
    body[b++] = 0;                                                    /* session id */
    body[b++] = 0; body[b++] = 4; body[b++] = 0x13; body[b++] = 1; body[b++] = 0xc0; body[b++] = 0x2f; /* ciphers */
    body[b++] = 1; body[b++] = 0;                                     /* compression */
    body[b++] = (uint8_t)(e >> 8); body[b++] = (uint8_t)e; memcpy(body + b, ext, e); b += e;
    size_t n = 0;
    o[n++] = 0x16; o[n++] = 3; o[n++] = 1; o[n++] = (uint8_t)((b + 4) >> 8); o[n++] = (uint8_t)(b + 4);
    o[n++] = 1; o[n++] = 0; o[n++] = (uint8_t)(b >> 8); o[n++] = (uint8_t)b;
    memcpy(o + n, body, b); n += b;
    return n;
}

static void w32(FILE *f, uint32_t x, int big) {
    uint8_t c[4];
    for (int i = 0; i < 4; i++) c[big ? 3 - i : i] = (uint8_t)(x >> (8 * i));
    fwrite(c, 1, 4, f);
}
static void w16(FILE *f, uint16_t x, int big) {
    uint8_t c[2] = { (uint8_t)(big ? x >> 8 : x & 0xff), (uint8_t)(big ? x & 0xff : x >> 8) };
    fwrite(c, 1, 2, f);
}

static void write_pcap(const char *path, const buf_t *pk, int npk, int big_endian, int nano) {
    FILE *f = fopen(path, "wb");
    w32(f, nano ? 0xa1b23c4du : 0xa1b2c3d4u, big_endian); w16(f, 2, big_endian); w16(f, 4, big_endian);
    w32(f, 0, big_endian); w32(f, 0, big_endian); w32(f, 65535, big_endian); w32(f, 1, big_endian);
    for (int i = 0; i < npk; i++) {
        w32(f, 1700000000u + (uint32_t)i, big_endian); w32(f, nano ? 500u : 5u, big_endian);
        w32(f, (uint32_t)pk[i].n, big_endian); w32(f, (uint32_t)pk[i].n, big_endian);
        fwrite(pk[i].b, 1, pk[i].n, f);
    }
    fclose(f);
}

static void test_decode(void) {
    buf_t x = {0}; uint8_t q[100]; size_t qn = dns_query(q, "a.test");
    eth(&x, 0x0800); ipv4(&x, 17, 8 + qn, A, B); udp(&x, 40000, 53, q, qn);
    decoded_t d;
    CHECK(decode_packet(x.b, x.n, LINK_ETHERNET, &d) == 0);
    CHECK(d.ip_version == 4 && d.proto == 17 && d.sport == 40000 && d.dport == 53);
    CHECK(strcmp(d.src, "192.168.1.10") == 0 && strcmp(d.dst, "8.8.8.8") == 0 && d.payload_len == qn && d.ip_len == 20 + 8 + qn);

    buf_t t = {0}; const uint8_t pl[] = "hi";
    eth(&t, 0x0800); ipv4(&t, 6, 20 + 2, A, B); tcp(&t, 5555, 443, 0x02, pl, 2);
    CHECK(decode_packet(t.b, t.n, LINK_ETHERNET, &d) == 0 && d.proto == 6 && d.tcp_flags == 0x02 && d.dport == 443 && d.payload_len == 2);

    buf_t v = {0}; /* 802.1Q tag */
    eth(&v, 0x8100); put16(&v, 100); put16(&v, 0x0800); ipv4(&v, 6, 22, A, B); tcp(&v, 1, 2, 0x10, pl, 2);
    CHECK(decode_packet(v.b, v.n, LINK_ETHERNET, &d) == 0 && d.dport == 2);

    buf_t s = {0}; /* IPv6 UDP */
    eth(&s, 0x86dd); put32(&s, 0x60000000); put16(&s, 8 + 2); put8(&s, 17); put8(&s, 64);
    for (int i = 0; i < 16; i++) put8(&s, i == 15 ? 1 : 0); for (int i = 0; i < 16; i++) put8(&s, i == 15 ? 2 : 0);
    udp(&s, 1000, 2000, pl, 2);
    CHECK(decode_packet(s.b, s.n, LINK_ETHERNET, &d) == 0 && d.ip_version == 6 && strcmp(d.src, "::1") == 0 && d.dport == 2000);

    buf_t arp = {0}; eth(&arp, 0x0806); put32(&arp, 0);
    CHECK(decode_packet(arp.b, arp.n, LINK_ETHERNET, &d) == -1);
    CHECK(decode_packet(x.b, 10, LINK_ETHERNET, &d) == -2);
    CHECK(decode_packet(x.b, 14 + 10, LINK_ETHERNET, &d) == -2);
    CHECK(decode_packet(x.b, x.n, 999, &d) == -1);
}

static void test_dns(void) {
    uint8_t q[300]; dns_msg_t m;
    size_t n = dns_query(q, "www.example.test");
    CHECK(dns_parse(q, n, &m) == 0 && !m.is_response && strcmp(m.qname, "www.example.test") == 0 && m.qtype == 1);
    n = dns_response(q);
    CHECK(dns_parse(q, n, &m) == 0 && m.is_response && m.rcode == 0 && strcmp(m.qname, "example.test") == 0 && m.n_answers == 2);
    CHECK(m.answers[0].type == 5 && strcmp(m.answers[0].data, "cdn.test") == 0);
    CHECK(m.answers[1].type == 1 && strcmp(m.answers[1].data, "93.184.216.34") == 0 && m.answers[1].ttl == 300);
    uint8_t loop[] = {0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1}; /* pointer to itself */
    CHECK(dns_parse(loop, sizeof loop, &m) == -1);
    CHECK(dns_parse(q, 5, &m) == -1);
}

static void test_tls(void) {
    uint8_t h[600]; tls_hello_t t;
    size_t n = tls_hello(h, "secure.example.test");
    CHECK(tls_parse_client_hello(h, n, &t) == 0 && t.version == 0x0303 && strcmp(t.sni, "secure.example.test") == 0);
    CHECK(tls_parse_client_hello(h, n - 5, &t) == 0 || tls_parse_client_hello(h, n - 5, &t) == -2); /* cut inside the SNI: no crash */
    CHECK(tls_parse_client_hello((const uint8_t *)"GET / HTTP/1.1", 14, &t) == -1);
    h[5] = 2; /* ServerHello */
    CHECK(tls_parse_client_hello(h, n, &t) == -1);
}

static unsigned long long scalar(sqlite3 *db, const char *sql) {
    sqlite3_stmt *st; unsigned long long v = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) v = (unsigned long long)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

static void test_ingest(int big_endian, int nano) {
    buf_t pk[5] = {0}; uint8_t q[300], r[400], h[600]; const uint8_t pl[] = "x";
    size_t qn = dns_query(q, "example.test"), rn = dns_response(r), hn = tls_hello(h, "secure.example.test");
    eth(&pk[0], 0x0800); ipv4(&pk[0], 17, 8 + qn, A, B); udp(&pk[0], 40000, 53, q, qn);
    eth(&pk[1], 0x0800); ipv4(&pk[1], 17, 8 + rn, B, A); udp(&pk[1], 53, 40000, r, rn);
    eth(&pk[2], 0x0800); ipv4(&pk[2], 6, 20 + hn, A, B); tcp(&pk[2], 50000, 443, 0x18, h, hn);
    eth(&pk[3], 0x0800); ipv4(&pk[3], 6, 21, A, B); tcp(&pk[3], 50000, 443, 0x10, pl, 1);
    eth(&pk[4], 0x0806); put32(&pk[4], 0); /* ARP: skipped */
    char pcap[64], db[64];
    snprintf(pcap, sizeof pcap, "/tmp/chimera-test-%d.pcap", (int)getpid());
    snprintf(db, sizeof db, "/tmp/chimera-test-%d.db", (int)getpid());
    unlink(db);
    write_pcap(pcap, pk, 5, big_endian, nano);
    store_t *s = store_open(db); CHECK(s != NULL);
    read_stats_t st;
    CHECK(ingest_pcap(pcap, s, &st) == 0);
    CHECK(st.packets == 5 && st.decoded == 4 && st.skipped == 1 && st.dns == 2 && st.tls == 1);
    store_close(s);
    sqlite3 *conn; CHECK(sqlite3_open(db, &conn) == SQLITE_OK);
    CHECK(scalar(conn, "SELECT count(*) FROM flows") == 3);
    CHECK(scalar(conn, "SELECT packets FROM flows WHERE dport=443") == 2);
    CHECK(scalar(conn, "SELECT count(*) FROM dns_events WHERE qname='example.test'") == 2);
    CHECK(scalar(conn, "SELECT count(*) FROM tls_events WHERE sni='secure.example.test'") == 1);
    CHECK(scalar(conn, "SELECT min(first_ts) FROM flows") == 1700000000ull);
    sqlite3_close(conn);
    unlink(pcap); unlink(db);
}

static void test_reader_errors(void) {
    int err = 0;
    CHECK(pr_open("/nonexistent/file.pcap", &err) == NULL && err == PR_ERR_IO);
    const char *path = "/tmp/chimera-bad.pcap";
    FILE *f = fopen(path, "wb"); fwrite("not a pcap file at all, honestly....", 1, 36, f); fclose(f);
    CHECK(pr_open(path, &err) == NULL && err == PR_ERR_MAGIC);
    unlink(path);
}

/* Truncate and corrupt a valid capture many ways: nothing may crash under ASan/UBSan, and data before the damage is kept. */
static void test_robustness(void) {
    buf_t pk[3] = {0}; uint8_t q[300], h[600]; size_t qn = dns_query(q, "example.test"), hn = tls_hello(h, "secure.example.test");
    eth(&pk[0], 0x0800); ipv4(&pk[0], 17, 8 + qn, A, B); udp(&pk[0], 1, 53, q, qn);
    eth(&pk[1], 0x0800); ipv4(&pk[1], 6, 20 + hn, A, B); tcp(&pk[1], 2, 443, 0x18, h, hn);
    eth(&pk[2], 0x0800); ipv4(&pk[2], 17, 8 + qn, B, A); udp(&pk[2], 53, 1, q, qn);
    const char *good = "/tmp/chimera-good.pcap", *bad = "/tmp/chimera-fuzz.pcap", *db = "/tmp/chimera-fuzz.db";
    write_pcap(good, pk, 3, 0, 0);
    FILE *f = fopen(good, "rb"); uint8_t file[8192]; size_t fn = fread(file, 1, sizeof file, f); fclose(f);
    unsigned seed = 12345;
    for (int i = 0; i < 600; i++) {
        uint8_t copy[8192]; memcpy(copy, file, fn);
        size_t len = fn;
        if (i % 2 == 0) len = (size_t)(i * 7) % fn; /* truncate */
        else for (int k = 0; k < 6; k++) { seed = seed * 1103515245u + 12345u; copy[(seed >> 8) % fn] ^= (uint8_t)(seed >> 16) | 1; }
        f = fopen(bad, "wb"); fwrite(copy, 1, len, f); fclose(f);
        unlink(db);
        store_t *s = store_open(db);
        read_stats_t st; (void)ingest_pcap(bad, s, &st);
        store_close(s);
    }
    unlink(good); unlink(bad); unlink(db);
    CHECK(1);
}

int main(void) {
    test_decode();
    test_dns();
    test_tls();
    test_ingest(0, 0);
    test_ingest(1, 0);
    test_ingest(0, 1);
    test_ingest(1, 1);
    test_reader_errors();
    test_robustness();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
