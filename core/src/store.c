#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chimera.h"
#include "schema_sql.h" /* generated from sql/schema.sql by the Makefile */

struct store {
    sqlite3 *db;
    sqlite3_stmt *flow, *dns, *tls;
};

static int prepare(sqlite3 *db, sqlite3_stmt **st, const char *sql) {
    return sqlite3_prepare_v2(db, sql, -1, st, NULL) == SQLITE_OK ? 0 : -1;
}

store_t *store_open(const char *path) {
    store_t *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    if (sqlite3_open(path, &s->db) != SQLITE_OK) goto fail;
    if (sqlite3_exec(s->db, SCHEMA, NULL, NULL, NULL) != SQLITE_OK) goto fail;
    if (prepare(s->db, &s->flow,
                "INSERT INTO flows(proto,src,sport,dst,dport,first_ts,last_ts,packets,bytes) VALUES(?,?,?,?,?,?,?,1,?) "
                "ON CONFLICT(proto,src,sport,dst,dport) DO UPDATE SET "
                "first_ts=MIN(first_ts,excluded.first_ts), last_ts=MAX(last_ts,excluded.last_ts), packets=packets+1, bytes=bytes+excluded.bytes") < 0) goto fail;
    if (prepare(s->db, &s->dns, "INSERT INTO dns_events(ts,src,dst,is_response,rcode,qname,qtype,answers) VALUES(?,?,?,?,?,?,?,?)") < 0) goto fail;
    if (prepare(s->db, &s->tls, "INSERT INTO tls_events(ts,src,sport,dst,dport,version,sni) VALUES(?,?,?,?,?,?,?)") < 0) goto fail;
    return s;
fail:
    store_close(s);
    return NULL;
}

int store_begin(store_t *s) { return sqlite3_exec(s->db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK ? 0 : -1; }
int store_commit(store_t *s) { return sqlite3_exec(s->db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK ? 0 : -1; }

static int step(sqlite3_stmt *st) {
    int rc = sqlite3_step(st);
    sqlite3_reset(st);
    sqlite3_clear_bindings(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int store_flow(store_t *s, const pkt_hdr_t *h, const decoded_t *d) {
    sqlite3_stmt *st = s->flow;
    sqlite3_bind_int(st, 1, d->proto);
    sqlite3_bind_text(st, 2, d->src, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, d->sport);
    sqlite3_bind_text(st, 4, d->dst, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 5, d->dport);
    sqlite3_bind_int64(st, 6, h->ts_sec);
    sqlite3_bind_int64(st, 7, h->ts_sec);
    sqlite3_bind_int64(st, 8, (sqlite3_int64)d->ip_len);
    return step(st);
}

int store_dns(store_t *s, const pkt_hdr_t *h, const decoded_t *d, const dns_msg_t *m) {
    char answers[DNS_MAX_ANSWERS * 300];
    size_t o = 0;
    answers[0] = '\0';
    for (int i = 0; i < m->n_answers; i++) {
        int n = snprintf(answers + o, sizeof answers - o, "%s%u=%s", i ? ";" : "", m->answers[i].type, m->answers[i].data);
        if (n < 0 || (size_t)n >= sizeof answers - o) break;
        o += (size_t)n;
    }
    sqlite3_stmt *st = s->dns;
    sqlite3_bind_int64(st, 1, h->ts_sec);
    sqlite3_bind_text(st, 2, d->src, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, d->dst, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 4, m->is_response);
    sqlite3_bind_int(st, 5, m->rcode);
    sqlite3_bind_text(st, 6, m->qname, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 7, m->qtype);
    sqlite3_bind_text(st, 8, answers, -1, SQLITE_TRANSIENT);
    return step(st);
}

int store_tls(store_t *s, const pkt_hdr_t *h, const decoded_t *d, const tls_hello_t *t) {
    sqlite3_stmt *st = s->tls;
    sqlite3_bind_int64(st, 1, h->ts_sec);
    sqlite3_bind_text(st, 2, d->src, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, d->sport);
    sqlite3_bind_text(st, 4, d->dst, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 5, d->dport);
    sqlite3_bind_int(st, 6, t->version);
    sqlite3_bind_text(st, 7, t->sni, -1, SQLITE_STATIC);
    return step(st);
}

void store_close(store_t *s) {
    if (!s) return;
    sqlite3_finalize(s->flow);
    sqlite3_finalize(s->dns);
    sqlite3_finalize(s->tls);
    if (s->db) sqlite3_close(s->db);
    free(s);
}
