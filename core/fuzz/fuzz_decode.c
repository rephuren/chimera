/* The first byte picks the link type, the rest is the frame. If the frame decodes, the payload goes on to the DNS and TLS parsers
   exactly as ingest does, so one harness covers the whole packet path. */
#include "chimera.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const uint32_t links[] = {LINK_ETHERNET, LINK_RAW, LINK_NULL, LINK_LINUX_SLL, 7};
    if (size < 1) return 0;
    decoded_t d;
    if (decode_packet(data + 1, size - 1, links[data[0] % 5], &d) != 0) return 0;
    if (d.payload_len > size) __builtin_trap(); /* a payload can never be longer than the frame */
    if (d.proto == 17) {
        dns_msg_t m;
        (void)dns_parse(d.payload, d.payload_len, &m);
    } else if (d.proto == 6) {
        tls_hello_t t;
        (void)tls_parse_client_hello(d.payload, d.payload_len, &t);
    }
    return 0;
}
