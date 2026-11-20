#include "chimera.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    tls_hello_t t;
    (void)tls_parse_client_hello(data, size, &t);
    return 0;
}
