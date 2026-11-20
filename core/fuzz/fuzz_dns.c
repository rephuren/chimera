#include "chimera.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    dns_msg_t m;
    (void)dns_parse(data, size, &m);
    return 0;
}
