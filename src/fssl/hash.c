#include "fssl/fssl.h"

void fssl_hasher_write(Hasher* hasher, const uint8_t* data, size_t len) {
  hasher->write(hasher->instance, data, len);
}

bool fssl_hasher_finish(Hasher* hasher, uint8_t* buf, size_t buf_capacity, size_t* written) {
  return hasher->finish(hasher->instance, buf, buf_capacity, written);
}
