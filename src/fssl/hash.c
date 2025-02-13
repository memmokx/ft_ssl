#include "fssl/fssl.h"

ssize_t fssl_hasher_write(Hasher* hasher, const uint8_t* data, size_t len) {
  return hasher->write(hasher->instance, data, len);
}

bool fssl_hasher_finish(Hasher* hasher, uint8_t* buf, size_t buf_capacity) {
  return hasher->finish(hasher->instance, buf, buf_capacity);
}
