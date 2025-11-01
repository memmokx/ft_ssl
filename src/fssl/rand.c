#include <fssl/fssl.h>
#include <stdlib.h>

#include <sys/random.h>

uint8_t* fssl_rand_bytes(const size_t n, fssl_error_t* err) {
  // TODO: temporary implementation
  uint8_t* buffer = malloc(n);
  if (!buffer) {
    fssl_seterr(err, FSSL_ERR_OUT_OF_MEMORY);
    return nullptr;
  }

  if (getrandom(buffer, n, 0) == -1) {
    free(buffer);
    fssl_seterr(err, FSSL_ERR_RAND_FAILURE);
    return nullptr;
  }

  return buffer;
}