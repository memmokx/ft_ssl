#include <fssl/fssl.h>
#include <stdlib.h>

#include <sys/random.h>

fssl_error_t fssl_rand_read(uint8_t* buf, const size_t n) {
  const ssize_t r = getrandom(buf, n, 0);
  if (r < 0)
    return FSSL_ERR_RAND_FAILURE;
  if (r != (ssize_t)n)
    return FSSL_ERR_SHORT_READ;

  return FSSL_SUCCESS;
}

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