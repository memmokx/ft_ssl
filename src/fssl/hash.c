#include <stdlib.h>

#include "fssl/fssl.h"
#include "libft/memory.h"

Hasher fssl_hasher_new(fssl_hash_t hash) {
  Hasher hasher = (Hasher){
      .instance = ft_calloc(1, hash.ctx_size),
      .hash = hash,
  };

  fssl_hasher_reset(&hasher);

  return hasher;
}

void fssl_hasher_write(const Hasher* hasher, const uint8_t* data, size_t len) {
  hasher->hash.write_fn(hasher->instance, data, len);
}

bool fssl_hasher_finish(const Hasher* hasher, uint8_t* buf, size_t buf_capacity) {
  return hasher->hash.finish_fn(hasher->instance, buf, buf_capacity);
}

void fssl_hasher_reset(const Hasher* hasher) {
  hasher->hash.reset_fn(hasher->instance);
}

void fssl_hasher_destroy(Hasher* hasher) {
  free(hasher->instance);
  hasher->instance = nullptr;
}