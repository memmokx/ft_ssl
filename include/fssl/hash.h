#ifndef FSSL_HASH_H
#define FSSL_HASH_H

#include <fssl/defines.h>
#include <stddef.h>
#include <stdint.h>
#include "error.h"

typedef void (*fssl_hash_write_fn)(void*, const uint8_t*, size_t);
typedef bool (*fssl_hash_finish_fn)(void*, uint8_t*, size_t);
typedef void (*fssl_hash_reset_fn)(void*);

typedef struct {
  size_t ctx_size;
  size_t sum_size;
  size_t block_size;
  fssl_hash_write_fn write_fn;
  fssl_hash_finish_fn finish_fn;
  fssl_hash_reset_fn reset_fn;
} fssl_hash_t;

typedef struct {
  void* instance;
  fssl_hash_t hash;
} Hasher;

Hasher fssl_hasher_new(fssl_hash_t hash);
void fssl_hasher_write(const Hasher* hasher, const uint8_t* data, size_t len);
bool fssl_hasher_finish(const Hasher* hasher, uint8_t* buf, size_t buf_capacity);
void fssl_hasher_reset(const Hasher* hasher);
size_t fssl_hasher_sum_size(const Hasher* hasher);
size_t fssl_hasher_block_size(const Hasher* hasher);
void fssl_hasher_destroy(Hasher* hasher);

typedef struct {
  Hasher* h;
  uint8_t opad[FSSL_HASH_MAX_BLOCK_SIZE];
} fssl_hmac_ctx;

fssl_error_t fssl_hmac_init(fssl_hmac_ctx* ctx,
                            Hasher* inner,
                            const uint8_t* key,
                            size_t key_len);

void fssl_hmac_write(const fssl_hmac_ctx* ctx, const uint8_t* data, size_t len);
bool fssl_hmac_finish(const fssl_hmac_ctx* ctx, uint8_t* out, size_t out_len);

#endif
