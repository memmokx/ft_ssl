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

fssl_force_inline size_t fssl_hasher_block_size(const Hasher* hasher) {
  return hasher->hash.block_size;
}

fssl_force_inline size_t fssl_hasher_sum_size(const Hasher* hasher) {
  return hasher->hash.sum_size;
}

bool fssl_hash(const Hasher* hasher,
               const uint8_t* data,
               const size_t len,
               uint8_t* out,
               const size_t out_len) {
  fssl_hasher_reset(hasher);
  fssl_hasher_write(hasher, data, len);
  const bool result = fssl_hasher_finish(hasher, out, out_len);
  fssl_hasher_reset(hasher);
  return result;
}

void fssl_hasher_destroy(Hasher* hasher) {
  free(hasher->instance);
  hasher->instance = nullptr;
}

fssl_error_t fssl_hmac_init(fssl_hmac_ctx* ctx,
                            Hasher* inner,
                            const uint8_t* key,
                            size_t key_len) {
  uint8_t bkey[FSSL_HASH_MAX_BLOCK_SIZE] = {};
  uint8_t ipad[FSSL_HASH_MAX_BLOCK_SIZE] = {};

  if (!ctx || !inner || !key)
    return FSSL_ERR_INVALID_ARGUMENT;

  const size_t block_size = fssl_hasher_block_size(inner);

  // computeBlockSizedKey
  if (key_len > block_size)
    fssl_hash(inner, key, key_len, bkey, sizeof(bkey));
  else
    ft_memcpy(bkey, key, key_len);

  *ctx = (fssl_hmac_ctx){inner, {}};

  for (size_t i = 0; i < block_size; ++i) {
    ctx->opad[i] = bkey[i] ^ 0x5c;
    ipad[i] = bkey[i] ^ 0x36;
  }

  fssl_hasher_reset(inner);
  fssl_hasher_write(inner, ipad, block_size);
  return FSSL_SUCCESS;
}

void fssl_hmac_write(const fssl_hmac_ctx* ctx, const uint8_t* data, size_t len) {
  fssl_hasher_write(ctx->h, data, len);
}

bool fssl_hmac_finish(const fssl_hmac_ctx* ctx, uint8_t* out, size_t out_len) {
  uint8_t inner[FSSL_HASH_MAX_BLOCK_SIZE] = {};

  const size_t block_size = fssl_hasher_block_size(ctx->h);
  const size_t sum_size = fssl_hasher_sum_size(ctx->h);

  fssl_hasher_finish(ctx->h, inner, sizeof(inner));
  fssl_hasher_reset(ctx->h);

  // H(opad || H(ipad || message))
  fssl_hasher_write(ctx->h, ctx->opad, block_size);
  fssl_hasher_write(ctx->h, inner, sum_size);

  const bool result = fssl_hasher_finish(ctx->h, out, out_len);
  fssl_hasher_reset(ctx->h);
  return result;
}