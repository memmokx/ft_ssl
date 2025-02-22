#ifndef FSSL_BLAKE2_H
#define FSSL_BLAKE2_H

#include "hash.h"

#define FSSL_BLAKE2_SUM_SIZE 32
#define FSSL_BLAKE2_BLOCK_SIZE 64

typedef struct {
  uint32_t state[8];
  uint8_t buffer[64];
  uint32_t t[2];
  uint64_t size;
  uint8_t buffer_len;
  bool last;
} fssl_blake2_ctx;

Hasher fssl_blake2_hasher(fssl_blake2_ctx* ctx);
void fssl_blake2_init(fssl_blake2_ctx* ctx);
void fssl_blake2_write(fssl_blake2_ctx* ctx, const uint8_t* data, size_t len);
bool fssl_blake2_finish(fssl_blake2_ctx* ctx,
                        uint8_t* buf,
                        size_t buf_capacity,
                        size_t* written);

#endif
