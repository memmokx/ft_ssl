#ifndef FSSL_BLAKE2_H
#define FSSL_BLAKE2_H

#include "hash.h"

#define FSSL_BLAKE2_SUM_SIZE 32
#define FSSL_BLAKE2_BLOCK_SIZE 64

typedef struct {
  uint32_t state[8];
  uint8_t buffer[64];
  uint64_t t;
  uint8_t buffer_len;
  bool last;
} fssl_blake2_ctx;

void fssl_blake2_init(fssl_blake2_ctx* ctx);
void fssl_blake2_write(fssl_blake2_ctx* ctx, const uint8_t* data, size_t len);
bool fssl_blake2_finish(fssl_blake2_ctx* ctx, uint8_t* buf, size_t buf_capacity);

extern const fssl_hash_t fssl_hash_blake2;

#endif
