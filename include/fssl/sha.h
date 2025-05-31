#ifndef FSSL_SHA_H
#define FSSL_SHA_H

#include "hash.h"

#define FSSL_SHA256_SUM_SIZE 32
#define FSSL_SHA256_BLOCK_SIZE 64

typedef struct {
  uint32_t state[8];
  uint8_t buffer[64];
  // The total length that has been processed so far
  uint64_t size;
  uint8_t buffer_len;
} fssl_sha256_ctx;

void fssl_sha256_init(fssl_sha256_ctx* ctx);
void fssl_sha256_write(fssl_sha256_ctx* ctx, const uint8_t* data, size_t len);
bool fssl_sha256_finish(fssl_sha256_ctx* ctx, uint8_t* buf, size_t buf_capacity);

extern const fssl_hash_t fssl_hash_sha256;

#define FSSL_SHA1_SUM_SIZE 20
#define FSSL_SHA1_BLOCK_SIZE 64

typedef struct {
  uint32_t state[5];
  uint8_t buffer[64];
  // The total length that has been processed so far
  uint64_t size;
  uint8_t buffer_len;
} fssl_sha1_ctx;

void fssl_sha1_init(fssl_sha1_ctx* ctx);
void fssl_sha1_write(fssl_sha1_ctx* ctx, const uint8_t* data, size_t len);
bool fssl_sha1_finish(fssl_sha1_ctx* ctx, uint8_t* buf, size_t buf_capacity);

extern const fssl_hash_t fssl_hash_sha1;

#endif
