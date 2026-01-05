#ifndef FSSL_SHA_H
#define FSSL_SHA_H

#include "hash.h"

static constexpr auto FSSL_SHA256_SUM_SIZE = 32;
static constexpr auto FSSL_SHA256_BLOCK_SIZE = 64;

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

static constexpr auto FSSL_SHA1_SUM_SIZE = 20;
static constexpr auto FSSL_SHA1_BLOCK_SIZE = 64;

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

static constexpr auto FSSL_SHA512_SUM_SIZE = 64;
static constexpr auto FSSL_SHA512_BLOCK_SIZE = 128;

typedef struct {
  uint64_t state[8];
  uint8_t buffer[128];
  // The total length that has been processed so far
  uint64_t size;
  uint8_t buffer_len;
} fssl_sha512_ctx;

void fssl_sha512_init(fssl_sha512_ctx* ctx);
void fssl_sha512_write(fssl_sha512_ctx* ctx, const uint8_t* data, size_t len);
bool fssl_sha512_finish(fssl_sha512_ctx* ctx, uint8_t* buf, size_t buf_capacity);

extern const fssl_hash_t fssl_hash_sha512;

#endif
