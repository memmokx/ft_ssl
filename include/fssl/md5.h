#ifndef FSSL_MD5_H
#define FSSL_MD5_H

#include "hash.h"

#define FSSL_MD5_SUM_SIZE 16

typedef struct {
  uint32_t state[4];
  uint8_t buffer[64];
} fssl_md5_ctx;

Hasher fssl_md5_hasher(fssl_md5_ctx* ctx);
ssize_t fssl_md5_write(fssl_md5_ctx* ctx, const uint8_t* data, size_t len);
bool fssl_md5_finish(fssl_md5_ctx* ctx, uint8_t* buf, size_t buf_capacity);

#endif
