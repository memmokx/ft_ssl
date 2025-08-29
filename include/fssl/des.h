#ifndef FSSL_DES_H
#define FSSL_DES_H

#include "cipher.h"

#define FSSL_DES_KEY_SIZE 8
#define FSSL_DES_BLOCK_SIZE 8

typedef struct {
  uint64_t sk[16];
} fssl_des_ctx;

fssl_error_t fssl_des_init(fssl_des_ctx* ctx, const uint8_t* key);
void fssl_des_deinit(fssl_des_ctx* ctx);

extern const fssl_block_cipher_t fssl_cipher_des;

#endif
