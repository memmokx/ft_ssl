#ifndef FSSL_DES_H
#define FSSL_DES_H

#include "cipher.h"

#define FSSL_DES_KEY_SIZE 8
#define FSSL_DES_BLOCK_SIZE 8

typedef struct {
  uint64_t sk[16];
} fssl_des_ctx;

fssl_error_t fssl_des_init(void* ctx, const uint8_t* key);

extern const fssl_cipher_desc_t fssl_cipher_des;

#endif
