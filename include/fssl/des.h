#ifndef FSSL_DES_H
#define FSSL_DES_H

#include "cipher.h"

#define FSSL_DES_KEY_SIZE 8
#define FSSL_DES_BLOCK_SIZE 8

typedef struct {
  uint64_t sk[16];
} fssl_des_ctx;

fssl_error_t fssl_des_init(void* ctx, const uint8_t* key);

void fssl_des_encrypt_block(void* ctx, const uint8_t* in, uint8_t* out);
void fssl_des_decrypt_block(void* ctx, const uint8_t* in, uint8_t* out);

extern const fssl_cipher_desc_t fssl_cipher_des;

#define FSSL_DES3_KEY_SIZE (FSSL_DES_KEY_SIZE * 3)
#define FSSL_DES3_BLOCK_SIZE FSSL_DES_BLOCK_SIZE

typedef struct {
  fssl_des_ctx c1;
  fssl_des_ctx c2;
  fssl_des_ctx c3;
} fssl_des3_ctx;

fssl_error_t fssl_des3_init(void* ctx, const uint8_t* key);

extern const fssl_cipher_desc_t fssl_cipher_des3;

#endif
