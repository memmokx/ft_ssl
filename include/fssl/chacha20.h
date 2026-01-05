#ifndef FSSL_CHACHA20_H
#define FSSL_CHACHA20_H

#include "cipher.h"
#include "defines.h"

static constexpr auto FSSL_CHACHA20_KEY_SIZE = 32;
static constexpr auto FSSL_CHACHA20_IV_SIZE = 12;
static constexpr auto FSSL_CHACHA20_BLOCK_SIZE = 64;

typedef struct {
  uint32_t state[16];
  uint8_t ks[FSSL_CHACHA20_BLOCK_SIZE];
  size_t ks_ptr;
} fssl_chacha20_ctx;

fssl_error_t fssl_chacha20_init(void* ctx, const uint8_t* key);
fssl_error_t fssl_chacha20_set_iv(void* ctx, const fssl_slice_t* iv);

void fssl_chacha20_stream(void* ctx, const uint8_t* in, uint8_t* out, size_t n);

extern const fssl_cipher_desc_t fssl_cipher_chacha20;

#endif
