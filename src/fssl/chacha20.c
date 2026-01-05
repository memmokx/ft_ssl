#include <fssl/chacha20.h>
#include <stdint.h>
#include "fssl/cipher.h"
#include "fssl/defines.h"
#include "fssl/error.h"

fssl_error_t fssl_chacha20_init(void* ptr, const uint8_t* key) {
  fssl_chacha20_ctx* ctx = ptr;

  if (!ctx || !key)
    return FSSL_ERR_INVALID_ARGUMENT;

  *ctx = (fssl_chacha20_ctx){};

  ctx->state[0] = 0x61707865;
  ctx->state[1] = 0x3320646e;
  ctx->state[2] = 0x79622d32;
  ctx->state[3] = 0x6b206574;

  for (size_t i = 0; i < 8; ++i)
    ctx->state[i + 4] = fssl_le_read_u32(key + i * 4);

  ctx->ks_ptr = FSSL_CHACHA20_BLOCK_SIZE;

  return FSSL_SUCCESS;
}

fssl_error_t fssl_chacha20_set_iv(void* ptr, const fssl_slice_t* iv) {
  fssl_chacha20_ctx* ctx = ptr;

  if (!ctx || !iv)
    return FSSL_ERR_INVALID_ARGUMENT;
  if (iv->size != FSSL_CHACHA20_IV_SIZE)
    return FSSL_ERR_INVALID_ARGUMENT;

  ctx->state[12] = 0;

  ctx->state[13] = fssl_le_read_u32(iv->data);
  ctx->state[14] = fssl_le_read_u32(iv->data + 4);
  ctx->state[15] = fssl_le_read_u32(iv->data + 8);

  ctx->ks_ptr = FSSL_CHACHA20_BLOCK_SIZE;

  return FSSL_SUCCESS;
}

static fssl_force_inline uint32_t rotl32(const uint32_t v, const uint32_t n) {
  return (v << n) | (v >> (32 - n));
}

#define Qround(a, b, c, d) \
  do {                     \
    a += b;                \
    d ^= a;                \
    d = rotl32(d, 16);     \
    c += d;                \
    b ^= c;                \
    b = rotl32(b, 12);     \
    a += b;                \
    d ^= a;                \
    d = rotl32(d, 8);      \
    c += d;                \
    b ^= c;                \
    b = rotl32(b, 7);      \
  } while (false)

static void fssl_chacha20_block(const uint32_t* state, uint8_t* ks) {
  uint32_t x[16];

  for (size_t i = 0; i < 16; ++i)
    x[i] = state[i];

  for (size_t i = 0; i < 10; ++i) {
    Qround(x[0], x[4], x[8], x[12]);
    Qround(x[1], x[5], x[9], x[13]);
    Qround(x[2], x[6], x[10], x[14]);
    Qround(x[3], x[7], x[11], x[15]);

    Qround(x[0], x[5], x[10], x[15]);
    Qround(x[1], x[6], x[11], x[12]);
    Qround(x[2], x[7], x[8], x[13]);
    Qround(x[3], x[4], x[9], x[14]);
  }

  for (size_t i = 0; i < 16; ++i) {
    fssl_le_write_u32(ks + i * 4, x[i] + state[i]);
  }
}

void fssl_chacha20_stream(void* ptr, const uint8_t* in, uint8_t* out, size_t n) {
  fssl_chacha20_ctx* ctx = ptr;

  if (!ctx || !out)
    return;

  if (!in)
    in = out;

  for (size_t i = 0; i < n; ++i) {
    if (ctx->ks_ptr >= FSSL_CHACHA20_BLOCK_SIZE) {
      fssl_chacha20_block(ctx->state, ctx->ks);
      ctx->state[12]++;
      ctx->ks_ptr = 0;
    }

    out[i] = in[i] ^ ctx->ks[ctx->ks_ptr++];
  }
}

const fssl_cipher_desc_t fssl_cipher_chacha20 = {
    .name = "chacha20",
    .type = CIPHER_STREAM,

    .block_size = FSSL_CHACHA20_BLOCK_SIZE,
    .key_size = FSSL_CHACHA20_KEY_SIZE,
    .ctx_size = sizeof(fssl_chacha20_ctx),

    .init = fssl_chacha20_init,
    .set_iv = fssl_chacha20_set_iv,

    .encrypt = nullptr,
    .decrypt = nullptr,

    .encrypt_stream = fssl_chacha20_stream,
    .decrypt_stream = fssl_chacha20_stream,
};
