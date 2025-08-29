#include <fssl/fssl.h>
#include <libft/memory.h>

static const uint8_t pc_1[] = {
    7,  15, 23, 31, 39, 47, 55, 63, 6,  14, 22, 30, 38, 46, 54, 62, 5,  13, 21,
    29, 37, 45, 53, 61, 4,  12, 20, 28, 1,  9,  17, 25, 33, 41, 49, 57, 2,  10,
    18, 26, 34, 42, 50, 58, 3,  11, 19, 27, 35, 43, 51, 59, 36, 44, 52, 60,
};

static const uint8_t pc_2[] = {
    42, 39, 45, 32, 55, 51, 53, 28, 41, 50, 35, 46, 33, 37, 44, 52,
    30, 48, 40, 49, 29, 36, 43, 54, 15, 4,  25, 19, 9,  1,  26, 16,
    5,  11, 23, 8,  12, 7,  17, 0,  22, 3,  10, 14, 6,  20, 27, 24,
};

static fssl_force_inline uint64_t permute(uint64_t w, const uint8_t* table, size_t n) {
  uint64_t r = 0;

  for (size_t i = 0; i < n; ++i) {
    uint64_t b = (w >> table[i]) & 1;
    r |= (b << ((n - 1) - i));
  }

  return r;
}

static fssl_force_inline uint32_t rol28(uint32_t v, size_t r) {
  return ((v << r) | (v >> (28 - r))) & 0x0fffffff;
}

fssl_error_t fssl_des_init(fssl_des_ctx* ctx, const uint8_t* key) {
  if (ctx == nullptr || key == nullptr)
    return FSSL_ERR_INVALID_ARGUMENT;

  *ctx = (fssl_des_ctx){};

  uint64_t k = permute(fssl_be_read_u64(key), pc_1, sizeof(pc_1));

  // Each half has 28 bits
  uint32_t c = (k >> 28) & 0x0fffffff;
  uint32_t d = k & 0x0fffffff;

  for (size_t i = 0; i < 16; ++i) {
    if (i == 0 || i == 1 || i == 8 || i == 15) {
      c = rol28(c, 1);
      d = rol28(d, 1);
    } else {
      c = rol28(c, 2);
      d = rol28(d, 2);
    }

    ctx->sk[i] = permute(((uint64_t)c << 28) | (uint64_t)d, pc_2, sizeof(pc_2));
  }

  return FSSL_SUCCESS;
}

void fssl_des_deinit(fssl_des_ctx* ctx) {
  if (ctx == nullptr)
    return;

  *ctx = (fssl_des_ctx){};
}

void fssl_des_encrypt_block(fssl_des_ctx* ctx, const uint8_t* in, uint8_t* out) {
  (void)ctx;
  (void)in;
  (void)out;
}

void fssl_des_decrypt_block(fssl_des_ctx* ctx, const uint8_t* in, uint8_t* out) {
  (void)ctx;
  (void)in;
  (void)out;
}

const fssl_block_cipher_t fssl_cipher_des = {
    .ctx_size = sizeof(fssl_des_ctx),
    .block_size = FSSL_DES_BLOCK_SIZE,
    .key_size = FSSL_DES_KEY_SIZE,

    .init_fn = (fssl_block_cipher_init_fn)fssl_des_init,
    .deinit_fn = (fssl_block_cipher_deinit_fn)fssl_des_deinit,
    .block_encrypt_fn = (fssl_block_cipher_encrypt_fn)fssl_des_encrypt_block,
    .block_decrypt_fn = (fssl_block_cipher_decrypt_fn)fssl_des_decrypt_block,
};