#include <fssl/fssl.h>

fssl_error_t fssl_des3_init(void* ctx, const uint8_t* key) {
  fssl_des3_ctx* des3 = ctx;
  fssl_error_t err;

  if (!ctx || !key)
    return FSSL_ERR_INVALID_ARGUMENT;

  if ((err = fssl_des_init(&des3->c1, key)) != FSSL_SUCCESS)
    return err;
  if ((err = fssl_des_init(&des3->c2, key + FSSL_DES_KEY_SIZE)) != FSSL_SUCCESS)
    return err;
  return fssl_des_init(&des3->c3, key + (FSSL_DES_KEY_SIZE * 2));
}

static void fssl_des3_encrypt_block(void* ctx, const uint8_t* in, uint8_t* out) {
  fssl_des3_ctx* des3 = ctx;

  if (!ctx || !out)
    return;

  if (!in)
    in = out;

  // E_k1(D_k2(E_k3(plaintext)))
  fssl_des_encrypt_block(&des3->c1, in, out);
  fssl_des_decrypt_block(&des3->c2, out, out);
  fssl_des_encrypt_block(&des3->c3, out, out);
}

static void fssl_des3_decrypt_block(void* ctx, const uint8_t* in, uint8_t* out) {
  fssl_des3_ctx* des3 = ctx;

  if (!ctx || !out)
    return;

  // Inplace
  if (!in)
    in = out;

  // D_k1(E_k2(D_k3(ciphertext)))
  fssl_des_decrypt_block(&des3->c3, in, out);
  fssl_des_encrypt_block(&des3->c2, out, out);
  fssl_des_decrypt_block(&des3->c1, out, out);
}

const fssl_cipher_desc_t fssl_cipher_des3 = {
    .name = "des3",

    .type = CIPHER_BLOCK,
    .block_size = FSSL_DES3_BLOCK_SIZE,
    .key_size = FSSL_DES3_KEY_SIZE,
    .ctx_size = sizeof(fssl_des3_ctx),

    .init = fssl_des3_init,
    .encrypt = fssl_des3_encrypt_block,
    .decrypt = fssl_des3_decrypt_block,
};
