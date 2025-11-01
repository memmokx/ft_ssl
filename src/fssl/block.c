#include <fssl/fssl.h>

size_t fssl_ecb_encrypt(const fssl_block_cipher_t* cipher,
                        void* ctx,
                        const uint8_t* in,
                        size_t in_size,
                        uint8_t* out,
                        const fssl_slice_t* iv) {
  (void)iv;
  size_t written = 0;

  while (in_size >= cipher->block_size) {
    cipher->block_encrypt_fn(ctx, in, out);
    in += cipher->block_size;
    out += cipher->block_size;
    written += cipher->block_size;

    in_size -= cipher->block_size;
  }

  return written;
}

size_t fssl_ecb_decrypt(const fssl_block_cipher_t* cipher,
                        void* ctx,
                        const uint8_t* in,
                        size_t in_size,
                        uint8_t* out,
                        const fssl_slice_t* iv) {
  (void)iv;
  size_t written = 0;

  while (in_size >= cipher->block_size) {
    cipher->block_decrypt_fn(ctx, in, out);
    in += cipher->block_size;
    out += cipher->block_size;
    written += cipher->block_size;

    in_size -= cipher->block_size;
  }

  return written;
}

fssl_block_mode_t fssl_ecb_init(fssl_block_cipher_t* cipher) {
  return (fssl_block_mode_t){{}, cipher, fssl_ecb_encrypt, fssl_ecb_decrypt};
}

size_t fssl_block_encrypt(const fssl_block_mode_t* mode,
                          void* ctx,
                          const uint8_t* in,
                          size_t in_size,
                          uint8_t* out) {
  return mode->encrypt_fn(mode->cipher, ctx, in, in_size, out, &mode->iv);
}

size_t fssl_block_decrypt(const fssl_block_mode_t* mode,
                          void* ctx,
                          const uint8_t* in,
                          size_t in_size,
                          uint8_t* out) {
  return mode->decrypt_fn(mode->cipher, ctx, in, in_size, out, &mode->iv);
}
