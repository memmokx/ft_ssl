#ifndef FSSL_CIPHER_H
#define FSSL_CIPHER_H

#include <fssl/defines.h>
#include <fssl/error.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*!
 * @brief The signature for cipher block functions. This function will be called
 * on each block of data to encrypt.
 */
typedef void (*fssl_block_cipher_encrypt_fn)(void* ctx,
                                             const uint8_t* in,
                                             uint8_t* out);

/*!
 * @brief The signature for cipher block functions. This function will be called
 * on each block of data to decrypt.
 */
typedef void (*fssl_block_cipher_decrypt_fn)(void* ctx,
                                             const uint8_t* in,
                                             uint8_t* out);

/*!
 * @brief The signature for block cipher initialization functions. This function
 * will be called once to initialize the cipher context with the given key.
 */
typedef fssl_error_t (*fssl_block_cipher_init_fn)(void* ctx, const uint8_t* key);

/*!
 * @brief The signature for block cipher de-initialization functions. This
 * function will be called once to release any resources allocated by the cipher
 * context.
 */
typedef void (*fssl_block_cipher_deinit_fn)(void* ctx);

typedef struct {
  size_t ctx_size;
  size_t block_size;
  size_t key_size;

  fssl_block_cipher_init_fn init_fn;
  fssl_block_cipher_deinit_fn deinit_fn;
  fssl_block_cipher_encrypt_fn block_encrypt_fn;
  fssl_block_cipher_decrypt_fn block_decrypt_fn;
} fssl_block_cipher_t;

/*!
 * @brief The signature for block mode functions.
 * @param in The input data to encrypt/decrypt.
 * @param in_size The size of the input data.
 * @param out The output buffer.
 * @param out_size The capacity of the output buffer.
 */
typedef size_t (*fssl_block_mode_fn)(const uint8_t* in,
                                     size_t in_size,
                                     uint8_t* out,
                                     size_t out_size);

typedef struct {
  size_t iv_size;

  fssl_block_mode_fn encrypt_fn;
  fssl_block_mode_fn decrypt_fn;
} fssl_block_mode_t;

#endif
