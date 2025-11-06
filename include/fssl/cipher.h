#ifndef FSSL_CIPHER_H
#define FSSL_CIPHER_H

#include <fssl/defines.h>
#include <fssl/error.h>

typedef enum {
  CIPHER_MODE_ECB,
  CIPHER_MODE_CBC,
  CIPHER_MODE_CTR,
  CIPHER_MODE_CFB,
  CIPHER_MODE_OFB,
  CIPHER_MODE_PCBC,
  CIPHER_MODE_STREAM,
} fssl_cipher_mode_t;

typedef enum {
  CIPHER_BLOCK,
  CIPHER_STREAM,
} fssl_cipher_type_t;

typedef fssl_error_t (*fssl_cipher_init_fn)(void* ctx, const uint8_t* key);
typedef void (*fssl_cipher_encrypt_fn)(void* ctx, const uint8_t* in, uint8_t* out);
typedef void (*fssl_cipher_decrypt_fn)(void* ctx, const uint8_t* in, uint8_t* out);

typedef void (*fssl_cipher_stream_encrypt_fn)(void* ctx,
                                              const uint8_t* in,
                                              uint8_t* out,
                                              size_t n);
typedef void (*fssl_cipher_stream_decrypt_fn)(void* ctx,
                                              const uint8_t* in,
                                              uint8_t* out,
                                              size_t n);

typedef struct {
  const char* name;
  fssl_cipher_type_t type;

  size_t block_size;
  size_t key_size;
  size_t ctx_size;

  fssl_cipher_init_fn init;
  fssl_cipher_encrypt_fn encrypt;
  fssl_cipher_decrypt_fn decrypt;
  fssl_cipher_stream_encrypt_fn encrypt_stream;
  fssl_cipher_stream_decrypt_fn decrypt_stream;
} fssl_cipher_desc_t;

typedef struct _fssl_cipher_s fssl_cipher_t;

typedef struct _fssl_cipher_s {
  void* instance;
  const fssl_cipher_desc_t* desc;
  fssl_cipher_mode_t mode;

  struct {
    uint8_t data[FSSL_MAX_IV_SIZE];
    size_t size;
  } iv;

  union {
    struct {
      uint8_t state[FSSL_MAX_BLOCK_SIZE];
    } cbc;
  } mode_data;

  ssize_t (*encrypt)(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n);
  ssize_t (*decrypt)(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n);
} fssl_cipher_t;

fssl_error_t fssl_cipher_new(fssl_cipher_t* cipher,
                             const fssl_cipher_desc_t* desc,
                             fssl_cipher_mode_t mode);

fssl_error_t fssl_cipher_set_key(fssl_cipher_t* cipher, const uint8_t* key);
fssl_error_t fssl_cipher_set_iv(fssl_cipher_t* cipher, const fssl_slice_t* iv);

fssl_cipher_type_t fssl_cipher_type(const fssl_cipher_t* cipher);
size_t fssl_cipher_block_size(const fssl_cipher_t* cipher);
size_t fssl_cipher_key_size(const fssl_cipher_t* cipher);

ssize_t fssl_cipher_encrypt(fssl_cipher_t* cipher,
                            const uint8_t* in,
                            uint8_t* out,
                            size_t n);

ssize_t fssl_cipher_decrypt(fssl_cipher_t* cipher,
                            const uint8_t* in,
                            uint8_t* out,
                            size_t n);

void fssl_cipher_reset(fssl_cipher_t* cipher);
void fssl_cipher_deinit(fssl_cipher_t* cipher);

fssl_error_t fssl_pkcs5_pad(uint8_t* out,
                            size_t n,
                            size_t buf_capacity,
                            size_t block_size,
                            size_t* written);

fssl_error_t fssl_pkcs5_unpad(const uint8_t* in, size_t n, size_t block_size, size_t* padded);

#endif
