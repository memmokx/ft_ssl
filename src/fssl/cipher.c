#include <fssl/fssl.h>
#include <stdlib.h>

#include "libft/memory.h"

#define declmode(name, ...)                                                    \
  __VA_ARGS__ ssize_t name##_encrypt(fssl_cipher_t* cipher, const uint8_t* in, \
                                     uint8_t* out, size_t n);                  \
  __VA_ARGS__ ssize_t name##_decrypt(fssl_cipher_t* cipher, const uint8_t* in, \
                                     uint8_t* out, size_t n);

declmode(ecb, static);
declmode(cbc, static);
declmode(ctr, static);
declmode(cfb, static);
declmode(ofb, static);
declmode(pcbc, static);

fssl_error_t fssl_cipher_new(fssl_cipher_t* cipher,
                             const fssl_cipher_desc_t* desc,
                             const fssl_cipher_mode_t mode) {
  fssl_error_t err = FSSL_SUCCESS;
  fssl_cipher_t c = {};

  if (!cipher)
    return FSSL_ERR_INVALID_ARGUMENT;

  c.instance = ft_calloc(1, desc->ctx_size);
  if (!c.instance) {
    err = FSSL_ERR_OUT_OF_MEMORY;
    goto done;
  }

  c.desc = desc;
  c.mode = mode;

#define setmodefunc(a, b) \
  do {                    \
    c.encrypt = (a);      \
    c.decrypt = (b);      \
  } while (false)

  switch (mode) {
    case CIPHER_MODE_ECB:
      setmodefunc(ecb_encrypt, ecb_decrypt);
      break;
    case CIPHER_MODE_CBC:
      setmodefunc(cbc_encrypt, cbc_decrypt);
      break;
    case CIPHER_MODE_CTR:
      setmodefunc(ctr_encrypt, ctr_decrypt);
      break;
    case CIPHER_MODE_CFB:
      setmodefunc(cfb_encrypt, cfb_decrypt);
      break;
    case CIPHER_MODE_OFB:
      setmodefunc(ofb_encrypt, ofb_decrypt);
      break;
    case CIPHER_MODE_PCBC:
      setmodefunc(pcbc_encrypt, pcbc_decrypt);
      break;
    default:
      break;
  }
done:
  *cipher = fssl_haserr(err) ? (fssl_cipher_t){} : c;
  return err;
}

void fssl_cipher_deinit(fssl_cipher_t* cipher) {
  if (!cipher)
    return;
  if (cipher->instance)
    free(cipher->instance);
  *cipher = (fssl_cipher_t){};
}

ssize_t fssl_cipher_encrypt(fssl_cipher_t* cipher,
                            const uint8_t* in,
                            uint8_t* out,
                            const size_t n) {
  if (!cipher || !out)
    return -1;
  return cipher->encrypt(cipher, in, out, n);
}

ssize_t fssl_cipher_decrypt(fssl_cipher_t* cipher,
                            const uint8_t* in,
                            uint8_t* out,
                            const size_t n) {
  if (!cipher || !out)
    return -1;
  return cipher->decrypt(cipher, in, out, n);
}

fssl_error_t fssl_cipher_set_key(fssl_cipher_t* cipher, const uint8_t* key) {
  if (!cipher || !key)
    return FSSL_ERR_INVALID_ARGUMENT;

  cipher->desc->init(cipher->instance, key);

  return FSSL_SUCCESS;
}

fssl_error_t fssl_cipher_set_iv(fssl_cipher_t* cipher, const fssl_slice_t* iv) {
  if (!cipher || !iv || !iv->data)
    return FSSL_ERR_INVALID_ARGUMENT;

  size_t size = iv->size;
  if (size > FSSL_MAX_IV_SIZE)
    size = FSSL_MAX_IV_SIZE;

  ft_memcpy(cipher->iv.data, iv->data, size);
  return FSSL_SUCCESS;
}

static ssize_t ecb_encrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  (void)ctx;
  (void)in;
  (void)out;
  (void)n;
  return -1;
}

static ssize_t ecb_decrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  (void)ctx;
  (void)in;
  (void)out;
  (void)n;
  return -1;
}

static ssize_t cbc_encrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  (void)ctx;
  (void)in;
  (void)out;
  (void)n;
  return -1;
}

static ssize_t cbc_decrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  (void)ctx;
  (void)in;
  (void)out;
  (void)n;
  return -1;
}

static ssize_t ctr_encrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  (void)ctx;
  (void)in;
  (void)out;
  (void)n;
  return -1;
}

static ssize_t ctr_decrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  (void)ctx;
  (void)in;
  (void)out;
  (void)n;
  return -1;
}

static ssize_t cfb_encrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  (void)ctx;
  (void)in;
  (void)out;
  (void)n;
  return -1;
}

static ssize_t cfb_decrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  (void)ctx;
  (void)in;
  (void)out;
  (void)n;
  return -1;
}

static ssize_t ofb_encrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  (void)ctx;
  (void)in;
  (void)out;
  (void)n;
  return -1;
}

static ssize_t ofb_decrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  (void)ctx;
  (void)in;
  (void)out;
  (void)n;
  return -1;
}

static ssize_t pcbc_encrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  (void)ctx;
  (void)in;
  (void)out;
  (void)n;
  return -1;
}

static ssize_t pcbc_decrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  (void)ctx;
  (void)in;
  (void)out;
  (void)n;
  return -1;
}
