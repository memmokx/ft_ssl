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

ssize_t fssl_force_inline fssl_cipher_encrypt(fssl_cipher_t* cipher,
                                              const uint8_t* in,
                                              uint8_t* out,
                                              const size_t n) {
  if (!cipher || !out)
    return -1;
  return cipher->encrypt(cipher, in, out, n);
}

ssize_t fssl_force_inline fssl_cipher_decrypt(fssl_cipher_t* cipher,
                                              const uint8_t* in,
                                              uint8_t* out,
                                              const size_t n) {
  if (!cipher || !out)
    return -1;
  return cipher->decrypt(cipher, in, out, n);
}

fssl_error_t fssl_force_inline fssl_cipher_set_key(fssl_cipher_t* cipher,
                                                   const uint8_t* key) {
  if (!cipher || !key)
    return FSSL_ERR_INVALID_ARGUMENT;

  cipher->desc->init(cipher->instance, key);

  return FSSL_SUCCESS;
}

static fssl_error_t fssl_cipher_set_mode_data_internal(fssl_cipher_t* c,
                                                       const fssl_slice_t iv) {
  const size_t size = iv.size;
  const uint8_t* data = iv.data;

  switch (c->mode) {
    case CIPHER_MODE_CBC:
      if (size != fssl_cipher_block_size(c))
        return FSSL_ERR_INVALID_ARGUMENT;
      ft_memcpy(c->mode_data.cbc.state, data, size);
      break;
    default:
      break;
  }

  return FSSL_SUCCESS;
}

fssl_error_t fssl_force_inline fssl_cipher_set_iv(fssl_cipher_t* cipher,
                                                  const fssl_slice_t* iv) {
  fssl_error_t err = FSSL_SUCCESS;

  if (!cipher || !iv || !iv->data)
    return FSSL_ERR_INVALID_ARGUMENT;

  size_t size = iv->size;
  if (size > FSSL_MAX_IV_SIZE)
    size = FSSL_MAX_IV_SIZE;

  if ((err = fssl_cipher_set_mode_data_internal(cipher, (fssl_slice_t){iv->data, size})) !=
      FSSL_SUCCESS)
    goto out;

  ft_memcpy(cipher->iv.data, iv->data, size);
  cipher->iv.size = size;

out:
  return err;
}

void fssl_cipher_reset(fssl_cipher_t* c) {
  if (!c)
    return;

  fssl_cipher_set_mode_data_internal(c, (fssl_slice_t){c->iv.data, c->iv.size});
}

size_t fssl_force_inline fssl_cipher_block_size(const fssl_cipher_t* cipher) {
  return cipher->desc->block_size;
}

size_t fssl_force_inline fssl_cipher_key_size(const fssl_cipher_t* cipher) {
  return cipher->desc->key_size;
}

static ssize_t ecb_encrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  const size_t block_size = fssl_cipher_block_size(ctx);
  size_t w = 0;

  if (n % block_size != 0)
    return -1;

  while (n >= block_size) {
    ctx->desc->encrypt(ctx->instance, in, out);

    w += block_size;
    in += block_size;
    out += block_size;

    n -= block_size;
  }

  return (ssize_t)w;
}

static ssize_t ecb_decrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  const bool inplace = in == nullptr;
  const size_t block_size = fssl_cipher_block_size(ctx);
  size_t w = 0;

  if (n % block_size != 0)
    return -1;

  while (n >= block_size) {
    ctx->desc->decrypt(ctx->instance, (inplace) ? nullptr : in, out);

    w += block_size;
    in += block_size * (!inplace);  // keep ubsan happy
    out += block_size;

    n -= block_size;
  }

  return (ssize_t)w;
}

static ssize_t cbc_encrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  const size_t block_size = fssl_cipher_block_size(ctx);
  size_t w = 0;

  if (n % block_size != 0)
    return -1;

  uint8_t buf[FSSL_MAX_BLOCK_SIZE];

  // Copy the previous state or the IV if this is the first time.
  for (size_t i = 0; i < block_size; i++)
    buf[i] = ctx->mode_data.cbc.state[i];

  while (n >= block_size) {
    for (size_t i = 0; i < block_size; i++)
      buf[i] ^= in[i];

    ctx->desc->encrypt(ctx->instance, buf, out);

    for (size_t i = 0; i < block_size; i++)
      buf[i] = out[i];

    w += block_size;
    in += block_size;
    out += block_size;

    n -= block_size;
  }

  for (size_t i = 0; i < block_size; i++)
    ctx->mode_data.cbc.state[i] = buf[i];

  return (ssize_t)w;
}

static ssize_t cbc_decrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  const bool inplace = in == nullptr;
  const size_t block_size = fssl_cipher_block_size(ctx);

  uint8_t* state = ctx->mode_data.cbc.state;
  size_t w = 0;

  if (n % block_size != 0)
    return -1;

  uint8_t buf[FSSL_MAX_BLOCK_SIZE];

  while (n >= block_size) {
    for (size_t i = 0; i < block_size; i++)
      buf[i] = state[i];

    // The current ciphertext block is used to xor the next decrypted block
    // but since we decrypt in place we need to save it!
    if (inplace)
      for (size_t i = 0; i < block_size; i++)
        state[i] = out[i];

    ctx->desc->decrypt(ctx->instance, (inplace) ? nullptr : in, out);

    for (size_t i = 0; i < block_size; i++)
      out[i] ^= buf[i];

    // Save the ciphertext for the next block
    if (!inplace)
      for (size_t i = 0; i < block_size; i++)
        state[i] = in[i];

    w += block_size;
    in += block_size * (!inplace); // keep ubsan happy
    out += block_size;

    n -= block_size;
  }

  return (ssize_t)w;
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
