#include "fssl/cipher.h"
#include <fssl/fssl.h>
#include <stdio.h>
#include <stdlib.h>

#include "libft/memory.h"
#include "libft/string.h"

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
declmode(stream, static);

static const auto ERR_INVALID_MODE = libft_static_string(
    "fssl: internal error: the given block mode and cipher pair is invalid\n");

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
    case CIPHER_MODE_STREAM:
      if (desc->type != CIPHER_STREAM) {
        err = FSSL_ERR_INVALID_ARGUMENT;
        write(STDERR_FILENO, ERR_INVALID_MODE.ptr, ERR_INVALID_MODE.len);
      } else {
        if (desc->encrypt_stream == nullptr || desc->decrypt_stream == nullptr)
          err = FSSL_ERR_INVALID_ARGUMENT;
        setmodefunc(stream_encrypt, stream_decrypt);
      }
      break;
    default:
      err = FSSL_ERR_INVALID_ARGUMENT;
      write(STDERR_FILENO, ERR_INVALID_MODE.ptr, ERR_INVALID_MODE.len);
      break;
  }
done:
  if (fssl_haserr(err) && c.instance)
    free(c.instance);
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

fssl_force_inline ssize_t fssl_cipher_encrypt(fssl_cipher_t* cipher,
                                              const uint8_t* in,
                                              uint8_t* out,
                                              const size_t n) {
  if (!cipher || !out)
    return -1;
  return cipher->encrypt(cipher, in, out, n);
}

fssl_force_inline ssize_t fssl_cipher_decrypt(fssl_cipher_t* cipher,
                                              const uint8_t* in,
                                              uint8_t* out,
                                              const size_t n) {
  if (!cipher || !out)
    return -1;
  return cipher->decrypt(cipher, in, out, n);
}

fssl_force_inline fssl_error_t fssl_cipher_set_key(fssl_cipher_t* cipher,
                                                   const uint8_t* key) {
  if (!cipher || !key)
    return FSSL_ERR_INVALID_ARGUMENT;

  return cipher->desc->init(cipher->instance, key);
}

static const auto ERR_BLOCK_SIZE_TOO_SMALL = libft_static_string(
    "fssl: internal error: block size is too small for CTR mode\n");

static fssl_force_inline size_t fssl_cipher_iv_size_internal(const fssl_cipher_t* cipher) {
  switch (cipher->mode) {
    case CIPHER_MODE_ECB:
    case CIPHER_MODE_STREAM:
      return 0;
    case CIPHER_MODE_CBC:
    case CIPHER_MODE_OFB:
    case CIPHER_MODE_CFB:
      return fssl_cipher_block_size(cipher);
    case CIPHER_MODE_CTR:
      // In CTR mode the IV is (NONCE || COUNTER), the length of the IV is the same
      // as the block size as for all block ciphers. Here we return the size of the nonce.
      const size_t block_size = fssl_cipher_block_size(cipher);
      // Even if this is highly insecure the minimum block_size we accept is 8
      if (block_size < 2 * sizeof(uint32_t)) {
        write(STDERR_FILENO, ERR_BLOCK_SIZE_TOO_SMALL.ptr, ERR_BLOCK_SIZE_TOO_SMALL.len);
        __builtin_trap();
      }

      // TODO: Maybe create multiple modes? e.g: CTR_64LE, CTR_32BE
      return block_size - sizeof(uint32_t);
    default:
      __builtin_trap();
  }
}

static fssl_force_inline fssl_error_t
fssl_cipher_set_mode_data_internal(fssl_cipher_t* c, const fssl_slice_t iv) {
  const size_t size = iv.size;
  const uint8_t* data = iv.data;

  // Stream ciphers don't have an IV size requirement.
  if (c->desc->type != CIPHER_STREAM && size != fssl_cipher_iv_size_internal(c))
    return FSSL_ERR_INVALID_ARGUMENT;

  ft_bzero(&c->mode_data, sizeof(c->mode_data));

  switch (c->mode) {
    case CIPHER_MODE_CBC:
      ft_memcpy(c->mode_data.cbc.state, data, size);
      break;
    case CIPHER_MODE_CTR:
      ft_memcpy(c->mode_data.ctr.iv, data, size);
      break;
    case CIPHER_MODE_OFB:
      ft_memcpy(c->mode_data.ofb.stream, data, size);
      break;
    case CIPHER_MODE_CFB:
      ft_memcpy(c->mode_data.cfb.stream, data, size);
      break;
    case CIPHER_MODE_STREAM:
      if (c->desc->set_iv)
        return c->desc->set_iv(c->instance, &iv);
    default:
      break;
  }

  return FSSL_SUCCESS;
}

fssl_force_inline fssl_error_t fssl_cipher_set_iv(fssl_cipher_t* cipher,
                                                  const fssl_slice_t* iv) {
  fssl_error_t err = FSSL_SUCCESS;

  if (!cipher || !iv || !iv->data)
    return FSSL_ERR_INVALID_ARGUMENT;

  size_t size = iv->size;
  if (size > FSSL_MAX_IV_SIZE)
    size = FSSL_MAX_IV_SIZE;

  if ((err = fssl_cipher_set_mode_data_internal(cipher, (fssl_slice_t){iv->data, size})) !=
      FSSL_SUCCESS)
    return err;

  ft_memcpy(cipher->iv.data, iv->data, size);
  cipher->iv.size = size;

  return err;
}

void fssl_cipher_reset(fssl_cipher_t* c) {
  if (!c)
    return;

  fssl_cipher_set_mode_data_internal(c, (fssl_slice_t){c->iv.data, c->iv.size});
}

fssl_force_inline fssl_cipher_type_t fssl_cipher_type(const fssl_cipher_t* cipher) {
  return cipher->desc->type;
}

fssl_force_inline size_t fssl_cipher_block_size(const fssl_cipher_t* cipher) {
  return cipher->desc->block_size;
}

fssl_force_inline size_t fssl_cipher_key_size(const fssl_cipher_t* cipher) {
  return cipher->desc->key_size;
}

fssl_force_inline size_t fssl_cipher_iv_size(const fssl_cipher_t* cipher) {
  return fssl_cipher_iv_size_internal(cipher);
}

fssl_force_inline bool fssl_cipher_streamable(const fssl_cipher_t* cipher) {
  if (cipher->desc->type == CIPHER_STREAM)
    return true;

  switch (cipher->mode) {
    case CIPHER_MODE_CTR:
    case CIPHER_MODE_CFB:
    case CIPHER_MODE_OFB:
      return true;
    default:
      return false;
  }
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
  const size_t block_size = fssl_cipher_block_size(ctx);
  size_t w = 0;

  if (n % block_size != 0)
    return -1;

  if (!in)
    in = out;

  while (n >= block_size) {
    ctx->desc->decrypt(ctx->instance, in, out);

    w += block_size;
    in += block_size;
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
    in += block_size * (!inplace);  // keep ubsan happy
    out += block_size;

    n -= block_size;
  }

  return (ssize_t)w;
}

static ssize_t ctr_encrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  if (!ctx || !out)
    return -1;

  const size_t block_size = fssl_cipher_block_size(ctx);
  const size_t nonce_size = ctx->iv.size;

  // position in the stream
  uint8_t* sptr = &ctx->mode_data.ctr.sptr;
  uint32_t* ctr = &ctx->mode_data.ctr.u32;
  uint8_t* stream = ctx->mode_data.ctr.stream;

  size_t w = 0;

  if (!in)
    in = out;

  if (*sptr > 0) {
    size_t remaining = block_size - *sptr;
    if (remaining > n)
      remaining = n;

    for (size_t i = 0; i < remaining; i++)
      out[i] = in[i] ^ stream[i + *sptr];

    *sptr += remaining;
    if (*sptr >= block_size)
      *sptr = 0;
    w += remaining;
    if (w >= n)
      goto done;
  }

  const size_t blocks = (n - w) / block_size;
  const auto iv = ctx->mode_data.ctr.iv;

  uint8_t block[FSSL_MAX_BLOCK_SIZE];
  for (size_t b = 0; b < blocks; b++) {
    fssl_be_write_u32(iv + nonce_size, *ctr);
    ctx->desc->encrypt(ctx->instance, iv, block);

    const auto inp = in + w;
    const auto outp = out + w;

    for (size_t i = 0; i < block_size; i++)
      outp[i] = inp[i] ^ block[i];
    w += block_size;
    *ctr += 1;
  }

  const size_t remaining = n - w;
  if (remaining > 0) {
    fssl_be_write_u32(iv + nonce_size, *ctr + 1);
    ctx->desc->encrypt(ctx->instance, iv, block);

    for (size_t i = 0; i < remaining; i++)
      out[w + i] = in[w + i] ^ block[i];

    w += remaining;
    *ctr += 1;

    *sptr = remaining;
    ft_memcpy(ctx->mode_data.ctr.stream, block, block_size);
  }

done:
  return (ssize_t)w;
}

static ssize_t ctr_decrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  return ctr_encrypt(ctx, in == nullptr ? out : in, out, n);
}

static ssize_t cfb_encrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  const size_t block_size = fssl_cipher_block_size(ctx);

  uint8_t* stream = ctx->mode_data.cfb.stream;
  uint8_t* sptr = &ctx->mode_data.cfb.sptr;

  size_t w = 0;

  if (!in)
    in = out;

  if (*sptr > 0) {
    size_t remaining = block_size - *sptr;
    if (remaining > n)
      remaining = n;
    for (size_t i = 0; i < remaining; i++) {
      out[i] = in[i] ^ stream[i + *sptr];
      stream[i + *sptr] = out[i];
    }

    w += remaining;
    *sptr += remaining;
    if (*sptr >= block_size)
      *sptr = 0;
    if (w >= n)
      goto done;
  }

  const size_t blocks = (n - w) / block_size;

  for (size_t b = 0; b < blocks; b++) {
    ctx->desc->encrypt(ctx->instance, stream, stream);

    const auto inp = in + w;
    const auto outp = out + w;

    for (size_t i = 0; i < block_size; i++) {
      outp[i] = inp[i] ^ stream[i];
      stream[i] = outp[i];
    }

    w += block_size;
  }

  const size_t remaining = n - w;
  if (remaining > 0) {
    ctx->desc->encrypt(ctx->instance, stream, stream);
    for (size_t i = 0; i < remaining; i++) {
      out[w + i] = in[w + i] ^ stream[i];
      stream[i] = out[w + i];
    }

    w += remaining;
    *sptr = remaining;
  }

done:
  return (ssize_t)w;
}

// TODO: de-duplicate logic
static ssize_t cfb_decrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  const size_t block_size = fssl_cipher_block_size(ctx);

  uint8_t* stream = ctx->mode_data.cfb.stream;
  uint8_t* sptr = &ctx->mode_data.cfb.sptr;
  // To keep the ciphertext bytes
  uint8_t tmp = 0;
  size_t w = 0;

  if (!in)
    in = out;

  if (*sptr > 0) {
    size_t remaining = block_size - *sptr;
    if (remaining > n)
      remaining = n;
    for (size_t i = 0; i < remaining; i++) {
      tmp = in[i];
      out[i] = tmp ^ stream[i + *sptr];
      stream[i + *sptr] = tmp;
    }

    w += remaining;
    *sptr += remaining;
    if (*sptr >= block_size)
      *sptr = 0;
    if (w >= n)
      goto done;
  }

  const size_t blocks = (n - w) / block_size;

  for (size_t b = 0; b < blocks; b++) {
    ctx->desc->encrypt(ctx->instance, stream, stream);

    const auto inp = in + w;
    const auto outp = out + w;

    for (size_t i = 0; i < block_size; i++) {
      tmp = inp[i];
      outp[i] = tmp ^ stream[i];
      stream[i] = tmp;
    }

    w += block_size;
  }

  const size_t remaining = n - w;
  if (remaining > 0) {
    ctx->desc->encrypt(ctx->instance, stream, stream);
    for (size_t i = 0; i < remaining; i++) {
      tmp = in[w + i];
      out[w + i] = tmp ^ stream[i];
      stream[i] = tmp;
    }

    w += remaining;
    *sptr = remaining;
  }

done:
  return (ssize_t)w;
}

static ssize_t ofb_encrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  if (!ctx || !in || !out)
    return -1;

  const size_t block_size = fssl_cipher_block_size(ctx);
  uint8_t* stream = ctx->mode_data.ofb.stream;
  uint8_t* sptr = &ctx->mode_data.ofb.sptr;

  size_t w = 0;

  if (*sptr > 0) {
    size_t remaining = block_size - *sptr;
    if (remaining > n)
      remaining = n;

    for (size_t i = 0; i < remaining; i++)
      out[i] = in[i] ^ stream[i + *sptr];

    *sptr += remaining;
    if (*sptr >= block_size)
      *sptr = 0;
    w += remaining;
    if (w >= n)
      goto done;
  }

  const size_t blocks = (n - w) / block_size;
  for (size_t b = 0; b < blocks; b++) {
    ctx->desc->encrypt(ctx->instance, stream, stream);

    const auto inp = in + w;
    const auto outp = out + w;

    for (size_t i = 0; i < block_size; i++)
      outp[i] = inp[i] ^ stream[i];
    w += block_size;
  }

  const size_t remaining = n - w;
  if (remaining > 0) {
    ctx->desc->encrypt(ctx->instance, stream, stream);

    for (size_t i = 0; i < remaining; i++)
      out[w + i] = in[w + i] ^ stream[i];

    w += remaining;
    *sptr = remaining;
  }

done:
  return (ssize_t)w;
}

static ssize_t ofb_decrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  return ofb_encrypt(ctx, in == nullptr ? out : in, out, n);
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

static ssize_t stream_encrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  ctx->desc->encrypt_stream(ctx->instance, in, out, n);
  return n;
}

static ssize_t stream_decrypt(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n) {
  ctx->desc->decrypt_stream(ctx->instance, in, out, n);
  return n;
}
