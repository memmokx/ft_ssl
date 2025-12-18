#include "io.h"

#define IO_ENC_BUFFER_SIZE (8192 * 2)

typedef struct {
  IoReader base;
  IoReader* inner;
  fssl_cipher_t* cipher;

  bool eof;

  // Decryption buffer
  uint8_t dbuf[IO_ENC_BUFFER_SIZE + FSSL_MAX_BLOCK_SIZE];
  size_t dbuflen;
  size_t dbufptr;

  // Ciphertext buffer
  uint8_t buf[IO_ENC_BUFFER_SIZE];
  size_t buflen;
  size_t bufptr;

  // TODO: implement this, CTR mode can be streamable
  bool streamable;

  // Are we holding the last block
  bool holding;
  // The last block we decrypted
  uint8_t holdbuf[FSSL_MAX_BLOCK_SIZE];

  size_t block_size;
} CipherReader;

static void cipher_reader_copy(CipherReader* ctx, uint8_t* buf, const size_t n, size_t* w) {
  IO_READER_RETARGET(ctx->dbufptr, ctx->dbuflen, ctx->dbuf);

  const size_t available = ctx->dbuflen - ctx->dbufptr;
  if (available == 0)
    return;

  const size_t usable = min(available, n - *w);
  ft_memcpy(buf + *w, ctx->dbuf + ctx->dbufptr, usable);
  ctx->dbufptr += usable;
  *w += usable;
}

static ssize_t cipher_reader_fetch(CipherReader* ctx) {
  if (ctx->eof)
    return 0;

  IO_READER_RETARGET(ctx->bufptr, ctx->buflen, ctx->buf);

  const size_t before = ctx->buflen;
  while (!ctx->eof && sizeof(ctx->buf) - ctx->buflen > 0) {
    const size_t n = sizeof(ctx->buf) - ctx->buflen;
    const ssize_t r = io_reader_read(ctx->inner, ctx->buf + ctx->buflen, n);
    if (r < 0)
      return -1;
    if (r == 0)
      ctx->eof = true;
    ctx->buflen += r;
  }

  return (ssize_t)(ctx->buflen - before);
}

static ssize_t cipher_reader_fill(CipherReader* ctx) {
  size_t remaining = ctx->buflen - ctx->bufptr;
  if (ctx->streamable && remaining > 0)
    return (ssize_t)remaining;

  while (remaining < ctx->block_size) {
    const ssize_t r = cipher_reader_fetch(ctx);
    if (r < 0)
      return -1;
    if (r == 0)
      return 0;
    remaining = ctx->buflen - ctx->bufptr;
  }

  return (ssize_t)remaining;
}

static ssize_t cipher_reader_decrypt(CipherReader* ctx, uint8_t* buf, size_t n, size_t* w) {
  const size_t remaining = ctx->buflen - ctx->bufptr;
  // if we're streamable, decrypt everything
  const size_t todecrypt =
      ctx->streamable ? remaining : (remaining / ctx->block_size) * ctx->block_size;

  ssize_t r = 0;
  if (ctx->streamable)
    r = fssl_cipher_decrypt(ctx->cipher, ctx->buf + ctx->bufptr, ctx->dbuf, todecrypt);
  else {
    ssl_assert(ctx->dbufptr == 0);
    ssl_assert(ctx->dbuflen == 0);

    r = fssl_cipher_decrypt(ctx->cipher, ctx->buf + ctx->bufptr,
                            ctx->dbuf + (ctx->holding ? ctx->block_size : 0),
                            todecrypt);
  }
  if (r < 0) {
    ssl_log_err("cipher_reader: decrypt: error decrypting (n=%lu)\n", todecrypt);
    return -1;
  }

  ctx->bufptr += (size_t)r;
  ctx->dbuflen += (size_t)r;  // The number of bytes we decrypted

  // If not streamable, put the last block on hold as it may be padded
  if (!ctx->streamable) {
    // We successfully decrypted, so the buffer on hold is safe now
    if (ctx->holding) {
      ft_memcpy(ctx->dbuf, ctx->holdbuf, ctx->block_size);
      ctx->dbuflen += ctx->block_size;
      ctx->holding = false;
    }

    ctx->dbuflen -= ctx->block_size;
    ft_memcpy(ctx->holdbuf, ctx->dbuf + ctx->dbuflen, ctx->block_size);
    ctx->holding = true;
  }

  if (ctx->dbuflen != 0)
    cipher_reader_copy(ctx, buf, n, w);

  return 0;
}

static ssize_t cipher_reader_unpad(CipherReader* ctx) {
  size_t padded = 0;
  if (fssl_pkcs5_unpad(ctx->holdbuf, ctx->block_size, ctx->block_size, &padded) !=
      FSSL_SUCCESS) {
    ssl_log_err("cipher_reader: bad padding\n");
    return -1;
  }

  ft_memcpy(ctx->dbuf + ctx->dbuflen, ctx->holdbuf, ctx->block_size - padded);
  ctx->dbuflen += (ctx->block_size - padded);
  ctx->holding = false;

  return 0;
}

static ssize_t cipher_reader_read(IoReader* p, uint8_t* buf, const size_t n) {
  size_t w = 0;
  const auto ctx = (CipherReader*)p;
  if (!ctx || !buf)
    return -1;

  cipher_reader_copy(ctx, buf, n, &w);

  while (w < n) {
    if (ctx->dbufptr >= ctx->dbuflen)
      ctx->dbufptr = ctx->dbuflen = 0;

    // refill input buffer with data from the parent/inner reader
    const ssize_t remaining = cipher_reader_fill(ctx);
    if (remaining < 0)
      return -1;
    if (remaining == 0)  // EOF
      goto out;

    if (cipher_reader_decrypt(ctx, buf, n, &w) < 0)
      return -1;
  }

out:
  // we reached EOF, so we need to unpad the last block as no more data will be read.
  if (!ctx->streamable && ctx->eof && cipher_reader_unpad(ctx) < 0)
    return -1;
  if (w < n)
    cipher_reader_copy(ctx, buf, n, &w);

  return (ssize_t)w;
}

static void cipher_reader_reset(IoReader* p) {
  const auto ctx = (CipherReader*)p;
  if (!ctx)
    return;

  const auto c = ctx->cipher;
  const auto base = ctx->base;
  const auto inner = ctx->inner;
  const auto block_size = ctx->block_size;

  io_reader_reset(inner);
  *ctx = (CipherReader){
      .base = base, .inner = inner, .cipher = c, .block_size = block_size};
}

static void cipher_reader_deinit(IoReader* p) {
  if (!p)
    return;

  const auto ctx = (CipherReader*)p;
  io_free(ctx->inner);
  *ctx = (CipherReader){};
}

static const IoReaderVT cipher_reader_vtable = {
    .read = cipher_reader_read,
    .reset = cipher_reader_reset,
    .deinit = cipher_reader_deinit,
};

/*!
 * @brief Create a new \c CipherReader that allows decryption of the data read from
 * the parent.
 *
 * This object DOES NOT own the cipher object, it will not be freed on _deinit.
 * \c io_reader_reset calls WILL call \c fssl_cipher_reset.
 * @param parent The parent \c IoReader, data will be read from it and then decrypted.
 * @param cipher The cipher object, it will be used to decrypt the read data.
 * @return \c nullptr if memory allocation fail. On success: new \c CipherReader object.
 */
IoReader* cipher_reader_new(IoReader* parent, fssl_cipher_t* cipher) {
  CipherReader* instance = malloc(sizeof(CipherReader));
  if (!instance)
    return nullptr;

  *instance = (CipherReader){
      .base = {.vt = &cipher_reader_vtable},
      .inner = parent,
      .cipher = cipher,
      .streamable = fssl_cipher_streamable(cipher),
      .block_size = fssl_cipher_block_size(cipher),
  };

  return (IoReader*)instance;
}

typedef struct {
  IoWriter base;
  IoWriter* inner;
  fssl_cipher_t* cipher;

  size_t written;

  // Pending buffer
  uint8_t pbuf[IO_ENC_BUFFER_SIZE + FSSL_MAX_BLOCK_SIZE];
  size_t pbuflen;

  // Encryption buffer
  uint8_t ebuf[IO_ENC_BUFFER_SIZE];
  size_t block_size;
} CipherWriter;

#define sizeofpending(ctx) (sizeof((ctx)->pbuf) - FSSL_MAX_BLOCK_SIZE)

/*!
 * Write \a n bytes from \a buf into the internal writer, this will encrypt them
 * beforehand. This writer will encrypt in blocks of \c IO_ENC_BUFFER_SIZE
 * @return
 */
static ssize_t cipher_writer_write(IoWriter* p, const uint8_t* buf, size_t n) {
  const auto ctx = (CipherWriter*)p;

  size_t w = 0;
  while (w < n) {
    while (w < n && ctx->pbuflen < sizeofpending(ctx)) {
      const size_t available = min(sizeofpending(ctx) - ctx->pbuflen, n - w);
      ft_memmove(ctx->pbuf + ctx->pbuflen, buf + w, available);

      w += available;
      ctx->pbuflen += available;
    }

    if (ctx->pbuflen == sizeofpending(ctx)) {
      const size_t toencrypt = ctx->pbuflen - ctx->block_size;
      const ssize_t encrypted =
          fssl_cipher_encrypt(ctx->cipher, ctx->pbuf, ctx->ebuf, toencrypt);
      // Erase plaintext from memory in every case, but keep the last block
      ft_bzero(ctx->pbuf, toencrypt);
      if (encrypted < 0) {
        ssl_log_err("cipher_writer: encrypt: error during encryption (n=%lu)\n",
                    toencrypt);
        return -1;
      }

      ssl_assert((size_t)encrypted == toencrypt);
      // Move the last block to the front
      ft_memmove(ctx->pbuf, ctx->pbuf + toencrypt, ctx->block_size);
      ctx->pbuflen -= encrypted;

      if (io_writer_write(ctx->inner, ctx->ebuf, toencrypt) < 0)
        return -1;
    }
  }

  return (ssize_t)w;
}

static void cipher_writer_reset(IoWriter* p) {
  const auto ctx = (CipherWriter*)p;
  if (!ctx)
    return;

  const auto c = ctx->cipher;
  const auto base = ctx->base;
  const auto inner = ctx->inner;
  const auto block_size = ctx->block_size;

  io_writer_reset(inner);

  *ctx = (CipherWriter){
      .base = base, .inner = inner, .cipher = c, .block_size = block_size};
}

static void cipher_writer_deinit(IoWriter* p) {
  const auto ctx = (CipherWriter*)p;
  if (!ctx)
    return;

  io_free(ctx->inner);
  *ctx = (CipherWriter){};
}

/*!
 * Pad and encrypt the remaining data. Closes the underlying \c IoWriter.
 */
static void cipher_writer_close(IoWriter* p) {
  const auto ctx = (CipherWriter*)p;
  if (!ctx)
    return;

  if (ctx->pbuflen > 0) {
    size_t added = 0;
    const fssl_error_t err = fssl_pkcs5_pad(ctx->pbuf + ctx->pbuflen, ctx->pbuflen,
                                            sizeof(ctx->pbuf), ctx->block_size, &added);
    if fssl_haserr (err) {
      ssl_log_err("cipher_writer: padding error: %s\n", fssl_error_string(err));
      goto out;
    }

    if ((ctx->pbuflen + added) % ctx->block_size != 0) {
      ssl_log_err("cipher_writer: bad pad: block_size=%lu\n", ctx->block_size);
      goto out;
    }

    const ssize_t encrypted =
        fssl_cipher_encrypt(ctx->cipher, ctx->pbuf, ctx->ebuf, ctx->pbuflen + added);

    ft_bzero(ctx->pbuf, ctx->pbuflen + added);
    if (encrypted < 0)
      goto out;

    io_writer_write(ctx->inner, ctx->ebuf, encrypted);
    ctx->pbuflen = 0;
  }

out:
  io_writer_close(ctx->inner);
}

static const IoWriterVT cipher_writer_vtable = {
    .write = cipher_writer_write,
    .reset = cipher_writer_reset,
    .deinit = cipher_writer_deinit,
    .close = cipher_writer_close,
};

/*!
 * Create a new CipherWriter which encrypts data it receives using the given \a `cipher`.
 * When closed it will pad and encrypt the remaining data then flush it to the parent \c IoWriter.
 *
 * @param parent The parent \c IoWriter, encrypted data will be written into it.
 * @param cipher The cipher object used to encrypt the data.
 * @return \c nullptr on error, otherwise a \c IoWriter
 */
IoWriter* cipher_writer_new(IoWriter* parent, fssl_cipher_t* cipher) {
  CipherWriter* instance = malloc(sizeof(CipherWriter));
  if (!instance)
    return nullptr;

  *instance = (CipherWriter){
      .base = {.vt = &cipher_writer_vtable},
      .inner = parent,
      .cipher = cipher,
      .block_size = fssl_cipher_block_size(cipher),
  };

  return (IoWriter*)instance;
}
