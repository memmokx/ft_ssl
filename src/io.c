#include "libft/io.h"

#include <assert.h>
#include <fssl/fssl.h>
#include <libft/memory.h>
#include <stdlib.h>

#include "io.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>

ssize_t io_reader_read(IoReader* reader, uint8_t* buf, size_t n) {
  ssl_assert(reader && reader->vt);

  return reader->vt->read(reader, buf, n);
}

void io_reader_reset(IoReader* reader) {
  ssl_assert(reader && reader->vt);

  reader->vt->reset(reader);
}

/*!
 * @brief Free an IoReader object.
 *
 * This will call the deinit method, then free the reader itself.
 *
 * Warning: if no deinit method is provided, the reader will not be deinitialized.
 * @param reader The reader to free.
 */
void io_reader_free(IoReader* reader) {
  if (reader && reader->vt && reader->vt->deinit) {
    reader->vt->deinit(reader);
    free(reader);
  }
}

ssize_t io_writer_write(IoWriter* writer, const uint8_t* buf, size_t n) {
  ssl_assert(writer && writer->vt);

  return writer->vt->write(writer, buf, n);
}

void io_writer_reset(IoWriter* writer) {
  ssl_assert(writer && writer->vt);

  writer->vt->reset(writer);
}

/*!
 * @brief Free an IoWriter object.
 *
 * This will call the deinit method, then free the writer itself.
 *
 * Warning: if no deinit method is provided, the writer will not be deinitialized.
 * @param writer The writer to free.
 */
void io_writer_free(IoWriter* writer) {
  if (writer && writer->vt && writer->vt->deinit) {
    writer->vt->deinit(writer);
    free(writer);
  }
}

void io_writer_close(IoWriter* writer) {
  ssl_assert(writer && writer->vt);

  if (writer->vt->close)
    writer->vt->close(writer);
}

#define IO_READER_RETARGET(_ptr, _len, _buf) \
  do {                                       \
    if (_ptr > 0 && _ptr < _len) {           \
      const size_t _rest = _len - _ptr;      \
      ft_memmove(_buf, _buf + _ptr, _rest);  \
      _len = _rest;                          \
      _ptr = 0;                              \
    } else if (_ptr >= _len)                 \
      _ptr = _len = 0;                       \
  } while (false)

// --- Base64 reader

static bool is_whitespace(const uint8_t c) {
  return (c == ' ') || (c == '\t') || (c == '\n') || (c == '\r') || (c == '\v') ||
         (c == '\f');
}

static ssize_t b64_read_more(Base64Reader* ctx) {
  if (ctx->eof)
    return 0;

  // Check that there's still data in the input buffer
  IO_READER_RETARGET(ctx->iptr, ctx->ilen, ctx->input);

  const size_t n = sizeof(ctx->input) - ctx->ilen;
  // There still space available in the input buffer. Fill it
  if (n > 0) {
    const ssize_t r = io_reader_read(ctx->inner, ctx->input + ctx->ilen, n);
    if (r < 0)
      return -1;
    if (r == 0) {
      ctx->eof = true;
      return 0;
    }
    ctx->ilen += r;
  }

  // Filter out whitespaces
  if (ctx->ignore_nl && ctx->ilen > 0) {
    size_t w = 0;
    for (size_t r = 0; r < ctx->ilen; ++r) {
      const uint8_t c = ctx->input[r];
      if (!is_whitespace(c))
        ctx->input[w++] = c;
    }
    ctx->ilen = w;
  }

  return (ssize_t)ctx->ilen;
}

static ssize_t b64_decode_chunk(Base64Reader* ctx) {
  IO_READER_RETARGET(ctx->optr, ctx->olen, ctx->output);

  size_t w = 0;
  while (ctx->olen < sizeof(ctx->output)) {
    size_t remaining = ctx->ilen - ctx->iptr;
    if (remaining < 4) {
      const ssize_t r = b64_read_more(ctx);
      if (r < 0)
        return -1;
      if (r == 0)
        break;
      if (r + remaining < 4)
        continue;
    }

    remaining = ctx->ilen - ctx->iptr;
    ssl_assert(remaining >= 4);

    const size_t ocap = sizeof(ctx->output) - ctx->olen;
    const size_t n = min(remaining / 4 * 4, fssl_base64_encoded_size(ocap));
    if (n < 4)
      break;  // The caller need to process some data

    size_t written = 0;
    const fssl_error_t err =
        fssl_base64_decode((const char*)ctx->input + ctx->iptr, n,
                           ctx->output + ctx->olen, ocap, &written);
    if (fssl_haserr(err)) {
      ssl_log_warn("info: n:%lu, remaining:%lu, olen:%lu, iptr:%lu\n", n, remaining,
                   ctx->olen, ctx->iptr);
      ssl_log_warn("b64: error decoding: %s\n", fssl_error_string(err));
      return -1;
    }

    ctx->iptr += n;
    ctx->olen += written;
    w += written;
  }

  return (ssize_t)w;
}

/*!
 * @param ptr The base64 reader.
 * @param buf The output buffer to write the decoded read_bytes.
 * @param n The capacity of the output buffer.
 * @return The number of bytes it has written in buf.
 */
static ssize_t b64_reader_read(IoReader* ptr, uint8_t* buf, const size_t n) {
  const auto ctx = (Base64Reader*)ptr;

  if (!ptr || !buf) {
    return -1;
  }

  size_t w = 0;
  while (w < n) {
    if (ctx->optr < ctx->olen) {
      const size_t available = ctx->olen - ctx->optr;
      const size_t usable = min(available, n - w);

      ft_memcpy(buf + w, ctx->output + ctx->optr, usable);
      ctx->optr += usable;
      w += usable;

      if (w >= n)
        break;

      ssl_assert(ctx->optr >= ctx->olen);
    }

    // Refill the decoded buffer
    const ssize_t decoded = b64_decode_chunk(ctx);
    if (decoded < 0)
      return -1;
    if (decoded == 0)
      break;
  }

  return (ssize_t)w;
}

static void b64_reader_reset(IoReader* io) {
  const auto ctx = (Base64Reader*)io;
  if (!ctx)
    return;

  const auto inner = ctx->inner;
  const auto base = ctx->base;
  const auto ignore_nl = ctx->ignore_nl;

  *ctx = (Base64Reader){
      .base = base,
      .inner = inner,
      .ignore_nl = ignore_nl,
  };
}

static void b64_reader_deinit(IoReader* io) {
  if (!io)
    return;

  const auto ctx = (Base64Reader*)io;
  io_free(ctx->inner);
  *ctx = (Base64Reader){};
}

static const IoReaderVT b64_reader_vtable = {
    .read = b64_reader_read,
    .reset = b64_reader_reset,
    .deinit = b64_reader_deinit,
};

IoReader* b64_reader_new(IoReader* reader, const bool ignore_nl) {
  Base64Reader* instance = malloc(sizeof(Base64Reader));
  if (!instance)
    return nullptr;

  *instance = (Base64Reader){
      .base = {.vt = &b64_reader_vtable},
      .inner = reader,
      .ignore_nl = ignore_nl,
  };

  return (IoReader*)instance;
}

// --- File reader

static ssize_t file_reader_read(IoReader* ptr, uint8_t* buf, const size_t n) {
  const auto ctx = (FileReader*)ptr;
  if (!ctx || !buf)
    return -1;

  const ssize_t result = read(ctx->fd, buf, n);
  if (result < 0)
    ssl_log_warn("file_reader: read: %s\n", strerror(errno));
  return result;
}

static void file_reader_reset(IoReader* ptr) {
  (void)ptr;
}

static void file_reader_deinit(IoReader* ptr) {
  if (!ptr)
    return;

  const auto instance = (FileReader*)ptr;
  if (instance->close)
    close(instance->fd);
}

static const IoReaderVT file_reader_vtable = {
    .read = file_reader_read,
    .reset = file_reader_reset,
    .deinit = file_reader_deinit,
};

IoReader* file_reader_new(const char* file, const bool close_on_deinit) {
  FileReader* instance = malloc(sizeof(FileReader));
  if (!instance)
    return nullptr;

  const int fd = open(file, O_RDONLY);
  if (fd < 0) {
    ssl_log_warn("file_reader: open(%s): %s\n", file, strerror(errno));
    free(instance);
    return nullptr;
  }

  *instance = (FileReader){
      .base = {.vt = &file_reader_vtable},
      .fd = fd,
      .close = close_on_deinit,
  };

  return (IoReader*)instance;
}

const IoReader* io_stdin = (IoReader*)&(FileReader){
    .base =
        {
            .vt = &(IoReaderVT){.read = file_reader_read,
                                .reset = file_reader_reset,
                                .deinit = nullptr},
        },
    .fd = STDIN_FILENO,
    .close = false,
};

// --- Base64 writer

static ssize_t b64_writer_write(IoWriter* ptr, const uint8_t* buf, size_t n) {
  const auto ctx = (Base64Writer*)ptr;
  if (!ctx || !buf)
    return -1;

  size_t w = 0;
  if (ctx->buflen > 0) {
    size_t i = 0;
    for (; i < n && ctx->buflen < 3; ++i)
      ctx->buf[ctx->buflen++] = buf[i];

    w += i;
    buf += i;
    n -= i;
    if (ctx->buflen < 3)
      goto done;

    size_t written = 0;
    const fssl_error_t err =
        fssl_base64_encode(ctx->buf, ctx->buflen, (char*)ctx->output,
                           sizeof(ctx->output), &written);
    if (fssl_haserr(err)) {
      ssl_log_warn("b64_writer: encode err: %s\n", fssl_error_string(err));
      return -1;
    }

    ssl_assert(written == 4);

    if (io_writer_write(ctx->inner, ctx->output, written) < 0)
      return -1;
    ctx->buflen = 0;
  }

  while (n >= 3) {
    size_t chunk_size = fssl_base64_decoded_size(sizeof(ctx->output));
    if (chunk_size > n)
      chunk_size = n - (n % 3);

    ssl_assert(chunk_size % 3 == 0);

    size_t written = 0;
    const fssl_error_t err = fssl_base64_encode(buf, chunk_size, (char*)ctx->output,
                                                sizeof(ctx->output), &written);
    if (fssl_haserr(err)) {
      ssl_log_warn("b64_writer: encode err: %s\n", fssl_error_string(err));
      return -1;
    }

    ssl_assert(written == fssl_base64_encoded_size(chunk_size));

    // TODO: set error state?
    if (io_writer_write(ctx->inner, ctx->output, written) < 0)
      return -1;

    w += chunk_size;
    buf += chunk_size;
    n -= chunk_size;
  }

  if (n != 0) {
    ft_memcpy(ctx->buf, buf, n);
    ctx->buflen = n;
    w += n;
  }

done:
  return (ssize_t)w;
}

static void b64_writer_reset(IoWriter* ptr) {
  const auto ctx = (Base64Writer*)ptr;
  if (!ctx)
    return;

  const auto inner = ctx->inner;
  const auto base = ctx->base;

  io_writer_reset(inner);
  *ctx = (Base64Writer){.base = base, .inner = inner};
}

static void b64_writer_deinit(IoWriter* ptr) {
  if (!ptr)
    return;

  const auto ctx = (Base64Writer*)ptr;

  io_free(ctx->inner);
  *ctx = (Base64Writer){};
}

static void b64_writer_close(IoWriter* ptr) {
  const auto ctx = (Base64Writer*)ptr;

  if (!ctx)
    return;

  if (ctx->buflen > 0) {
    size_t written = 0;
    const fssl_error_t err =
        fssl_base64_encode(ctx->buf, ctx->buflen, (char*)ctx->output,
                           sizeof(ctx->output), &written);
    if (fssl_haserr(err)) {
      ssl_log_warn("b64_writer: encode err: %s\n", fssl_error_string(err));
      return;  // TODO: error
    }

    if (io_writer_write(ctx->inner, ctx->output, written) < 0)
      return;
  }
}

static const IoWriterVT b64_writer_vtable = {
    .write = b64_writer_write,
    .reset = b64_writer_reset,
    .deinit = b64_writer_deinit,
    .close = b64_writer_close,
};

IoWriter* b64_writer_new(IoWriter* inner) {
  Base64Writer* instance = malloc(sizeof(Base64Writer));
  if (!instance)
    return nullptr;

  *instance = (Base64Writer){.base = {.vt = &b64_writer_vtable}, .inner = inner};
  return (IoWriter*)instance;
}

// --- Encryption related Io

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

/*!
 * @brief Read bytes from the underlying reader to fill the internal buffer.
 */
static ssize_t cipher_reader_fetch_more(CipherReader* ctx) {
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

static ssize_t cipher_reader_read(IoReader* p, uint8_t* buf, const size_t n) {
  const auto ctx = (CipherReader*)p;
  size_t w = 0;

  IO_READER_RETARGET(ctx->dbufptr, ctx->dbuflen, ctx->dbuf);

  if (ctx->dbuflen - ctx->dbufptr > 0) {
    const size_t tomove = min(ctx->dbuflen - ctx->dbufptr, n);
    ft_memcpy(buf, ctx->dbuf + ctx->dbufptr, tomove);
    ctx->dbufptr += tomove;
    w += tomove;
  }

  while (w < n) {
    if (ctx->dbufptr >= ctx->dbuflen)
      ctx->dbufptr = ctx->dbuflen = 0;

    // We want to be able to decrypt at least a block
    // TODO: streamable: if we are using a streamable cipher this is useless.
    size_t remaining;
    for (remaining = ctx->buflen - ctx->bufptr; remaining < ctx->block_size;
         remaining = ctx->buflen - ctx->bufptr) {
      const ssize_t r = cipher_reader_fetch_more(ctx);
      if (r < 0)
        return -1;
      if (r == 0)
        goto out;
    }

    // We have at least a block to decrypt
    const size_t todecrypt = remaining / ctx->block_size * ctx->block_size;

    ssl_assert(todecrypt % ctx->block_size == 0);
    ssl_assert(todecrypt <= sizeof(ctx->dbuf) - sizeof(ctx->holdbuf));
    ssl_assert(ctx->dbufptr == 0);
    ssl_assert(ctx->dbuflen == 0);

    const ssize_t r =
        fssl_cipher_decrypt(ctx->cipher, ctx->buf + ctx->bufptr,
                            ctx->dbuf + (ctx->holding ? ctx->block_size : 0),
                            todecrypt);
    if (r < 0) {
      ssl_log_err("cipher_reader: decrypt: error decrypting (n=%lu)\n", todecrypt);
      return -1;
    }

    ctx->bufptr += (size_t)r;
    ctx->dbuflen += (size_t)r;  // The number of bytes we decrypted

    // We successfully decrypted, so the buffer on hold is safe now
    if (ctx->holding) {
      ft_memcpy(ctx->dbuf, ctx->holdbuf, ctx->block_size);
      ctx->dbuflen += ctx->block_size;
      ctx->holding = false;
    }

    ctx->dbuflen -= ctx->block_size;
    ft_memcpy(ctx->holdbuf, ctx->dbuf + ctx->dbuflen, ctx->block_size);
    ctx->holding = true;

    if (ctx->dbuflen == 0)
      continue;

    const size_t towrite = min(ctx->dbuflen, n - w);
    ft_memcpy(buf + w, ctx->dbuf, towrite);
    ctx->dbufptr += towrite;
    w += towrite;
  }

out:
  if (ctx->holding && ctx->eof) {
    size_t padded = 0;
    if (fssl_pkcs5_unpad(ctx->holdbuf, ctx->block_size, ctx->block_size, &padded) !=
        FSSL_SUCCESS) {
      ssl_log_err("cipher_reader: bad padding\n");
      return -1;
    }

    ft_memcpy(ctx->dbuf + ctx->dbuflen, ctx->holdbuf, ctx->block_size - padded);
    ctx->dbuflen += (ctx->block_size - padded);
    ctx->holding = false;
  }

  if (w < n && ctx->dbuflen - ctx->dbufptr > 0) {
    const size_t towrite = min(ctx->dbuflen - ctx->dbufptr, n - w);
    ft_memcpy(buf + w, ctx->dbuf + ctx->dbufptr, towrite);
    ctx->dbufptr += towrite;
    w += towrite;
  }

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

// TODO: add padding function argument
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

      if (io_writer_write((IoWriter*)ctx->inner, ctx->ebuf, toencrypt) < 0)
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

// TODO: add padding function argument
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

// --- File Writer

static ssize_t file_writer_write(IoWriter* ptr, const uint8_t* buf, size_t n) {
  const auto ctx = (FileWriter*)ptr;

  if (!ctx || !buf)
    return -1;

  const ssize_t result = write(ctx->fd, buf, n);
  if (result < 0) {
    ssl_log_err("file_writer: write(%d, ...): %s\n", ctx->fd, strerror(errno));
    return -1;
  }

  return result;
}

static void file_writer_reset(IoWriter* ctx) {
  (void)ctx;
}

static void file_writer_deinit(IoWriter* ptr) {
  const auto w = (FileWriter*)ptr;
  if (!w)
    return;

  if (w->close)
    close(w->fd);
  *w = (FileWriter){};
}

static const IoWriterVT file_writer_vtable = {
    .write = file_writer_write,
    .reset = file_writer_reset,
    .deinit = file_writer_deinit,
};

IoWriter* file_writer_new(const char* file, const bool close_on_deinit, const int oflag) {
  FileWriter* instance = malloc(sizeof(FileWriter));
  if (!instance)
    return nullptr;

  // TODO: permissions?
  const int fd = open(file, O_WRONLY | oflag, 0644);
  if (fd < 0) {
    ssl_log_err("file_writer: open(%s): %s\n", file, strerror(errno));
    free(instance);
    return nullptr;
  }

  *instance = (FileWriter){
      .base = {.vt = &file_writer_vtable}, .fd = fd, .close = close_on_deinit};
  return (IoWriter*)instance;
}

const IoWriter* io_stdout = (IoWriter*)&(FileWriter){
    .base =
        {
            .vt = &(IoWriterVT){.write = file_writer_write,
                                .reset = file_writer_reset,
                                .deinit = nullptr},
        },
    .fd = STDOUT_FILENO,
    .close = false,
};

ssize_t io_copy(IoReader* reader, IoWriter* writer) {
  if (!reader || !writer)
    return -1;

  uint8_t buffer[8192];

  ssize_t total = 0;
  while (true) {
    const ssize_t r = io_reader_read(reader, buffer, sizeof(buffer));
    if (r < 0)
      return -1;
    if (r == 0)
      break;

    const ssize_t w = io_writer_write(writer, buffer, r);
    if (w < 0)
      return -1;
    if (w == 0)
      break;

    if (r != w) {
      ssl_log_warn("w != r. {w: %lu, r: %lu}\n", w, r);
      break;
    }

    total += r;
  }

  return total;
}
