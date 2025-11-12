#include "libft/io.h"

#include <assert.h>
#include <fssl/fssl.h>
#include <libft/memory.h>
#include <stdlib.h>

#include "io.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>

ssize_t io_reader_read(const IoReader* reader, uint8_t* buf, size_t n) {
  return reader->read(reader->instance, buf, n);
}

void io_reader_reset(const IoReader* reader) {
  if (reader && reader->reset)
    reader->reset(reader->instance);
}

void io_reader_deinit(IoReader* reader) {
  if (reader && reader->deinit)
    reader->deinit(&reader->instance);
}

ssize_t io_writer_write(const IoWriter* writer, const uint8_t* buf, size_t n) {
  return writer->write(writer->instance, buf, n);
}

void io_writer_reset(const IoWriter* writer) {
  writer->reset(writer->instance);
}

void io_writer_deinit(IoWriter* writer) {
  if (writer && writer->deinit)
    writer->deinit(&writer->instance);
}

void io_writer_close(const IoWriterCloser* writer) {
  if (writer && writer->close)
    writer->close(writer->W.instance);
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
 * @param ptr The base64 reader context.
 * @param buf The output buffer to write the decoded read_bytes.
 * @param n The capacity of the output buffer.
 * @return The number of bytes it has written in buf.
 */
static ssize_t b64_reader_read(void* ptr, uint8_t* buf, const size_t n) {
  Base64Reader* ctx = ptr;

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

static void b64_reader_reset(void* ptr) {
  if (!ptr)
    return;

  Base64Reader* ctx = ptr;
  IoReader* inner = ctx->inner;

  *ctx = (Base64Reader){};
  ctx->inner = inner;
}

static void b64_reader_deinit(void** ptr) {
  if (!ptr || !*ptr)
    return;

  Base64Reader* ctx = *ptr;

  io_reader_deinit(ctx->inner);
  *ctx = (Base64Reader){};
  free(ctx);
  *ptr = nullptr;
}

Option(IoReader) b64_reader_new(IoReader* reader, const bool ignore_nl) {
  Base64Reader* instance = malloc(sizeof(Base64Reader));
  if (!instance) {
    return None(IoReader);
  }

  *instance = (Base64Reader){
      .inner = reader,
      .ignore_nl = ignore_nl,
  };

  const IoReader r = {
      .instance = instance,
      .read = b64_reader_read,
      .reset = b64_reader_reset,
      .deinit = b64_reader_deinit,
  };

  return (Option(IoReader))Some(r);
}

// --- File reader

static ssize_t file_reader_read(void* ptr, uint8_t* buf, const size_t n) {
  FileReader* ctx = ptr;

  if (!ctx || !buf)
    return -1;

  const ssize_t result = read(ctx->fd, buf, n);
  if (result < 0)
    ssl_log_warn("file_reader: read: %s\n", strerror(errno));
  return result;
}

static void file_reader_reset(void* ctx) {
  (void)ctx;
}

static void file_reader_deinit(void** ptr) {
  if (!ptr || !*ptr)
    return;

  FileReader* instance = *ptr;
  if (instance->close)
    close(instance->fd);
  free(instance);
  *ptr = nullptr;
}

static void nil_reader_deinit(void** ctx) {
  (void)ctx;
}

Option(IoReader) file_reader_new(const char* file, const bool close_on_deinit) {
  FileReader* instance = malloc(sizeof(FileReader));
  if (!instance) {
    return None(IoReader);
  }

  const int fd = open(file, O_RDONLY);
  if (fd < 0) {
    ssl_log_warn("file_reader: open(%s): %s\n", file, strerror(errno));
    free(instance);
    return None(IoReader);
  }

  *instance = (FileReader){
      .fd = fd,
      .close = close_on_deinit,
  };

  const IoReader r = {
      .instance = instance,
      .read = file_reader_read,
      .reset = file_reader_reset,
      .deinit = file_reader_deinit,
  };

  return (Option(IoReader))Some(r);
}

const IoReader io_stdin = {
    .instance = &(FileReader){.fd = STDIN_FILENO, .close = false},
    .read = file_reader_read,
    .reset = file_reader_reset,
    .deinit = nil_reader_deinit,
};

// --- Base64 writer

static ssize_t b64_writer_write(void* ptr, const uint8_t* buf, size_t n) {
  Base64Writer* ctx = ptr;

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

static void b64_writer_reset(void* ptr) {
  Base64Writer* ctx = ptr;

  if (!ctx)
    return;

  IoWriter* inner = ctx->inner;
  *ctx = (Base64Writer){.inner = inner};
}

static void b64_writer_deinit(void** ptr) {
  if (!ptr || !*ptr)
    return;

  Base64Writer* ctx = *ptr;

  io_writer_deinit(ctx->inner);
  *ctx = (Base64Writer){};
  free(ctx);
  *ptr = nullptr;
}

static void b64_writer_close(void* ptr) {
  Base64Writer* ctx = ptr;

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

Option(IoWriterCloser) b64_writer_new(IoWriter* inner) {
  Base64Writer* instance = malloc(sizeof(Base64Writer));
  if (!instance) {
    return None(IoWriterCloser);
  }

  *instance = (Base64Writer){.inner = inner};

  const IoWriter wr = {
      .instance = instance,
      .write = b64_writer_write,
      .reset = b64_writer_reset,
      .deinit = b64_writer_deinit,
  };

  return (Option(IoWriterCloser))Some(((IoWriterCloser){
      .W = wr,
      .close = b64_writer_close,
  }));
}

// --- IoWriter utilities

static void nil_writer_close_fn(void* ctx) {
  (void)ctx;
}

static void nil_writer_deinit_fn(void** ctx) {
  (void)ctx;
}

IoWriterCloser io_writer_closer_from(const IoWriter writer) {
  return (IoWriterCloser){
      .W = writer,
      .close = nil_writer_close_fn,
  };
}

// --- Encryption related Io

#define IO_ENC_BUFFER_SIZE (8192 * 2)

typedef struct {
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

static ssize_t cipher_reader_read(void* p, uint8_t* buf, const size_t n) {
  CipherReader* ctx = p;
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

static void cipher_reader_reset(void* p) {
  CipherReader* ctx = p;
  if (!ctx)
    return;

  const auto c = ctx->cipher;
  const auto inner = ctx->inner;
  const auto block_size = ctx->block_size;

  io_reader_reset(inner);
  *ctx = (CipherReader){.inner = inner, .cipher = c, .block_size = block_size};
}

static void cipher_reader_deinit(void** p) {
  if (!p || !*p)
    return;

  CipherReader* ctx = *p;
  io_reader_deinit(ctx->inner);
  *ctx = (CipherReader){};
  free(ctx);
  *p = nullptr;
}

// TODO: add padding function argument
/*!
 * @brief Create a new \c CipherReader that allows decryption of the data read from
 * the parent.
 *
 * This object DOES NOT own the cipher object, it will not be freed on _deinit.
 * \c io_reader_reset calls WILL call \c fssl_cipher_reset.
 * @param parent The parent \c IoReader, data will be read from it and then decrypted.
 * @param cipher The cipher object, it will be used to decrypt the read data.
 * @return \c None if memory allocation fail. On success: new \c CipherReader object.
 */
Option(IoReader) cipher_reader_new(IoReader* parent, fssl_cipher_t* cipher) {
  CipherReader* instance = malloc(sizeof(CipherReader));
  if (!instance)
    return None(IoReader);

  *instance = (CipherReader){
      .inner = parent,
      .cipher = cipher,
      .block_size = fssl_cipher_block_size(cipher),
  };

  const IoReader r = {
      instance,
      cipher_reader_read,
      cipher_reader_reset,
      cipher_reader_deinit,
  };

  return (Option(IoReader))Some(r);
}

typedef struct {
  IoWriterCloser* inner;
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
static ssize_t cipher_writer_write(void* p, const uint8_t* buf, size_t n) {
  CipherWriter* ctx = p;

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

static void cipher_writer_reset(void* p) {
  CipherWriter* ctx = p;
  if (!ctx)
    return;

  const auto c = ctx->cipher;
  const auto inner = ctx->inner;
  const auto block_size = ctx->block_size;

  io_writer_reset((IoWriter*)inner);

  *ctx = (CipherWriter){.inner = inner, .cipher = c, .block_size = block_size};
}

static void cipher_writer_deinit(void** p) {
  if (!p || !*p)
    return;

  CipherWriter* ctx = *p;

  io_writer_deinit((IoWriter*)ctx->inner);
  *ctx = (CipherWriter){};
  free(ctx);
  *p = nullptr;
}

/*!
 * Pad and encrypt the remaining data. Closes the underlying \c IoWriter.
 */
static void cipher_writer_close(void* p) {
  CipherWriter* ctx = p;
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

    io_writer_write((IoWriter*)ctx->inner, ctx->ebuf, encrypted);
    ctx->pbuflen = 0;
  }

out:
  io_writer_close(ctx->inner);
}

// TODO: add padding function argument
/*!
 * Create a new CipherWriter which encrypts data it receives using the given \a `cipher`.
 * When closed it will pad and encrypt the remaining data then flush it to the parent \c IoWriter.
 *
 * @param parent The parent \c IoWriterCloser, encrypted data will be written into it.
 * @param cipher The cipher object used to encrypt the data.
 * @return \c None on error, otherwise a \c IoWriterCloser
 */
Option(IoWriterCloser) cipher_writer_new(IoWriterCloser* parent, fssl_cipher_t* cipher) {
  CipherWriter* instance = malloc(sizeof(CipherWriter));
  if (!instance)
    return None(IoWriterCloser);

  *instance = (CipherWriter){
      .inner = parent,
      .cipher = cipher,
      .block_size = fssl_cipher_block_size(cipher),
  };

  const IoWriterCloser w = {
      .W =
          {
              instance,
              cipher_writer_write,
              cipher_writer_reset,
              cipher_writer_deinit,
          },
      cipher_writer_close,
  };

  return (Option(IoWriterCloser))Some(w);
}

// --- File Writer

static ssize_t file_writer_write(void* ptr, const uint8_t* buf, size_t n) {
  FileWriter* ctx = ptr;

  if (!ctx || !buf)
    return -1;

  const ssize_t result = write(ctx->fd, buf, n);
  if (result < 0) {
    ssl_log_err("file_writer: write(%d, ...): %s\n", ctx->fd, strerror(errno));
    return -1;
  }

  return result;
}

static void file_writer_reset(void* ctx) {
  (void)ctx;
}

static void file_writer_deinit(void** ptr) {
  if (!ptr || !*ptr)
    return;

  FileWriter* w = *ptr;
  if (w->close)
    close(w->fd);
  free(w);
  *ptr = nullptr;
}

Option(IoWriter)
    file_writer_new(const char* file, const bool close_on_deinit, const int oflag) {
  FileWriter* instance = malloc(sizeof(FileWriter));
  if (!instance) {
    return None(IoWriter);
  }

  // TODO: permissions?
  const int fd = open(file, O_WRONLY | oflag, 0644);
  if (fd < 0) {
    ssl_log_err("file_writer: open(%s): %s\n", file, strerror(errno));
    free(instance);
    return None(IoWriter);
  }

  *instance = (FileWriter){.fd = fd, .close = close_on_deinit};

  return (Option(IoWriter))Some(((IoWriter){
      .instance = instance,
      .write = file_writer_write,
      .reset = file_writer_reset,
      .deinit = file_writer_deinit,
  }));
}

const IoWriter io_stdout = {
    .instance = &(FileWriter){.fd = STDOUT_FILENO, .close = false},
    .write = file_writer_write,
    .reset = file_writer_reset,
    .deinit = nil_writer_deinit_fn,
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
