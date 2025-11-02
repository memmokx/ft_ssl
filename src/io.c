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
  reader->reset(reader->instance);
}

void io_reader_deinit(IoReader* reader) {
  reader->deinit(&reader->instance);
}

ssize_t io_writer_write(const IoWriter* writer, const uint8_t* buf, size_t n) {
  return writer->write(writer->instance, buf, n);
}

void io_writer_reset(const IoWriter* writer) {
  writer->reset(writer->instance);
}
void io_writer_deinit(IoWriter* writer) {
  writer->deinit(&writer->instance);
}

void io_writer_close(const IoWriterCloser* writer) {
  writer->close(writer->W.instance);
}

// --- Base64 reader

static ssize_t b64_read_more(Base64Reader* ctx) {
  if (ctx->eof)
    return 0;

  // Check that there's still data in the input buffer
  if (ctx->iptr > 0 && ctx->iptr < ctx->ilen) {
    const size_t rest = ctx->ilen - ctx->iptr;
    ft_memmove(ctx->input, ctx->input + ctx->iptr, rest);
    ctx->ilen -= rest;
    ctx->iptr -= rest;
  } else if (ctx->iptr >= ctx->ilen)
    ctx->iptr = ctx->ilen = 0;

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
      if (c != '\n' && c != '\r') {
        ctx->input[w++] = c;
      }
    }
    ctx->ilen = w;
  }

  return (ssize_t)ctx->ilen;
}

static ssize_t b64_decode_chunk(Base64Reader* ctx) {
  if (ctx->optr > 0 && ctx->optr < ctx->olen) {
    const size_t rest = ctx->olen - ctx->optr;
    ft_memmove(ctx->output, ctx->output + ctx->optr, rest);
    ctx->olen -= rest;
    ctx->optr -= rest;
  } else if (ctx->optr >= ctx->olen)
    ctx->optr = ctx->olen = 0;

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
      ssl_log_warn("info: n:%d, remaining:%d, olen:%d, iptr:%d\n", n, remaining,
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
 * @param ctx The base64 reader context.
 * @param buf The output buffer to write the decoded read_bytes.
 * @param n The capacity of the output buffer.
 * @return The number of bytes it has written in buf.
 */
static ssize_t b64_reader_read(Base64Reader* ctx, uint8_t* buf, const size_t n) {
  if (!ctx || !buf) {
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

static void b64_reader_reset(Base64Reader* ctx) {
  IoReader* inner = ctx->inner;

  *ctx = (Base64Reader){};
  ctx->inner = inner;
}

static void b64_reader_deinit(Base64Reader** ctx) {
  if (!ctx || !*ctx)
    return;

  io_reader_deinit((*ctx)->inner);
  **ctx = (Base64Reader){};
  free(*ctx);
  *ctx = nullptr;
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
      .read = (reader_read_fn)b64_reader_read,
      .reset = (reader_reset_fn)b64_reader_reset,
      .deinit = (reader_deinit_fn)b64_reader_deinit,
  };

  return (Option(IoReader))Some(r);
}

// --- File reader

static ssize_t file_reader_read(FileReader* ctx, uint8_t* buf, const size_t n) {
  if (!ctx || !buf)
    return -1;

  const ssize_t result = read(ctx->fd, buf, n);
  if (result < 0)
    ssl_log_warn("file_reader: read: %s\n", strerror(errno));
  return result;
}

static void file_reader_reset(FileReader* ctx) {
  (void)ctx;
}

static void file_reader_deinit(FileReader** ctx) {
  if (!ctx || !*ctx)
    return;

  FileReader* instance = *ctx;
  if (instance->close)
    close(instance->fd);
  free(instance);
  *ctx = nullptr;
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
    ssl_log_warn("file_reader: open(%s): %s\n", strerror(errno));
    free(instance);
    return None(IoReader);
  }

  *instance = (FileReader){
      .fd = fd,
      .close = close_on_deinit,
  };

  const IoReader r = {
      .instance = instance,
      .read = (reader_read_fn)file_reader_read,
      .reset = (reader_reset_fn)file_reader_reset,
      .deinit = (reader_deinit_fn)file_reader_deinit,
  };

  return (Option(IoReader))Some(r);
}

const IoReader io_stdin = {
    .instance = &(FileReader){.fd = STDIN_FILENO, .close = false},
    .read = (reader_read_fn)file_reader_read,
    .reset = (reader_reset_fn)file_reader_reset,
    .deinit = (reader_deinit_fn)nil_reader_deinit,
};

// --- Base64 writer

static ssize_t b64_writer_write(Base64Writer* ctx, const uint8_t* buf, size_t n) {
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

static void b64_writer_reset(Base64Writer* ctx) {
  if (!ctx)
    return;

  IoWriter* inner = ctx->inner;
  *ctx = (Base64Writer){.inner = inner};
}

static void b64_writer_deinit(Base64Writer** ctx) {
  if (!ctx || !*ctx)
    return;

  io_writer_deinit((*ctx)->inner);
  **ctx = (Base64Writer){};
  free(*ctx);
  *ctx = nullptr;
}

static void b64_writer_close(Base64Writer* ctx) {
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
      .write = (writer_write_fn)b64_writer_write,
      .reset = (writer_reset_fn)b64_writer_reset,
      .deinit = (writer_deinit_fn)b64_writer_deinit,
  };

  return (Option(IoWriterCloser))Some(((IoWriterCloser){
      .W = wr,
      .close = (writer_close_fn)b64_writer_close,
  }));
}

// --- IoWriter utilities

static void nil_writer_close_fn(const void* ctx) {
  (void)ctx;
}

static void nil_writer_deinit_fn(void** ctx) {
  (void)ctx;
}

IoWriterCloser io_writer_closer_from(const IoWriter writer) {
  return (IoWriterCloser){
      .W = writer,
      .close = (writer_close_fn)nil_writer_close_fn,
  };
}

// --- File Writer

static ssize_t file_writer_write(FileWriter* ctx, const uint8_t* buf, size_t n) {
  if (!ctx || !buf)
    return -1;

  const ssize_t result = write(ctx->fd, buf, n);
  if (result < 0) {
    ssl_log_err("file_writer: write(%d, ...): %s\n", ctx->fd, strerror(errno));
    return -1;
  }

  return result;
}

static void file_writer_reset(const FileWriter* ctx) {
  (void)ctx;
}

static void file_writer_deinit(FileWriter** ctx) {
  if (!ctx || !*ctx)
    return;

  FileWriter* w = *ctx;
  if (w->close)
    close(w->fd);
  free(w);
  *ctx = nullptr;
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
      .write = (writer_write_fn)file_writer_write,
      .reset = (writer_reset_fn)file_writer_reset,
      .deinit = (writer_deinit_fn)file_writer_deinit,
  }));
}

const IoWriter io_stdout = {
    .instance = &(FileWriter){.fd = STDOUT_FILENO, .close = false},
    .write = (writer_write_fn)file_writer_write,
    .reset = (writer_reset_fn)file_writer_reset,
    .deinit = (writer_deinit_fn)nil_writer_deinit_fn,
};

ssize_t io_copy(IoReader* reader, IoWriter* writer) {
  if (!reader || !writer)
    return -1;

  uint8_t buffer[2048];

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
      ssl_log_warn("w != r. {w: %d, r: %d}\n", w, r);
      break;
    }

    total += r;
  }

  return total;
}