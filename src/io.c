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

// --- Base64 reader

static ssize_t b64_read_more(Base64Reader* ctx) {
  if (ctx->eof)
    return 0;

  // Check that there's still data in the input buffer
  if (ctx->iptr > 0 && ctx->iptr < ctx->ilen) {
    const size_t rest = ctx->ilen - ctx->iptr;
    ft_memmove(ctx->input, ctx->input + ctx->iptr, rest);
  } else if (ctx->iptr >= ctx->ilen) {
    ctx->iptr = ctx->ilen = 0;
  }

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
  size_t w = 0;
  while (ctx->olen < sizeof(ctx->output)) {
    const ssize_t r = b64_read_more(ctx);
    if (r < 0)
      return -1;
    if (r == 0)
      break;

    const size_t remaining = ctx->ilen - ctx->iptr;
    if (remaining < 4)
      continue;

    const size_t n = remaining / 4 * 4;
    size_t written = 0;

    const fssl_error_t err =
        fssl_base64_decode((const char*)ctx->input + ctx->iptr, n,
                           ctx->output + ctx->olen, sizeof(ctx->output) - ctx->olen,
                           &written);
    if (fssl_haserr(err)) {
      ssl_log_warn("b64: error decoding: %s\n", fssl_error_string(err));
      return -1;
    }

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

  // The number of bytes we wrote in buf
  size_t w = 0;
  while (w < n) {
    // We still have some decoded data left
    if (ctx->optr < ctx->olen) {
      const size_t available = ctx->olen - ctx->optr;
      const size_t usable = min(available, n - w);

      ft_memcpy(buf + w, ctx->output + ctx->optr, usable);
      ctx->optr += usable;
      w += usable;

      if (w >= n)
        break;
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
  instance->close = close_on_deinit;

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
    .deinit = (reader_deinit_fn)file_reader_deinit,
};