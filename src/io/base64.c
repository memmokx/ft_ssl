#include "io.h"

typedef enum {
  // We simply copy data from the `output` buffer to the user buffer.
  B64_READER_COPY,
  // We need to decode more data from the input buffer
  B64_READER_DECODE,
  // We need to read more data from the inner reader
  B64_READER_FETCH,
  // Reached EOF
  B64_READER_EOF,
  // Error occurred.
  B64_READER_ERROR,
  // We read all the possible data.
  B64_READER_FINISHED,
} b64_reader_state_t;

typedef struct {
  IoReader base;
  IoReader* inner;

  b64_reader_state_t state;

  uint8_t input[1024];
  uint8_t output[1024];

  size_t ilen;
  size_t iptr;
  size_t olen;
  size_t optr;

  bool eof;
  bool ignore_nl;
} Base64Reader;

static bool is_whitespace(const uint8_t c) {
  return (c == ' ') || (c == '\t') || (c == '\n') || (c == '\r') || (c == '\v') ||
         (c == '\f');
}

static b64_reader_state_t b64_reader_copy(Base64Reader* ctx,
                                          uint8_t* buf,
                                          size_t n,
                                          size_t* w) {
  IO_READER_RETARGET(ctx->optr, ctx->olen, ctx->output);

  const size_t available = ctx->olen - ctx->optr;
  if (available == 0)
    return B64_READER_DECODE;

  const size_t usable = ssl_min(available, n - *w);
  ft_memcpy(buf + *w, ctx->output + ctx->optr, usable);
  ctx->optr += usable;
  *w += usable;

  // If we consumed everything we'll need to decode more
  if (ctx->optr >= ctx->olen) {
    ctx->optr = ctx->olen = 0;
    return B64_READER_DECODE;
  }

  return B64_READER_COPY;
}

/*!
 * Decode data from the input buffer into the output buffer.
 * @return \c B64_READER_COPY if data is available. \c B64_READER_FETCH if there
 * isn't enough data to decode.
 */
static b64_reader_state_t b64_reader_decode(Base64Reader* ctx) {
  const size_t remaining = ctx->ilen - ctx->iptr;
  if (remaining < 4)
    return B64_READER_FETCH;  // we need at least a 4 bytes chunk
  IO_READER_RETARGET(ctx->optr, ctx->olen, ctx->output);

  const size_t ocap = sizeof(ctx->output) - ctx->olen;
  const size_t n = ssl_min(remaining / 4 * 4, fssl_base64_encoded_size(ocap));
  if (n < 4)
    return B64_READER_COPY;  // The caller need to process some data

  size_t written = 0;
  const fssl_error_t err = fssl_base64_decode((const char*)ctx->input + ctx->iptr, n,
                                              ctx->output + ctx->olen, ocap, &written);
  if (fssl_haserr(err)) {
    ssl_log_warn("info: n:%lu, remaining:%lu, olen:%lu, iptr:%lu\n", n, remaining,
                 ctx->olen, ctx->iptr);
    ssl_log_warn("b64: error decoding: %s\n", fssl_error_string(err));
    return -1;
  }

  ctx->iptr += n;
  ctx->olen += written;

  return B64_READER_COPY;
}

/*!
 * Fetch more data from the inner reader into the input buffer.
 * @return \c B64_READER_DECODE if data is available. \c B64_READER_EOF if EOF is reached.
 * \c B64_READER_ERROR if an error occurred.
 */
static b64_reader_state_t b64_reader_fetch(Base64Reader* ctx) {
  if (ctx->eof)
    return B64_READER_EOF;

  IO_READER_RETARGET(ctx->iptr, ctx->ilen, ctx->input);

  const size_t available = sizeof(ctx->input) - ctx->ilen;
  if (available == 0) {
    ssl_log_err("b64: input buffer full\n");
    return B64_READER_ERROR;
  }

  {
    const ssize_t r = io_reader_read(ctx->inner, ctx->input + ctx->ilen, available);
    if (r < 0)
      return B64_READER_ERROR;
    if (r == 0) {
      ctx->eof = true;
      return B64_READER_EOF;
    }

    ctx->ilen += r;
  }

  if (ctx->ignore_nl) {
    size_t w = 0;
    for (size_t r = 0; r < ctx->ilen; ++r) {
      const uint8_t c = ctx->input[r];
      if (!is_whitespace(c))
        ctx->input[w++] = c;
    }
    ctx->ilen = w;
  }

  return B64_READER_DECODE;
}

/*!
 * Drain the remaining data from the input buffer.
 * @return \c B64_READER_COPY to signal that remaining data was decoded. \c
 * B64_READER_ERROR if an error occurred. \c B64_READER_FINISHED if no more data is
 * available.
 */
static b64_reader_state_t b64_reader_drain(Base64Reader* ctx) {
  if (ctx->olen > ctx->optr)
    return B64_READER_COPY;

  IO_READER_RETARGET(ctx->iptr, ctx->ilen, ctx->input);
  const size_t remaining = ctx->ilen - ctx->iptr;
  if (remaining > 0) {
    if (remaining < 4) {
      ssl_log_warn("b64: incomplete final chunk\n");
      return B64_READER_ERROR;
    }

    size_t written = 0;
    const fssl_error_t err =
        fssl_base64_decode((const char*)ctx->input, remaining, ctx->output,
                           sizeof(ctx->output), &written);
    if (fssl_haserr(err)) {
      ssl_log_warn("b64: error decoding final chunk: %s\n", fssl_error_string(err));
      return B64_READER_ERROR;
    }

    ctx->iptr = ctx->ilen = 0;
    ctx->optr = 0;
    ctx->olen = written;

    return B64_READER_COPY;
  }

  return B64_READER_FINISHED;
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
    switch (ctx->state) {
      case B64_READER_COPY:
        ctx->state = b64_reader_copy(ctx, buf, n, &w);
        break;
      case B64_READER_DECODE:
        ctx->state = b64_reader_decode(ctx);
        break;
      case B64_READER_FETCH:
        ctx->state = b64_reader_fetch(ctx);
        break;
      case B64_READER_EOF:
        ctx->state = b64_reader_drain(ctx);
        break;
      case B64_READER_ERROR:
        return -1;
      case B64_READER_FINISHED:
        return (ssize_t)w;
    }
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
      .state = B64_READER_COPY,
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
      .state = B64_READER_COPY,
      .inner = reader,
      .ignore_nl = ignore_nl,
  };

  return (IoReader*)instance;
}

typedef struct {
  IoWriter base;
  IoWriter* inner;

  uint8_t output[1024];
  size_t buflen;

  uint8_t buf[3];
} Base64Writer;

static ssize_t b64_writer_flush(Base64Writer* ctx, const uint8_t* data, const size_t len) {
  size_t written = 0;
  const fssl_error_t err =
      fssl_base64_encode(data, len, (char*)ctx->output, sizeof(ctx->output), &written);
  if (fssl_haserr(err)) {
    ssl_log_warn("b64_writer: encode err: %s\n", fssl_error_string(err));
    return -1;
  }

  if (io_writer_write(ctx->inner, ctx->output, written) < 0)
    return -1;

  return (ssize_t)written;
}

static ssize_t b64_writer_write(IoWriter* ptr, const uint8_t* buf, size_t n) {
  const auto ctx = (Base64Writer*)ptr;
  if (!ctx || !buf)
    return -1;

  size_t w = 0;
  if (ctx->buflen > 0) {
    while (n > 0 && ctx->buflen < 3) {
      ctx->buf[ctx->buflen++] = buf[w];
      n--;
      w++;
    }

    if (ctx->buflen < 3)
      goto done;
    if (b64_writer_flush(ctx, ctx->buf, sizeof(ctx->buflen)) < 0)
      return -1;

    ctx->buflen = 0;
  }

  while (n >= 3) {
    size_t chunk_size = fssl_base64_decoded_size(sizeof(ctx->output));
    if (chunk_size > n)
      chunk_size = n - (n % 3);

    ssl_assert(chunk_size % 3 == 0);

    if (b64_writer_flush(ctx, buf + w, chunk_size) < 0)
      return -1;

    w += chunk_size;
    n -= chunk_size;
  }

  while (n > 0) {
    ctx->buf[ctx->buflen++] = buf[w];
    n--;
    w++;
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

  if (ctx->buflen > 0)
    b64_writer_flush(ctx, ctx->buf, ctx->buflen);

  io_writer_close(ctx->inner);
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
