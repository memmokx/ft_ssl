#ifndef FSSL_DEFINES_H
#define FSSL_DEFINES_H

#define fssl_force_inline __attribute__((always_inline)) inline

#define fssl_le_write_u64(p, n)  \
  do {                           \
    (p)[7] = ((n) >> 56) & 0xff; \
    (p)[6] = ((n) >> 48) & 0xff; \
    (p)[5] = ((n) >> 40) & 0xff; \
    (p)[4] = ((n) >> 32) & 0xff; \
    (p)[3] = ((n) >> 24) & 0xff; \
    (p)[2] = ((n) >> 16) & 0xff; \
    (p)[1] = ((n) >> 8) & 0xff;  \
    (p)[0] = (n) & 0xff;         \
  } while (false)

#define fssl_be_write_u64(p, n)  \
  do {                           \
    (p)[0] = ((n) >> 56) & 0xff; \
    (p)[1] = ((n) >> 48) & 0xff; \
    (p)[2] = ((n) >> 40) & 0xff; \
    (p)[3] = ((n) >> 32) & 0xff; \
    (p)[4] = ((n) >> 24) & 0xff; \
    (p)[5] = ((n) >> 16) & 0xff; \
    (p)[6] = ((n) >> 8) & 0xff;  \
    (p)[7] = (n) & 0xff;         \
  } while (false)

#define fssl_be_write_u32(p, n)  \
  do {                           \
    (p)[0] = ((n) >> 24) & 0xff; \
    (p)[1] = ((n) >> 16) & 0xff; \
    (p)[2] = ((n) >> 8) & 0xff;  \
    (p)[3] = (n) & 0xff;         \
  } while (false)

#define fssl_le_write_u32(p, n)  \
  do {                           \
    (p)[3] = ((n) >> 24) & 0xff; \
    (p)[2] = ((n) >> 16) & 0xff; \
    (p)[1] = ((n) >> 8) & 0xff;  \
    (p)[0] = (n) & 0xff;         \
  } while (false)

#define fssl_le_read_u32(p)                                                  \
  ((uint32_t)((p)[0]) | (uint32_t)((p)[1] << 8) | (uint32_t)((p)[2] << 16) | \
   (uint32_t)((p)[3] << 24))

#define fssl_be_read_u32(p)                                                  \
  ((uint32_t)((p)[3]) | (uint32_t)((p)[2] << 8) | (uint32_t)((p)[1] << 16) | \
   (uint32_t)((p)[0] << 24))

/*
 * Original implementation
  ctx->size += len;

  // There's some data left in the buffer, try to fill it first.
  if (ctx->buffer_len != 0) {
    const size_t free = FSSL_MD5_BLOCK_SIZE - ctx->buffer_len;
    const size_t min = (len < free) ? len : free;

    ft_memcpy(ctx->buffer + ctx->buffer_len, data, min);
    ctx->buffer_len += min;

    len -= min;
    data += min;
  }

  // If the buffer was filled process it.
  if (ctx->buffer_len == FSSL_MD5_BLOCK_SIZE) {
    fssl_md5_block(ctx, ctx->buffer);
    ctx->buffer_len = 0;
  }

  // When we enter this path the previous buffer has been processed.
  if (len >= FSSL_MD5_BLOCK_SIZE) {
    const size_t blocks = len / FSSL_MD5_BLOCK_SIZE;

    for (size_t i = 0; i < blocks; ++i) {
      fssl_md5_block(ctx, data + (i * FSSL_MD5_BLOCK_SIZE));
    }

    data += blocks * FSSL_MD5_BLOCK_SIZE;
    len %= FSSL_MD5_BLOCK_SIZE;
  }

  if (len != 0) {
    ft_memcpy(ctx->buffer + ctx->buffer_len, data, len);
    ctx->buffer_len += len;
  }
 */
#define fssl_digest_write(__ctx, __data, __len, __block_fn, __block_size)  \
  do {                                                                     \
    (__ctx)->size += (__len);                                              \
    if ((__ctx)->buffer_len != 0) {                                        \
      const size_t free = (__block_size) - (__ctx)->buffer_len;            \
      const size_t min = ((__len) < free) ? (__len) : free;                \
      ft_memcpy((__ctx)->buffer + (__ctx)->buffer_len, (__data), min);     \
      (__ctx)->buffer_len += min;                                          \
      (__len) -= min;                                                      \
      (__data) += min;                                                     \
    }                                                                      \
    if ((__ctx)->buffer_len == (__block_size)) {                           \
      (__block_fn)((__ctx), (__ctx)->buffer);                              \
      (__ctx)->buffer_len = 0;                                             \
    }                                                                      \
    if ((__len) >= (__block_size)) {                                       \
      const size_t blocks = (__len) / (__block_size);                      \
      for (size_t i = 0; i < blocks; ++i) {                                \
        (__block_fn)((__ctx), (__data) + (i * (__block_size)));            \
      }                                                                    \
      (__data) += blocks * (__block_size);                                 \
      (__len) %= (__block_size);                                           \
    }                                                                      \
    if ((__len) != 0) {                                                    \
      ft_memcpy((__ctx)->buffer + (__ctx)->buffer_len, (__data), (__len)); \
      (__ctx)->buffer_len += (__len);                                      \
    }                                                                      \
  } while (false)

#endif
