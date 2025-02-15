#include <assert.h>
#include <fssl/fssl.h>
#include <libft/memory.h>

constexpr uint32_t s[] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

constexpr uint32_t k[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

static fssl_force_inline uint32_t rotl32(uint32_t a, uint32_t r) {
  return (a << r) | (a >> (32 - r));
}

static fssl_force_inline void fssl_md5_block(fssl_md5_ctx* ctx, const uint8_t* block) {
  constexpr size_t md5_block_words = FSSL_MD5_BLOCK_SIZE / 4;

  uint32_t a = ctx->state[0];
  uint32_t b = ctx->state[1];
  uint32_t c = ctx->state[2];
  uint32_t d = ctx->state[3];

  uint32_t words[md5_block_words] = {};
  for (size_t j = 0; j < md5_block_words; j++) {
    words[j] = fssl_le_read_u32((uint8_t*)(block + (j * 4)));
  }

  for (uint32_t i = 0; i < 64; ++i) {
    uint32_t f, g;

    if (i <= 15) {
      f = (b & c) | (~b & d);
      g = i;
    } else if (i <= 31) {
      f = (d & b) | (~d & c);
      g = (5 * i + 1) & 0xf;
    } else if (i <= 47) {
      f = b ^ c ^ d;
      g = (3 * i + 5) & 0xf;
    } else {
      f = c ^ (b | ~d);
      g = (7 * i) & 0xf;
    }

    f += a + k[i] + words[g];
    a = d;
    d = c;
    c = b;
    b += rotl32(f, s[i]);
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
}

void fssl_md5_init(fssl_md5_ctx* ctx) {
  *ctx = (fssl_md5_ctx){
      .state = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476},
      .buffer = {},
      .size = 0,
      .buffer_len = 0,
  };
}

void fssl_md5_write(fssl_md5_ctx* ctx, const uint8_t* data, size_t len) {
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
    // TODO(push): remove assert.
    assert(ctx->buffer_len == 0);

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
}

bool fssl_md5_finish(fssl_md5_ctx* ctx, uint8_t* buf, size_t buf_capacity, size_t *written) {
  const size_t padding = (56 - (1 + ctx->size)) % 64;
  const uint64_t len = ctx->size * 8;
  // 1 for the single end-bit.
  // 64 for the possible padding.
  // 8 for the encoded len.
  uint8_t scratch[1 + 64 + 8] = {0x80};

  if (buf_capacity < FSSL_MD5_SUM_SIZE)
    return false;

  fssl_le_write_u64(scratch + 1 + padding, len);

  fssl_md5_write(ctx, scratch, 1 + padding + 8);

  fssl_le_write_u32(buf, ctx->state[0]);
  fssl_le_write_u32(buf + 4, ctx->state[1]);
  fssl_le_write_u32(buf + 8, ctx->state[2]);
  fssl_le_write_u32(buf + 12, ctx->state[3]);

  if (written != nullptr)
    *written = FSSL_MD5_SUM_SIZE;

  return true;
}

Hasher fssl_md5_hasher(fssl_md5_ctx* ctx) {
  return (Hasher){
      .instance = ctx,
      .write = (fssl_hasher_write_fn)fssl_md5_write,
      .finish = (fssl_hasher_finish_fn)fssl_md5_finish,
  };
}
