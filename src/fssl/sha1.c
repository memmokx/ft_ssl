#include <assert.h>
#include <fssl/fssl.h>
#include <libft/memory.h>

static fssl_force_inline uint32_t rotl32(uint32_t a, uint32_t r) {
  return (a << r) | (a >> (32 - r));
}

static fssl_force_inline void fssl_sha1_block(fssl_sha1_ctx* ctx, const uint8_t* block) {
  uint32_t w[80];
  size_t i = 0;

  for (i = 0; i < 16; ++i) {
    w[i] = fssl_be_read_u32((uint8_t*)(block + (i * 4)));
  }

  // Message schedule: extend the sixteen 32-bit words into eighty 32-bit words:
  for (; i < 80; ++i) {
    w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
  }

  uint32_t a = ctx->state[0];
  uint32_t b = ctx->state[1];
  uint32_t c = ctx->state[2];
  uint32_t d = ctx->state[3];
  uint32_t e = ctx->state[4];

  for (i = 0; i < 80; ++i) {
    uint32_t k = 0, f = 0;

    if (i <= 19) {
      f = (b & c) | (~b & d);
      k = 0x5A827999;
    } else if (i <= 39) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1;
    } else if (i <= 59) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDC;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6;
    }

    const uint32_t tmp = rotl32(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = rotl32(b, 30);
    b = a;
    a = tmp;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
}

void fssl_sha1_init(fssl_sha1_ctx* ctx) {
  *ctx = (fssl_sha1_ctx){
      .state =
          {
              0x67452301,
              0xEFCDAB89,
              0x98BADCFE,
              0x10325476,
              0xC3D2E1F0,
          },
      .buffer = {},
      .size = 0,
      .buffer_len = 0,
  };
}

void fssl_sha1_write(fssl_sha1_ctx* ctx, const uint8_t* data, size_t len) {
  fssl_digest_write(ctx, data, len, fssl_sha1_block, FSSL_SHA1_BLOCK_SIZE);
}

bool fssl_sha1_finish(fssl_sha1_ctx* ctx, uint8_t* buf, size_t buf_capacity) {
  const size_t padding = (56 - (1 + ctx->size)) % 64;
  const uint64_t len = ctx->size * 8;
  // 1 for the single end-bit.
  // 64 for the possible padding.
  // 8 for the encoded len.
  uint8_t scratch[1 + 64 + 8] = {0x80};

  if (buf_capacity < FSSL_SHA1_SUM_SIZE)
    return false;

  fssl_be_write_u64(scratch + 1 + padding, len);
  fssl_sha1_write(ctx, scratch, 1 + padding + 8);

  fssl_be_write_u32(buf, ctx->state[0]);
  fssl_be_write_u32(buf + 4, ctx->state[1]);
  fssl_be_write_u32(buf + 8, ctx->state[2]);
  fssl_be_write_u32(buf + 12, ctx->state[3]);
  fssl_be_write_u32(buf + 16, ctx->state[4]);

  return true;
}

fssl_wrap_hash_impl(fssl_sha1);

const fssl_hash_t fssl_hash_sha1 = {
    .ctx_size = sizeof(fssl_sha1_ctx),
    .sum_size = FSSL_SHA1_SUM_SIZE,
    .block_size = FSSL_SHA1_BLOCK_SIZE,
    .write_fn = fssl_sha1_write_impl,
    .finish_fn = fssl_sha1_finish_impl,
    .reset_fn = fssl_sha1_init_impl,
};
