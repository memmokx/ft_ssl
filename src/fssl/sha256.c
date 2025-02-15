#include <assert.h>
#include <fssl/fssl.h>
#include <libft/memory.h>

constexpr uint32_t k[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static fssl_force_inline uint32_t rotr32(uint32_t a, uint32_t r) {
  return (a >> r) | (a << (32 - r));
}

#define ROTXOR(p, __a, __b, __c) \
  (rotr32((p), __a) ^ rotr32((p), __b) ^ rotr32((p), __c))

#define ROTXORSHIFT(p, __a, __b, __c) \
  (rotr32((p), __a) ^ rotr32((p), __b) ^ ((p) >> __c))

static fssl_force_inline void fssl_sha256_block(fssl_sha256_ctx* ctx,
                                                const uint8_t* block) {
  uint32_t a, b, c, d, e, f, g, h;
  uint32_t w[64];
  size_t i = 0;

  for (i = 0; i < 16; ++i) {
    w[i] = fssl_be_read_u32((uint8_t*)(block + (i * 4)));
  }

  for (; i < 64; ++i) {
    uint32_t s0 = ROTXORSHIFT(w[i - 15], 7, 18, 3);
    uint32_t s1 = ROTXORSHIFT(w[i - 2], 17, 19, 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (i = 0; i < 64; ++i) {
    uint32_t s1 = ROTXOR(e, 6, 11, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t tmp1 = h + s1 + ch + k[i] + w[i];
    uint32_t s0 = ROTXOR(a, 2, 13, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);

    h = g;
    g = f;
    f = e;
    e = d + tmp1;
    d = c;
    c = b;
    b = a;
    a = tmp1 + s0 + maj;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

void fssl_sha256_init(fssl_sha256_ctx* ctx) {
  *ctx = (fssl_sha256_ctx){
      .state =
          {
              0x6a09e667,
              0xbb67ae85,
              0x3c6ef372,
              0xa54ff53a,
              0x510e527f,
              0x9b05688c,
              0x1f83d9ab,
              0x5be0cd19,
          },
      .buffer = {},
      .size = 0,
      .buffer_len = 0,
  };
}

void fssl_sha256_write(fssl_sha256_ctx* ctx, const uint8_t* data, size_t len) {
  ctx->size += len;

  // There's some data left in the buffer, try to fill it first.
  if (ctx->buffer_len != 0) {
    const size_t free = FSSL_SHA256_BLOCK_SIZE - ctx->buffer_len;
    const size_t min = (len < free) ? len : free;

    ft_memcpy(ctx->buffer + ctx->buffer_len, data, min);
    ctx->buffer_len += min;

    len -= min;
    data += min;
  }

  // If the buffer was filled process it.
  if (ctx->buffer_len == FSSL_SHA256_BLOCK_SIZE) {
    fssl_sha256_block(ctx, ctx->buffer);
    ctx->buffer_len = 0;
  }

  // When we enter this path the previous buffer has been processed.
  if (len >= FSSL_SHA256_BLOCK_SIZE) {
    // TODO(push): remove assert.
    assert(ctx->buffer_len == 0);

    const size_t blocks = len / FSSL_SHA256_BLOCK_SIZE;

    for (size_t i = 0; i < blocks; ++i) {
      fssl_sha256_block(ctx, data + (i * FSSL_SHA256_BLOCK_SIZE));
    }

    data += blocks * FSSL_SHA256_BLOCK_SIZE;
    len %= FSSL_SHA256_BLOCK_SIZE;
  }

  if (len != 0) {
    ft_memcpy(ctx->buffer + ctx->buffer_len, data, len);
    ctx->buffer_len += len;
  }
}

bool fssl_sha256_finish(fssl_sha256_ctx* ctx,
                        uint8_t* buf,
                        size_t buf_capacity,
                        size_t* written) {
  const size_t padding = (56 - (1 + ctx->size)) % 64;
  const uint64_t len = ctx->size * 8;
  // 1 for the single end-bit.
  // 64 for the possible padding.
  // 8 for the encoded len.
  uint8_t scratch[1 + 64 + 8] = {0x80};

  if (buf_capacity < FSSL_SHA256_SUM_SIZE)
    return false;

  assert((1 + padding + ctx->size + 8) % 64 == 0);

  fssl_be_write_u64(scratch + 1 + padding, len);

  fssl_sha256_write(ctx, scratch, 1 + padding + 8);

  fssl_be_write_u32(buf, ctx->state[0]);
  fssl_be_write_u32(buf + 4, ctx->state[1]);
  fssl_be_write_u32(buf + 8, ctx->state[2]);
  fssl_be_write_u32(buf + 12, ctx->state[3]);
  fssl_be_write_u32(buf + 16, ctx->state[4]);
  fssl_be_write_u32(buf + 20, ctx->state[5]);
  fssl_be_write_u32(buf + 24, ctx->state[6]);
  fssl_be_write_u32(buf + 28, ctx->state[7]);

  if (written != nullptr)
    *written = FSSL_SHA256_SUM_SIZE;

  return true;
}

Hasher fssl_sha256_hasher(fssl_sha256_ctx* ctx) {
  return (Hasher){
      .instance = ctx,
      .write = (fssl_hasher_write_fn)fssl_sha256_write,
      .finish = (fssl_hasher_finish_fn)fssl_sha256_finish,
      .reset = (fssl_hasher_reset_fn)fssl_sha256_init,
  };
}
