#include <fssl/fssl.h>
#include <libft/memory.h>

constexpr uint64_t k[] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

static fssl_force_inline uint64_t rotr64(uint64_t a, uint64_t r) {
  return (a >> r) | (a << (64 - r));
}

#define ROTXOR(p, __a, __b, __c) \
  (rotr64((p), __a) ^ rotr64((p), __b) ^ rotr64((p), __c))

#define ROTXORSHIFT(p, __a, __b, __c) \
  (rotr64((p), __a) ^ rotr64((p), __b) ^ ((p) >> __c))

static fssl_force_inline void fssl_sha512_block(fssl_sha512_ctx* ctx,
                                                const uint8_t* block) {
  uint64_t a, b, c, d, e, f, g, h;
  uint64_t w[80];
  size_t i = 0;

  for (i = 0; i < 16; ++i) {
    w[i] = fssl_be_read_u64((uint8_t*)(block + (i * 8)));
  }

  for (; i < 80; ++i) {
    uint64_t s0 = ROTXORSHIFT(w[i - 15], 1, 8, 7);
    uint64_t s1 = ROTXORSHIFT(w[i - 2], 19, 61, 6);
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

  for (i = 0; i < 80; ++i) {
    uint64_t s1 = ROTXOR(e, 14, 18, 41);
    uint64_t ch = (e & f) ^ (~e & g);
    uint64_t tmp1 = h + s1 + ch + k[i] + w[i];
    uint64_t s0 = ROTXOR(a, 28, 34, 39);
    uint64_t maj = (a & b) ^ (a & c) ^ (b & c);

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

void fssl_sha512_init(fssl_sha512_ctx* ctx) {
  *ctx = (fssl_sha512_ctx){
      .state =
          {
              0x6a09e667f3bcc908,
              0xbb67ae8584caa73b,
              0x3c6ef372fe94f82b,
              0xa54ff53a5f1d36f1,
              0x510e527fade682d1,
              0x9b05688c2b3e6c1f,
              0x1f83d9abfb41bd6b,
              0x5be0cd19137e2179,
          },
      .buffer = {},
      .size = 0,
      .buffer_len = 0,
  };
}

void fssl_sha512_write(fssl_sha512_ctx* ctx, const uint8_t* data, size_t len) {
  fssl_digest_write(ctx, data, len, fssl_sha512_block, FSSL_SHA512_BLOCK_SIZE);
}

bool fssl_sha512_finish(fssl_sha512_ctx* ctx, uint8_t* buf, size_t buf_capacity) {
  const size_t padding = (112 - (1 + ctx->size)) % 128;
  const __uint128_t len = (__uint128_t)ctx->size * 8;
  // 1 for the single end-bit.
  // 128 for the possible padding.
  // 16 for the encoded len.
  uint8_t scratch[1 + FSSL_SHA512_BLOCK_SIZE + 16] = {0x80};

  if (buf_capacity < FSSL_SHA512_SUM_SIZE)
    return false;

  fssl_be_write_u64(scratch + 1 + padding, (uint64_t)(len >> 64));
  fssl_be_write_u64(scratch + 1 + padding + 8, (uint64_t)(len & (uint64_t)-1));

  fssl_sha512_write(ctx, scratch, 1 + padding + 16);

  fssl_be_write_u64(buf, ctx->state[0]);
  fssl_be_write_u64(buf + 8, ctx->state[1]);
  fssl_be_write_u64(buf + 16, ctx->state[2]);
  fssl_be_write_u64(buf + 24, ctx->state[3]);
  fssl_be_write_u64(buf + 32, ctx->state[4]);
  fssl_be_write_u64(buf + 40, ctx->state[5]);
  fssl_be_write_u64(buf + 48, ctx->state[6]);
  fssl_be_write_u64(buf + 56, ctx->state[7]);

  return true;
}

const fssl_hash_t fssl_hash_sha512 = {
    .ctx_size = sizeof(fssl_sha512_ctx),
    .sum_size = FSSL_SHA512_SUM_SIZE,
    .write_fn = (fssl_hash_write_fn)fssl_sha512_write,
    .finish_fn = (fssl_hash_finish_fn)fssl_sha512_finish,
    .reset_fn = (fssl_hash_reset_fn)fssl_sha512_init,
};
