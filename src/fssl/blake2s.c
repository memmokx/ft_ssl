#include <assert.h>
#include <fssl/fssl.h>
#include <libft/memory.h>

static const uint32_t iv[] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

const uint8_t sigma[][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

static fssl_force_inline uint32_t rotr32(uint32_t a, uint32_t r) {
  return (a >> r) | (a << (32 - r));
}

#define G(a, b, c, d, x, y)         \
  {                                 \
    v[a] = v[a] + v[b] + x;         \
    v[d] = rotr32(v[d] ^ v[a], 16); \
    v[c] = v[c] + v[d];             \
    v[b] = rotr32(v[b] ^ v[c], 12); \
    v[a] = v[a] + v[b] + y;         \
    v[d] = rotr32(v[d] ^ v[a], 8);  \
    v[c] = v[c] + v[d];             \
    v[b] = rotr32(v[b] ^ v[c], 7);  \
  }

static fssl_force_inline void fssl_blake2_block(fssl_blake2_ctx* ctx,
                                                const uint8_t* block) {
  uint32_t v[16] = {
      ctx->state[0], ctx->state[1], ctx->state[2], ctx->state[3],
      ctx->state[4], ctx->state[5], ctx->state[6], ctx->state[7],
      iv[0],         iv[1],         iv[2],         iv[3],
      iv[4],         iv[5],         iv[6],         iv[7],
  };
  uint32_t m[16];

  for (size_t i = 0; i < 16; ++i)
    m[i] = fssl_le_read_u32((uint8_t*)(block + (i * 4)));

  v[12] ^= (uint32_t)(ctx->t & UINT32_MAX);  // low
  v[13] ^= (uint32_t)(ctx->t >> 32);         // high
  if (ctx->last)
    v[14] = ~v[14];

  for (size_t i = 0; i < 10; ++i) {
    G(0, 4, 8, 12, m[sigma[i][0]], m[sigma[i][1]]);
    G(1, 5, 9, 13, m[sigma[i][2]], m[sigma[i][3]]);
    G(2, 6, 10, 14, m[sigma[i][4]], m[sigma[i][5]]);
    G(3, 7, 11, 15, m[sigma[i][6]], m[sigma[i][7]]);
    G(0, 5, 10, 15, m[sigma[i][8]], m[sigma[i][9]]);
    G(1, 6, 11, 12, m[sigma[i][10]], m[sigma[i][11]]);
    G(2, 7, 8, 13, m[sigma[i][12]], m[sigma[i][13]]);
    G(3, 4, 9, 14, m[sigma[i][14]], m[sigma[i][15]]);
  }

  for (size_t i = 0; i < 8; ++i)
    ctx->state[i] ^= v[i] ^ v[i + 8];
}

void fssl_blake2_init(fssl_blake2_ctx* ctx) {
  *ctx = (fssl_blake2_ctx){};

  for (size_t i = 0; i < 8; ++i)
    ctx->state[i] = iv[i];
  ctx->state[0] ^= 0x01010000 ^ FSSL_BLAKE2_SUM_SIZE;
}

void fssl_blake2_write(fssl_blake2_ctx* ctx, const uint8_t* data, size_t len) {
  // This function does not compress the possible last block, the _finish function will take care of it,
  // not doing so would cause problems when writing blocks that are a multiple of the block size.

  // If the buffer is full, flush it
  if (ctx->buffer_len == FSSL_BLAKE2_BLOCK_SIZE) {
    ctx->t += ctx->buffer_len;
    fssl_blake2_block(ctx, ctx->buffer);
    ctx->buffer_len = 0;
  }

  if (ctx->buffer_len < FSSL_BLAKE2_BLOCK_SIZE) {
    const size_t free = FSSL_BLAKE2_BLOCK_SIZE - ctx->buffer_len;
    const size_t min = (len < free) ? len : free;

    ft_memcpy(ctx->buffer + ctx->buffer_len, data, min);
    ctx->buffer_len += min;

    len -= min;
    data += min;
  }

  // If the buffer was filled process it. But only if we're sure that there's data
  // coming after.
  if (ctx->buffer_len == FSSL_BLAKE2_BLOCK_SIZE && len > 0) {
    ctx->t += ctx->buffer_len;
    fssl_blake2_block(ctx, ctx->buffer);
    ctx->buffer_len = 0;
  }

  // When we enter this path the previous buffer has been processed.
  if (len > FSSL_BLAKE2_BLOCK_SIZE) {
    assert(ctx->buffer_len == 0);

    const int multiple = (len % FSSL_BLAKE2_BLOCK_SIZE == 0);
    // If the len is a multiple of BLOCK_SIZE, we skip the last block.
    const size_t blocks = (len / FSSL_BLAKE2_BLOCK_SIZE) - multiple;

    for (size_t i = 0; i < blocks; ++i) {
      ctx->t += FSSL_BLAKE2_BLOCK_SIZE;
      fssl_blake2_block(ctx, data + (i * FSSL_BLAKE2_BLOCK_SIZE));
    }

    data += blocks * FSSL_BLAKE2_BLOCK_SIZE;
    len %= FSSL_BLAKE2_BLOCK_SIZE;
    len += FSSL_BLAKE2_BLOCK_SIZE *
           multiple;  // The remaining block in case the len was indeed a multiple of BLOCK_SIZE
  }

  if (len != 0) {
    ft_memcpy(ctx->buffer + ctx->buffer_len, data, len);
    ctx->buffer_len += len;
  }
}

bool fssl_blake2_finish(fssl_blake2_ctx* ctx,
                        uint8_t* buf,
                        size_t buf_capacity,
                        size_t* written) {
  if (buf_capacity < FSSL_BLAKE2_SUM_SIZE)
    return false;

  ctx->t += ctx->buffer_len;
  while (ctx->buffer_len < FSSL_BLAKE2_BLOCK_SIZE)
    ctx->buffer[ctx->buffer_len++] = 0;

  ctx->last = true;
  fssl_blake2_block(ctx, ctx->buffer);
  ctx->last = false;

  fssl_le_write_u32(buf, ctx->state[0]);
  fssl_le_write_u32(buf + 4, ctx->state[1]);
  fssl_le_write_u32(buf + 8, ctx->state[2]);
  fssl_le_write_u32(buf + 12, ctx->state[3]);
  fssl_le_write_u32(buf + 16, ctx->state[4]);
  fssl_le_write_u32(buf + 20, ctx->state[5]);
  fssl_le_write_u32(buf + 24, ctx->state[6]);
  fssl_le_write_u32(buf + 28, ctx->state[7]);

  if (written != nullptr)
    *written = FSSL_BLAKE2_SUM_SIZE;

  return true;
}

Hasher fssl_blake2_hasher(fssl_blake2_ctx* ctx) {
  return (Hasher){
      .instance = ctx,
      .write = (fssl_hasher_write_fn)fssl_blake2_write,
      .finish = (fssl_hasher_finish_fn)fssl_blake2_finish,
      .reset = (fssl_hasher_reset_fn)fssl_blake2_init,
  };
}
