#include <fssl/fssl.h>
#include <libft/memory.h>

static const uint8_t pc_1[] = {
    57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18, 10, 2,  59, 51, 43,
    35, 27, 19, 11, 3,  60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7,  62, 54,
    46, 38, 30, 22, 14, 6,  61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4,
};

static const uint8_t pc_2[] = {
    14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10, 23, 19, 12, 4,
    26, 8,  16, 7,  27, 20, 13, 2,  41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
};

static const uint8_t ip[] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
};

static const uint8_t ip_inv[] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9,  49, 17, 57, 25,
};

static const uint8_t E[] = {
    32, 1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9,  10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
};

static const uint8_t Q[] = {
    16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
    2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25,
};

static fssl_force_inline uint64_t pbox(uint64_t w, const uint8_t* table, size_t n, size_t b) {
  uint64_t r = 0;

  for (size_t i = 0; i < n; ++i) {
    r <<= 1;
    r ^= (w >> (b - table[i])) & 1;
  }

  return r;
}

static fssl_force_inline uint32_t rol28(uint32_t v, size_t r) {
  return ((v << r) | (v >> (28 - r))) & 0x0fffffff;
}

fssl_error_t fssl_des_init(fssl_des_ctx* ctx, const uint8_t* key) {
  if (ctx == nullptr || key == nullptr)
    return FSSL_ERR_INVALID_ARGUMENT;

  *ctx = (fssl_des_ctx){};

  const uint64_t k = pbox(fssl_be_read_u64(key), pc_1, sizeof(pc_1), 64);

  // Each half has 28 bits
  uint32_t c = (k >> 28) & 0x0fffffff;
  uint32_t d = k & 0x0fffffff;

  for (size_t i = 0; i < 16; ++i) {
    if (i == 0 || i == 1 || i == 8 || i == 15) {
      c = rol28(c, 1);
      d = rol28(d, 1);
    } else {
      c = rol28(c, 2);
      d = rol28(d, 2);
    }

    ctx->sk[i] = pbox(((uint64_t)c << 28) | (uint64_t)d, pc_2, sizeof(pc_2), 56);
  }

  return FSSL_SUCCESS;
}

void fssl_des_deinit(fssl_des_ctx* ctx) {
  if (ctx == nullptr)
    return;

  *ctx = (fssl_des_ctx){};
}

constexpr uint8_t sboxes[8][64] = {
    // S1
    {
        14, 4,  13, 1, 2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0, 7,
        0,  15, 7,  4, 14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3, 8,
        4,  1,  14, 8, 13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5, 0,
        15, 12, 8,  2, 4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6, 13,
    },
    // S2
    {
        15, 1,  8,  14, 6,  11, 3,  4,  9,  7, 2,  13, 12, 0, 5,  10,
        3,  13, 4,  7,  15, 2,  8,  14, 12, 0, 1,  10, 6,  9, 11, 5,
        0,  14, 7,  11, 10, 4,  13, 1,  5,  8, 12, 6,  9,  3, 2,  15,
        13, 8,  10, 1,  3,  15, 4,  2,  11, 6, 7,  12, 0,  5, 14, 9,
    },
    // S3
    {
        10, 0,  9,  14, 6, 3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8,
        13, 7,  0,  9,  3, 4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1,
        13, 6,  4,  9,  8, 15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7,
        1,  10, 13, 0,  6, 9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12,
    },
    // S4
    {
        7,  13, 14, 3, 0,  6,  9,  10, 1,  2, 8, 5,  11, 12, 4,  15,
        13, 8,  11, 5, 6,  15, 0,  3,  4,  7, 2, 12, 1,  10, 14, 9,
        10, 6,  9,  0, 12, 11, 7,  13, 15, 1, 3, 14, 5,  2,  8,  4,
        3,  15, 0,  6, 10, 1,  13, 8,  9,  4, 5, 11, 12, 7,  2,  14,
    },
    // S5
    {
        2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0, 14, 9,
        14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9, 8,  6,
        4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3, 0,  14,
        11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4, 5,  3,
    },
    // S6
    {
        12, 1,  10, 15, 9, 2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11,
        10, 15, 4,  2,  7, 12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8,
        9,  14, 15, 5,  2, 8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,
        4,  3,  2,  12, 9, 5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13,
    },
    // S7
    {
        4,  11, 2,  14, 15, 0, 8,  13, 3,  12, 9, 7,  5,  10, 6, 1,
        13, 0,  11, 7,  4,  9, 1,  10, 14, 3,  5, 12, 2,  15, 8, 6,
        1,  4,  11, 13, 12, 3, 7,  14, 10, 15, 6, 8,  0,  5,  9, 2,
        6,  11, 13, 8,  1,  4, 10, 7,  9,  5,  0, 15, 14, 2,  3, 12,
    },
    // S8
    {
        13, 2,  8,  4, 6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7,
        1,  15, 13, 8, 10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2,
        7,  11, 4,  1, 9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8,
        2,  1,  14, 7, 4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11,
    },
};

/*!
 * Apply the sbox `index` on `B`
 * @param B The 6-bit value
 * @param index The index of the s-box
 * @return The 4-bit result of s-box function
 */
static fssl_force_inline uint64_t sbox(const uint64_t B, size_t index) {
  const uint8_t* box = &sboxes[index][0];

  // The first and last bits of B represent in base 2 a number in the decimal range 0 to 3 (or binary 00 to 11). Let that number be i.
  const uint8_t i = (((B >> 5) & 1) << 1) | (B & 1);
  // The middle 4 bits of B represent in base 2 a number in the decimal range 0 to 15 (binary 0000 to 1111). Let that number be j
  const uint8_t j = (B >> 1) & 0b1111;

  // `i` is the row and `j` the column
  return box[i * 16 + j];
}

/*!
 * The feistel function of DES.
 */
static fssl_force_inline uint32_t feistel(const uint32_t x, uint64_t k) {
  uint64_t tmp = pbox(x, E, sizeof(E), 32);
  tmp ^= k;

  uint64_t result = 0;
  // For each 6 bit group in `tmp` apply its associated sbox function that will produce
  // a 4-bit output. For example the first 6-bit group starting from LSB will use the
  // S8 sbox, which will output the first 4-bit (from LSB) of the 32-bit result.
  for (size_t i = 0; i < 8; ++i) {
    const uint64_t y = (tmp >> (6 * (8 - (i + 1)))) & 0x3f;
    result <<= 4;
    result ^= sbox(y, i);
  }

  return (uint32_t)pbox(result, Q, sizeof(Q), 32);
}


void fssl_des_encrypt_block(const fssl_des_ctx* ctx, const uint8_t* in, uint8_t* out) {
  // Initial permutation
  const uint64_t block = pbox(fssl_be_read_u64(in), ip, sizeof(ip), 64);

  uint32_t r = block & 0xffffffff;
  uint32_t l = block >> 32;

  for (size_t n = 0; n < 16; ++n) {
    const uint32_t lp = l;
    const uint32_t rp = r;

    l = rp;
    r = lp ^ feistel(rp, ctx->sk[n]);
  }

  // Inverse Initial permutation
  const uint64_t result =
      pbox((uint64_t)r << 32 | (uint64_t)l, ip_inv, sizeof(ip_inv), 64);
  fssl_be_write_u64(out, result);
}

void fssl_des_decrypt_block(fssl_des_ctx* ctx, const uint8_t* in, uint8_t* out) {
  // Initial permutation
  const uint64_t block = pbox(fssl_be_read_u64(in), ip, sizeof(ip), 64);

  uint32_t r = block & 0xffffffff;
  uint32_t l = block >> 32;

  for (size_t n = 0; n < 16; ++n) {
    const uint32_t lp = l;
    const uint32_t rp = r;

    l = rp;
    r = lp ^ feistel(rp, ctx->sk[15 - n]);
  }

  // Inverse Initial permutation
  const uint64_t result =
      pbox((uint64_t)r << 32 | (uint64_t)l, ip_inv, sizeof(ip_inv), 64);
  fssl_be_write_u64(out, result);
}

const fssl_block_cipher_t fssl_cipher_des = {
    .ctx_size = sizeof(fssl_des_ctx),
    .block_size = FSSL_DES_BLOCK_SIZE,
    .key_size = FSSL_DES_KEY_SIZE,

    .init_fn = (fssl_block_cipher_init_fn)fssl_des_init,
    .deinit_fn = (fssl_block_cipher_deinit_fn)fssl_des_deinit,
    .block_encrypt_fn = (fssl_block_cipher_encrypt_fn)fssl_des_encrypt_block,
    .block_decrypt_fn = (fssl_block_cipher_decrypt_fn)fssl_des_decrypt_block,
};
