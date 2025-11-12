#include <criterion/criterion.h>
#include <fssl/fssl.h>
#include <stdint.h>
#include <stdio.h>

Test(fssl, des_key_schedule) {
  // K = 0x133457799BBCDFF1
  uint8_t key[FSSL_DES_KEY_SIZE] = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
  fssl_des_ctx ctx;
  if (fssl_des_init(&ctx, key) != FSSL_SUCCESS) {
    cr_assert(false, "fssl_des_init failed");
    return;
  }

  // KS[1]:  000110 110000 001011 101111 111111 000111 000001 110010
  // KS[2]:  011110 011010 111011 011001 110110 111100 100111 100101
  // KS[3]:  010101 011111 110010 001010 010000 101100 111110 011001
  // KS[4]:  011100 101010 110111 010110 110110 110011 010100 011101
  // KS[5]:  011111 001110 110000 000111 111010 110101 001110 101000
  // KS[6]:  011000 111010 010100 111110 010100 000111 101100 101111
  // KS[7]:  111011 001000 010010 110111 111101 100001 100010 111100
  // KS[8]:  111101 111000 101000 111010 110000 010011 101111 111011
  // KS[9]:  111000 001101 101111 101011 111011 011110 011110 000001
  // KS[10]:  101100 011111 001101 000111 101110 100100 011001 001111
  // KS[11]:  001000 010101 111111 010011 110111 101101 001110 000110
  // KS[12]:  011101 010111 000111 110101 100101 000110 011111 101001
  // KS[13]:  100101 111100 010111 010001 111110 101011 101001 000001
  // KS[14]:  010111 110100 001110 110111 111100 101110 011100 111010
  // KS[15]:  101111 111001 000110 001101 001111 010011 111100 001010
  // KS[16]:  110010 110011 110110 001011 000011 100001 011111 110101
  uint64_t expected_sk[16] = {
      0x1b02effc7072, 0x79aed9dbc9e5, 0x55fc8a42cf99, 0x72add6db351d,
      0x7cec07eb53a8, 0x63a53e507b2f, 0xec84b7f618bc, 0xf78a3ac13bfb,
      0xe0dbebede781, 0xb1f347ba464f, 0x215fd3ded386, 0x7571f59467e9,
      0x97c5d1faba41, 0x5f43b7f2e73a, 0xbf918d3d3f0a, 0xcb3d8b0e17f5};

  for (size_t i = 0; i < 16; ++i) {
    cr_assert_eq(ctx.sk[i], expected_sk[i],
                 "Subkey %zu mismatch: got 0x%lx, expected 0x%lx", i, ctx.sk[i],
                 expected_sk[i]);
  }
}

Test(fssl, des_encrypt_block) {
  uint8_t key[FSSL_DES_KEY_SIZE] = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
  fssl_des_ctx ctx;
  if (fssl_des_init(&ctx, key) != FSSL_SUCCESS) {
    cr_assert(false, "fssl_des_init failed");
    return;
  }

  uint8_t msg[FSSL_DES_BLOCK_SIZE] = {0b00000001, 0b00100011, 0b01000101,
                                      0b01100111, 0b10001001, 0b10101011,
                                      0b11001101, 0b11101111};
  fssl_cipher_des.encrypt(&ctx, msg, msg);

  uint8_t expected[FSSL_DES_BLOCK_SIZE] = {0x85, 0xE8, 0x13, 0x54,
                                           0x0F, 0x0A, 0xB4, 0x05};

  for (size_t i = 0; i < FSSL_DES_BLOCK_SIZE; ++i) {
    cr_assert_eq(msg[i], expected[i],
                 "Ciphertext %zu mismatch: got 0x%x, expected 0x%x", i, msg[i],
                 expected[i]);
  }
}

#include <assert.h>

static fssl_cipher_t init_cipher(const fssl_cipher_desc_t* cipher,
                                 fssl_cipher_mode_t mode,
                                 uint8_t* key,
                                 const fssl_slice_t* iv) {
  fssl_cipher_t c;
  if (fssl_cipher_new(&c, (void*)cipher, mode) != FSSL_SUCCESS)
    assert(false && "fssl_cipher_new failed");
  if (key)
    fssl_cipher_set_key(&c, key);
  if (iv)
    fssl_cipher_set_iv(&c, iv);
  return c;
}

static ssize_t encrypt(fssl_cipher_t* c, const uint8_t* msg, size_t msg_len, uint8_t* out) {
  uint8_t in[2048] = {};

  memcpy(in, msg, msg_len);
  size_t padded = 0;
  if (fssl_pkcs5_pad(in + msg_len, msg_len, sizeof(in) - msg_len,
                     fssl_cipher_block_size(c), &padded) != FSSL_SUCCESS)
    cr_assert(false, "fssl_pkcs5_pad failed");

  return fssl_cipher_encrypt(c, in, out, msg_len + padded);
}

static size_t decrypt(fssl_cipher_t* c, uint8_t* ct, size_t size) {
  fssl_cipher_decrypt(c, nullptr, ct, size);

  size_t padded = 0;
  if (fssl_pkcs5_unpad(ct, size, fssl_cipher_block_size(c), &padded) != FSSL_SUCCESS)
    cr_assert(false, "fssl_pkcs5_unpad failed");

  return size - padded;
}

// https://cyberchef.io/#recipe=DES_Encrypt(%7B'option':'Hex','string':'624B8CE75AA2A249'%7D,%7B'option':'Hex','string':''%7D,'ECB','Raw','Raw')To_Hex('0x%20with%20comma',0)&input=SGVsbG8gV29ybGQgIQ

#define TEST_ENCRYPT(cipher, mode, key, iv, msg, msg_size, expected, expected_size) \
  do {                                                                              \
    uint8_t _out[1024] = {};                                                        \
    fssl_cipher_t _c = init_cipher((cipher), mode, key, iv);                        \
    ssize_t _r = encrypt(&_c, msg, (msg_size), _out);                               \
    if (_r < 0)                                                                     \
      cr_assert(false, "encrypt failed");                                           \
    cr_assert_eq(_r, (expected_size), "Ciphertext size doesn't match expected");    \
    cr_assert_arr_eq(_out, expected, (expected_size), "Ciphertext mismatch");       \
    fssl_cipher_reset(&_c);                                                         \
    _r = decrypt(&_c, _out, _r);                                                    \
    cr_assert_eq(_r, (msg_size), "Decrypted size doesn't match");                   \
    for (size_t _i = 0; _i < (size_t)_r; ++_i) {                                    \
      cr_assert_eq(_out[_i], msg[_i],                                               \
                   "Decrypted %zu mismatch: got 0x%x, expected 0x%x", _i, _out[_i], \
                   msg[_i]);                                                        \
    }                                                                               \
    fssl_cipher_deinit(&_c);                                                        \
  } while (false)

#define TEST_ENCRYPT_DES(mode, key, iv, msg, msg_size, expected, expected_size) \
  TEST_ENCRYPT(&fssl_cipher_des, mode, key, iv, msg, msg_size, expected, expected_size)

#define TEST_ENCRYPT_DES3(mode, key, iv, msg, msg_size, expected, expected_size) \
  TEST_ENCRYPT(&fssl_cipher_des3, mode, key, iv, msg, msg_size, expected, expected_size)

Test(fssl, des_encrypt_ecb) {
  // Hello World !
  const uint8_t msg[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57,
                         0x6f, 0x72, 0x6c, 0x64, 0x20, 0x21};
  const uint8_t expected[] = {0x8d, 0xa1, 0x5b, 0xfa, 0x88, 0x90, 0xa7, 0x00,
                              0xeb, 0x0a, 0x95, 0xfc, 0xdf, 0x64, 0xdf, 0x85};
  uint8_t key[FSSL_DES_KEY_SIZE] = {0x62, 0x4b, 0x8c, 0xe7, 0x5a, 0xa2, 0xa2, 0x49};

  TEST_ENCRYPT_DES(CIPHER_MODE_ECB, key, nullptr, msg, sizeof(msg), expected,
               sizeof(expected));
}

Test(fssl, des_encrypt_cbc) {
  // Hello World !
  const uint8_t msg[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57,
                         0x6f, 0x72, 0x6c, 0x64, 0x20, 0x21};
  const uint8_t expected[] = {0xf0, 0xdb, 0x35, 0xb2, 0x7c, 0x60, 0x49, 0x8a,
                              0x31, 0x99, 0x7b, 0x60, 0x8d, 0x03, 0x64, 0x97};
  uint8_t key[FSSL_DES_KEY_SIZE] = {0x0f, 0x84, 0x4b, 0x6b, 0x3b, 0xfb, 0xdf, 0xea};
  uint8_t ivb[FSSL_DES_BLOCK_SIZE] = {0x4b, 0x9b, 0xb7, 0x27,
                                      0xde, 0x06, 0x1c, 0x8c};

  fssl_slice_t iv = {.data = ivb, .size = sizeof(ivb)};

  TEST_ENCRYPT_DES(CIPHER_MODE_CBC, key, &iv, msg, sizeof(msg), expected, sizeof(expected));
}

Test(fssl, des3_encrypt_ecb) {
  // Hello World !
  const uint8_t msg[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57,
                         0x6f, 0x72, 0x6c, 0x64, 0x20, 0x21};
  const uint8_t expected[] = {0x30,0x2c,0x1f,0x93,0xcb,0xab,0x5c,0xc8,0xe3,0x51,0xc2,0x9e,0x59,0xa4,0x7b,0xad};
  uint8_t key[FSSL_DES3_KEY_SIZE] = {0xc0,0x30,0xc3,0xc9,0xc7,0x55,0xe5,0xd2,0x1a,0x74,0x85,0x74,0x22,0x92,0x50,0x3c,0xbb,0x4e,0xbc,0x43,0x70,0x2d,0x94,0xa9};

  TEST_ENCRYPT_DES3(CIPHER_MODE_ECB, key, nullptr, msg, sizeof(msg), expected,
               sizeof(expected));
}

Test(fssl, des3_encrypt_cbc) {
  // Hello World !
  const uint8_t msg[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57,
                         0x6f, 0x72, 0x6c, 0x64, 0x20, 0x21};
  const uint8_t expected[] = {0x0e,0xce,0xb3,0x8f,0xfd,0xbd,0x66,0xe2,0xe6,0xf8,0x34,0xe5,0xd2,0x69,0x47,0x91};
  uint8_t key[FSSL_DES3_KEY_SIZE] = {0xc0,0x30,0xc3,0xc9,0xc7,0x55,0xe5,0xd2,0x1a,0x74,0x85,0x74,0x22,0x92,0x50,0x3c,0xbb,0x4e,0xbc,0x43,0x70,0x2d,0x94,0xa9};
  uint8_t ivb[FSSL_DES3_BLOCK_SIZE] = {0x83,0xe7,0x9d,0xeb,0x73,0xa9,0xc4,0xc0};

  fssl_slice_t iv = {.data = ivb, .size = sizeof(ivb)};

  TEST_ENCRYPT_DES3(CIPHER_MODE_CBC, key, &iv, msg, sizeof(msg), expected, sizeof(expected));
}
