#include <criterion/criterion.h>
#include <fssl/fssl.h>
#include <stdint.h>

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

Test(fssl, des_encrypt_ecb) {
  // const char msg[] = "Hello World !";
  uint8_t key[FSSL_DES_KEY_SIZE] = {0x62, 0x4b, 0x8c, 0xe7, 0x5a, 0xa2, 0xa2, 0x49};

  fssl_cipher_t c;
  if (fssl_cipher_new(&c, (void*)&fssl_cipher_des, CIPHER_MODE_ECB) != FSSL_SUCCESS)
    cr_assert(false, "fssl_cipher_new failed");
  fssl_cipher_set_key(&c, key);
  fssl_cipher_deinit(&c);
}