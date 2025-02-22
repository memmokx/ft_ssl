#include <criterion/criterion.h>
#include <fssl/fssl.h>

char* blake2_hash_string_to_hex(const char* str) {
  uint8_t output[FSSL_BLAKE2_SUM_SIZE] = {0};
  char hex_output[fssl_hex_encoded_size(FSSL_BLAKE2_SUM_SIZE) + 1] = {};

  fssl_blake2_ctx ctx;
  fssl_blake2_init(&ctx);
  fssl_blake2_write(&ctx, (uint8_t*)str, strlen(str));
  fssl_blake2_finish(&ctx, output, sizeof(output), nullptr);
  fssl_hex_encode(output, FSSL_BLAKE2_SUM_SIZE, hex_output, sizeof(hex_output));

  return strdup(hex_output);
}

Test(fssl, blake2_test_vectors) {
  char* empty = blake2_hash_string_to_hex("");
  char* a = blake2_hash_string_to_hex("abc");
  char* m448 = blake2_hash_string_to_hex(
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
  char* m896 = blake2_hash_string_to_hex(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmn"
      "opqklmnopqrlmnopqrsmnopqrstnopqrstu");

  cr_assert_str_eq(
      empty, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
  cr_assert_str_eq(
      a, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
  cr_assert_str_eq(
      m448, "6f4df5116a6f332edab1d9e10ee87df6557beab6259d7663f3bcd5722c13f189");
  cr_assert_str_eq(
      m896, "358dd2ed0780d4054e76cb6f3a5bce2841e8e2f547431d4d09db21b66d941fc7");

  free(m448);
  free(m896);
  free(empty);
  free(a);
}
