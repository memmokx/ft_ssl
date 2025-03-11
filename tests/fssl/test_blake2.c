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
  char* m64 = blake2_hash_string_to_hex(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  char* m62 = blake2_hash_string_to_hex(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  char* m128 = blake2_hash_string_to_hex(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  char* m127 = blake2_hash_string_to_hex(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

  cr_assert_str_eq(
      empty, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
  cr_assert_str_eq(
      a, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
  cr_assert_str_eq(
      m448, "6f4df5116a6f332edab1d9e10ee87df6557beab6259d7663f3bcd5722c13f189");
  cr_assert_str_eq(
      m896, "358dd2ed0780d4054e76cb6f3a5bce2841e8e2f547431d4d09db21b66d941fc7");
  cr_assert_str_eq(
      m64, "651d2f5f20952eacaea2fba2f2af2bcd633e511ea2d2e4c9ae2ac0d9ffb7b252");
  cr_assert_str_eq(
      m62, "1109521feed362d8ac50e28784406e8b8577e9103f74c7dde7e7c5339a700e9f");
  cr_assert_str_eq(
      m128, "3ac477e27353f9019b81694afe60c8049403784f91a58288428ea318bfa82809");
  cr_assert_str_eq(m127, "50424a14cfc0a3cdfcfafb0eed5b7731bfc401a05ccc93f16ed9757f1b7529f2");

  free(m127);
  free(m62);
  free(m128);
  free(m64);
  free(m448);
  free(m896);
  free(empty);
  free(a);
}
