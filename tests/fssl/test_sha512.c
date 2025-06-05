#include <criterion/criterion.h>
#include <fssl/fssl.h>

char* sha512_hash_string_to_hex(const char* str) {
  uint8_t output[FSSL_SHA512_SUM_SIZE] = {0};
  char hex_output[fssl_hex_encoded_size(FSSL_SHA512_SUM_SIZE) + 1] = {};

  fssl_sha512_ctx ctx;
  fssl_sha512_init(&ctx);
  fssl_sha512_write(&ctx, (uint8_t*)str, strlen(str));
  fssl_sha512_finish(&ctx, output, sizeof(output));
  fssl_hex_encode(output, FSSL_SHA512_SUM_SIZE, hex_output, sizeof(hex_output));

  return strdup(hex_output);
}

Test(fssl, sha512_test_vectors) {
  char* empty = sha512_hash_string_to_hex("");
  char* a = sha512_hash_string_to_hex("abc");
  char* m448 = sha512_hash_string_to_hex(
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
  char* m896 = sha512_hash_string_to_hex(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmn"
      "opqklmnopqrlmnopqrsmnopqrstnopqrstu");

  cr_assert_str_eq(
      empty,
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f"
      "2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
  cr_assert_str_eq(
      a,
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc"
      "1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  cr_assert_str_eq(
      m448,
      "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b0"
      "7f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
  cr_assert_str_eq(
      m896,
      "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f"
      "7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");

  free(m448);
  free(m896);
  free(empty);
  free(a);
}
