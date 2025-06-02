#include <criterion/criterion.h>
#include <fssl/fssl.h>

char* sha1_hash_string_to_hex(const char* str) {
  uint8_t output[FSSL_SHA1_SUM_SIZE] = {0};
  char hex_output[fssl_hex_encoded_size(FSSL_SHA1_SUM_SIZE) + 1] = {};

  fssl_sha1_ctx ctx;
  fssl_sha1_init(&ctx);
  fssl_sha1_write(&ctx, (uint8_t*)str, strlen(str));
  fssl_sha1_finish(&ctx, output, sizeof(output));
  fssl_hex_encode(output, FSSL_SHA1_SUM_SIZE, hex_output, sizeof(hex_output));

  return strdup(hex_output);
}

Test(fssl, sha1_test_vectors) {
  char* empty = sha1_hash_string_to_hex("");
  char* a = sha1_hash_string_to_hex("abc");
  char* m448 = sha1_hash_string_to_hex(
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
  char* m896 = sha1_hash_string_to_hex(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmn"
      "opqklmnopqrlmnopqrsmnopqrstnopqrstu");

  cr_assert_str_eq(empty, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
  cr_assert_str_eq(a, "a9993e364706816aba3e25717850c26c9cd0d89d");
  cr_assert_str_eq(m448, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
  cr_assert_str_eq(m896, "a49b2446a02c645bf419f995b67091253a04a259");

  free(m448);
  free(m896);
  free(empty);
  free(a);
}
