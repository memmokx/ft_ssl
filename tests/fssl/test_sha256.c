#include <criterion/criterion.h>
#include <fssl/fssl.h>

char* sha256_hash_string_to_hex(const char* str) {
  uint8_t output[FSSL_SHA256_SUM_SIZE] = {0};
  char hex_output[fssl_hex_encoded_size(FSSL_SHA256_SUM_SIZE) + 1] = {};

  fssl_sha256_ctx ctx;
  fssl_sha256_init(&ctx);
  fssl_sha256_write(&ctx, (uint8_t*)str, strlen(str));
  fssl_sha256_finish(&ctx, output, sizeof(output), nullptr);
  fssl_hex_encode(output, FSSL_SHA256_SUM_SIZE, hex_output, sizeof(hex_output));

  return strdup(hex_output);
}

Test(fssl, sha256_test_vectors) {
  char* empty = sha256_hash_string_to_hex("");
  char* a = sha256_hash_string_to_hex("abc");
  char* m448 = sha256_hash_string_to_hex(
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
  char* m896 = sha256_hash_string_to_hex(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmn"
      "opqklmnopqrlmnopqrsmnopqrstnopqrstu");

  cr_assert_str_eq(
      empty, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  cr_assert_str_eq(
      a, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  cr_assert_str_eq(
      m448, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  cr_assert_str_eq(
      m896, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");

  free(m448);
  free(m896);
  free(empty);
  free(a);
}
