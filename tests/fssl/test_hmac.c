#include <assert.h>
#include <criterion/criterion.h>
#include <fssl/fssl.h>

char* hmac(fssl_hash_t h, const char* key, const char* message) {
  Hasher hasher = fssl_hasher_new(h);
  if (!hasher.instance)
    return nullptr;

  fssl_hmac_ctx ctx;
  fssl_hmac_init(&ctx, &hasher, (const uint8_t*)key, strlen(key));
  fssl_hmac_write(&ctx, (const uint8_t*)message, strlen(message));

  const size_t sum_size = fssl_hasher_sum_size(&hasher);
  uint8_t sum[FSSL_HASH_MAX_BLOCK_SIZE] = {};

  char* out = calloc(1, fssl_hex_encoded_size(sum_size) + 1);
  if (!out)
    return nullptr;

  if (!fssl_hmac_finish(&ctx, sum, sizeof(sum)))
    assert(false && "hmac finish failed");

  fssl_hex_encode(sum, sum_size, out, fssl_hex_encoded_size(sum_size) + 1);
  fssl_hasher_destroy(&hasher);
  return out;
}

Test(fssl, hmac_md5) {
  char* result =
      hmac(fssl_hash_md5, "key", "The quick brown fox jumps over the lazy dog");
  cr_assert_str_eq(result, "80070713463e7749b90c2dc24911e275");
  free(result);
}

Test(fssl, hmac_sha1) {
  char* result =
      hmac(fssl_hash_sha256, "key", "The quick brown fox jumps over the lazy dog");
  cr_assert_str_eq(
      result, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
  free(result);
}

Test(fssl, hmac_sha256) {
  char* result =
      hmac(fssl_hash_sha256, "key", "The quick brown fox jumps over the lazy dog");
  cr_assert_str_eq(
      result, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
  free(result);
}

Test(fssl, hmac_sha512) {
  char* result =
      hmac(fssl_hash_sha512, "key", "The quick brown fox jumps over the lazy dog");
  cr_assert_str_eq(
      result,
      "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b"
      "791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a");
  free(result);
}
