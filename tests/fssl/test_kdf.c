#include <assert.h>
#include <criterion/criterion.h>
#include <fssl/fssl.h>

char* pbkdf2(fssl_hash_t h,
             uint8_t* pass,
             size_t pass_len,
             uint8_t* salt,
             size_t salt_len,
             size_t iters,
             size_t klen) {
  Hasher hasher = fssl_hasher_new(h);
  if (!hasher.instance)
    return nullptr;

  uint8_t* K = calloc(1, klen);
  if (!K)
    return nullptr;

  if (fssl_pbkdf2_hmac(&hasher, iters, pass, pass_len, salt, salt_len, K, klen) !=
      FSSL_SUCCESS)
    assert(false && "pbkdf2 failed");

  char* out = calloc(1, fssl_hex_encoded_size(klen) + 1);
  if (!out)
    return nullptr;

  fssl_hex_encode(K, klen, out, fssl_hex_encoded_size(klen) + 1);
  fssl_hasher_destroy(&hasher);
  free(K);
  return out;
}

#define CC (uint8_t*)

Test(fssl, pbkdf2_case_1_sha256) {
  char* result = pbkdf2(fssl_hash_sha256, CC "password", 8, CC "salt", 4, 1, 20);
  cr_assert_str_eq(result, "120fb6cffcf8b32c43e7225256c4f837a86548c9");
  free(result);
}

Test(fssl, pbkdf2_case_1_sha512) {
  char* result = pbkdf2(fssl_hash_sha512, CC "password", 8, CC "salt", 4, 1, 20);
  cr_assert_str_eq(result, "867f70cf1ade02cff3752599a3a53dc4af34c7a6");
  free(result);
}

Test(fssl, pbkdf2_case_2_sha256) {
  char* result = pbkdf2(fssl_hash_sha256, CC "password", 8, CC "salt", 4, 2, 20);
  cr_assert_str_eq(result, "ae4d0c95af6b46d32d0adff928f06dd02a303f8e");
  free(result);
}

Test(fssl, pbkdf2_case_2_sha512) {
  char* result = pbkdf2(fssl_hash_sha512, CC "password", 8, CC "salt", 4, 2, 20);
  cr_assert_str_eq(result, "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e");
  free(result);
}

Test(fssl, pbkdf2_case_3_sha256) {
  char* result = pbkdf2(fssl_hash_sha256, CC "password", 8, CC "salt", 4, 4096, 20);
  cr_assert_str_eq(result, "c5e478d59288c841aa530db6845c4c8d962893a0");
  free(result);
}

Test(fssl, pbkdf2_case_3_sha512) {
  char* result = pbkdf2(fssl_hash_sha512, CC "password", 8, CC "salt", 4, 4096, 20);
  cr_assert_str_eq(result, "d197b1b33db0143e018b12f3d1d1479e6cdebdcc");
  free(result);
}

Test(fssl, pbkdf2_case_5_sha256) {
  char* result = pbkdf2(fssl_hash_sha256, CC "passwordPASSWORDpassword", 24,
                        CC "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096, 25);
  cr_assert_str_eq(result, "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c");
  free(result);
}

Test(fssl, pbkdf2_case_5_sha512) {
  char* result = pbkdf2(fssl_hash_sha512, CC "passwordPASSWORDpassword", 24,
                        CC "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096, 25);
  cr_assert_str_eq(result, "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868");
  free(result);
}

Test(fssl, pbkdf2_case_8_sha256) {
  char* result = pbkdf2(fssl_hash_sha256, CC "Password", 8, CC "NaCl", 4, 80'000, 128);
  cr_assert_str_eq(
      result,
      "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a122583"
      "3549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d62aae85a11cdde829d89cb6ffd"
      "1ab0e63a981f8747d2f2f9fe5874165c83c168d2eed1d2d5ca4052dec2be5715623da019b8c0e"
      "c87dc36aa751c38f9893d15c3");
  free(result);
}

Test(fssl, pbkdf2_case_8_sha512) {
  char* result = pbkdf2(fssl_hash_sha512, CC "Password", 8, CC "NaCl", 4, 80'000, 128);
  cr_assert_str_eq(
      result,
      "e6337d6fbeb645c794d4a9b5b75b7b30dac9ac50376a91df1f4460f6060d5addb2c1fd1f84409"
      "abacc67de7eb4056e6bb06c2d82c3ef4ccd1bded0f675ed97c65c33d39f81248454327aa6d03f"
      "d049fc5cbb2b5e6dac08e8ace996cdc960b1bd4530b7e754773d75f67a733fdb99baf6470e42f"
      "fcb753c15c352d4800fb6f9d6");
  free(result);
}

Test(fssl, pbkdf2_case_9_sha256) {
  char* result = pbkdf2(fssl_hash_sha256, CC "Password", 8,
                        (uint8_t[]){'s', 'a', 0, 'l', 't'}, 5, 4096, 256);
  cr_assert_str_eq(
      result,
      "436c82c6af9010bb0fdb274791934ac7dee21745dd11fb57bb90112ab187c495ad82df776ad7c"
      "efb606f34fedca59baa5922a57f3e91bc0e11960da7ec87ed0471b456a0808b60dff757b7d313"
      "d4068bf8d337a99caede24f3248f87d1bf16892b70b076a07dd163a8a09db788ae34300ff2f2d"
      "0a92c9e678186183622a636f4cbce15680dfea46f6d224e51c299d4946aa2471133a649288eef"
      "3e4227b609cf203dba65e9fa69e63d35b6ff435ff51664cbd6773d72ebc341d239f0084b00438"
      "8d6afa504eee6719a7ae1bb9daf6b7628d851fab335f1d13948e8ee6f7ab033a32df447f8d095"
      "0809a70066605d6960847ed436fa52cdfbcf261b44d2a87061");
  free(result);
}

Test(fssl, pbkdf2_case_9_sha512) {
  char* result = pbkdf2(fssl_hash_sha512, CC "Password", 8,
                        (uint8_t[]){'s', 'a', 0, 'l', 't'}, 5, 4096, 256);
  cr_assert_str_eq(
      result,
      "10176fb32cb98cd7bb31e2bb5c8f6e425c103333a2e496058e3fd2bd88f657485c89ef92daa06"
      "68316bc23ebd1ef88f6dd14157b2320b5d54b5f26377c5dc279b1dcdec044bd6f91b166917c80"
      "e1e99ef861b1d2c7bce1b961178125fb86867f6db489a2eae0022e7bc9cf421f044319fac765d"
      "70cb89b45c214590e2ffb2c2b565ab3b9d07571fde0027b1dc57f8fd25afa842c1056dd459af4"
      "074d7510a0c020b914a5e202445d4d3f151070589dd6a2554fc506018c4f001df6239643dc867"
      "71286ae4910769d8385531bba57544d63c3640b90c98f1445ebdd129475e02086b600f0beb5b0"
      "5cc6ca9b3633b452b7dad634e9336f56ec4c3ac0b4fe54ced8");
  free(result);
}
