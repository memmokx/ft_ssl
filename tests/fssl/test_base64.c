#include <criterion/criterion.h>
#include <fssl/fssl.h>
#include <stdint.h>

typedef struct {
  uint8_t* decoded;
  size_t dlen;
  char* encoded;
  size_t elen;
} TestPair;

#define test_pair(_decoded, _encoded)                                         \
  (TestPair) {                                                                \
    .decoded = (_decoded), .dlen = sizeof((_decoded)), .encoded = (_encoded), \
    .elen = sizeof((_encoded)) - 1,                                           \
  }

const TestPair tests[] = {
    test_pair(((uint8_t[]){0x14, 0xfb, 0x9c, 0x03, 0xd9, 0x7e}), "FPucA9l+"),
    test_pair(((uint8_t[]){0x14, 0xfb, 0x9c, 0x03, 0xd9}), "FPucA9k="),
    test_pair(((uint8_t[]){0x14, 0xfb, 0x9c, 0x03}), "FPucAw=="),

    test_pair(((uint8_t[]){}), ""),
    test_pair(((uint8_t[]){'f'}), "Zg=="),
    test_pair(((uint8_t[]){'f', 'o'}), "Zm8="),
    test_pair(((uint8_t[]){'f', 'o', 'o'}), "Zm9v"),
    test_pair(((uint8_t[]){'f', 'o', 'o', 'b'}), "Zm9vYg=="),
    test_pair(((uint8_t[]){'f', 'o', 'o', 'b', 'a'}), "Zm9vYmE="),
    test_pair(((uint8_t[]){'f', 'o', 'o', 'b', 'a', 'r'}), "Zm9vYmFy"),

    test_pair(((uint8_t[]){'s', 'u', 'r', 'e', '.'}), "c3VyZS4="),
    test_pair(((uint8_t[]){'s', 'u', 'r', 'e'}), "c3VyZQ=="),
    test_pair(((uint8_t[]){'s', 'u', 'r'}), "c3Vy"),
    test_pair(((uint8_t[]){'s', 'u'}), "c3U="),
    test_pair(((uint8_t[]){'l', 'e', 'a', 's', 'u', 'r', 'e', '.'}), "bGVhc3VyZS4="),
    test_pair(((uint8_t[]){'e', 'a', 's', 'u', 'r', 'e', '.'}), "ZWFzdXJlLg=="),
    test_pair(((uint8_t[]){'a', 's', 'u', 'r', 'e', '.'}), "YXN1cmUu"),
    test_pair(((uint8_t[]){'s', 'u', 'r', 'e', '.'}), "c3VyZS4="),

    test_pair(((uint8_t[]){'M'}), "TQ=="),
    test_pair(((uint8_t[]){'M', 'a'}), "TWE="),
    test_pair(((uint8_t[]){'M', 'a', 'n'}), "TWFu"),
    test_pair(((uint8_t[]){'p', 'l', 'e', 'a', 's', 'u', 'r', 'e', '.'}),
              "cGxlYXN1cmUu"),
    test_pair(((uint8_t[]){'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}),
              "MTIzNDU2Nzg5MA=="),
    test_pair(((uint8_t[]){'~', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')'}),
              "fiFAIyQlXiYqKCk="),
    test_pair(((uint8_t[]){'\r', '\n', '\t'}), "DQoJ"),
    test_pair(((uint8_t[]){'A', ' ', 'b', 'i', 'g', ' ', 't', 'e', 's', 't'}),
              "QSBiaWcgdGVzdA=="),
};

Test(fssl, b64_test_vectors) {
  char encoded_buf[1024] = {};

  for (size_t i = 0; i < sizeof(tests) / sizeof(TestPair); i++) {
    const TestPair* test = &tests[i];

    size_t written = 0;
    fssl_error_t err = fssl_base64_encode(test->decoded, test->dlen, encoded_buf,
                                          test->elen, &written);

    cr_assert_eq(err, FSSL_SUCCESS, "[%zu] Unexpected error: %s", i,
                 fssl_error_string(err));
    cr_assert_eq(
        written, test->elen,
        "[%zu ]Incorrect amount of bytes encoded: got: %ld want: %ld. got: '%s' "
        "want: '%s'",
        i, written, test->elen, encoded_buf, test->encoded);

    cr_assert_str_eq(encoded_buf, test->encoded);
    memset(encoded_buf, 0, sizeof(encoded_buf));
  }

  uint8_t decoded_buf[1024] = {};

  for (size_t i = 0; i < sizeof(tests) / sizeof(TestPair); i++) {
    const TestPair* test = &tests[i];

    size_t written = 0;
    fssl_error_t err = fssl_base64_decode(test->encoded, test->elen, decoded_buf,
                                          test->dlen, &written);

    cr_assert_eq(err, FSSL_SUCCESS, "[%zu] Unexpected error: %s", i,
                 fssl_error_string(err));
    cr_assert_eq(written, test->dlen,
                 "[%zu] Incorrect amount of bytes decoded: got: %ld want: %ld", i,
                 written, test->dlen);

    for (size_t j = 0; j < written; ++j) {
      cr_assert_eq(decoded_buf[j], test->decoded[j],
                   "Decode mismatch at byte %zu: got 0x%x, expected 0x%x", j,
                   decoded_buf[j], test->decoded[j]);
    }
  }
}
