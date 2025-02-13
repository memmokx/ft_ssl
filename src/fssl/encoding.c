#include "fssl/fssl.h"

static const char* fssl_status_table[] = {
    [SUCCESS] = "Success.",
    [TOO_SMALL_BUFFER] = "Provided buffer is too small.",
    [INVALID_CHAR] = "Input data contain an invalid character.",
    [FAILURE] = "Unable to encode/decode input data."};

static const char fssl_hex_table[] = "0123456789abcdef";

const char* fssl_encoding_status_string(fssl_encoding_status status) {
  return fssl_status_table[status];
}

fssl_encoding_status fssl_hex_encode(const uint8_t* data,
                                     size_t len,
                                     char* buf,
                                     size_t buf_capacity) {
  const size_t target_len = fssl_hex_encoded_size(len);

  if (target_len > buf_capacity)
    return TOO_SMALL_BUFFER;

  for (size_t i = 0; i < target_len; i += 2) {
    const uint8_t c = *data;

    buf[i] = fssl_hex_table[c >> 4];
    buf[i + 1] = fssl_hex_table[c & 0x0f];

    data++;
  }

  return SUCCESS;
}

// clang-format off
static const uint8_t fssl_hex_decode_table[] = {
    [0 ... 47] = 0xff,
    [58 ... 96] = 0xff,
    [103 ... 255] = 0xff,

    ['0'] = 0x00, ['a'] = 0xa,
    ['1'] = 0x01, ['b'] = 0xb,
    ['2'] = 0x02, ['c'] = 0xc,
    ['3'] = 0x03, ['d'] = 0xd,
    ['4'] = 0x04, ['e'] = 0xe,
    ['5'] = 0x05, ['f'] = 0xf,
    ['6'] = 0x06,
    ['7'] = 0x07,
    ['8'] = 0x08,
    ['9'] = 0x09,
};
// clang-format on

fssl_encoding_status fssl_hex_decode(const char* data,
                                     size_t len,
                                     uint8_t* buf,
                                     size_t buf_capacity) {
  if (fssl_hex_decoded_size(len) > buf_capacity)
    return TOO_SMALL_BUFFER;

  size_t ctr = 0;
  for (size_t i = 0; i < len; i += 2) {
    const uint8_t high_nibble = fssl_hex_decode_table[(size_t)data[i]];
    const uint8_t low_nibble = fssl_hex_decode_table[(size_t)data[i + 1]];

    buf[ctr] = (high_nibble << 4) | low_nibble;

    ctr++;
  }

  return SUCCESS;
}
