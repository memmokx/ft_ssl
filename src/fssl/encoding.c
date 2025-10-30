#include "fssl/fssl.h"

static const char fssl_hex_table[] = "0123456789abcdef";

fssl_error_t fssl_hex_encode(const uint8_t* data, size_t len, char* buf, size_t buf_capacity) {
  const size_t target_len = fssl_hex_encoded_size(len);

  if (target_len > buf_capacity)
    return FSSL_ERR_BUFFER_TOO_SMALL;

  for (size_t i = 0; i < target_len; i += 2) {
    const uint8_t c = *data;

    buf[i] = fssl_hex_table[c >> 4];
    buf[i + 1] = fssl_hex_table[c & 0x0f];

    data++;
  }

  return FSSL_SUCCESS;
}

// clang-format off
static const uint8_t fssl_hex_decode_table[] = {
    [0 ... 47] = 0xff,
    [58 ... 64] = 0xff,
    [71 ... 96] = 0xff,
    [103 ... 255] = 0xff,

    ['0'] = 0x00, ['a'] = 0xa, ['A'] = 0xa,
    ['1'] = 0x01, ['b'] = 0xb, ['B'] = 0xb,
    ['2'] = 0x02, ['c'] = 0xc, ['C'] = 0xc,
    ['3'] = 0x03, ['d'] = 0xd, ['D'] = 0xd,
    ['4'] = 0x04, ['e'] = 0xe, ['E'] = 0xe,
    ['5'] = 0x05, ['f'] = 0xf, ['F'] = 0xf,
    ['6'] = 0x06,
    ['7'] = 0x07,
    ['8'] = 0x08,
    ['9'] = 0x09,

};
// clang-format on

fssl_error_t fssl_hex_decode(const char* data,
                             size_t len,
                             uint8_t* buf,
                             size_t buf_capacity,
                             size_t* written) {
  if (fssl_hex_decoded_size(len) > buf_capacity)
    return FSSL_ERR_BUFFER_TOO_SMALL;

  size_t ctr = 0;
  for (size_t i = 0; i < len; i += 2) {
    const uint8_t high_nibble = fssl_hex_decode_table[(size_t)data[i]];
    const uint8_t low_nibble = fssl_hex_decode_table[(size_t)data[i + 1]];

    if (high_nibble == 0xff || low_nibble == 0xff)
      return FSSL_ERR_INVALID_CHARACTER;

    buf[ctr] = (high_nibble << 4) | low_nibble;

    ctr++;
  }

  if (written)
    *written = ctr;

  return FSSL_SUCCESS;
}
