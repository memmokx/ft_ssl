#include "fssl/fssl.h"

static constexpr char fssl_hex_table[] = "0123456789abcdef";

fssl_error_t fssl_hex_encode(const uint8_t* data, size_t len, char* buf, size_t buf_capacity) {
  const size_t target_len = fssl_hex_encoded_size(len);

  if (!data || !buf)
    return FSSL_ERR_INVALID_ARGUMENT;
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
  if (!data || !buf)
    return FSSL_ERR_INVALID_ARGUMENT;
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

static constexpr char fssl_base64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
// table = [0xff] * 256
//
// for i, c in enumerate(alphabet):
//     char = ord(c)
//     assert table[char] == 0xff, "Duplicate"
//     table[char] = i
//
// for i in range(0, 256, 16):
//     b = ", ".join(f"0x{c:02x}" for c in table[i:i+16])
//     print(f"{b}, // {i:03d}-{i+15:03d}")
static constexpr uint8_t fssl_base64_decode_table[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // 000-015
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // 016-031
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,  // 032-047
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // 048-063
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,  // 064-079
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,  // 080-095
    0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,  // 096-111
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff,  // 112-127
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // 128-143
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // 144-159
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // 160-175
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // 176-191
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // 192-207
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // 208-223
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // 224-239
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // 240-255
};

fssl_error_t fssl_base64_encode(const uint8_t* data,
                                const size_t len,
                                char* buf,
                                const size_t buf_capacity,
                                size_t* written) {
  const size_t target_len = fssl_base64_encoded_size(len);
  const size_t n = (len / 3) * 3;

  if (!data || !buf)
    return FSSL_ERR_INVALID_ARGUMENT;
  if (target_len > buf_capacity)
    return FSSL_ERR_BUFFER_TOO_SMALL;

  size_t ctr = 0;
  size_t i = 0;
  for (; i < n; i += 3) {
    const uint32_t d = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];

    buf[ctr++] = fssl_base64_table[d >> 18 & 0x3f];
    buf[ctr++] = fssl_base64_table[d >> 12 & 0x3f];
    buf[ctr++] = fssl_base64_table[d >> 6 & 0x3f];
    buf[ctr++] = fssl_base64_table[d & 0x3f];
  }

  const size_t remaining = len - i;
  if (remaining != 0) {
    uint32_t d = data[i] << 16;
    if (remaining == 2)
      d |= data[i + 1] << 8;

    buf[ctr++] = fssl_base64_table[d >> 18 & 0x3f];
    buf[ctr++] = fssl_base64_table[d >> 12 & 0x3f];
    switch (remaining) {
      case 2:
        buf[ctr++] = fssl_base64_table[d >> 6 & 0x3f];
        buf[ctr++] = '=';
        break;
      case 1:
        buf[ctr++] = '=';
        buf[ctr++] = '=';
        break;
      default:
        break;
    }
  }

  if (written)
    *written = ctr;

  return FSSL_SUCCESS;
}

fssl_error_t fssl_base64_decode(const char* data,
                                const size_t len,
                                uint8_t* buf,
                                const size_t buf_capacity,
                                size_t* written) {
  size_t ctr = 0;
  size_t padding = 0;

  if (!data || !buf)
    return FSSL_ERR_INVALID_ARGUMENT;
  if (len % 4 != 0)
    return FSSL_ERR_INVALID_ARGUMENT;
  if (len == 0)
    goto done;

  while (data[len - padding - 1] == '=')
    padding++;

  if (fssl_base64_decoded_size(len) - padding > buf_capacity)
    return FSSL_ERR_BUFFER_TOO_SMALL;

  for (size_t i = 0; i < len; i += 4) {
    const uint32_t raw = fssl_be_read_u32(data + i);

    size_t discard = 0;
    if ((raw & 0xffff) == 0x3d3d) {
      if (i + 4 != len)
        return FSSL_ERR_INVALID_CHARACTER;
      discard = 2;
    } else if ((raw & 0xff) == '=')
      discard = 1;

    const uint32_t d1 = fssl_base64_decode_table[raw >> 24 & 0xff];
    const uint32_t d2 = fssl_base64_decode_table[raw >> 16 & 0xff];
    const uint32_t d3 = (discard > 1) ? 0 : fssl_base64_decode_table[raw >> 8 & 0xff];
    const uint32_t d4 = (discard != 0) ? 0 : fssl_base64_decode_table[raw & 0xff];

    const uint32_t d = d1 << 24 | d2 << 16 | d3 << 8 | d4;
    // This means that one of the MSB from at least one value was toggled, which is
    // only possible if we had 0xff as value.
    if ((d & 0x80808080) != 0)
      return FSSL_ERR_INVALID_CHARACTER;

    // Transpose the decoded bits to their packed representation.
    // Originally we had 4 groups of 8 bits, but top 2 bits were unused.
    // This also discards the padding bits.
    const uint32_t packed = (((d >> 24) & 0x3f) << 18 | ((d >> 16) & 0x3f) << 12 |
                             ((d >> 8) & 0x3f) << 6 | (d & 0x3f)) >>
                            (discard * 8);

    size_t j = 3 - discard;
    while (j) {
      j--;

      buf[ctr++] = (packed >> (8 * j)) & 0xff;
    }
  }

done:
  if (written)
    *written = ctr;

  return FSSL_SUCCESS;
}