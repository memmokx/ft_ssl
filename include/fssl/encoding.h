#ifndef FSSL_ENCODING_H
#define FSSL_ENCODING_H

#include <stddef.h>
#include <stdint.h>
#include "error.h"

#define fssl_hex_encoded_size(size) ((size) * 2)
#define fssl_hex_decoded_size(size) ((size) / 2)

#define fssl_base64_encoded_size(size)      \
  ({                                        \
    auto _size = (size);                    \
    auto _mod = _size % 4;                  \
    _mod != 0 ? (_size + 4 - _mod) : _size; \
  })

#define fssl_base64_decoded_size(size) ((size) / 4 * 3)

fssl_error_t fssl_hex_encode(const uint8_t* data, size_t len, char* buf, size_t buf_capacity);

fssl_error_t fssl_hex_decode(const char* data,
                             size_t len,
                             uint8_t* buf,
                             size_t buf_capacity,
                             size_t* written);

fssl_error_t fssl_base64_encode(const uint8_t* data,
                                size_t len,
                                char* buf,
                                size_t buf_capacity,
                                size_t* written);

fssl_error_t fssl_base64_decode(const char* data,
                                size_t len,
                                uint8_t* buf,
                                size_t buf_capacity,
                                size_t* written);
#endif
