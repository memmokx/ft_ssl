#ifndef FSSL_ENCODING_H
#define FSSL_ENCODING_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
  SUCCESS = 0,
  TOO_SMALL_BUFFER,
  INVALID_CHAR,
  FAILURE,
} fssl_encoding_status;

const char* fssl_encoding_status_string(fssl_encoding_status status);

#define fssl_hex_encoded_size(size) (size * 2)
#define fssl_hex_decoded_size(size) (size / 2)

fssl_encoding_status fssl_hex_encode(const uint8_t* data,
                                     size_t len,
                                     char* buf,
                                     size_t buf_capacity);

fssl_encoding_status fssl_hex_decode(const char* data,
                                     size_t len,
                                     uint8_t* buf,
                                     size_t buf_capacity);

#endif
