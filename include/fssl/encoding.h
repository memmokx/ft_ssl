#ifndef FSSL_ENCODING_H
#define FSSL_ENCODING_H

#include <stddef.h>
#include <stdint.h>
#include "error.h"

#define fssl_hex_encoded_size(size) ((size) * 2)
#define fssl_hex_decoded_size(size) ((size) / 2)

fssl_error_t fssl_hex_encode(const uint8_t* data,
                                     size_t len,
                                     char* buf,
                                     size_t buf_capacity);

fssl_error_t fssl_hex_decode(const char* data,
                                     size_t len,
                                     uint8_t* buf,
                                     size_t buf_capacity,
                                     size_t* written);

#endif
