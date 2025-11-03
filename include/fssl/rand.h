#ifndef FSSL_RAND_H
#define FSSL_RAND_H

#include "error.h"

fssl_error_t fssl_rand_read(uint8_t* buf, size_t n);
uint8_t* fssl_rand_bytes(size_t n, fssl_error_t* err);

#endif