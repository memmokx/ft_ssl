#ifndef FSSL_RAND_H
#define FSSL_RAND_H

#include "error.h"

uint8_t* fssl_rand_bytes(size_t n, fssl_error_t *err);

#endif