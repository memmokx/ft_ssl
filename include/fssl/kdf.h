#ifndef FSSL_KDF_H
#define FSSL_KDF_H

#include "hash.h"

fssl_error_t fssl_pbkdf2_hmac(Hasher* hasher,
                              size_t iters,
                              const uint8_t* pass,
                              size_t pass_len,
                              const uint8_t* salt,
                              size_t salt_len,
                              uint8_t* dk,
                              size_t dklen);

#endif