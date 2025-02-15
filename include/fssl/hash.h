#ifndef FSSL_HASH_H
#define FSSL_HASH_H

#include <fssl/defines.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef void (*fssl_hasher_write_fn)(void*, const uint8_t*, size_t);
typedef bool (*fssl_hasher_finish_fn)(void*, uint8_t*, size_t, size_t*);
typedef void (*fssl_hasher_reset_fn)(void*);

typedef struct {
  void* instance;
  fssl_hasher_write_fn write;
  fssl_hasher_finish_fn finish;
  fssl_hasher_reset_fn reset;
} Hasher;

void fssl_hasher_write(Hasher* hasher, const uint8_t* data, size_t len);
bool fssl_hasher_finish(Hasher* hasher, uint8_t* buf, size_t buf_capacity, size_t* written);
void fssl_hasher_reset(Hasher* hasher);

#endif
