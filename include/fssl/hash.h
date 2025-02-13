#ifndef FSSL_HASH_H
#define FSSL_HASH_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef ssize_t (*fssl_hasher_write_fn)(void*, const uint8_t*, size_t);
typedef bool (*fssl_hasher_finish_fn)(void*, uint8_t*, size_t);

typedef struct {
  void* instance;
  fssl_hasher_write_fn write;
  fssl_hasher_finish_fn finish;
} Hasher;

ssize_t fssl_hasher_write(Hasher* hasher, const uint8_t* data, size_t len);
bool fssl_hasher_finish(Hasher* hasher, uint8_t* buf, size_t buf_capacity);

#endif
