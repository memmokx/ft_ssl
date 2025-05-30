#ifndef FSSL_HASH_H
#define FSSL_HASH_H

#include <fssl/defines.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef void (*fssl_hash_write_fn)(void*, const uint8_t*, size_t);
typedef bool (*fssl_hash_finish_fn)(void*, uint8_t*, size_t);
typedef void (*fssl_hash_reset_fn)(void*);

typedef struct {
  size_t ctx_size;
  size_t sum_size;
  fssl_hash_write_fn write_fn;
  fssl_hash_finish_fn finish_fn;
  fssl_hash_reset_fn reset_fn;
} fssl_hash_t;

typedef struct {
  void* instance;
  fssl_hash_t hash;
} Hasher;

Hasher fssl_hasher_new(fssl_hash_t hash);
void fssl_hasher_write(const Hasher* hasher, const uint8_t* data, size_t len);
bool fssl_hasher_finish(const Hasher* hasher, uint8_t* buf, size_t buf_capacity);
void fssl_hasher_reset(const Hasher* hasher);
void fssl_hasher_destroy(Hasher* hasher);

#endif
