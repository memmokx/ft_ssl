#include "fssl/fssl.h"

ssize_t fssl_md5_write(fssl_md5_ctx* ctx, const uint8_t* data, size_t len) {
}


bool fssl_md5_finish(fssl_md5_ctx* ctx, uint8_t* buf, size_t buf_capacity) {
  if (buf_capacity < FSSL_MD5_SUM_SIZE)
    return false;
  return 0;
}

Hasher fssl_md5_hasher(fssl_md5_ctx* ctx) {
  return (Hasher){
      .instance = ctx,
      .write = (fssl_hasher_write_fn)fssl_md5_write,
      .finish = (fssl_hasher_finish_fn)fssl_md5_finish,
  };
}
