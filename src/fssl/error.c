#include <fssl/fssl.h>

static const char* table[] = {
#define X(name, str) [name] = str,
    FOREACH_FSSL_ERROR(X)
#undef X
};

const char* fssl_error_string(const fssl_error_t error) {
  return table[error];
}
