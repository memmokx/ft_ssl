#ifndef FSSL_ERROR_H
#define FSSL_ERROR_H

typedef enum {
  FSSL_SUCCESS = 0,
  FSSL_ERR_INVALID_ARGUMENT,
  FSSL_ERR_OUT_OF_MEMORY,
} fssl_error_t;

#endif
