#ifndef FSSL_ERROR_H
#define FSSL_ERROR_H

#define FOREACH_FSSL_ERROR(V)                                                \
  V(FSSL_SUCCESS, "Success")                                                 \
  V(FSSL_ERR_INVALID_CHARACTER, "Input data contains an invalid character.") \
  V(FSSL_ERR_INVALID_ARGUMENT, "The argument is not valid.")                 \
  V(FSSL_ERR_BUFFER_TOO_SMALL, "Buffer is too small.")                       \
  V(FSSL_ERR_RAND_FAILURE, "Unable to fetch randomness.")                    \
  V(FSSL_ERR_INTERNAL, "Internal Error.")                                    \
  V(FSSL_ERR_SHORT_READ, "Unable to read enough bytes.")                                    \
  V(FSSL_ERR_INVALID_PADDING, "Invalid padding.")                                    \
  V(FSSL_ERR_OUT_OF_MEMORY, "Out of memory.")

typedef enum {
#define X(name, ...) name,
  FOREACH_FSSL_ERROR(X)
#undef X
} fssl_error_t;

const char* fssl_error_string(fssl_error_t error);

#define fssl_seterr(_err, _value) \
  do {                            \
    if ((_err))                   \
      *(_err) = (_value);         \
  } while (false)

#define fssl_haserr(_err) ((_err) != FSSL_SUCCESS)

#endif
