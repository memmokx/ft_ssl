#include <fssl/fssl.h>

fssl_error_t fssl_pkcs5_pad(uint8_t* out,
                            const size_t n,
                            const size_t buf_capacity,
                            const size_t block_size,
                            size_t* written) {
  if (block_size > UINT8_MAX)
    return FSSL_ERR_INVALID_ARGUMENT;
  if (!out)
    return FSSL_ERR_INVALID_ARGUMENT;

  const size_t added = block_size - (n % block_size);
  if (n + added > buf_capacity)
    return FSSL_ERR_BUFFER_TOO_SMALL;

  for (size_t i = 0; i < added; ++i)
    out[i] = (uint8_t)(added & UINT8_MAX);

  if (written)
    *written = added;
  return FSSL_SUCCESS;
}

fssl_error_t fssl_pkcs5_unpad(const uint8_t* in,
                              const size_t n,
                              const size_t block_size,
                              size_t* padded) {
  if (block_size > UINT8_MAX)
    return FSSL_ERR_INVALID_ARGUMENT;
  if (!in || !padded)
    return FSSL_ERR_INVALID_ARGUMENT;

  const uint8_t added = in[n - 1];
  if (added > n)
    return FSSL_ERR_INVALID_PADDING;

  bool corrupted = false;
  for (size_t i = added; i != 0; --i)
    corrupted |= (in[n - i] != added);

  if (corrupted)
    return FSSL_ERR_INVALID_PADDING;

  *padded = added;

  return FSSL_SUCCESS;
}