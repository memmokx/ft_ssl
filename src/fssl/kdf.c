#include <fssl/kdf.h>
#include <libft/memory.h>

fssl_error_t fssl_pbkdf2_hmac(Hasher* hasher,
                              const size_t iters,
                              const uint8_t* pass,
                              const size_t pass_len,
                              const uint8_t* salt,
                              const size_t salt_len,
                              uint8_t* dk,
                              size_t dklen) {
  const size_t hlen = fssl_hasher_sum_size(hasher);

  uint8_t C[sizeof(uint32_t)] = {};
  const fssl_buffer_t T = {(uint8_t[FSSL_HASH_MAX_BLOCK_SIZE]){}, hlen};
  const fssl_buffer_t U = {(uint8_t[FSSL_HASH_MAX_BLOCK_SIZE]){}, hlen};

  fssl_hmac_ctx H;
  const auto err = fssl_hmac_init(&H, hasher, pass, pass_len);
  if (err != FSSL_SUCCESS)
    return err;

  for (size_t c = 1; dklen > 0; c++) {
    // Create F
    fssl_hmac_reset(&H);

    // U1 = PRF(Password, Salt + INT_32_BE(i))
    fssl_hmac_write(&H, salt, salt_len);
    fssl_be_write_u32(C, (uint32_t)c);
    fssl_hmac_write(&H, C, sizeof(C));
    fssl_hmac_finish(&H, U.data, U.size);

    // T = U_1 ^ U_2 ^ ... ^ U_iters
    for (size_t i = 0; i < U.size; i++)
      T.data[i] = U.data[i];

    for (size_t i = 1; i < iters; i++) {
      fssl_hmac_reset(&H);
      fssl_hmac_write(&H, U.data, U.size);
      fssl_hmac_finish(&H, U.data, U.size);

      // XOR the accumulated U_n result with the one we just computed
      for (size_t j = 0; j < hlen; j++)
        T.data[j] ^= U.data[j];
    }

    size_t w = hlen;
    if (dklen < w)
      w = dklen;

    ft_memcpy(dk, T.data, w);
    dk += w;
    dklen -= w;
  }

  return FSSL_SUCCESS;
}