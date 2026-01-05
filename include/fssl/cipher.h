#ifndef FSSL_CIPHER_H
#define FSSL_CIPHER_H

#include <fssl/defines.h>
#include <fssl/error.h>

/*!
 * The different types of block modes supported.
 */
typedef enum {
  CIPHER_MODE_ECB,
  CIPHER_MODE_CBC,
  CIPHER_MODE_CTR,
  CIPHER_MODE_CFB,
  CIPHER_MODE_OFB,
  CIPHER_MODE_PCBC,
  CIPHER_MODE_STREAM,
} fssl_cipher_mode_t;

/*!
 * The different types of ciphers supported.
 */
typedef enum {
  /* A block cipher, when encrypting/decrypting, it must be done
   * on blocks whose size is a multiple of the cipher block size.
   */
  CIPHER_BLOCK,
  /* A stream cipher */
  CIPHER_STREAM,
} fssl_cipher_type_t;

typedef fssl_error_t (*fssl_cipher_init_fn)(void* ctx, const uint8_t* key);
typedef void (*fssl_cipher_encrypt_fn)(void* ctx, const uint8_t* in, uint8_t* out);
typedef void (*fssl_cipher_decrypt_fn)(void* ctx, const uint8_t* in, uint8_t* out);
typedef fssl_error_t (*fssl_cipher_set_iv_fn)(void* ctx, const fssl_slice_t* iv);

typedef void (*fssl_cipher_stream_encrypt_fn)(void* ctx,
                                              const uint8_t* in,
                                              uint8_t* out,
                                              size_t n);
typedef void (*fssl_cipher_stream_decrypt_fn)(void* ctx,
                                              const uint8_t* in,
                                              uint8_t* out,
                                              size_t n);

/*!
 * Descriptor for a cipher algorithm.
 */
typedef struct {
  const char* name;
  fssl_cipher_type_t type;

  size_t block_size;
  size_t key_size;
  size_t ctx_size;

  fssl_cipher_init_fn init;
  fssl_cipher_set_iv_fn set_iv;
  fssl_cipher_encrypt_fn encrypt;
  fssl_cipher_decrypt_fn decrypt;
  fssl_cipher_stream_encrypt_fn encrypt_stream;
  fssl_cipher_stream_decrypt_fn decrypt_stream;
} fssl_cipher_desc_t;

typedef struct _fssl_cipher_s fssl_cipher_t;

typedef struct _fssl_cipher_s {
  void* instance;
  const fssl_cipher_desc_t* desc;
  fssl_cipher_mode_t mode;

  struct {
    uint8_t data[FSSL_MAX_IV_SIZE];
    size_t size;
  } iv;

  union {
    struct {
      uint8_t state[FSSL_MAX_BLOCK_SIZE];
    } cbc;
    struct {
      uint8_t stream[FSSL_MAX_BLOCK_SIZE];
      // Where are we in the stream
      uint8_t sptr;
    } cfb;
    struct {
      uint8_t stream[FSSL_MAX_BLOCK_SIZE];
      // Where are we in the stream
      uint8_t sptr;
    } ofb;
    struct {
      // E(iv)
      uint8_t stream[FSSL_MAX_BLOCK_SIZE];
      uint8_t iv[FSSL_MAX_BLOCK_SIZE];
      // Counter
      union {
        uint32_t u32;
      };

      // Where are we in the stream
      uint8_t sptr;
    } ctr;
  } mode_data;

  ssize_t (*encrypt)(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n);
  ssize_t (*decrypt)(fssl_cipher_t* ctx, const uint8_t* in, uint8_t* out, size_t n);
} fssl_cipher_t;

/*!
 * Initialize a new cipher instance.
 * The cipher instance must be deinitialized with fssl_cipher_deinit().
 * @param cipher[out]
 * @param desc A cipher descriptor.
 * @param mode A cipher mode. If the cipher type is \c CIPHER_STREAM, this must be CIPHER_MODE_STREAM.
 * @return \c FSSL_SUCCESS on success, or an error code on failure.
 */
fssl_error_t fssl_cipher_new(fssl_cipher_t* cipher,
                             const fssl_cipher_desc_t* desc,
                             fssl_cipher_mode_t mode);

/*!
 * Set the key for the cipher instance.
 * @param cipher The cipher instance.
 * @param key The key bytes, must be of size fssl_cipher_key_size().
 * @return \c FSSL_SUCCESS on success, or an error code on failure.
 * The reasons for failure depend on the cipher implementation.
 */
fssl_error_t fssl_cipher_set_key(fssl_cipher_t* cipher, const uint8_t* key);

/*!
 * Set the initialization vector for the cipher instance.
 * @param cipher The cipher instance.
 * @param iv The initialization vector slice, must be of size fssl_cipher_iv_size().
 * @return \c FSSL_SUCCESS on success, or an error code on failure.
 * It may fail if the size of `iv` is incorrect.
 */
fssl_error_t fssl_cipher_set_iv(fssl_cipher_t* cipher, const fssl_slice_t* iv);

/*!
 * @return The type of the given cipher.
 */
fssl_cipher_type_t fssl_cipher_type(const fssl_cipher_t* cipher);

/*!
 * @return The block size of the given cipher in bytes.
 */
size_t fssl_cipher_block_size(const fssl_cipher_t* cipher);

/*!
 * @return The key size of the given cipher in bytes.
 */
size_t fssl_cipher_key_size(const fssl_cipher_t* cipher);

/*!
 * @return The expected IV size of the given cipher and block mode pair, in bytes.
 */
size_t fssl_cipher_iv_size(const fssl_cipher_t* cipher);

/*!
 * @return Whether the given cipher is streamable or not. A cipher is streamable
 * if it is a stream cipher, or if it is a block cipher in a streamable mode
 * (CTR, CFB, OFB).
 */
bool fssl_cipher_streamable(const fssl_cipher_t* cipher);

/*!
 * Encrypt data using the given cipher.
 * @param cipher The cipher instance.
 * @param in The input data. If \c nullptr, the data is encrypted in-place.
 * @param out The output buffer, must be at least \c n bytes.
 * @param n The number of bytes to encrypt.
 * @return The number of bytes written to \c out, or -1 on failure.
 */
ssize_t fssl_cipher_encrypt(fssl_cipher_t* cipher,
                            const uint8_t* in,
                            uint8_t* out,
                            size_t n);

/*!
 * Decrypt data using the given cipher.
 * @param cipher The cipher instance.
 * @param in The input data. If \c nullptr, the data is decrypted in-place.
 * @param out The output buffer, must be at least \c n bytes.
 * @param n The number of bytes to decrypt.
 * @return The number of bytes written to \c out, or -1 on failure.
 */
ssize_t fssl_cipher_decrypt(fssl_cipher_t* cipher,
                            const uint8_t* in,
                            uint8_t* out,
                            size_t n);

/*!
 * Reset the internal state of the cipher instance.
 * This will reset any mode-specific data (like IVs, counters, etc).
 * The key and IV set previously will remain unchanged.
 * @param cipher The cipher instance.
 */
void fssl_cipher_reset(fssl_cipher_t* cipher);

/*!
 * Deinitialize the cipher instance, releasing any allocated resources.
 * @param cipher The cipher instance.
 */
void fssl_cipher_deinit(fssl_cipher_t* cipher);

/*!
 * Apply PKCS#5 padding to the given buffer.
 * @param out The output buffer where the padded data will be written to.
 * @param n The size of the input data.
 * @param buf_capacity The total capacity of the output buffer.
 * @param block_size The block size to pad to.
 * @param written[out] The number of additional bytes written to the output buffer.
 * @return An error code indicating success or failure.
 * It may fail if the output buffer is not large enough.
 */
fssl_error_t fssl_pkcs5_pad(uint8_t* out,
                            size_t n,
                            size_t buf_capacity,
                            size_t block_size,
                            size_t* written);

/*!
 * Find the number of PKCS#5 padding bytes in the given buffer.
 * @param in The input buffer containing the padded data.
 * @param n The size of the input data.
 * @param block_size The block size used for padding.
 * @param padded[out] The number of padding bytes found.
 * @return An error code indicating success or failure.
 * It may fail if the padding is invalid.
 */
fssl_error_t fssl_pkcs5_unpad(const uint8_t* in, size_t n, size_t block_size, size_t* padded);

#endif
