#include <cipher.h>
#include <libft/io.h>

#include "libft/memory.h"

constexpr auto CIPHER_FLAG_BASE64 = 'a';
constexpr auto CIPHER_FLAG_DECRYPT = 'd';
constexpr auto CIPHER_FLAG_ENCRYPT = 'e';
constexpr auto CIPHER_FLAG_INPUT = 'i';
constexpr auto CIPHER_FLAG_KEY = 'k';
constexpr auto CIPHER_FLAG_OUTPUT = 'o';
constexpr auto CIPHER_FLAG_PASSWORD = 'p';
constexpr auto CIPHER_FLAG_SALT = 's';
constexpr auto CIPHER_FLAG_IV = 'v';

typedef enum {
  PADDING_NONE,
  PADDING_PAD,
} Padding;

typedef enum {
  OP_ENCRYPT,
  OP_DECRYPT,
} Operation;

typedef struct {
  uint8_t* iv;
  uint8_t* key;
} DeriveResult;

typedef struct {
  uint8_t* data;
  fssl_error_t err;
} DecodeResult;

#define logerr(fmt, ...) ft_fprintf(STDERR_FILENO, fmt, __VA_ARGS__)
#define seterr(_err, _value) \
  do {                       \
    if ((_err))              \
      *(_err) = (_value);    \
  } while (false)

#define haserr(_err) ((_err) != FSSL_SUCCESS)
#define checkerr(_ptr, _check) \
  if (haserr(_check) && ((_ptr) ? *(_ptr) = (_check) : (void)0, 1))

static uint8_t* decode(const string data,
                       const Padding padding,
                       const size_t expected_size,
                       fssl_error_t* err) {
  uint8_t* buffer = malloc(expected_size);
  if (!buffer) {
    seterr(err, FSSL_ERR_OUT_OF_MEMORY);
    return nullptr;
  }

  size_t written = 0;
  const fssl_error_t result =
      fssl_hex_decode(data.ptr, data.len, buffer, expected_size, &written);
  checkerr(err, result) {
    goto err;
  }

  if (padding == PADDING_NONE && written != expected_size) {
    seterr(err, FSSL_ERR_INVALID_ARGUMENT);
    goto err;
  }

  // Pad with zeroes if we were asked to.
  if (padding == PADDING_PAD && written < expected_size) {
    ft_bzero(&buffer[written], expected_size-written);
  }

  return buffer;
err:
  free(buffer);
  return nullptr;
}

static uint8_t* flag_decode_or_rand(const cli_flag_t* flag,
                                    const size_t expected,
                                    const char flag_c,
                                    fssl_error_t* err) {
  fssl_error_t result = FSSL_SUCCESS;
  uint8_t* decoded = flag != nullptr
                         ? decode(flag->value.str, PADDING_NONE, expected, &result)
                         : fssl_rand_bytes(expected, &result);

  checkerr(err, result) {
    logerr("ft_ssl: error -%c flag: %s\n", flag_c, fssl_error_string(result));
    return nullptr;
  }

  return decoded;
}

/*!
 * Based on the given flags, return the current mode of operation.
 * @return The operation to perform. If no specific flags are set: returns `OP_ENCRYPT`
 * by default. If both modes are set, the only one that matters is the last one.
 */
static Operation command_operation(cli_flags_t* flags) {
  Operation op = OP_ENCRYPT;

  const cli_flag_t* encrypt = cli_flags_get(flags, CIPHER_FLAG_ENCRYPT);
  const cli_flag_t* decrypt = cli_flags_get(flags, CIPHER_FLAG_DECRYPT);

  if (encrypt == nullptr && decrypt != nullptr)
    op = OP_DECRYPT;
  else if (encrypt && decrypt) {
    op = encrypt->order > decrypt->order ? OP_ENCRYPT : OP_DECRYPT;
  }

  return op;
}

constexpr auto CIPHER_MAX_PASS = 1024;

static string read_password(string command,
                            const Operation operation,
                            fssl_error_t* err,
                            bool* mismatch) {
  const char* op = operation == OP_ENCRYPT ? "encryption" : "decryption";
  char buf[CIPHER_MAX_PASS] = {};

  string prompt = {};
  string password = {};
  string first = {};

  string command_dup = string_new(command.ptr);
  if (!command_dup.ptr) {
    seterr(err, FSSL_ERR_OUT_OF_MEMORY);
    goto err;
  }

  string_to_upper(&command_dup);

  prompt = ft_sprintf("enter %s %s password:", command_dup.ptr, op);
  if (!prompt.ptr) {
    seterr(err, FSSL_ERR_OUT_OF_MEMORY);
    goto err;
  }

  first = string_new(fssl_read_password(prompt.ptr, buf, sizeof(buf)));
  if (!first.ptr) {
    seterr(err, FSSL_ERR_INTERNAL);
    goto err;
  }

  prompt = string_concat(&libft_static_string("Verifying - "), &prompt, 0b01);
  if (!prompt.ptr) {
    seterr(err, FSSL_ERR_OUT_OF_MEMORY);
    goto err;
  }

  ft_bzero(buf, sizeof(buf));

  password = string_new(fssl_read_password(prompt.ptr, buf, sizeof(buf)));
  if (!password.ptr) {
    seterr(err, FSSL_ERR_INTERNAL);
    goto err;
  }

  *mismatch = !string_equal(&first, &password);
  goto done;

err:
  password = (string){};
done:
  if (first.ptr)
    string_destroy(&first);
  if (prompt.ptr)
    string_destroy(&prompt);
  if (command_dup.ptr)
    string_destroy(&command_dup);
  ft_bzero(buf, sizeof(buf));
  return password;
}

uint8_t* fssl_pbkdf(const string password,
                    const uint8_t* salt,
                    const size_t salt_len,
                    const size_t target_size,
                    fssl_error_t* err) {
  (void)target_size;
  // TODO: temporary function
  fssl_sha256_ctx ctx;
  fssl_sha256_init(&ctx);

  fssl_sha256_write(&ctx, salt, salt_len);
  fssl_sha256_write(&ctx, (uint8_t*)password.ptr, password.len);

  uint8_t* buf = malloc(FSSL_SHA256_SUM_SIZE);
  if (!buf) {
    seterr(err, FSSL_ERR_OUT_OF_MEMORY);
    return nullptr;
  }

  fssl_sha256_finish(&ctx, buf, FSSL_SHA256_SUM_SIZE);
  return buf;
}

/*!
 *
 * @param command
 * @param operation
 * @param kf The key flag content.
 * @param pf The password flag content.
 * @param sf The salt flag content.
 * @param ivf The iv flag content.
 * @param key_size
 * @param iv_size
 * @param salt_size
 * @param err
 */
static DeriveResult derive_inputs(string command,
                                  const Operation operation,
                                  const cli_flag_t* kf,
                                  const cli_flag_t* pf,
                                  const cli_flag_t* sf,
                                  const cli_flag_t* ivf,
                                  const size_t key_size,
                                  const size_t iv_size,
                                  const size_t salt_size,
                                  fssl_error_t* err) {
  uint8_t* key = nullptr;
  uint8_t* iv = nullptr;
  uint8_t* salt = nullptr;
  string pass = {};

  fssl_error_t result = FSSL_SUCCESS;
  bool mismatch = false;

  if (kf) {
    key = decode(kf->value.str, PADDING_PAD, key_size, &result);
  } else {
    if (pf) {
      pass = string_new(pf->value.str.ptr);
      if (!pass.ptr)
        result = FSSL_ERR_OUT_OF_MEMORY;
    } else {
      pass = read_password(command, operation, &result, &mismatch);
    }

    // In case we read the password and the user failed to verify.
    if (mismatch) {
      ft_fprintf(STDERR_FILENO, "Verify failure\nbad password read\n");
      seterr(err, FSSL_ERR_INTERNAL);
      goto err;
    }

    checkerr(err, result) {
      logerr("ft_ssl: error -%c flag: %s\n", CIPHER_FLAG_PASSWORD,
             fssl_error_string(result));
      goto err;
    }

    salt = flag_decode_or_rand(sf, salt_size, CIPHER_FLAG_SALT, &result);
    checkerr(err, result) {
      goto err;
    }

    key = fssl_pbkdf(pass, salt, salt_size, key_size, &result);
  }

  // We failed to decode the key flag OR the KDF failed.
  checkerr(err, result) {
    logerr("ft_ssl: error -%c flag: %s\n", CIPHER_FLAG_KEY, fssl_error_string(result));
    goto err;
  }

  iv = flag_decode_or_rand(ivf, iv_size, CIPHER_FLAG_IV, &result);
  checkerr(err, result) {
    goto err;
  }

  if (pass.ptr)
    string_destroy(&pass);
  if (salt)
    free(salt);

  return (DeriveResult){.key = key, .iv = iv};

err:
  if (key)
    free(key);
  if (iv)
    free(iv);
  if (pass.ptr)
    string_destroy(&pass);
  if (salt)
    free(salt);
  return (DeriveResult){};
}

int cipher_command_impl(string command,
                        const cli_command_data* data,
                        cli_flags_t* flags,
                        int argc,
                        char** argv) {
  int exit_code = 0;
  fssl_error_t err = FSSL_SUCCESS;

  const fssl_cipher_mode_t mode = data->cipher.mode;
  const fssl_block_cipher_t* cipher = &data->cipher.cipher;

  // Enable base64 for the output if we encrypt, or the input if we decrypt
  const bool base64 = cli_flags_get(flags, CIPHER_FLAG_BASE64) != nullptr;
  // Mode of operation. Defaults to `OP_ENCRYPT`.
  const Operation operation = command_operation(flags);
  // Input file for message. String variant.
  const cli_flag_t* input_flag = cli_flags_get(flags, CIPHER_FLAG_INPUT);
  // Key in hex. String variant.
  const cli_flag_t* key_flag = cli_flags_get(flags, CIPHER_FLAG_KEY);
  // Output file for message. String variant.
  const cli_flag_t* output_flag = cli_flags_get(flags, CIPHER_FLAG_OUTPUT);
  // The password in ASCII. String variant.
  const cli_flag_t* password_flag = cli_flags_get(flags, CIPHER_FLAG_PASSWORD);
  // The salt in hex. String variant.
  const cli_flag_t* salt_flag = cli_flags_get(flags, CIPHER_FLAG_SALT);
  // The initialization vector in hex. String variant.
  const cli_flag_t* iv_flag = cli_flags_get(flags, CIPHER_FLAG_IV);

  const DeriveResult derived =
      derive_inputs(command, operation, key_flag, password_flag, salt_flag, iv_flag,
                    cipher->key_size, /*iv_size*/ cipher->block_size,
                    cipher->block_size, &err);
  if (haserr(err)) {
    exit_code = err;
    goto done;
  }

  ft_fprintf(STDERR_FILENO, "key: {");
  for (size_t i = 0; i < cipher->key_size; i++) {
    ft_fprintf(STDERR_FILENO, "0x%x", derived.key[i]);
    if (i != cipher->key_size - 1)
      ft_fprintf(STDERR_FILENO, " ");
  }
  ft_fprintf(STDERR_FILENO, "}\niv: {");
  for (size_t i = 0; i < cipher->block_size; i++) {
    ft_fprintf(STDERR_FILENO, "0x%x", derived.iv[i]);
    if (i != cipher->block_size - 1)
      ft_fprintf(STDERR_FILENO, " ");
  }
  ft_fprintf(STDERR_FILENO, "}\n");

  (void)output_flag;
  (void)input_flag;
  (void)base64;
  (void)derived;
  (void)data;
  (void)flags;
  (void)argc;
  (void)argv;
  (void)command;
  (void)cipher;

  switch (mode) {
    case NONE:
    case ECB:
    case CBC:
    case CTR:
    case CFB:
    case OFB:
    case PCBC:
    default:
      logerr("ft_ssl: %s: Unknown cipher mode: %d\n", command.ptr, mode);
      exit_code = 1;
  }

done:
  free(derived.key);
  free(derived.iv);
  return exit_code;
}