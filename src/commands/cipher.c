#include <commands.h>
#include <io.h>

#include <libft/io.h>
#include <libft/memory.h>

constexpr auto CIPHER_MAX_KEY_LEN = 64; /* 512 bits */
constexpr auto CIPHER_MAX_IV_LEN = 32;  /* 256 bits */
constexpr auto CIPHER_MAX_SALT_LEN = 32;

constexpr auto CIPHER_SALT_LEN = 8;

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
  uint8_t key[CIPHER_MAX_KEY_LEN];
  uint8_t iv[CIPHER_MAX_IV_LEN];
  uint8_t salt[CIPHER_MAX_SALT_LEN];
} DeriveResult;

typedef struct {
  uint8_t* data;
  fssl_error_t err;
} DecodeResult;

#define seterr(_err, _value) \
  do {                       \
    if ((_err))              \
      *(_err) = (_value);    \
  } while (false)

#define haserr(_err) ((_err) != FSSL_SUCCESS)
#define checkerr(_ptr, _check) \
  if (haserr(_check) && ((_ptr) ? *(_ptr) = (_check) : (void)0, 1))

static fssl_error_t cipher_decode_hex(const string data,
                                      uint8_t* out,
                                      const size_t expected_size) {
  // buffer filled with 0 chars to handle incomplete data
  char buf[fssl_hex_encoded_size(CIPHER_MAX_KEY_LEN)] = {'0'};
  const size_t encoded_size = fssl_hex_encoded_size(expected_size);
  fssl_error_t err = FSSL_SUCCESS;

  ft_memcpy(buf, data.ptr, data.len);

  size_t written = 0;
  err = fssl_hex_decode(buf, encoded_size, out, expected_size, &written);

  ssl_assert(written == expected_size);

  return err;
}

static fssl_error_t cipher_bytes_to_key(const string password,
                                        const uint8_t* salt,
                                        uint8_t* key,
                                        const size_t key_size,
                                        uint8_t* iv,
                                        const size_t iv_size) {
  // pbkdf1 but like openssl EVP_BytesToKey
  uint8_t digest[FSSL_SHA256_SUM_SIZE] = {};
  fssl_sha256_ctx ctx;

  size_t kl = key_size;
  size_t il = iv_size;

  int addmd = 0;
  while (true) {
    fssl_sha256_init(&ctx);

    if (addmd++)
      fssl_sha256_write(&ctx, digest, sizeof(digest));

    fssl_sha256_write(&ctx, (uint8_t*)password.ptr, password.len);
    fssl_sha256_write(&ctx, salt, CIPHER_SALT_LEN);

    fssl_sha256_finish(&ctx, digest, sizeof(digest));

    size_t i = 0;
    if (kl) {
      const size_t bytes = min(kl, sizeof(digest));
      ft_memcpy(key + (key_size - kl), digest, bytes);

      kl -= bytes;
      i += bytes;
    }

    if (il && i != sizeof(digest)) {
      const size_t bytes = min(il, sizeof(digest) - i);
      ft_memcpy(iv + (iv_size - il), digest + i, bytes);

      il -= bytes;
    }

    if (kl == 0 && il == 0)
      break;
  }

  return FSSL_SUCCESS;
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

  if (!encrypt && decrypt)
    op = OP_DECRYPT;
  else if (encrypt && decrypt) {
    op = encrypt->order > decrypt->order ? OP_ENCRYPT : OP_DECRYPT;
  }

  return op;
}

constexpr auto CIPHER_MAX_PASS = 1024;

static string cipher_read_password(const Operation operation,
                                   fssl_error_t* err,
                                   bool* mismatch) {
  const char* op = operation == OP_ENCRYPT ? "encryption" : "decryption";
  char buf[CIPHER_MAX_PASS] = {};

  string prompt = {};
  string password = {};
  string first = {};

  string command_dup = string_new(g_current_command.ptr);
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

  // In decrypt mode, we do not verify the password twice.
  if (operation == OP_DECRYPT) {
    password = first;
    first = (string){};
    goto done;
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

static constexpr char magic[] = {'S', 'a', 'l', 't', 'e', 'd', '_', '_'};
static_assert(sizeof(magic) == sizeof(uint64_t));

static fssl_error_t cipher_fill_salt(IoReader* reader,
                                     const Operation operation,
                                     const cli_flag_t* sf,
                                     uint8_t* salt) {
  if (sf)
    return cipher_decode_hex(sf->value.str, salt, CIPHER_SALT_LEN);
  if (operation == OP_ENCRYPT)
    return fssl_rand_read(salt, CIPHER_SALT_LEN);

  uint8_t buf[sizeof(magic) + CIPHER_SALT_LEN] = {};
  if (io_reader_read(reader, buf, sizeof(magic)) != sizeof(magic)) {
    logerr("error reading input\n");
    return FSSL_ERR_INTERNAL;
  }

  if (*(uint64_t*)buf != *(uint64_t*)magic) {
    logerr("invalid magic\n");
    return FSSL_ERR_INTERNAL;
  }

  if (io_reader_read(reader, salt, CIPHER_SALT_LEN) != CIPHER_SALT_LEN) {
    logerr("error reading input\n");
    return FSSL_ERR_INTERNAL;
  }

  return FSSL_SUCCESS;
}

static string cipher_get_password(const Operation operation,
                                  const cli_flag_t* pf,
                                  fssl_error_t* err) {
  fssl_error_t result = FSSL_SUCCESS;
  // Did the user enter the same password? Only for encryption
  bool mismatch = false;
  string password = {};

  if (pf) {
    password = string_new(pf->value.str.ptr);
    if (!password.ptr)
      result = FSSL_ERR_OUT_OF_MEMORY;
  } else
    password = cipher_read_password(operation, &result, &mismatch);

  // In case we read the password and the user failed to verify.
  if (mismatch) {
    string_destroy(&password);
    logerr("Verify failure, bad password read\n");
    seterr(err, FSSL_ERR_INTERNAL);
  }

  checkerr(err, result) {
    string_destroy(&password);
  }

  return password;
}

static DeriveResult cipher_derive_data(IoReader* reader,
                                       const Operation operation,
                                       const cli_flag_t* kf,
                                       const cli_flag_t* pf,
                                       const cli_flag_t* sf,
                                       const cli_flag_t* ivf,
                                       const size_t key_size,
                                       const size_t iv_size,
                                       fssl_error_t* err) {
  fssl_error_t status = FSSL_SUCCESS;
  uint8_t salt[CIPHER_MAX_SALT_LEN], key[CIPHER_MAX_KEY_LEN], iv[CIPHER_MAX_IV_LEN];
  string password = {};
  DeriveResult result = {};

  // Read password in all cases. Unless the key was given
  if (!kf) {
    password = cipher_get_password(operation, pf, &status);
    checkerr(err, status) {
      logerr("Unable to obtain password\n");
      goto done;
    }
  }

  if (password.ptr) {
    if ((status = cipher_fill_salt(reader, operation, sf, salt)) != FSSL_SUCCESS) {
      logerr("Unable to obtain salt\n");
      seterr(err, status);
      goto done;
    }

    status = cipher_bytes_to_key(password, salt, key, key_size, iv, iv_size);
    checkerr(err, status) {
      logerr("KDF failure\n");
      goto done;
    }
  }

  if (iv_size > 0 && ivf &&
      (status = cipher_decode_hex(ivf->value.str, iv, iv_size)) != FSSL_SUCCESS) {
    logerr("Invalid iv: %s\n", fssl_error_string(status));
    seterr(err, status);
    goto done;
  }

  // no IV set
  if (!ivf && !password.ptr && iv_size > 0) {
    logerr("iv undefined\n");
    seterr(err, FSSL_ERR_INTERNAL);
    goto done;
  }

  if (kf && (status = cipher_decode_hex(kf->value.str, key, key_size)) != FSSL_SUCCESS) {
    logerr("Invalid key: %s\n", fssl_error_string(status));
    seterr(err, status);
    goto done;
  }

  ft_memcpy(result.iv, iv, iv_size);
  ft_memcpy(result.key, key, key_size);
  ft_memcpy(result.salt, salt, CIPHER_MAX_SALT_LEN);

done:
  string_destroy(&password);
  return result;
}

static __attribute_maybe_unused__ Option(IoReader)
    cipher_get_reader(IoReader* parent, const cli_flag_t* input, const bool base64) {
  if (input) {
    const string* file = &input->value.str;
    auto const tmp = file_reader_new(file->ptr, true);
    option_let_some_else(tmp, *parent) else {
      logerr("Unable to open input file\n");
      goto err;
    }
  }

  if (base64) {
    auto const tmp = b64_reader_new(parent, true);
    if (option_is_none(tmp)) {
      logerr("Out of memory\n");
      goto err;
    }

    return tmp;
  }

  return (Option(IoReader))Some(*parent);

err:
  return None(IoReader);
}

static __attribute_maybe_unused__ Option(IoWriterCloser)
    cipher_get_writer(IoWriter* parent, const cli_flag_t* output, const bool base64) {
  if (output) {
    const string* file = &output->value.str;
    auto const tmp = file_writer_new(file->ptr, true, O_CREAT);
    option_let_some_else(tmp, *parent) else {
      logerr("Unable to open output file\n");
      goto err;
    }
  }

  if (base64) {
    auto const tmp = b64_writer_new(parent);
    if (option_is_none(tmp)) {
      logerr("Out of memory\n");
      goto err;
    }

    return tmp;
  }

err:
  return None(IoWriterCloser);
}

static size_t cipher_get_iv_size(const fssl_block_cipher_t* cipher,
                                 const fssl_block_cipher_mode_t mode) {
  switch (mode) {
    case CBC:
    case CTR:
    case CFB:
    case OFB:
    case PCBC:
      return cipher->block_size;
    default:
      return 0;
  }
}

#include <stdio.h>

int cipher_command_impl(string command,
                        const cli_command_data* data,
                        cli_flags_t* flags,
                        int,
                        char**) {
  SSL_COMMAND_PROLOGUE(command);

  int exit_code = 0;
  fssl_error_t err = FSSL_SUCCESS;

  const fssl_block_cipher_mode_t mode = data->cipher.mode;
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

  const size_t iv_size = cipher_get_iv_size(cipher, mode);

  IoReader input = io_stdin;
  // IoWriter output = io_stdout;

  IoReader reader = {};
  IoWriterCloser writer = {};

  auto const in = cipher_get_reader(&input, input_flag, base64);
  option_let_some_else(in, reader) else {
    exit_code = EXIT_FAILURE;
    goto done;
  }

  const DeriveResult derived =
      cipher_derive_data(&reader, operation, key_flag, password_flag, salt_flag,
                         iv_flag, cipher->key_size, /* iv_size */ iv_size, &err);
  if (haserr(err)) {
    exit_code = err;
    goto done;
  }

#define pbytes(name, n, e)           \
  do {                               \
    printf("%s=", name);             \
    for (size_t i = 0; i < (n); ++i) \
      printf("%02X", (e)[i]);        \
    printf("\n");                    \
  } while (false)

  const bool has_salt = (!key_flag || password_flag || salt_flag);
  if (has_salt) {
    pbytes("salt", CIPHER_SALT_LEN, derived.salt);
  }

  pbytes("key", cipher->key_size, derived.key);
  if (iv_size > 0) {
    pbytes("iv", iv_size, derived.iv);
  }

  (void)output_flag;

  switch (mode) {
    case ECB:
    case CBC:
    case CTR:
    case CFB:
    case OFB:
    case PCBC:
      exit_code = EXIT_SUCCESS;
      break;
    default:
      logerr("Unknown cipher mode: %d\n", mode);
      exit_code = 1;
  }

done:
  io_writer_close(&writer);

  io_reader_deinit(&reader);
  io_writer_deinit((IoWriter*)&writer);
  return exit_code;
}