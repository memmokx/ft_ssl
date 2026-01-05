#include <cli/cli.h>
#include <commands.h>
#include "libft/io.h"
#include "libft/memory.h"

uint8_t g_failed = 0;

#define cdata(_type, _data) {._type = _data}
#define cipherdata(_cipher, _mode) {.desc = &_cipher, .mode = _mode}

#define UNIQUE_NAME_CONCAT(base, counter) base##counter
#define UNIQUE_NAME_IMPL(base, counter) UNIQUE_NAME_CONCAT(base, counter)
#define UNIQUE_NAME(base) UNIQUE_NAME_IMPL(base, __COUNTER__)

#define HASH_COMMAND_FLAGS   \
  {                          \
      CLI_FLAG('p', Set),    \
      CLI_FLAG('q', Set),    \
      CLI_FLAG('r', Set),    \
      CLI_FLAG('s', String), \
  }

#define DES_COMMAND_FLAGS                                                  \
  {                                                                        \
      CLI_FLAG('a', Set),    CLI_FLAG('d', Set),    CLI_FLAG('e', Set),    \
      CLI_FLAG('i', String), CLI_FLAG('o', String), CLI_FLAG('k', String), \
      CLI_FLAG('p', String), CLI_FLAG('s', String), CLI_FLAG('v', String), \
  }

#define B64_COMMAND_FLAGS    \
  {                          \
      CLI_FLAG('d', Set),    \
      CLI_FLAG('e', Set),    \
      CLI_FLAG('i', String), \
      CLI_FLAG('o', String), \
  }

#define FOREACH_HASH_COMMAND(V)                                                       \
  V("md5", cdata(hash, fssl_hash_md5), HASH_COMMAND_FLAGS, digest_command_impl)       \
  V("sha1", cdata(hash, fssl_hash_sha1), HASH_COMMAND_FLAGS, digest_command_impl)     \
  V("sha256", cdata(hash, fssl_hash_sha256), HASH_COMMAND_FLAGS, digest_command_impl) \
  V("sha512", cdata(hash, fssl_hash_sha512), HASH_COMMAND_FLAGS, digest_command_impl) \
  V("blake2", cdata(hash, fssl_hash_blake2), HASH_COMMAND_FLAGS, digest_command_impl)

#if FSSL_CLI_FEATURES > FSSL_DES_VANILLA
#define FOREACH_BONUS_CIPHER(V)                                                      \
  V("des-ctr", cdata(cipher, cipherdata(fssl_cipher_des, CIPHER_MODE_CTR)),          \
    DES_COMMAND_FLAGS, cipher_command_impl)                                          \
  V("des-cfb", cdata(cipher, cipherdata(fssl_cipher_des, CIPHER_MODE_CFB)),          \
    DES_COMMAND_FLAGS, cipher_command_impl)                                          \
  V("des-ofb", cdata(cipher, cipherdata(fssl_cipher_des, CIPHER_MODE_OFB)),          \
    DES_COMMAND_FLAGS, cipher_command_impl)                                          \
  V("des3", cdata(cipher, cipherdata(fssl_cipher_des3, CIPHER_MODE_CBC)),            \
    DES_COMMAND_FLAGS, cipher_command_impl)                                          \
  V("des3-ecb", cdata(cipher, cipherdata(fssl_cipher_des3, CIPHER_MODE_ECB)),        \
    DES_COMMAND_FLAGS, cipher_command_impl)                                          \
  V("des3-cbc", cdata(cipher, cipherdata(fssl_cipher_des3, CIPHER_MODE_CBC)),        \
    DES_COMMAND_FLAGS, cipher_command_impl)                                          \
  V("des3-ctr", cdata(cipher, cipherdata(fssl_cipher_des3, CIPHER_MODE_CTR)),        \
    DES_COMMAND_FLAGS, cipher_command_impl)                                          \
  V("des3-cfb", cdata(cipher, cipherdata(fssl_cipher_des3, CIPHER_MODE_CFB)),        \
    DES_COMMAND_FLAGS, cipher_command_impl)                                          \
  V("des3-ofb", cdata(cipher, cipherdata(fssl_cipher_des3, CIPHER_MODE_OFB)),        \
    DES_COMMAND_FLAGS, cipher_command_impl)                                          \
  V("chacha20", cdata(cipher, cipherdata(fssl_cipher_chacha20, CIPHER_MODE_STREAM)), \
    DES_COMMAND_FLAGS, cipher_command_impl)

#else
#define FOREACH_BONUS_CIPHER(V)
#endif

#define FOREACH_CIPHER_COMMAND(V)                                           \
  V("base64", {}, B64_COMMAND_FLAGS, base64_command_impl)                   \
  V("des", cdata(cipher, cipherdata(fssl_cipher_des, CIPHER_MODE_CBC)),     \
    DES_COMMAND_FLAGS, cipher_command_impl)                                 \
  V("des-ecb", cdata(cipher, cipherdata(fssl_cipher_des, CIPHER_MODE_ECB)), \
    DES_COMMAND_FLAGS, cipher_command_impl)                                 \
  V("des-cbc", cdata(cipher, cipherdata(fssl_cipher_des, CIPHER_MODE_CBC)), \
    DES_COMMAND_FLAGS, cipher_command_impl)                                 \
  FOREACH_BONUS_CIPHER(V)

#define FOREACH_COMMAND(V) \
  FOREACH_HASH_COMMAND(V)  \
  FOREACH_CIPHER_COMMAND(V)

#define X(_name, _data, _flags, _action)                                 \
  __attribute__((constructor)) static void UNIQUE_NAME(register_cmd)() { \
    g_failed |= !cli_register_command((cli_command_t){                   \
        .name = libft_static_string(_name),                              \
        .action = _action,                                               \
        .data = _data,                                                   \
        .flags = _flags,                                                 \
    });                                                                  \
  }

FOREACH_COMMAND(X)

#undef X

const char* fssl_cli_usage =
    "\nStandard Commands:\n\n"

    "Message Digest Commands:\n"
#define X(name, ...) name "\n"
    FOREACH_HASH_COMMAND(X)
#undef X

        "\nCipher Commands:\n"
#define X(name, ...) name "\n"
    FOREACH_CIPHER_COMMAND(X)
#undef X
    ;

#if FSSL_CLI_FEATURES > FSSL_MD5_VANILLA
int cli_interactive_mode(App* app) {
  int exit_code = 0;
  char** argv = nullptr;
  string line = {};
  string_split_result split = {};

  while (true) {
    ft_putstr("ft_ssl > ");
    line = string_new_owned(get_next_line(STDIN_FILENO));
    if (line.ptr == nullptr)
      break;
    if (line.len != 0 && line.ptr[line.len - 1] == '\n') {
      line.ptr[line.len - 1] = 0;
      line.len -= 1;
    }

    split = string_split(&line, ' ');
    if (split.strs == nullptr)
      break;

    int argc = (int)split.size;
    argv = ft_calloc(split.size, sizeof(char*));
    if (argv == nullptr)
      break;

    for (int i = 0; i < argc; ++i)
      argv[i] = split.strs[i].ptr;

    exit_code = cli_app_run(app, argc, argv);
    cli_app_reset_flags(app);

    string_destroy(&line);
    split_destroy(&split);
    if (argv != nullptr)
      free(argv);
    argv = nullptr;
  }

  string_destroy(&line);
  split_destroy(&split);
  if (argv != nullptr)
    free(argv);  // The pointers are owned by the split_result

  return exit_code;
}
#endif
