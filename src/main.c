#include <cli/cli.h>
#include <digest.h>
#include "libft/io.h"
#include "libft/memory.h"

uint8_t g_failed = 0;

#define HASH_COMMAND_FLAGS   \
  {                          \
      CLI_FLAG('p', Set),    \
      CLI_FLAG('q', Set),    \
      CLI_FLAG('r', Set),    \
      CLI_FLAG('s', String), \
  }

#define FOREACH_HASH_COMMAND(V)                             \
  V(md5, {.hash = fssl_hash_md5}, HASH_COMMAND_FLAGS)       \
  V(sha1, {.hash = fssl_hash_sha1}, HASH_COMMAND_FLAGS)     \
  V(sha256, {.hash = fssl_hash_sha256}, HASH_COMMAND_FLAGS) \
  V(sha512, {.hash = fssl_hash_sha512}, HASH_COMMAND_FLAGS) \
  V(blake2, {.hash = fssl_hash_blake2}, HASH_COMMAND_FLAGS)

#define FOREACH_COMMAND(V) FOREACH_HASH_COMMAND(V)

#define REGISTER_COMMAND(_name, _data, _flags)                        \
  __attribute__((constructor)) static void register_##_name##_cmd() { \
    g_failed |= !cli_register_command((cli_command_t){                \
        .name = libft_static_string(#_name),                          \
        .action = digest_command_impl,                                \
        .data = _data,                                                \
        .flags = _flags,                                              \
    });                                                               \
  }

FOREACH_COMMAND(REGISTER_COMMAND)
#undef REGISTER_COMMAND

const char* fssl_cli_usage = "\nCommands:\n"

#define REGISTER_COMMAND(name, ...) #name "\n"
    FOREACH_COMMAND(REGISTER_COMMAND)
#undef REGISTER_COMMAND

        "\nFlags:\n"
        "-p -q -r -s\n";

#if FSSL_CLI_FEATURES > FSSL_MD5_VANILLA
static int cli_interactive_mode(App* app) {
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

int main(int argc, char** argv) {
  int exit_code = 1;
  App ft_ssl = cli_app_init(fssl_cli_usage);
  if (g_failed)
    goto out;

#if FSSL_CLI_FEATURES > FSSL_MD5_VANILLA
  // Interactive mode
  if (argc == 1) {
    exit_code = cli_interactive_mode(&ft_ssl);
    goto out;
  }
#endif

  exit_code = cli_app_run(&ft_ssl, argc - 1, argv + 1);

out:
  cli_app_deinit(&ft_ssl);
  return exit_code;
}
