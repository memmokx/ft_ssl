#include <cli/cli.h>
#include <digest.h>
#include "libft/io.h"
#include "libft/memory.h"

uint8_t g_failed = 0;

__attribute__((constructor)) static void register_md5_cmd() {
  g_failed |= cli_register_command(CLI_COMMAND(
      "md5", digest_command_impl, {.hash = fssl_hash_md5}, CLI_FLAG('p', Set),
      CLI_FLAG('q', Set), CLI_FLAG('r', Set), CLI_FLAG('s', String)));
}

__attribute__((constructor)) static void register_sha256_cmd() {
  g_failed |= cli_register_command(CLI_COMMAND(
      "sha256", digest_command_impl, {.hash = fssl_hash_sha256}, CLI_FLAG('p', Set),
      CLI_FLAG('q', Set), CLI_FLAG('r', Set), CLI_FLAG('s', String)));
}

#if FSSL_CLI_FEATURES > FSSL_MD5_VANILLA
__attribute__((constructor)) static void register_blake2_cmd() {
  g_failed |= cli_register_command(CLI_COMMAND(
      "blake2", digest_command_impl, {.hash = fssl_hash_blake2}, CLI_FLAG('p', Set),
      CLI_FLAG('q', Set), CLI_FLAG('r', Set), CLI_FLAG('s', String)));
}

__attribute__((constructor)) static void register_sha1_cmd() {
  g_failed |= cli_register_command(CLI_COMMAND(
      "sha1", digest_command_impl, {.hash = fssl_hash_sha1}, CLI_FLAG('p', Set),
      CLI_FLAG('q', Set), CLI_FLAG('r', Set), CLI_FLAG('s', String)));
}
#endif

const char* fssl_cli_usage =
    "\nCommands:\n"
    "md5\n"
    "sha256\n"
#if FSSL_CLI_FEATURES > FSSL_MD5_VANILLA
    "sha1\n"
    "blake2\n"
#endif
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

#if FSSL_CLI_FEATURES > FSSL_MD5_VANILLA
  // Interactive mode
  if (argc == 1) {
    exit_code = cli_interactive_mode(&ft_ssl);
    goto out;
  }
#endif

  exit_code = cli_app_run(&ft_ssl, argc - 1, argv + 1);

#if FSSL_CLI_FEATURES > FSSL_MD5_VANILLA
out:
#endif
  cli_app_deinit(&ft_ssl);
  return exit_code;
}
