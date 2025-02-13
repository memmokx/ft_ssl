#include <cli/cli.h>
#include <fssl/fssl.h>

#include <stdio.h>

int digest_command_impl(string command, cli_flags* flags, int argc, char** argv) {
  printf("[debug] %s called with '%s'\n", __func__, command.ptr);

  for (int i = 0; i < CLI_FLAGS_MAX; ++i) {
    if (flags->table[i].type != FlagNone) {
      const cli_flag flag = flags->table[i];
      switch (flag.type) {
        case FlagString:
          printf("[debug] flag: '%c' value: '%s'\n", flag.name, flag.value.str.ptr);
          break;
        case FlagSet:
          printf("[debug] flag: '%c' set\n", flag.name);
          break;
        case FlagInt:
          printf("[debug] flag: '%c' value: %li\n", flag.name, flag.value.i);
          break;
        default:
      }
    }
  }

  for (int i = 0; i < argc; ++i) {
    printf("[debug] %s called with arg[%d] '%s'\n", __func__, i, argv[i]);
  }

  return 0;
}
