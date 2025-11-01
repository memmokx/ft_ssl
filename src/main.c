#include <cli/cli.h>

extern uint8_t g_failed;
extern char* fssl_cli_usage;

#if FSSL_CLI_FEATURES > FSSL_MD5_BONUS
int cli_interactive_mode(App* app);
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
