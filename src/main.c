#include <cli/cli.h>
#include <digest.h>
#include <fssl/fssl.h>

static const cli_command md5_cmd = CLI_COMMAND("md5",
                                               digest_command_impl,
                                               CLI_FLAG('p', Set),
                                               CLI_FLAG('q', Set),
                                               CLI_FLAG('r', Set),
                                               CLI_FLAG('s', String));

static const cli_command sha256_cmd = CLI_COMMAND("sha256",
                                                  digest_command_impl,
                                                  CLI_FLAG('p', Set),
                                                  CLI_FLAG('q', Set),
                                                  CLI_FLAG('r', Set),
                                                  CLI_FLAG('s', String));

int main(int argc, char** argv) {
  App ft_ssl = cli_app_init();

  if (!cli_app_register_command(&ft_ssl, &md5_cmd))
    goto out;
  if (!cli_app_register_command(&ft_ssl, &sha256_cmd))
    goto out;

  cli_app_run(&ft_ssl, argc, argv);

out:
  cli_app_deinit(&ft_ssl);
  return 1;
}
