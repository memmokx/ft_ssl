#ifndef SSL_COMMANDS_H
#define SSL_COMMANDS_H

#include <cli/cli.h>
#include "common.h"

int digest_command_impl(string command,
                        const cli_command_data* data,
                        cli_flags_t* flags,
                        int argc,
                        char** argv);

int cipher_command_impl(string command,
                        const cli_command_data* data,
                        cli_flags_t* flags,
                        int argc,
                        char** argv);

int base64_command_impl(string command,
                        const cli_command_data* data,
                        cli_flags_t* flags,
                        int argc,
                        char** argv);

static __attribute_maybe_unused__ string g_current_command = {};

#define logerr(fmt, ...) \
  ssl_log_err("ft_ssl: %s: " fmt, g_current_command.ptr, ##__VA_ARGS__)
#define logwarn(fmt, ...) \
  ssl_log_warn("ft_ssl: %s: " fmt, g_current_command.ptr, ##__VA_ARGS__)

#define SSL_COMMAND_PROLOGUE(_command) \
  do {                                 \
    g_current_command = (_command);    \
  } while (false)

#endif