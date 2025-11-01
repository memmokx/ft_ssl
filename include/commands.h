#ifndef SSL_COMMANDS_H
#define SSL_COMMANDS_H

#include <cli/cli.h>

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

#endif