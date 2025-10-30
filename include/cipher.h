#ifndef SSL_CIPHER_H
#define SSL_CIPHER_H

#include <cli/cli.h>


int cipher_command_impl(string command,
                        const cli_command_data* data,
                        cli_flags_t* flags,
                        int argc,
                        char** argv);

#endif