#include <cli/cli.h>
#include <fssl/fssl.h>

#include <stdio.h>
#include "libft/io.h"

constexpr string md5_command_name = libft_static_string("md5");
constexpr string sha256_command_name = libft_static_string("sha256");

int digest_command_impl(string command, cli_flags_t* flags, int argc, char** argv) {
  printf("[debug] %s called with '%s'\n", __func__, command.ptr);

  cli_flag_t* hash_string =
      cli_flags_get(flags, 's');  // TODO: this should not be a magic char;

  if (hash_string != nullptr) {
    uint8_t output[FSSL_MD5_SUM_SIZE] = {0};
    char hex_output[fssl_hex_encoded_size(FSSL_MD5_SUM_SIZE) + 1] = {};

    const string str = hash_string->value.str;

    fssl_md5_ctx ctx;
    fssl_md5_init(&ctx);
    fssl_md5_write(&ctx, (uint8_t*)str.ptr, str.len);
    fssl_md5_finish(&ctx, output, sizeof(output));
    fssl_hex_encode(output, FSSL_MD5_SUM_SIZE, hex_output, sizeof(hex_output));
    ft_printf("MD5(\"%s\") = %s\n", str.ptr, hex_output);
  }

  return 0;
}
