#include <commands.h>

#include "io.h"

typedef enum {
  OP_ENCODE,
  OP_DECODE,
} Operation;

constexpr auto BASE64_FLAG_ENCODE = 'e';
constexpr auto BASE64_FLAG_DECODE = 'd';
constexpr auto BASE64_FLAG_INPUT = 'i';
// constexpr auto BASE64_FLAG_OUTPUT = 'o';

/*!
 * Based on the given flags, return the current mode of operation.
 * @return The operation to perform. If no specific flags are set: returns `OP_ENCODE`
 * by default. If both modes are set, the only one that matters is the last one.
 */
static Operation command_operation(cli_flags_t* flags) {
  Operation op = OP_ENCODE;

  const cli_flag_t* encode = cli_flags_get(flags, BASE64_FLAG_ENCODE);
  const cli_flag_t* decode = cli_flags_get(flags, BASE64_FLAG_DECODE);

  if (!encode && decode)
    op = OP_DECODE;
  else if (encode && decode) {
    op = encode->order > decode->order ? OP_ENCODE : OP_DECODE;
  }

  return op;
}

typedef struct {
  IoReader reader;
  bool freeable;
} Reader;

int base64_command_impl(string command,
                        const cli_command_data* data,
                        cli_flags_t* flags,
                        int argc,
                        char** argv) {
  (void)command;
  (void)data;
  (void)argc;
  (void)argv;

  int exit_code = 0;

  const Operation op = command_operation(flags);

  const cli_flag_t* input_flag = cli_flags_get(flags, BASE64_FLAG_INPUT);
  // const cli_flag_t* output_flag = cli_flags_get(flags, BASE64_FLAG_OUTPUT);

  Reader input = {
      .reader = io_stdin,
      .freeable = false,
  };

  IoReader reader = {};

  if (input_flag) {
    const Option(IoReader) tmp = file_reader_new(input_flag->value.str.ptr, true);
    if (option_is_none(tmp)) {
      ssl_log_warn("ft_ssl: base64: unable to open input file\n");
      exit_code = 1;
      goto done;
    }

    input = (Reader){tmp.v, true};
  }

  if (op != OP_DECODE) {
    ssl_log_err("operation not supported");
    exit_code = 1;
    goto done;
  }

  const Option(IoReader) b64 = b64_reader_new(&input.reader, true);
  if (option_is_none(b64)) {
    exit_code = FSSL_ERR_OUT_OF_MEMORY;
    goto done;
  }

  reader = b64.v;

  uint8_t buffer[2048] = {};
  while (true) {
    const ssize_t r = io_reader_read(&reader, buffer, sizeof(buffer));
    if (r < 0) {
      exit_code = 1;
      goto done;
    }
    if (r == 0)
      break;
    write(STDOUT_FILENO, buffer, r);
  }

done:
  if (reader.instance)
    io_reader_deinit(&reader);
  if (input.freeable)
    io_reader_deinit(&input.reader);
  return exit_code;
}
