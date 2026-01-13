#include <commands.h>
#include <io.h>
#include <stdlib.h>
#include "libft/io.h"

typedef enum {
  OP_ENCODE,
  OP_DECODE,
} Operation;

constexpr auto BASE64_FLAG_ENCODE = 'e';
constexpr auto BASE64_FLAG_DECODE = 'd';
constexpr auto BASE64_FLAG_INPUT = 'i';
constexpr auto BASE64_FLAG_OUTPUT = 'o';

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

static bool base64_reader(IoReader** reader,
                          const Operation op,
                          const cli_flag_t* input_flag) {
  if (input_flag) {
    const string* file = &input_flag->value.str;
    const auto tmp = file_reader_new(file->ptr, true);
    if (!tmp) {
      logerr("Unable to open input file\n");
      return false;
    }

    *reader = tmp;
  }

  if (op == OP_DECODE) {
    const auto tmp = b64_reader_new(*reader, true);
    if (!tmp) {
      logerr("Out of memory\n");
      return false;
    }

    *reader = tmp;
  }

  return true;
}

static bool base64_writer(IoWriter** writer,
                          const Operation op,
                          const cli_flag_t* output_flag) {
  if (output_flag) {
    const string* file = &output_flag->value.str;
    const auto tmp = file_writer_new(file->ptr, true, O_CREAT | O_TRUNC);
    if (!tmp) {
      logerr("Unable to open output file\n");
      return false;
    }

    *writer = tmp;
  }

  if (op == OP_ENCODE) {
    const auto tmp = b64_writer_new(*writer);
    if (!tmp) {
      logerr("Out of memory\n");
      return false;
    }

    *writer = tmp;
  }

  return true;
}

int base64_command_impl(string command,
                        const cli_command_data*,
                        cli_flags_t* flags,
                        int,
                        char**) {
  SSL_COMMAND_PROLOGUE(command);

  int exit_code = EXIT_SUCCESS;

  const Operation op = command_operation(flags);
  const cli_flag_t* input_flag = cli_flags_get(flags, BASE64_FLAG_INPUT);
  const cli_flag_t* output_flag = cli_flags_get(flags, BASE64_FLAG_OUTPUT);

  auto reader = (IoReader*)io_stdin;
  auto writer = (IoWriter*)io_stdout;

  if (!base64_reader(&reader, op, input_flag)) {
    exit_code = EXIT_FAILURE;
    goto done;
  }

  if (!base64_writer(&writer, op, output_flag)) {
    exit_code = EXIT_FAILURE;
    goto done;
  }

  if (io_copy(reader, writer) < 0) {
    logerr("I/O error\n");
    exit_code = EXIT_FAILURE;
  }

done:
  io_writer_close(writer);

  if (exit_code == EXIT_SUCCESS && output_flag == nullptr && op == OP_ENCODE)
    ft_putchar('\n');

  io_free(writer);
  io_free(reader);

  return exit_code;
}
