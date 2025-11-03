#include <commands.h>
#include <io.h>

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

static Option(IoReader)
    base64_reader(IoReader* parent, const Operation op, const cli_flag_t* input_flag) {
  if (input_flag) {
    const string* file = &input_flag->value.str;
    auto const tmp = file_reader_new(file->ptr, true);
    option_let_some_else(tmp, *parent) else {
      logerr("Unable to open input file\n");
      goto err;
    }
  }

  // We need to read base64 data, so wrap the parent with a base64 reader.
  if (op == OP_DECODE) {
    auto const tmp = b64_reader_new(parent, true);
    if (option_is_none(tmp)) {
      logerr("Out of memory\n");
      goto err;
    }

    return tmp;
  }

  return (Option(IoReader))Some(*parent);
err:
  return None(IoReader);
}

static Option(IoWriterCloser)
    base64_writer(IoWriter* parent, const Operation op, const cli_flag_t* output_flag) {
  if (output_flag) {
    const string* file = &output_flag->value.str;
    auto const tmp = file_writer_new(file->ptr, true, O_CREAT);
    option_let_some_else(tmp, *parent) else {
      logerr("Unable to open output file\n");
      goto err;
    }
  }

  if (op == OP_ENCODE) {
    auto const tmp = b64_writer_new(parent);
    if (option_is_none(tmp)) {
      logerr("Out of memory\n");
      goto err;
    }

    return tmp;
  }

  return (Option(IoWriterCloser))Some(io_writer_closer_from(*parent));
err:
  return None(IoWriterCloser);
}

int base64_command_impl(string command,
                        const cli_command_data*,
                        cli_flags_t* flags,
                        int,
                        char**) {
  SSL_COMMAND_PROLOGUE(command);

  int exit_code = 0;

  const Operation op = command_operation(flags);
  const cli_flag_t* input_flag = cli_flags_get(flags, BASE64_FLAG_INPUT);
  const cli_flag_t* output_flag = cli_flags_get(flags, BASE64_FLAG_OUTPUT);

  IoReader input = io_stdin;
  IoWriter output = io_stdout;

  IoReader reader = {};
  IoWriterCloser writer = {};

  const Option(IoReader) oreader = base64_reader(&input, op, input_flag);
  option_let_some_else(oreader, reader) else {
    exit_code = 1;
    goto done;
  }

  const Option(IoWriterCloser) owriter = base64_writer(&output, op, output_flag);
  option_let_some_else(owriter, writer) else {
    exit_code = 1;
    goto done;
  }

  if (io_copy(&reader, (IoWriter*)&writer) < 0)
    exit_code = 1;

done:
  io_writer_close(&writer);

  io_reader_deinit(&reader);
  io_writer_deinit((IoWriter*)&writer);

  return exit_code;
}
