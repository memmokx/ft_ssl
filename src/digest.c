#include <cli/cli.h>
#include <fssl/fssl.h>

#include <fcntl.h>
#include <libft/io.h>
#include <libft/memory.h>

static string hasher_get_hash(Hasher* hasher) {
  uint8_t hash_output[64] = {};
  char hash_hex[129] = {};

  fssl_hasher_finish(hasher, hash_output, sizeof(hash_output));
  fssl_hex_encode(hash_output, hasher->hash.sum_size, hash_hex, sizeof(hash_hex));
  fssl_hasher_reset(hasher);
  return string_new(hash_hex);
}

typedef struct {
  bool redirect : 1;
  bool reverse : 1;
  bool quiet : 1;
  bool file : 1;
  uint8_t _pad : 4;
} digest_flags_t;

static void digest_print_hash(Hasher* hasher,
                              string command,
                              string data,
                              digest_flags_t flags) {
  string command_upper = string_new(command.ptr);
  if (command_upper.ptr == nullptr)
    return;
  for (size_t i = 0; i < command_upper.len; ++i) {
    char* c = &command_upper.ptr[i];
    if (*c >= 'a' && *c <= 'z')
      *c -= 32;
  }

  string hash = hasher_get_hash(hasher);
  if (hash.ptr == nullptr)
    goto out;
  if (data.ptr == nullptr)
    goto next;

  if (!flags.reverse && !flags.redirect && !flags.quiet) {
    ft_printf(flags.file ? "%s (%s) = " : "%s (\"%s\") = ", command_upper.ptr, data.ptr);
  }

next:
  ft_putstr(hash.ptr);

  if (flags.reverse && !flags.redirect && data.ptr && !flags.quiet) {
    ft_printf(flags.file ? " %s" : " \"%s\"", data.ptr);
  }

  ft_putchar('\n');

out:
  string_destroy(&hash);
  string_destroy(&command_upper);
}

static bool digest_hash_stdin(Hasher* hasher, string command, digest_flags_t flags) {
  uint8_t buffer[8192 * 2];
  string storage = string_new_capacity(128);

  while (true) {
    const ssize_t n = read(STDIN_FILENO, buffer, sizeof(buffer) - 1);
    if (n < 1)
      break;

    fssl_hasher_write(hasher, buffer, n);
    buffer[n] = 0;
    if (flags.redirect &&
        string_append(&storage, (char*)buffer) != STRING_ALLOC_SUCCESS) {
      string_destroy(&storage);
      return false;
    }
  }

  if (flags.redirect) {
    if (flags.quiet)
      ft_putstr(storage.ptr);
    else {
      // Subject quirk
      if (storage.len > 0 && storage.ptr[storage.len - 1] == '\n')
        storage.ptr[storage.len - 1] = 0;
      ft_printf("(\"%s\")= ", storage.ptr);
    }
  } else if (!flags.quiet) {
    ft_putstr("(stdin)= ");
  }
  digest_print_hash(hasher, command, (string){}, flags);

  string_destroy(&storage);
  return true;
}

static bool digest_hash_file(Hasher* hasher,
                             string command,
                             const char* path,
                             digest_flags_t flags) {
  uint8_t buffer[8182 * 2];
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    ft_fprintf(STDERR_FILENO, "ft_ssl: %s: %s: Unable to open file.\n", command.ptr,
               path);
    return false;
  }

  ssize_t n = 0;
  while (true) {
    n = read(fd, buffer, sizeof(buffer));
    if (n < 1)
      break;

    fssl_hasher_write(hasher, buffer, n);
  }

  if (n == -1) {
    ft_fprintf(STDERR_FILENO, "ft_ssl: %s: %s: Unable to read file\n", command.ptr,
               path);
    close(fd);
    return false;
  }

  flags.file = true;
  digest_print_hash(hasher, command, string_new_owned((char*)path), flags);

  close(fd);
  return true;
}

static void digest_hash_string(Hasher* hasher,
                               string command,
                               string str,
                               digest_flags_t flags) {
  fssl_hasher_write(hasher, (uint8_t*)str.ptr, str.len);
  digest_print_hash(hasher, command, str, flags);
}

int digest_command_impl(string command,
                        const cli_command_data* data,
                        cli_flags_t* flags,
                        int argc,
                        char** argv) {
  int exit_code = 0;

  Hasher hasher = fssl_hasher_new(data->hash);
  if (hasher.instance == nullptr)
    return 1;

  cli_flag_t* flag_hash_string = cli_flags_get(flags, 's');
  digest_flags_t digest_flags = {
      .redirect = cli_flags_get(flags, 'p') != nullptr,
      .quiet = cli_flags_get(flags, 'q') != nullptr,
      .reverse = cli_flags_get(flags, 'r') != nullptr,
      .file = false,
  };

  if ((argc == 0 && flag_hash_string == nullptr) || digest_flags.redirect) {
    exit_code |= !digest_hash_stdin(&hasher, command, digest_flags);
  }

  // Once we processed stdin this is not useful anymore
  digest_flags.redirect = false;

  if (flag_hash_string != nullptr) {
    digest_hash_string(&hasher, command, flag_hash_string->value.str, digest_flags);
  }

  for (size_t i = 0; i < (size_t)argc; ++i) {
    exit_code |= !digest_hash_file(&hasher, command, argv[i], digest_flags);
  }

  fssl_hasher_destroy(&hasher);
  return exit_code;
}
