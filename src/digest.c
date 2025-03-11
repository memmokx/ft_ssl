#include <cli/cli.h>
#include <fssl/fssl.h>

#include <fcntl.h>
#include <libft/io.h>
#include <libft/memory.h>

constexpr string md5_command_name = libft_static_string("md5");
constexpr string sha256_command_name = libft_static_string("sha256");
constexpr string blake2_command_name = libft_static_string("blake2");

static Hasher create_hasher(const string* command) {
  Hasher hasher = {};

  if (string_equal(command, &md5_command_name)) {
    fssl_md5_ctx* ctx = ft_calloc(1, sizeof(fssl_md5_ctx));
    if (ctx == nullptr)
      return hasher;
    fssl_md5_init(ctx);
    return fssl_md5_hasher(ctx);
  }

  if (string_equal(command, &sha256_command_name)) {
    fssl_sha256_ctx* ctx = ft_calloc(1, sizeof(fssl_sha256_ctx));
    if (ctx == nullptr)
      return hasher;
    fssl_sha256_init(ctx);
    return fssl_sha256_hasher(ctx);
  }

  if (string_equal(command, &blake2_command_name)) {
    fssl_blake2_ctx * ctx = ft_calloc(1, sizeof(fssl_blake2_ctx));
    if (ctx == nullptr)
      return hasher;
    fssl_blake2_init(ctx);
    return fssl_blake2_hasher(ctx);
  }

  return hasher;
}

static string hasher_get_hash(Hasher* hasher) {
  uint8_t hash_output[64] = {};
  char hash_hex[129] = {};
  size_t written = 0;

  fssl_hasher_finish(hasher, hash_output, sizeof(hash_output), &written);
  fssl_hex_encode(hash_output, written, hash_hex, sizeof(hash_hex));
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

  if (!flags.reverse && !flags.redirect) {
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
    ssize_t n = read(STDIN_FILENO, buffer, sizeof(buffer) - 1);
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

  while (true) {
    ssize_t n = read(fd, buffer, sizeof(buffer));
    if (n < 1)
      break;

    fssl_hasher_write(hasher, buffer, n);
  }

  flags.file = true;
  digest_print_hash(hasher, command, string_new_owned((char*)path), flags);

  return true;
}

static void digest_hash_string(Hasher* hasher,
                               string command,
                               string str,
                               digest_flags_t flags) {
  fssl_hasher_write(hasher, (uint8_t*)str.ptr, str.len);
  digest_print_hash(hasher, command, str, flags);
}

int digest_command_impl(string command, cli_flags_t* flags, int argc, char** argv) {
  int exit_code = 0;

  Hasher hasher = create_hasher(&command);
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

  free(hasher.instance);
  return exit_code;
}
