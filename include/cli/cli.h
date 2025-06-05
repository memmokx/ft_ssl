#ifndef CLI_H
#define CLI_H

#include <fssl/fssl.h>
#include <libft/string.h>
#include <stdint.h>

#ifndef FSSL_CLI_FEATURES
#define FSSL_CLI_FEATURES 0
#endif

#define FSSL_MD5_VANILLA 0
#define FSSL_MD5_BONUS 1

constexpr size_t CLI_FLAGS_PER_COMMAND = 32;
constexpr size_t CLI_FLAGS_MAX = 256;

typedef enum {
  FlagNone = 0,
  FlagSet,
  FlagString,
  FlagInt,
} cli_flag_type;

typedef union {
  string str;
  int64_t i;
} cli_flag_value;

typedef struct {
  cli_flag_type type;
  cli_flag_value value;
  char name;
} cli_flag_t;

/*!
 * In the ft_ssl_* subjects the flags are always a single ascii char, this
 * allows us to store all the given flags for a single command in a 256 element
 * LUT.
 */
typedef struct {
  cli_flag_t table[CLI_FLAGS_MAX];
} cli_flags_t;

cli_flag_t* cli_flags_get(cli_flags_t* flags, char flag);

typedef union {
  fssl_hash_t hash;
} cli_command_data;

typedef int (
    *cli_command_action)(string, const cli_command_data*, cli_flags_t*, int, char**);

typedef struct {
  string name;
  cli_command_action action;
  cli_command_data data;
  // Maximum of 32 flags per command, should be plenty.
  struct {
    cli_flag_type ty;
    char name;
  } flags[CLI_FLAGS_PER_COMMAND];
} cli_command_t;

#define CLI_HAS_FLAG(flags, flag) (flags[(size_t)flag].type != FlagNone)
#define CLI_FLAG(name, ty) {Flag##ty, name}

typedef struct cmd_node_s {
  cli_command_t cmd;
  struct cmd_node_s* next;
} cmd_node_t;

void cmd_node_push(cmd_node_t** node, cmd_node_t* other);
cmd_node_t* cmd_node_last(cmd_node_t* node);
cmd_node_t* cmd_node_init(cli_command_t cmd);
void cmd_node_deinit(cmd_node_t** head);

typedef struct {
  cli_flags_t flags;
  const char* usage;
} App;

App cli_app_init(const char* usage);
void cli_app_deinit(App* app);
void cli_app_reset_flags(App* app);
bool cli_register_command(const cli_command_t cmd);
int cli_app_run(App* app, int argc, char** argv);

#endif