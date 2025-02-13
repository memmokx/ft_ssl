#ifndef CLI_H
#define CLI_H

#include <libft/string.h>
#include <stdint.h>

#define CLI_FLAGS_PER_COMMAND 32
#define CLI_FLAGS_MAX 256

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
} cli_flag;

/*!
 * In the ft_ssl_* subjects the flags are always a single ascii char, this
 * allows us to store all the given flags for a single command in a 256 element
 * LUT.
 */
typedef struct {
  cli_flag table[CLI_FLAGS_MAX];
} cli_flags;

typedef int (*cli_command_action)(string, cli_flags*, int, char**);

typedef struct {
  string name;
  cli_command_action action;
  // Maximum of 32 flags per command, should be plenty.
  struct {
    cli_flag_type ty;
    char name;
  } flags[CLI_FLAGS_PER_COMMAND];
} cli_command;

#define CLI_HAS_FLAG(flags, flag) (flags[(size_t)flag].type != FlagNone)
#define CLI_FLAG(name, ty) {Flag##ty, name}
#define CLI_COMMAND(name, action, ...) \
  (cli_command) {                      \
    libft_static_string(name), action, {                    \
      __VA_ARGS__                      \
    }                                  \
  }

typedef struct cmd_node_s {
  cli_command cmd;
  struct cmd_node_s* next;
} cmd_node;

void cmd_node_push(cmd_node** node, cmd_node* other);
cmd_node* cmd_node_last(cmd_node* node);
cmd_node* cmd_node_init(cli_command cmd);
void cmd_node_deinit(cmd_node** head);

typedef struct {
  cli_flags flags;
  cmd_node* cmd_head;
} App;

App cli_app_init();
void cli_app_deinit(App* app);
bool cli_app_register_command(App* app, const cli_command* cmd);
[[noreturn]] void cli_app_run(App* app, int argc, char** argv);

#endif