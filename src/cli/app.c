#include <cli/cli.h>
#include <libft/io.h>
#include <libft/string.h>
#include <stdlib.h>

App cli_app_init() {
  return (App){
      .flags = {},
      .cmd_head = nullptr,
  };
}

void cli_app_deinit(App* app) {
  cmd_node_deinit(&app->cmd_head);
}

bool cli_app_register_command(App* app, const cli_command* cmd) {
  cmd_node* new = cmd_node_init(*cmd);
  if (new == nullptr)
    return false;

  cmd_node_push(&app->cmd_head, new);
  return true;
}

static bool cli_command_has_flag(const cli_command* cmd, char flag) {
  for (int i = 0; i < CLI_FLAGS_PER_COMMAND; ++i) {
    if (cmd->flags[i].name == flag)
      return true;
  }

  return false;
}

static cli_flag_type cli_command_flag_type(const cli_command* cmd, char flag) {
  for (int i = 0; i < CLI_FLAGS_PER_COMMAND; ++i) {
    if (cmd->flags[i].name == flag)
      return cmd->flags[i].ty;
  }

  return FlagNone;
}

static cli_flag cli_flag_from_arg(char flag, cli_flag_type ty, char* arg) {
  if (ty == FlagString && arg != nullptr)
    return (cli_flag){
        .name = flag,
        .type = ty,
        .value = {.str = string_new_owned(arg)},
    };

  return (cli_flag){.name = flag, .type = ty, .value = {}};
}

static cli_command* cli_get_command(App* app, string name) {
  cmd_node* tmp = app->cmd_head;

  while (tmp) {
    cli_command* cmd = &tmp->cmd;
    if (string_equal(&cmd->name, &name))
      return cmd;
    tmp = tmp->next;
  }

  return nullptr;
}

static int cli_run_command(App* app, const cli_command* cmd, int argc, char** argv) {
  char flag;
  cli_flag_type ty;

  int i = 0;
  for (; i < argc; ++i) {
    const string arg = string_new_owned(argv[i]);
    const bool has_prefix = string_index_of(arg, '-') == 0;

    if (has_prefix) {
      // TODO: correct behaviour when the flag is invalid ?
      if (arg.len != 2 || !cli_command_has_flag(cmd, arg.ptr[1]))
        break;

      flag = arg.ptr[1];
      ty = cli_command_flag_type(cmd, flag);
      app->flags.table[(size_t)flag] =
          cli_flag_from_arg(flag, ty, (ty == FlagString) ? argv[++i] : nullptr);

      continue;
    }

    break;
  }

  return cmd->action(cmd->name, &app->flags, argc - i, &argv[i]);
}

int cli_app_run(App* app, int argc, char** argv) {
  int exit_code = 0;

  argc--;
  argv++;

  // TODO(bonus): Interactive mode ?
  if (argc == 0)
    goto out;

  const string name = string_new_owned(argv[0]);
  const cli_command* cmd = cli_get_command(app, name);
  if (cmd == nullptr) {
    ft_fprintf(STDERR_FILENO, "ft_ssl: Error: '%s' is an invalid command.",
               name.ptr);
    exit_code = 1;
    goto out;
  }

  exit_code = cli_run_command(app, cmd, argc - 1, argv + 1);

out:
  cli_app_deinit(app);
  return exit_code;
}
