#include <cli/cli.h>
#include <libft/io.h>
#include <libft/memory.h>
#include <libft/string.h>
#include <stdlib.h>

App cli_app_init(const char* usage) {
  return (App){
      .flags = {},
      .usage = usage,
  };
}

static cmd_node_t* cmd_head = nullptr;

static cmd_node_t* cli_get_commands(void) {
  return cmd_head;
}

void cli_app_deinit(App* app) {
  (void)app;
  cmd_node_deinit(&cmd_head);
}

void cli_app_reset_flags(App* app) {
  ft_bzero(&app->flags, sizeof(app->flags));
}

bool cli_register_command(const cli_command_t cmd) {
  cmd_node_t* new = cmd_node_init(cmd);
  if (new == nullptr)
    return false;

  cmd_node_push(&cmd_head, new);
  return true;
}

static bool cli_command_has_flag(const cli_command_t* cmd, char flag) {
  for (size_t i = 0; i < CLI_FLAGS_PER_COMMAND && cmd->flags[i].ty != FlagNone; ++i) {
    if (cmd->flags[i].name == flag)
      return true;
  }

  return false;
}

static cli_flag_type cli_command_flag_type(const cli_command_t* cmd, char flag) {
  for (size_t i = 0; i < CLI_FLAGS_PER_COMMAND && cmd->flags[i].ty != FlagNone; ++i) {
    if (cmd->flags[i].name == flag)
      return cmd->flags[i].ty;
  }

  return FlagNone;
}

static cli_flag_t cli_flag_from_arg(char flag, cli_flag_type ty, char* arg, uint32_t index) {
  if (ty == FlagString && arg != nullptr)
    return (cli_flag_t){
        .name = flag,
        .type = ty,
        .order = index,
        .value = {.str = string_new_owned(arg)},
    };

  return (cli_flag_t){.name = flag, .type = ty, .order = index, .value = {}};
}

static cli_command_t* cli_get_command(string name) {
  cmd_node_t* tmp = cli_get_commands();

  while (tmp) {
    cli_command_t* cmd = &tmp->cmd;
    if (string_equal(&cmd->name, &name))
      return cmd;
    tmp = tmp->next;
  }

  return nullptr;
}

static void cli_app_print_help(const App* app) {
  ft_fprintf(STDOUT_FILENO, "%s", app->usage);
}

static int cli_run_command(App* app, const cli_command_t* cmd, int argc, char** argv) {
  int i = 0;
  for (; i < argc; ++i) {
    const string arg = string_new_owned(argv[i]);
    const bool has_prefix = string_index_of(arg, '-') == 0;

    if (has_prefix) {
      if (arg.len != 2 || !cli_command_has_flag(cmd, arg.ptr[1])) {
        ft_fprintf(STDERR_FILENO, "ft_ssl: Error: '%s' is not a valid flag.\n", arg.ptr);
        cli_app_print_help(app);
        return 1;
      }

      const char flag = arg.ptr[1];
      const cli_flag_type ty = cli_command_flag_type(cmd, flag);
      if (ty == FlagString && i + 1 >= argc) {
        ft_fprintf(STDERR_FILENO,
                   "ft_ssl: Error: the '-s' flag requires a string argument.\n");
        cli_app_print_help(app);
        return 1;
      }

      const uint32_t order = i;
      app->flags.table[(size_t)flag] =
          cli_flag_from_arg(flag, ty, (ty == FlagString) ? argv[++i] : nullptr, order);

      continue;
    }

    break;
  }

  return cmd->action(cmd->name, &cmd->data, &app->flags, argc - i, &argv[i]);
}

int cli_app_run(App* app, int argc, char** argv) {
  int exit_code = 0;

  if (argc == 0) {
    ft_fprintf(STDERR_FILENO, "usage: ft_ssl command [flags] [file/string]\n");
    goto out;
  }

  const string name = string_new_owned(argv[0]);
  const cli_command_t* cmd = cli_get_command(name);
  if (cmd == nullptr) {
    ft_fprintf(STDERR_FILENO, "ft_ssl: Error: '%s' is an invalid command.\n", name.ptr);
    cli_app_print_help(app);
    exit_code = 1;
    goto out;
  }

  exit_code = cli_run_command(app, cmd, argc - 1, argv + 1);

out:
  return exit_code;
}

cli_flag_t* cli_flags_get(cli_flags_t* flags, char flag) {
  cli_flag_t* f = &flags->table[(size_t)flag];
  if (f->type == FlagNone)
    return nullptr;

  return f;
}
