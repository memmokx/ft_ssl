#include <cli/cli.h>
#include <stdlib.h>

cmd_node_t* cmd_node_init(cli_command_t cmd) {
  cmd_node_t* node = malloc(sizeof(cmd_node_t));
  if (node == nullptr)
    return nullptr;

  *node = (cmd_node_t){
      .cmd = cmd,
      .next = nullptr,
  };

  return node;
}

void cmd_node_deinit(cmd_node_t** head) {
  if (head == nullptr || *head == nullptr)
    return;

  cmd_node_deinit(&(*head)->next);
  free(*head);
  *head = nullptr;
}

void cmd_node_push(cmd_node_t** node, cmd_node_t* other) {
  cmd_node_t* last = cmd_node_last(*node);
  if (last == nullptr)
    *node = other;
  else
    last->next = other;
}

cmd_node_t* cmd_node_last(cmd_node_t* node) {
  if (node == nullptr)
    return nullptr;

  while (node->next) {
    node = node->next;
  }

  return node;
}
