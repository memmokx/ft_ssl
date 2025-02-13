#include <cli/cli.h>
#include <stdlib.h>

cmd_node* cmd_node_init(cli_command cmd) {
  cmd_node* node = malloc(sizeof(cmd_node));
  if (node == nullptr)
    return nullptr;

  *node = (cmd_node){
      .cmd = cmd,
      .next = nullptr,
  };

  return node;
}

void cmd_node_deinit(cmd_node** head) {
  if (head == nullptr || *head == nullptr)
    return;

  cmd_node_deinit(&(*head)->next);
  free(*head);
  *head = nullptr;
}

void cmd_node_push(cmd_node** node, cmd_node* other) {
  cmd_node* last = cmd_node_last(*node);
  if (last == nullptr)
    *node = other;
  else
    last->next = other;
}

cmd_node* cmd_node_last(cmd_node* node) {
  if (node == nullptr)
    return nullptr;

  while (node->next) {
    node = node->next;
  }

  return node;
}
