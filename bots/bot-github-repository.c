/*
 * A bot that retrieves information about a repository.
*/

#include <stdio.h>
#include "github.h"

int main() {
  struct github* client = github_config_init("bot.config", NULL);
  struct sized_buffer payload = {0};
  
  github_get_repository(client, "antropez", "orca", &payload);
  printf("%s\n", payload.start);
}
