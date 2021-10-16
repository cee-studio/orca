/*
 * An example bot to fetch active invites from a guild.
*/

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <locale.h>

#include "discord.h"

void print_usage() {
  fprintf(stderr, "%s", "bot-fetch-invites - an example bot to fetch invites from a server\n");
  fprintf(stderr, "%s", "USAGE: ./bot-fetch-invites <guild_id>\n");

  fprintf(stderr, "%s", "Positional arguments:\n");
  fprintf(stderr, "%s", "\tguild_id\tthe id of the guild to fetch invites from\n");

  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
  if(argc == 1) {
    print_usage();
  }

  int index;
  const char* config_file = "../config.json";
  struct discord* client = discord_config_init(config_file);
  struct discord_invite** invites = {0};

  discord_get_guild_invites(client, strtoul(argv[1], NULL, 10), &invites);
  
  for(index = 0; invites[index] != NULL; index++) {
    printf("Active invite: %s\n", (*invites)[index].code);
  }

  return 0;
}

