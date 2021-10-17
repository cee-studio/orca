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
  fprintf(stderr, "%s", "bot-fetch-welcome-screen - an example bot to the welcome screen of a server\n");
  fprintf(stderr, "%s", "USAGE: ./bot-fetch-welcome-screen <config> <guild_id>\n");

  fprintf(stderr, "%s", "Positional arguments:\n");
  fprintf(stderr, "%s", "\tconfig\tthe configuration file to use\n");
  fprintf(stderr, "%s", "\tguild_id\tthe id of the guild to get the welcome screen of\n");

  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
  const char* config_file;

  if (argc == 1) {
    print_usage();
  }
  else if (argc > 1) {
    config_file = argv[1];
  } else {
    config_file = "../config.json";
  }

  int index;
  ORCAcode response;
  struct discord *client = discord_config_init(config_file);
  struct discord_welcome_screen screen = {0};

  response = discord_get_guild_welcome_screen(client, strtoul(argv[2], NULL, 10), &screen);

  if (response != ORCA_OK) {
    printf("Something went wrong when fetching the guild's welcome screen. (%i)\n", response);
    printf("Full error message: %s\n", discord_strerror(response, client));
    exit(EXIT_FAILURE);
  }
  
  for (index = 0; screen.welcome_channels[index] != NULL; index++) {
    printf("Channel id in welcome screen: %li\n", screen.welcome_channels[index]->channel_id);
  }

  discord_welcome_screen_cleanup(&screen);

  return 0;
}

