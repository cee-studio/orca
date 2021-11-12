#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "discord.h"
#include "cee-utils.h"

void on_ready(struct discord *client, const struct discord_user *me)
{
  log_info("Succesfully connected to Discord as %s#%s!", me->username,
           me->discriminator);
}

void on_disconnect(struct discord *client,
                   const struct discord_user *bot,
                   const struct discord_message *msg)
{
  if (msg->author->bot) return;

  struct discord_create_message_params params = {
    .content = "Disconnecting ...",
  };
  discord_create_message(client, msg->channel_id, &params, NULL);

  discord_shutdown(client);
}

void on_spam(struct discord *client,
             const struct discord_user *bot,
             const struct discord_message *msg)
{
  if (msg->author->bot) return;

  char number[32];
  for (int i = 0; i < 10; ++i) {
    snprintf(number, sizeof(number), "%d", i);
    discord_create_message(client, msg->channel_id,
                           &(struct discord_create_message_params){
                             .content = number,
                           },
                           NULL);
  }
}

void on_force_error(struct discord *client,
                    const struct discord_user *bot,
                    const struct discord_message *msg)
{
  if (msg->author->bot) return;

  ORCAcode code = discord_delete_channel(client, 123, NULL);
  struct discord_create_message_params params = {
    .content = (char *)discord_strerror(code, client)
  };
  discord_create_message(client, msg->channel_id, &params, NULL);
}

void on_ping(struct discord *client,
             const struct discord_user *bot,
             const struct discord_message *msg)
{
  if (msg->author->bot) return;

  char text[256];
  sprintf(text, "Ping: %d", discord_get_ping(client));
  struct discord_create_message_params params = { .content = text };
  discord_create_message(client, msg->channel_id, &params, NULL);
}

int main(int argc, char *argv[])
{
  const char *config_file;
  if (argc > 1)
    config_file = argv[1];
  else
    config_file = "../config.json";

  discord_global_init();
  struct discord *client = discord_config_init(config_file);
  assert(NULL != client && "Couldn't initialize client");

  discord_set_prefix(client, "!");
  discord_set_on_ready(client, &on_ready);
  discord_set_on_command(client, "disconnect", &on_disconnect);
  discord_set_on_command(client, "spam", &on_spam);
  discord_set_on_command(client, "force_error", &on_force_error);
  discord_set_on_command(client, "ping", &on_ping);

  discord_run(client);

  discord_cleanup(client);
  discord_global_cleanup();
}
