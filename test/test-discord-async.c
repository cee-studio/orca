#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* strcmp() */
#include <pthread.h>
#include <assert.h>

#include "discord.h"
#include "cee-utils.h"
#include "json-actor.h" /* json_extract() */

void
on_ready(struct discord *client, const struct discord_user *me)
{
  log_info("Succesfully connected to Discord as %s#%s!", me->username,
           me->discriminator);
}

void
shutdown(struct discord *client,
         const struct discord_user *bot,
         const void *p_obj,
         ORCAcode code)
{
  discord_shutdown(client);
}

void
on_disconnect(struct discord *client,
              const struct discord_user *bot,
              const struct discord_message *msg)
{
  if (msg->author->bot) return;

  discord_create_message(discord_set_async(client,
                                           &(struct discord_async_attr){
                                             .callback = &shutdown,
                                             .high_priority = true,
                                           }),
                         msg->channel_id,
                         &(struct discord_create_message_params){
                           .content = "Disconnecting ...",
                         },
                         NULL);
}

void
send_msg(struct discord *client,
         const struct discord_user *bot,
         const void *p_obj,
         ORCAcode code)
{
  log_trace("SUCCESS!");
}

void
on_ping(struct discord *client,
        const struct discord_user *bot,
        const struct discord_message *msg)
{
  if (msg->author->bot) return;

  char text[256];
  sprintf(text, "Ping: %d", discord_get_ping(client));
  discord_create_message(discord_set_async(client,
                                           &(struct discord_async_attr){
                                             .callback = &send_msg,
                                           }),
                         msg->channel_id,
                         &(struct discord_create_message_params){
                           .content = text,
                         },
                         NULL);
}

void
on_spam1(struct discord *client,
         const struct discord_user *bot,
         const struct discord_message *msg)
{
  if (msg->author->bot) return;

  char text[32];
  for (int i = 0; i < 2; ++i) {
    snprintf(text, sizeof(text), "%d", i);
    discord_create_message(client, msg->channel_id,
                           &(struct discord_create_message_params){
                             .content = text,
                           },
                           NULL);
  }
}

void
on_spam2(struct discord *client,
         const struct discord_user *bot,
         const struct discord_message *msg)
{
  if (msg->author->bot) return;

  char text[32];
  for (int i = 0; i < 1024; ++i) {
    snprintf(text, sizeof(text), "%d", i);
    discord_create_message(discord_set_async(client,
                                             &(struct discord_async_attr){
                                               .callback = &send_msg,
                                             }),
                           msg->channel_id,
                           &(struct discord_create_message_params){
                             .content = text,
                           },
                           NULL);
  }
}

int
main(int argc, char *argv[])
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
  discord_set_on_command(client, "ping", &on_ping);
  discord_set_on_command(client, "spam1", &on_spam1);
  discord_set_on_command(client, "spam2", &on_spam2);

  discord_run(client);

  discord_cleanup(client);
  discord_global_cleanup();
}
