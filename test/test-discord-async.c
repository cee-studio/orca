#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* strcmp() */
#include <pthread.h>
#include <assert.h>

#include "discord.h"
#include "cee-utils.h"
#include "json-actor.h" /* json_extract() */

struct spam_cxt {
  u64_snowflake_t channel_id;
  unsigned long long counter;
};

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
reconnect(struct discord *client,
          const struct discord_user *bot,
          const void *p_obj,
          ORCAcode code)
{
  discord_reconnect(client, true);
}

void
on_reconnect(struct discord *client,
             const struct discord_user *bot,
             const struct discord_message *msg)
{
  if (msg->author->bot) return;

  discord_create_message(discord_set_async(client,
                                           &(struct discord_async_attr){
                                             .callback = &reconnect,
                                             .high_priority = true,
                                           }),
                         msg->channel_id,
                         &(struct discord_create_message_params){
                           .content = "Reconnecting ...",
                         },
                         NULL);
}

void checkpoint(struct discord *client,
                const struct discord_user *bot,
                const void *p_obj,
                ORCAcode code)
{
  log_trace("SUCCESS!");
}

void on_spam(struct discord *client,
             const struct discord_user *bot,
             const struct discord_message *msg)
{
  if (msg->author->bot) return;

  char text[32];
  for (int i = 0; i < 100; ++i) {
    snprintf(text, sizeof(text), "%d", i);
    discord_create_message(discord_set_async(client,
                                             &(struct discord_async_attr){
                                               .callback = &checkpoint,
                                             }),
                           msg->channel_id,
                           &(struct discord_create_message_params){
                             .content = text,
                           },
                           NULL);
  }
}

void send_msg(struct discord *client,
              const struct discord_user *bot,
              const void *p_obj,
              ORCAcode code)
{
  char text[32];
  struct spam_cxt *cxt = discord_get_data(client);

  snprintf(text, sizeof(text), "%llu", cxt->counter);

  discord_create_message(discord_set_async(client,
                                           &(struct discord_async_attr){
                                             .callback = &send_msg,
                                           }),
                         cxt->channel_id,
                         &(struct discord_create_message_params){
                           .content = text,
                         },
                         NULL);

  ++cxt->counter;
}

void on_spam_ordered(struct discord *client,
                     const struct discord_user *bot,
                     const struct discord_message *msg)
{
  if (msg->author->bot) return;

  /* TODO: trigger via timeout function */
  struct spam_cxt *cxt = discord_get_data(client);
  cxt->channel_id = msg->channel_id;
  send_msg(client, bot, NULL, ORCA_OK);
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

  struct spam_cxt cxt = { 0 };
  discord_set_data(client, &cxt);

  discord_set_on_ready(client, &on_ready);

  discord_set_prefix(client, "!");
  discord_set_on_command(client, "disconnect", &on_disconnect);
  discord_set_on_command(client, "reconnect", &on_reconnect);
  discord_set_on_command(client, "spam", &on_spam);
  discord_set_on_command(client, "spam-ordered", &on_spam_ordered);

  discord_run(client);

  discord_cleanup(client);
  discord_global_cleanup();
}
