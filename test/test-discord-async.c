#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* strcmp() */
#include <pthread.h>
#include <assert.h>

#include "discord.h"
#include "cee-utils.h"
#include "json-actor.h" /* json_extract() */

struct user_data {
  u64_snowflake_t channel_id;
  unsigned long long counter;
};

void on_ready(struct discord *client, const struct discord_user *me)
{
  log_info("Succesfully connected to Discord as %s#%s!", me->username,
           me->discriminator);
}

void shutdown(struct discord_context *cxt, const char buf[], const size_t len)
{
  discord_shutdown(cxt->client);
}

void on_disconnect(struct discord *client,
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

void reconnect(struct discord_context *cxt, const char buf[], const size_t len)
{
  discord_reconnect(cxt->client, true);
}

void on_reconnect(struct discord *client,
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

void send_batch(struct discord_context *cxt,
                const char buf[],
                const size_t len)
{
  struct user_data *data = discord_get_data(cxt->client);
  char text[32];

  for (int i = 0; i < 128; ++i) {
    snprintf(text, sizeof(text), "%d", i);
    discord_create_message(discord_set_async(client, NULL), data->channel_id,
                           &(struct discord_create_message_params){
                             .content = text,
                           },
                           NULL);
  }

  discord_create_message(discord_set_async(client,
                                           &(struct discord_async_attr){
                                             .callback = &send_batch,
                                           }),
                         data->channel_id,
                         &(struct discord_create_message_params){
                           .content = "CHECKPOINT",
                         },
                         NULL);
}

void on_spam(struct discord *client,
             const struct discord_user *bot,
             const struct discord_message *msg)
{
  if (msg->author->bot) return;

  struct user_data *data = discord_get_data(client);
  data->channel_id = msg->channel_id;

  send_batch(client, bot, NULL, 0, ORCA_OK);
}

void send_msg(struct discord_context *cxt, const char buf[], const size_t len)
{
  char text[32];
  struct user_data *data = discord_get_data(cxt->client);

  snprintf(text, sizeof(text), "%llu", data->counter);

  discord_create_message(discord_set_async(client,
                                           &(struct discord_async_attr){
                                             .callback = &send_msg,
                                           }),
                         data->channel_id,
                         &(struct discord_create_message_params){
                           .content = text,
                         },
                         NULL);

  ++data->counter;
}

void on_spam_ordered(struct discord *client,
                     const struct discord_user *bot,
                     const struct discord_message *msg)
{
  if (msg->author->bot) return;

  /* TODO: trigger via timeout function */
  struct user_data *data = discord_get_data(client);
  data->channel_id = msg->channel_id;
  send_msg(client, bot, NULL, 0, ORCA_OK);
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

  struct user_data data = { 0 };
  discord_set_data(client, &data);

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
