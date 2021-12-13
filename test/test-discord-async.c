#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* strcmp() */
#include <pthread.h>
#include <assert.h>

#include "discord.h"
#include "discord-internal.h"

#include "cee-utils.h"
#include "json-actor.h" /* json_extract() */

struct user_cxt {
  u64_snowflake_t channel_id;
  unsigned long long counter;
};

void on_ready(struct discord *client)
{
  const struct discord_user *bot = discord_get_self(client);

  log_info("Succesfully connected to Discord as %s#%s!", bot->username,
           bot->discriminator);
}

void disconnect(struct discord *client, const void *obj)
{
  discord_shutdown(client);
}

void reconnect(struct discord *client, const void *obj)
{
  discord_reconnect(client, true);
}

void on_disconnect(struct discord *client, const struct discord_message *msg)
{
  if (msg->author->bot) return;

  struct discord_async_attr attr = { .done = &disconnect, .high_p = true };
  struct discord_create_message_params params = { .content =
                                                    "Disconnecting ..." };

  discord_adapter_set_async(&client->adapter, &attr);
  discord_create_message(client, msg->channel_id, &params, NULL);
}

void on_reconnect(struct discord *client, const struct discord_message *msg)
{
  if (msg->author->bot) return;

  struct discord_async_attr attr = { .done = &reconnect, .high_p = true };
  struct discord_create_message_params params = { .content =
                                                    "Reconnecting ..." };

  discord_adapter_set_async(&client->adapter, &attr);
  discord_create_message(client, msg->channel_id, &params, NULL);
}

void on_single(struct discord *client, const struct discord_message *msg)
{
  if (msg->author->bot) return;

  struct discord_create_message_params params = { .content = "Hello" };
  discord_create_message_async(client, msg->channel_id, &params, NULL);
}

void send_batch(struct discord *client, const struct discord_message *msg)
{
  struct discord_create_message_params params = { 0 };
  char text[32];

  params.content = text;
  for (int i = 0; i < 128; ++i) {
    snprintf(text, sizeof(text), "%d", i);
    discord_create_message_async(client, msg->channel_id, &params, NULL);
  }

  params.content = "CHECKPOINT";
  discord_create_message_async(client, msg->channel_id, &params, &send_batch);
}

void on_spam(struct discord *client, const struct discord_message *msg)
{
  if (msg->author->bot) return;

  send_batch(client, msg);
}

void send_msg(struct discord *client, const struct discord_message *msg)
{
  struct discord_create_message_params params = { 0 };
  struct user_cxt *cxt = discord_get_data(client);
  char text[32];

  snprintf(text, sizeof(text), "%llu", cxt->counter);

  params.content = text;
  discord_create_message_async(client, msg->channel_id, &params, &send_msg);

  ++cxt->counter;
}

void on_spam_ordered(struct discord *client, const struct discord_message *msg)
{
  if (msg->author->bot) return;

  send_msg(client, msg);
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

  struct user_cxt cxt = { 0 };
  discord_set_data(client, &cxt);

  discord_set_on_ready(client, &on_ready);

  discord_set_prefix(client, "!");
  discord_set_on_command(client, "disconnect", &on_disconnect);
  discord_set_on_command(client, "reconnect", &on_reconnect);
  discord_set_on_command(client, "single", &on_single);
  discord_set_on_command(client, "spam", &on_spam);
  discord_set_on_command(client, "spam-ordered", &on_spam_ordered);

  discord_run(client);

  discord_cleanup(client);
  discord_global_cleanup();
}
