#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "discord.h"
#include "discord-internal.h"
#include "cee-utils.h"

ORCAcode
discord_create_webhook(struct discord *client,
                       const u64_snowflake_t channel_id,
                       struct discord_create_webhook_params *params,
                       struct discord_webhook *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_webhook, ret);
  struct sized_buffer body;
  char buf[1024];

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->name), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  body.size = discord_create_webhook_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                             "/channels/%" PRIu64 "/webhooks", channel_id);
}

ORCAcode
discord_get_channel_webhooks(struct discord *client,
                             const u64_snowflake_t channel_id,
                             struct discord_webhook ***ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_LIST_INIT(discord_webhook, ret);

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/channels/%" PRIu64 "/webhooks", channel_id);
}

ORCAcode
discord_get_guild_webhooks(struct discord *client,
                           const u64_snowflake_t guild_id,
                           struct discord_webhook ***ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_LIST_INIT(discord_webhook, ret);

  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/webhooks", guild_id);
}

ORCAcode
discord_get_webhook(struct discord *client,
                    const u64_snowflake_t webhook_id,
                    struct discord_webhook *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_webhook, ret);

  ORCA_EXPECT(client, webhook_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/webhooks/%" PRIu64, webhook_id);
}

ORCAcode
discord_get_webhook_with_token(struct discord *client,
                               const u64_snowflake_t webhook_id,
                               const char webhook_token[],
                               struct discord_webhook *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_webhook, ret);

  ORCA_EXPECT(client, webhook_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(webhook_token), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/webhooks/%" PRIu64 "/%s", webhook_id,
                             webhook_token);
}

ORCAcode
discord_modify_webhook(struct discord *client,
                       const u64_snowflake_t webhook_id,
                       struct discord_modify_webhook_params *params,
                       struct discord_webhook *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_webhook, ret);
  struct sized_buffer body;
  char buf[1024];

  ORCA_EXPECT(client, webhook_id != 0, ORCA_BAD_PARAMETER);

  body.size = discord_modify_webhook_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_PATCH,
                             "/webhooks/%" PRIu64, webhook_id);
}

ORCAcode
discord_modify_webhook_with_token(
  struct discord *client,
  const u64_snowflake_t webhook_id,
  const char webhook_token[],
  struct discord_modify_webhook_with_token_params *params,
  struct discord_webhook *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_webhook, ret);
  struct sized_buffer body;
  char buf[1024];

  ORCA_EXPECT(client, webhook_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(webhook_token), ORCA_BAD_PARAMETER);

  body.size =
    discord_modify_webhook_with_token_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_PATCH,
                             "/webhooks/%" PRIu64 "/%s", webhook_id,
                             webhook_token);
}

ORCAcode
discord_delete_webhook(struct discord *client,
                       const u64_snowflake_t webhook_id)
{
  ORCA_EXPECT(client, webhook_id != 0, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/webhooks/%" PRIu64, webhook_id);
}

ORCAcode
discord_delete_webhook_with_token(struct discord *client,
                                  const u64_snowflake_t webhook_id,
                                  const char webhook_token[])
{
  ORCA_EXPECT(client, webhook_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(webhook_token), ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/webhooks/%" PRIu64 "/%s", webhook_id,
                             webhook_token);
}

ORCAcode
discord_execute_webhook(struct discord *client,
                        const u64_snowflake_t webhook_id,
                        const char webhook_token[],
                        struct discord_execute_webhook_params *params,
                        struct discord_webhook *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_webhook, ret);
  struct sized_buffer body;
  enum http_method method;
  char buf[16384]; /**< @todo dynamic buffer */
  char query[4096] = "";
  size_t len = 0;

  ORCA_EXPECT(client, webhook_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(webhook_token), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);

  if (params->wait) {
    len = snprintf(query, sizeof(query), "wait=1");
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }
  if (params->thread_id) {
    len += snprintf(query + len, sizeof(query) - len, "%sthread_id=%" PRIu64,
                    len ? "&" : "", params->thread_id);
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }

  body.size = discord_execute_webhook_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  if (params->attachments) {
    method = HTTP_MIMEPOST;
    attr.attachments = params->attachments;
  }
  else {
    method = HTTP_POST;
  }

  return discord_adapter_run(&client->adapter, &attr, &body, method,
                             "/webhooks/%" PRIu64 "/%s%s%s", webhook_id,
                             webhook_token, *query ? "?" : "", query);
}

ORCAcode
discord_get_webhook_message(struct discord *client,
                            const u64_snowflake_t webhook_id,
                            const char webhook_token[],
                            const u64_snowflake_t message_id,
                            struct discord_message *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_message, ret);

  ORCA_EXPECT(client, webhook_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(webhook_token), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, message_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/webhooks/%" PRIu64 "/%s/%" PRIu64, webhook_id,
                             webhook_token, message_id);
}

ORCAcode
discord_edit_webhook_message(
  struct discord *client,
  const u64_snowflake_t webhook_id,
  const char webhook_token[],
  const u64_snowflake_t message_id,
  struct discord_edit_webhook_message_params *params,
  struct discord_message *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_message, ret);
  struct sized_buffer body;
  enum http_method method;
  char buf[16384]; /**< @todo dynamic buffer */

  ORCA_EXPECT(client, webhook_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(webhook_token), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, message_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);

  body.size =
    discord_edit_webhook_message_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  if (params->attachments) {
    method = HTTP_MIMEPOST;
    attr.attachments = params->attachments;
  }
  else {
    method = HTTP_POST;
  }

  return discord_adapter_run(&client->adapter, &attr, &body, method,
                             "/webhooks/%" PRIu64 "/%s/messages/%" PRIu64,
                             webhook_id, webhook_token, message_id);
}

ORCAcode
discord_delete_webhook_message(struct discord *client,
                               const u64_snowflake_t webhook_id,
                               const char webhook_token[],
                               const u64_snowflake_t message_id)
{
  ORCA_EXPECT(client, webhook_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(webhook_token), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, message_id != 0, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/webhooks/%" PRIu64 "/%s/messages/%" PRIu64,
                             webhook_id, webhook_token, message_id);
}
