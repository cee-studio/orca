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
  struct ua_resp_handle handle = { &discord_webhook_from_json_v, ret };
  struct sized_buffer body;
  char buf[1024];

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params || IS_EMPTY_STRING(params->name)) {
    logconf_error(&client->conf, "Missing 'params.name'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_create_webhook_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_POST,
                             "/channels/%" PRIu64 "/webhooks", channel_id);
}

ORCAcode
discord_get_channel_webhooks(struct discord *client,
                             const u64_snowflake_t channel_id,
                             struct discord_webhook ***ret)
{
  struct ua_resp_handle handle = { &discord_webhook_list_from_json_v, ret };

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/channels/%" PRIu64 "/webhooks", channel_id);
}

ORCAcode
discord_get_guild_webhooks(struct discord *client,
                           const u64_snowflake_t guild_id,
                           struct discord_webhook ***ret)
{
  struct ua_resp_handle handle = { &discord_webhook_list_from_json_v, ret };

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/webhooks", guild_id);
}

ORCAcode
discord_get_webhook(struct discord *client,
                    const u64_snowflake_t webhook_id,
                    struct discord_webhook *ret)
{
  struct ua_resp_handle handle = { &discord_webhook_from_json_v, ret };

  if (!webhook_id) {
    logconf_error(&client->conf, "Missing 'webhook_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/webhooks/%" PRIu64, webhook_id);
}

ORCAcode
discord_get_webhook_with_token(struct discord *client,
                               const u64_snowflake_t webhook_id,
                               const char webhook_token[],
                               struct discord_webhook *ret)
{
  struct ua_resp_handle handle = { &discord_webhook_from_json_v, ret };

  if (!webhook_id) {
    logconf_error(&client->conf, "Missing 'webhook_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(webhook_token)) {
    logconf_error(&client->conf, "Missing 'webhook_token'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/webhooks/%" PRIu64 "/%s", webhook_id,
                             webhook_token);
}

ORCAcode
discord_modify_webhook(struct discord *client,
                       const u64_snowflake_t webhook_id,
                       struct discord_modify_webhook_params *params,
                       struct discord_webhook *ret)
{
  struct ua_resp_handle handle = { &discord_webhook_from_json_v, ret };
  struct sized_buffer body;
  char buf[1024];

  if (!webhook_id) {
    logconf_error(&client->conf, "Missing 'webhook_id'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_modify_webhook_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_PATCH,
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
  struct ua_resp_handle handle = { &discord_webhook_from_json_v, ret };
  struct sized_buffer body;
  char buf[1024];

  if (!webhook_id) {
    logconf_error(&client->conf, "Missing 'webhook_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(webhook_token)) {
    logconf_error(&client->conf, "Missing 'webhook_token'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size =
    discord_modify_webhook_with_token_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_PATCH,
                             "/webhooks/%" PRIu64 "/%s", webhook_id,
                             webhook_token);
}

ORCAcode
discord_delete_webhook(struct discord *client,
                       const u64_snowflake_t webhook_id)
{
  if (!webhook_id) {
    logconf_error(&client->conf, "Missing 'webhook_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/webhooks/%" PRIu64, webhook_id);
}

ORCAcode
discord_delete_webhook_with_token(struct discord *client,
                                  const u64_snowflake_t webhook_id,
                                  const char webhook_token[])
{
  if (!webhook_id) {
    logconf_error(&client->conf, "Missing 'webhook_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(webhook_token)) {
    logconf_error(&client->conf, "Missing 'webhook_token'");
    return ORCA_MISSING_PARAMETER;
  }

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
  struct ua_resp_handle resp_handle = {
    ret ? &discord_webhook_from_json_v : NULL,
    ret,
  };
  struct sized_buffer body;
  char buf[16384]; /**< @todo dynamic buffer */
  char query[4096] = "";
  size_t len = 0;

  if (!webhook_id) {
    logconf_error(&client->conf, "Missing 'webhook_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(webhook_token)) {
    logconf_error(&client->conf, "Missing 'webhook_token'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

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
#if 0
    /* content-type is multipart/form-data */
    void *cxt[2] = { params->attachments, &body };
    ORCAcode code;

    ua_reqheader_add(client->adapter.ua, "Content-Type",
                     "multipart/form-data");
    ua_curl_mime_setopt(client->adapter.ua, &cxt, &_discord_params_to_mime);

    code =
      discord_adapter_run(&client->adapter, &resp_handle, NULL, HTTP_MIMEPOST,
                          "/webhooks/%" PRIu64 "/%s%s%s", webhook_id,
                          webhook_token, *query ? "?" : "", query);

    ua_reqheader_add(client->adapter.ua, "Content-Type", "application/json");

    return code;
#endif
  }

  /* content-type is application/json */
  return discord_adapter_run(&client->adapter, &resp_handle, &body, HTTP_POST,
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
  struct ua_resp_handle handle = { &discord_message_from_json_v, ret };

  if (!webhook_id) {
    logconf_error(&client->conf, "Missing 'webhook_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(webhook_token)) {
    logconf_error(&client->conf, "Missing 'webhook_token'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!message_id) {
    logconf_error(&client->conf, "Missing 'message_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
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

  struct ua_resp_handle resp_handle = {
    ret ? &discord_message_from_json_v : NULL,
    ret,
  };
  struct sized_buffer body;
  char buf[16384]; /**< @todo dynamic buffer */

  if (!webhook_id) {
    logconf_error(&client->conf, "Missing 'webhook_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(webhook_token)) {
    logconf_error(&client->conf, "Missing 'webhook_token'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!message_id) {
    logconf_error(&client->conf, "Missing 'message_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size =
    discord_edit_webhook_message_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  if (params->attachments) {
#if 0
    /* content-type is multipart/form-data */
    void *cxt[2] = { params->attachments, &body };
    ORCAcode code;

    ua_reqheader_add(client->adapter.ua, "Content-Type",
                     "multipart/form-data");
    ua_curl_mime_setopt(client->adapter.ua, &cxt, &_discord_params_to_mime);

    code =
      discord_adapter_run(&client->adapter, &resp_handle, NULL, HTTP_MIMEPOST,
                          "/webhooks/%" PRIu64 "/%s/messages/%" PRIu64,
                          webhook_id, webhook_token, message_id);

    ua_reqheader_add(client->adapter.ua, "Content-Type", "application/json");

    return code;
#endif
  }

  /* content-type is application/json */
  return discord_adapter_run(&client->adapter, &resp_handle, &body, HTTP_POST,
                             "/webhooks/%" PRIu64 "/%s/messages/%" PRIu64,
                             webhook_id, webhook_token, message_id);
}

ORCAcode
discord_delete_webhook_message(struct discord *client,
                               const u64_snowflake_t webhook_id,
                               const char webhook_token[],
                               const u64_snowflake_t message_id)
{
  if (!webhook_id) {
    logconf_error(&client->conf, "Missing 'webhook_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(webhook_token)) {
    logconf_error(&client->conf, "Missing 'webhook_token'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!message_id) {
    logconf_error(&client->conf, "Missing 'message_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/webhooks/%" PRIu64 "/%s/messages/%" PRIu64,
                             webhook_id, webhook_token, message_id);
}
