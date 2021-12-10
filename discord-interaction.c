#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "discord.h"
#include "discord-internal.h"
#include "cee-utils.h"

ORCAcode
discord_create_interaction_response(
  struct discord *client,
  const u64_snowflake_t interaction_id,
  const char interaction_token[],
  struct discord_interaction_response *params,
  struct discord_interaction_response *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_interaction_response, ret);
  struct sized_buffer body;
  char buf[4096];

  if (!interaction_id) {
    logconf_error(&client->conf, "Missing 'interaction_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(interaction_token)) {
    logconf_error(&client->conf, "Missing 'interaction_token'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_interaction_response_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                             "/interactions/%" PRIu64 "/%s/callback",
                             interaction_id, interaction_token);
}

ORCAcode
discord_get_original_interaction_response(
  struct discord *client,
  const u64_snowflake_t interaction_id,
  const char interaction_token[],
  struct discord_interaction_response *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_interaction_response, ret);

  if (!interaction_id) {
    logconf_error(&client->conf, "Missing 'interaction_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(interaction_token)) {
    logconf_error(&client->conf, "Missing 'interaction_token'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/webhooks/%" PRIu64 "/%s/messages/@original",
                             interaction_id, interaction_token);
}

ORCAcode
discord_edit_original_interaction_response(
  struct discord *client,
  const u64_snowflake_t interaction_id,
  const char interaction_token[],
  struct discord_edit_original_interaction_response_params *params,
  struct discord_interaction_response *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_interaction_response, ret);
  struct sized_buffer body;
  enum http_method method;
  char buf[16384]; /**< @todo dynamic buffer */

  if (!interaction_id) {
    logconf_error(&client->conf, "Missing 'interaction_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(interaction_token)) {
    logconf_error(&client->conf, "Missing 'interaction_token'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_edit_original_interaction_response_params_to_json(
    buf, sizeof(buf), params);
  body.start = buf;

  if (params->attachments) {
    method = HTTP_MIMEPOST;
    attr.attachments = params->attachments;
  }
  else {
    method = HTTP_POST;
  }

  return discord_adapter_run(&client->adapter, &attr, &body, method,
                             "/webhooks/%" PRIu64 "/%s/messages/@original",
                             interaction_id, interaction_token);
}

ORCAcode
discord_delete_original_interaction_response(
  struct discord *client,
  const u64_snowflake_t interaction_id,
  const char interaction_token[])
{
  if (!interaction_id) {
    logconf_error(&client->conf, "Missing 'interaction_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(interaction_token)) {
    logconf_error(&client->conf, "Missing 'interaction_token'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/webhooks/%" PRIu64 "/%s/messages/@original",
                             interaction_id, interaction_token);
}

ORCAcode
discord_create_followup_message(
  struct discord *client,
  const u64_snowflake_t application_id,
  const char interaction_token[],
  struct discord_create_followup_message_params *params,
  struct discord_webhook *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_webhook, ret);
  struct sized_buffer body;
  enum http_method method;
  char buf[16384]; /**< @todo dynamic buffer */
  char query[4096] = "";

  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(interaction_token)) {
    logconf_error(&client->conf, "Missing 'interaction_token'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

  if (params->thread_id) {
    size_t ret;

    ret =
      snprintf(query, sizeof(query), "thread_id=%" PRIu64, params->thread_id);
    ASSERT_S(ret < sizeof(query), "Out of bounds write attempt");
  }

  body.size =
    discord_create_followup_message_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  if (params->attachments) {
    method = HTTP_MIMEPOST;
    attr.attachments = params->attachments;
  }
  else {
    method = HTTP_POST;
  }

  return discord_adapter_run(&client->adapter, &attr, &body, method,
                             "/webhooks/%" PRIu64 "/%s%s%s", application_id,
                             interaction_token, *query ? "?" : "", query);
}

ORCAcode
discord_get_followup_message(struct discord *client,
                             const u64_snowflake_t application_id,
                             const char interaction_token[],
                             const u64_snowflake_t message_id,
                             struct discord_message *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_message, ret);

  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(interaction_token)) {
    logconf_error(&client->conf, "Missing 'interaction_token'");
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

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/webhooks/%" PRIu64 "/%s/%" PRIu64,
                             application_id, interaction_token, message_id);
}

ORCAcode
discord_edit_followup_message(
  struct discord *client,
  const u64_snowflake_t application_id,
  const char interaction_token[],
  const u64_snowflake_t message_id,
  struct discord_edit_followup_message_params *params,
  struct discord_message *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_message, ret);
  struct sized_buffer body;
  enum http_method method;
  char buf[16384]; /**< @todo dynamic buffer */

  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(interaction_token)) {
    logconf_error(&client->conf, "Missing 'interaction_token'");
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
    discord_edit_followup_message_params_to_json(buf, sizeof(buf), params);
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
                             application_id, interaction_token, message_id);
}

ORCAcode
discord_delete_followup_message(struct discord *client,
                                const u64_snowflake_t application_id,
                                const char interaction_token[],
                                const u64_snowflake_t message_id)
{
  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(interaction_token)) {
    logconf_error(&client->conf, "Missing 'interaction_token'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!message_id) {
    logconf_error(&client->conf, "Missing 'message_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/webhooks/%" PRIu64 "/%s/messages/%" PRIu64,
                             application_id, interaction_token, message_id);
}
