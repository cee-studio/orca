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
  struct ua_resp_handle handle = {
    ret ? &discord_interaction_response_from_json_v : NULL, ret
  };
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

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_POST,
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
  struct ua_resp_handle handle = { &discord_interaction_response_from_json_v,
                                   ret };

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

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
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
  struct ua_resp_handle handle = {
    ret ? &discord_interaction_response_from_json_v : NULL,
    ret,
  };
  struct sized_buffer body;
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
#if 0
    /* content-type is multipart/form-data */
    void *cxt[2] = { params->attachments, &body };
    ORCAcode code;

    ua_reqheader_add(client->adapter.ua, "Content-Type",
                     "multipart/form-data");
    ua_curl_mime_setopt(client->adapter.ua, &cxt, &_discord_params_to_mime);

    code = discord_adapter_run(&client->adapter, &handle, NULL, HTTP_MIMEPOST,
                               "/webhooks/%" PRIu64 "/%s/messages/@original",
                               interaction_id, interaction_token);

    ua_reqheader_add(client->adapter.ua, "Content-Type", "application/json");

    return code;
#endif
  }

  /* content-type is application/json */
  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_POST,
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
  struct ua_resp_handle resp_handle = {
    ret ? &discord_webhook_from_json_v : NULL,
    ret,
  };
  struct sized_buffer body;
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
#if 0
    /* content-type is multipart/form-data */
    void *cxt[2] = { params->attachments, &body };
    ORCAcode code;

    ua_reqheader_add(client->adapter.ua, "Content-Type",
                     "multipart/form-data");
    ua_curl_mime_setopt(client->adapter.ua, &cxt, &_discord_params_to_mime);

    code =
      discord_adapter_run(&client->adapter, &resp_handle, NULL, HTTP_MIMEPOST,
                          "/webhooks/%" PRIu64 "/%s%s%s", application_id,
                          interaction_token, *query ? "?" : "", query);

    ua_reqheader_add(client->adapter.ua, "Content-Type", "application/json");

    return code;
#endif
  }

  /* content-type is application/json */
  return discord_adapter_run(&client->adapter, &resp_handle, &body, HTTP_POST,
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
  struct ua_resp_handle handle = { &discord_message_from_json_v, ret };

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

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
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
  struct ua_resp_handle resp_handle = {
    ret ? &discord_message_from_json_v : NULL,
    ret,
  };
  struct sized_buffer body;
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

  if (!params->attachments) {
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
                          application_id, interaction_token, message_id);

    ua_reqheader_add(client->adapter.ua, "Content-Type", "application/json");

    return code;
#endif
  }

  /* content-type is application/json */
  return discord_adapter_run(&client->adapter, &resp_handle, &body, HTTP_POST,
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
