#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "discord.h"
#include "discord-internal.h"
#include "cee-utils.h"

ORCAcode
discord_get_channel(struct discord *client,
                    const u64_snowflake_t channel_id,
                    struct discord_channel *ret)
{
  struct ua_resp_handle handle = { &discord_channel_from_json_v, ret };

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/channels/%" PRIu64, channel_id);
}

ORCAcode
discord_modify_channel(struct discord *client,
                       const u64_snowflake_t channel_id,
                       struct discord_modify_channel_params *params,
                       struct discord_channel *ret)
{
  struct ua_resp_handle handle = { ret ? &discord_channel_from_json_v : NULL,
                                   ret };
  struct sized_buffer body;
  char buf[1024];

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_modify_channel_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_PATCH,
                             "/channels/%" PRIu64, channel_id);
}

ORCAcode
discord_delete_channel(struct discord *client,
                       const u64_snowflake_t channel_id,
                       struct discord_channel *ret)
{
  struct ua_resp_handle handle = { ret ? &discord_channel_from_json_v : NULL,
                                   ret };

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_DELETE,
                             "/channels/%" PRIu64, channel_id);
}

ORCAcode
discord_get_channel_messages(
  struct discord *client,
  const u64_snowflake_t channel_id,
  struct discord_get_channel_messages_params *params,
  struct discord_message ***ret)
{
  struct ua_resp_handle handle = { &discord_message_list_from_json_v, ret };
  char query[1024] = "";

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  if (params) {
    size_t offset = 0;
    if (params->limit) {
      offset += snprintf(query + offset, sizeof(query) - offset, "limit=%d",
                         params->limit);
      ASSERT_S(offset < sizeof(query), "Out of bounds write attempt");
    }
    if (params->around) {
      offset +=
        snprintf(query + offset, sizeof(query) - offset, "%saround=%" PRIu64,
                 *query ? "&" : "", params->around);
      ASSERT_S(offset < sizeof(query), "Out of bounds write attempt");
    }
    if (params->before) {
      offset +=
        snprintf(query + offset, sizeof(query) - offset, "%sbefore=%" PRIu64,
                 *query ? "&" : "", params->before);
      ASSERT_S(offset < sizeof(query), "Out of bounds write attempt");
    }
    if (params->after) {
      offset += snprintf(query + offset, sizeof(query) - offset,
                         "%safter=%" PRIu64, *query ? "&" : "", params->after);
      ASSERT_S(offset < sizeof(query), "Out of bounds write attempt");
    }
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/channels/%" PRIu64 "/messages%s%s", channel_id,
                             *query ? "?" : "", query);
}

ORCAcode
discord_get_channel_message(struct discord *client,
                            const u64_snowflake_t channel_id,
                            const u64_snowflake_t message_id,
                            struct discord_message *ret)
{
  struct ua_resp_handle handle = { &discord_message_from_json_v, ret };

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
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
                             "/channels/%" PRIu64 "/messages/%" PRIu64,
                             channel_id, message_id);
}

ORCAcode
discord_create_message(struct discord *client,
                       const u64_snowflake_t channel_id,
                       struct discord_create_message_params *params,
                       struct discord_message *ret)
{
  struct ua_resp_handle handle = { ret ? &discord_message_from_json_v : NULL,
                                   ret };
  struct sized_buffer body;
  char buf[16384]; /**< @todo dynamic buffer */
  ORCAcode code;

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_create_message_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  if (!params->attachments) {
    /* content-type is application/json */
    code = discord_adapter_run(&client->adapter, &handle, &body, HTTP_POST,
                               "/channels/%" PRIu64 "/messages", channel_id);
  }
  else {
    /* content-type is multipart/form-data */
    void *cxt[2] = { params->attachments, &body };

    ua_curl_mime_setopt(client->adapter.ua, cxt, &_discord_params_to_mime);

    ua_reqheader_add(client->adapter.ua, "Content-Type",
                     "multipart/form-data");

    code = discord_adapter_run(&client->adapter, &handle, NULL, HTTP_MIMEPOST,
                               "/channels/%" PRIu64 "/messages", channel_id);

    ua_reqheader_add(client->adapter.ua, "Content-Type", "application/json");
  }

  return code;
}

ORCAcode
discord_crosspost_message(struct discord *client,
                          const u64_snowflake_t channel_id,
                          const u64_snowflake_t message_id,
                          struct discord_message *ret)
{
  struct ua_resp_handle handle = { ret ? &discord_message_from_json_v : NULL,
                                   ret };

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!message_id) {
    logconf_error(&client->conf, "Missing 'message_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_POST,
                             "/channels/%" PRIu64 "/messages/%" PRIu64
                             "/crosspost",
                             channel_id, message_id);
}

ORCAcode
discord_create_reaction(struct discord *client,
                        const u64_snowflake_t channel_id,
                        const u64_snowflake_t message_id,
                        const u64_snowflake_t emoji_id,
                        const char emoji_name[])
{
  char *pct_emoji_name;
  char emoji_endpoint[256];
  ORCAcode code;

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!message_id) {
    logconf_error(&client->conf, "Missing 'message_id'");
    return ORCA_MISSING_PARAMETER;
  }

  pct_emoji_name = emoji_name ? url_encode((char *)emoji_name) : NULL;

  if (emoji_id)
    snprintf(emoji_endpoint, sizeof(emoji_endpoint), "%s:%" PRIu64,
             pct_emoji_name, emoji_id);
  else
    snprintf(emoji_endpoint, sizeof(emoji_endpoint), "%s", pct_emoji_name);

  code = discord_adapter_run(&client->adapter, NULL, NULL, HTTP_PUT,
                             "/channels/%" PRIu64 "/messages/%" PRIu64
                             "/reactions/%s/@me",
                             channel_id, message_id, emoji_endpoint);

  free(pct_emoji_name);

  return code;
}

ORCAcode
discord_delete_own_reaction(struct discord *client,
                            const u64_snowflake_t channel_id,
                            const u64_snowflake_t message_id,
                            const u64_snowflake_t emoji_id,
                            const char emoji_name[])
{
  char *pct_emoji_name;
  char emoji_endpoint[256];
  ORCAcode code;

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!message_id) {
    logconf_error(&client->conf, "Missing 'message_id'");
    return ORCA_MISSING_PARAMETER;
  }

  pct_emoji_name = emoji_name ? url_encode((char *)emoji_name) : NULL;

  if (emoji_id)
    snprintf(emoji_endpoint, sizeof(emoji_endpoint), "%s:%" PRIu64,
             pct_emoji_name, emoji_id);
  else
    snprintf(emoji_endpoint, sizeof(emoji_endpoint), "%s", pct_emoji_name);

  code = discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/channels/%" PRIu64 "/messages/%" PRIu64
                             "/reactions/%s/@me",
                             channel_id, message_id, emoji_endpoint);

  free(pct_emoji_name);

  return code;
}

ORCAcode
discord_delete_user_reaction(struct discord *client,
                             const u64_snowflake_t channel_id,
                             const u64_snowflake_t message_id,
                             const u64_snowflake_t user_id,
                             const u64_snowflake_t emoji_id,
                             const char emoji_name[])
{
  char *pct_emoji_name;
  char emoji_endpoint[256];
  ORCAcode code;

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!message_id) {
    logconf_error(&client->conf, "Missing 'message_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!user_id) {
    logconf_error(&client->conf, "Missing 'user_id'");
    return ORCA_MISSING_PARAMETER;
  }

  pct_emoji_name = emoji_name ? url_encode((char *)emoji_name) : NULL;

  if (emoji_id)
    snprintf(emoji_endpoint, sizeof(emoji_endpoint), "%s:%" PRIu64,
             pct_emoji_name, emoji_id);
  else
    snprintf(emoji_endpoint, sizeof(emoji_endpoint), "%s", pct_emoji_name);

  code = discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/channels/%" PRIu64 "/messages/%" PRIu64
                             "/reactions/%s/%" PRIu64,
                             channel_id, message_id, emoji_endpoint, user_id);

  free(pct_emoji_name);

  return code;
}

ORCAcode
discord_get_reactions(struct discord *client,
                      u64_snowflake_t channel_id,
                      u64_snowflake_t message_id,
                      const u64_snowflake_t emoji_id,
                      const char emoji_name[],
                      struct discord_get_reactions_params *params,
                      struct discord_user ***ret)
{
  struct ua_resp_handle handle = { &discord_user_list_from_json_v, ret };
  char query[1024] = "";
  char emoji_endpoint[256];
  char *pct_emoji_name;
  ORCAcode code;

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
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

  if (params) {
    size_t len;

    if (params->limit <= 0 || params->limit > 100) {
      logconf_error(&client->conf, "'params.limit' should be between [1-100]");
      return ORCA_BAD_PARAMETER;
    }

    if (params->after) {
      len = query_inject(query, sizeof(query),
                         "(after):F"
                         "(limit):d",
                         &cee_u64tostr, &params->after, &params->limit);
    }
    else {
      len = query_inject(query, sizeof(query), "(limit):d", &params->limit);
    }
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }

  pct_emoji_name = emoji_name ? url_encode((char *)emoji_name) : NULL;

  if (emoji_id)
    snprintf(emoji_endpoint, sizeof(emoji_endpoint), "%s:%" PRIu64,
             pct_emoji_name, emoji_id);
  else
    snprintf(emoji_endpoint, sizeof(emoji_endpoint), "%s", pct_emoji_name);

  code = discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/channels/%" PRIu64 "/messages/%" PRIu64
                             "/reactions/%s%s",
                             channel_id, message_id, emoji_endpoint, query);

  free(pct_emoji_name);

  return code;
}

ORCAcode
discord_delete_all_reactions(struct discord *client,
                             u64_snowflake_t channel_id,
                             u64_snowflake_t message_id)
{
  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!message_id) {
    logconf_error(&client->conf, "Missing 'message_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/channels/%" PRIu64 "/messages/%" PRIu64
                             "/reactions",
                             channel_id, message_id);
}

ORCAcode
discord_delete_all_reactions_for_emoji(struct discord *client,
                                       const u64_snowflake_t channel_id,
                                       const u64_snowflake_t message_id,
                                       const u64_snowflake_t emoji_id,
                                       const char emoji_name[])
{
  char *pct_emoji_name;
  char emoji_endpoint[256];
  ORCAcode code;

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!message_id) {
    logconf_error(&client->conf, "Missing 'message_id'");
    return ORCA_MISSING_PARAMETER;
  }

  pct_emoji_name = emoji_name ? url_encode((char *)emoji_name) : NULL;

  if (emoji_id)
    snprintf(emoji_endpoint, sizeof(emoji_endpoint), "%s:%" PRIu64,
             pct_emoji_name, emoji_id);
  else
    snprintf(emoji_endpoint, sizeof(emoji_endpoint), "%s", pct_emoji_name);

  code = discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/channels/%" PRIu64 "/messages/%" PRIu64
                             "/reactions/%s",
                             channel_id, message_id, emoji_endpoint);

  free(pct_emoji_name);

  return code;
}

ORCAcode
discord_edit_message(struct discord *client,
                     const u64_snowflake_t channel_id,
                     const u64_snowflake_t message_id,
                     struct discord_edit_message_params *params,
                     struct discord_message *ret)
{
  struct ua_resp_handle handle = { ret ? &discord_message_from_json_v : NULL,
                                   ret };
  struct sized_buffer body;
  char buf[16384]; /**< @todo dynamic buffer */

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
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

  body.size = discord_edit_message_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_PATCH,
                             "/channels/%" PRIu64 "/messages/%" PRIu64,
                             channel_id, message_id);
}

ORCAcode
discord_delete_message(struct discord *client,
                       u64_snowflake_t channel_id,
                       u64_snowflake_t message_id)
{
  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!message_id) {
    logconf_error(&client->conf, "Missing 'message_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/channels/%" PRIu64 "/messages/%" PRIu64,
                             channel_id, message_id);
}

/** @todo add duplicated ID verification */
ORCAcode
discord_bulk_delete_messages(struct discord *client,
                             u64_snowflake_t channel_id,
                             u64_snowflake_t **messages)
{
  u64_unix_ms_t now = discord_timestamp(client);
  struct sized_buffer body;
  char *buf = NULL;
  ORCAcode code;
  size_t count;
  int i;

  if (!messages) {
    logconf_error(&client->conf, "Missing 'messages'");
    return ORCA_MISSING_PARAMETER;
  }
  count = ntl_length_max((ntl_t)messages, 101);
  if (count < 2 || count > 100) {
    logconf_error(&client->conf, "Message count should be between 2 and 100");
    return ORCA_BAD_PARAMETER;
  }

  for (i = 0; messages[i]; ++i) {
    u64_unix_ms_t timestamp = (*messages[i] >> 22) + 1420070400000;

    if (now > timestamp && now - timestamp > 1209600000) {
      logconf_error(&client->conf,
                    "Messages should not be older than 2 weeks.");
      return ORCA_BAD_PARAMETER;
    }
  }

  body.size =
    json_ainject(&buf, "(messages):F", ja_u64_list_to_json, messages);
  body.start = buf;

  if (!buf) {
    logconf_error(&client->conf, "Couldn't create JSON Payload");
    return ORCA_BAD_JSON;
  }

  code = discord_adapter_run(&client->adapter, NULL, &body, HTTP_POST,
                             "/channels/%" PRIu64 "/messages/bulk-delete",
                             channel_id);

  free(buf);

  return code;
}

ORCAcode
discord_edit_channel_permissions(
  struct discord *client,
  const u64_snowflake_t channel_id,
  const u64_snowflake_t overwrite_id,
  struct discord_edit_channel_permissions_params *params)
{
  struct sized_buffer body;
  char buf[1024];

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!overwrite_id) {
    logconf_error(&client->conf, "Missing 'overwrite_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size =
    discord_edit_channel_permissions_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, NULL, &body, HTTP_PUT,
                             "/channels/%" PRIu64 "/permissions/%" PRIu64,
                             channel_id, overwrite_id);
}

ORCAcode
discord_get_channel_invites(struct discord *client,
                            const u64_snowflake_t channel_id,
                            struct discord_invite ***ret)
{
  struct ua_resp_handle handle = { &discord_invite_list_from_json_v, ret };

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/channels/%" PRIu64 "/invites", channel_id);
}

ORCAcode
discord_create_channel_invite(
  struct discord *client,
  const u64_snowflake_t channel_id,
  struct discord_create_channel_invite_params *params,
  struct discord_invite *ret)
{
  struct ua_resp_handle handle = { ret ? &discord_invite_from_json_v : NULL,
                                   ret };
  struct sized_buffer body;
  char buf[1024];
  size_t len;

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }

  if (params)
    len =
      discord_create_channel_invite_params_to_json(buf, sizeof(buf), params);
  else
    len = sprintf(buf, "{}");
  body.start = buf;
  body.size = len;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_POST,
                             "/channels/%" PRIu64 "/invites", channel_id);
}

ORCAcode
discord_delete_channel_permission(struct discord *client,
                                  const u64_snowflake_t channel_id,
                                  const u64_snowflake_t overwrite_id)
{
  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!overwrite_id) {
    logconf_error(&client->conf, "Missing 'overwrite_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/channels/%" PRIu64 "/permissions/%" PRIu64,
                             channel_id, overwrite_id);
}

ORCAcode
discord_follow_news_channel(struct discord *client,
                            const u64_snowflake_t channel_id,
                            struct discord_follow_news_channel_params *params,
                            struct discord_channel *ret)
{
  struct ua_resp_handle handle = { ret ? &discord_channel_from_json_v : NULL,
                                   ret };
  struct sized_buffer body;
  char buf[256]; /* should be more than enough for this */

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params || !params->webhook_channel_id) {
    logconf_error(&client->conf, "Missing 'params.webhook_channel_id'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size =
    discord_follow_news_channel_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_POST,
                             "/channels/%" PRIu64 "/followers", channel_id);
}

ORCAcode
discord_trigger_typing_indicator(struct discord *client,
                                 u64_snowflake_t channel_id)
{
  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_POST,
                             "/channels/%" PRIu64 "/typing", channel_id);
}

ORCAcode
discord_get_pinned_messages(struct discord *client,
                            const u64_snowflake_t channel_id,
                            struct discord_message ***ret)
{
  struct ua_resp_handle handle = { &discord_message_list_from_json_v, ret };

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/channels/%" PRIu64 "/pins", channel_id);
}

ORCAcode
discord_pin_message(struct discord *client,
                    const u64_snowflake_t channel_id,
                    const u64_snowflake_t message_id)
{
  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!message_id) {
    logconf_error(&client->conf, "Missing 'message_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_PUT,
                             "/channels/%" PRIu64 "/pins/%" PRIu64, channel_id,
                             message_id);
}

ORCAcode
discord_unpin_message(struct discord *client,
                      const u64_snowflake_t channel_id,
                      const u64_snowflake_t message_id)
{
  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!message_id) {
    logconf_error(&client->conf, "Missing 'message_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/channels/%" PRIu64 "/pins/%" PRIu64, channel_id,
                             message_id);
}

ORCAcode
discord_group_dm_add_recipient(
  struct discord *client,
  const u64_snowflake_t channel_id,
  const u64_snowflake_t user_id,
  struct discord_group_dm_add_recipient_params *params)
{
  struct sized_buffer body;
  char buf[1024];

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!user_id) {
    logconf_error(&client->conf, "Missing 'user_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size =
    discord_group_dm_add_recipient_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, NULL, &body, HTTP_PUT,
                             "/channels/%" PRIu64 "/recipients/%" PRIu64,
                             channel_id, user_id);
}

ORCAcode
discord_group_dm_remove_recipient(struct discord *client,
                                  const u64_snowflake_t channel_id,
                                  const u64_snowflake_t user_id)
{
  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!user_id) {
    logconf_error(&client->conf, "Missing 'user_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/channels/%" PRIu64 "/recipients/%" PRIu64,
                             channel_id, user_id);
}

ORCAcode
discord_start_thread_with_message(
  struct discord *client,
  const u64_snowflake_t channel_id,
  const u64_snowflake_t message_id,
  struct discord_start_thread_with_message_params *params,
  struct discord_channel *ret)
{
  struct ua_resp_handle handle = { ret ? &discord_channel_from_json_v : NULL,
                                   ret };
  struct sized_buffer body;
  char buf[1024];

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
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
    discord_start_thread_with_message_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_POST,
                             "/channels/%" PRIu64 "/messages/%" PRIu64
                             "/threads",
                             channel_id, message_id);
}

ORCAcode
discord_start_thread_without_message(
  struct discord *client,
  const u64_snowflake_t channel_id,
  struct discord_start_thread_without_message_params *params,
  struct discord_channel *ret)
{
  struct ua_resp_handle handle = { ret ? &discord_channel_from_json_v : NULL,
                                   ret };
  struct sized_buffer body;
  char buf[1024];

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_start_thread_without_message_params_to_json(
    buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_POST,
                             "/channels/%" PRIu64 "/threads", channel_id);
}

ORCAcode
discord_join_thread(struct discord *client, const u64_snowflake_t channel_id)
{
  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_PUT,
                             "/channels/%" PRIu64 "/thread-members/@me",
                             channel_id);
}

ORCAcode
discord_add_thread_member(struct discord *client,
                          const u64_snowflake_t channel_id,
                          const u64_snowflake_t user_id)
{
  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!user_id) {
    logconf_error(&client->conf, "Missing 'user_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_PUT,
                             "/channels/%" PRIu64 "/thread-members/" PRIu64,
                             channel_id, user_id);
}

ORCAcode
discord_leave_thread(struct discord *client, const u64_snowflake_t channel_id)
{
  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/channels/%" PRIu64 "/thread-members/@me",
                             channel_id);
}

ORCAcode
discord_remove_thread_member(struct discord *client,
                             const u64_snowflake_t channel_id,
                             const u64_snowflake_t user_id)
{
  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!user_id) {
    logconf_error(&client->conf, "Missing 'user_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/channels/%" PRIu64 "/thread-members/" PRIu64,
                             channel_id, user_id);
}

ORCAcode
discord_list_thread_members(struct discord *client,
                            const u64_snowflake_t channel_id,
                            struct discord_thread_member ***ret)
{
  struct ua_resp_handle handle = { &discord_thread_member_list_from_json_v,
                                   ret };

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/channels/%" PRIu64 "/thread-members",
                             channel_id);
}

ORCAcode
discord_list_active_threads(struct discord *client,
                            const u64_snowflake_t channel_id,
                            struct discord_thread_response_body *body)
{
  struct ua_resp_handle handle = { &discord_thread_response_body_from_json_v,
                                   body };

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!body) {
    logconf_error(&client->conf, "Missing 'body'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/channels/%" PRIu64 "/threads/active",
                             channel_id);
}

ORCAcode
discord_list_public_archived_threads(struct discord *client,
                                     const u64_snowflake_t channel_id,
                                     const u64_unix_ms_t before,
                                     const int limit,
                                     struct discord_thread_response_body *body)
{
  struct ua_resp_handle handle = { &discord_thread_response_body_from_json_v,
                                   body };
  char query[1024] = "";
  size_t offset = 0;

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!body) {
    logconf_error(&client->conf, "Missing 'body'");
    return ORCA_MISSING_PARAMETER;
  }

  if (before) {
    offset += snprintf(query + offset, sizeof(query) - offset,
                       "before=%" PRIu64, before);
    ASSERT_S(offset < sizeof(query), "Out of bounds write attempt");
  }
  if (limit) {
    offset += snprintf(query + offset, sizeof(query) - offset, "%slimit=%d",
                       *query ? "&" : "", limit);
    ASSERT_S(offset < sizeof(query), "Out of bounds write attempt");
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/channels/%" PRIu64
                             "/threads/archived/public%s%s",
                             channel_id, *query ? "?" : "", query);
}

ORCAcode
discord_list_private_archived_threads(
  struct discord *client,
  const u64_snowflake_t channel_id,
  const u64_unix_ms_t before,
  const int limit,
  struct discord_thread_response_body *body)
{
  struct ua_resp_handle handle = { &discord_thread_response_body_from_json_v,
                                   body };
  char query[1024] = "";
  size_t offset = 0;

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!body) {
    logconf_error(&client->conf, "Missing 'body'");
    return ORCA_MISSING_PARAMETER;
  }

  if (before) {
    offset += snprintf(query + offset, sizeof(query) - offset,
                       "before=%" PRIu64, before);
    ASSERT_S(offset < sizeof(query), "Out of bounds write attempt");
  }
  if (limit) {
    offset += snprintf(query + offset, sizeof(query) - offset, "%slimit=%d",
                       *query ? "&" : "", limit);
    ASSERT_S(offset < sizeof(query), "Out of bounds write attempt");
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/channels/%" PRIu64
                             "/threads/archived/private%s%s",
                             channel_id, *query ? "?" : "", query);
}

ORCAcode
discord_list_joined_private_archived_threads(
  struct discord *client,
  const u64_snowflake_t channel_id,
  const u64_unix_ms_t before,
  const int limit,
  struct discord_thread_response_body *body)
{
  struct ua_resp_handle handle = { &discord_thread_response_body_from_json_v,
                                   body };
  char query[1024] = "";
  size_t offset = 0;

  if (!channel_id) {
    logconf_error(&client->conf, "Missing 'channel_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!body) {
    logconf_error(&client->conf, "Missing 'body'");
    return ORCA_MISSING_PARAMETER;
  }

  if (before) {
    offset += snprintf(query + offset, sizeof(query) - offset,
                       "before=%" PRIu64, before);
    ASSERT_S(offset < sizeof(query), "Out of bounds write attempt");
  }
  if (limit) {
    offset += snprintf(query + offset, sizeof(query) - offset, "%slimit=%d",
                       *query ? "&" : "", limit);
    ASSERT_S(offset < sizeof(query), "Out of bounds write attempt");
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/channels/%" PRIu64
                             "/users/@me/threads/archived/private%s%s",
                             channel_id, *query ? "?" : "", query);
}

/* ASYNCHRONOUS WRAPPERS */

ORCAcode
discord_create_message_async(struct discord *client,
                             const u64_snowflake_t channel_id,
                             struct discord_create_message_params *params,
                             void (*ret)(struct discord *client,
                                         ORCAcode code,
                                         const struct discord_message *msg))
{
  struct discord_request_attr attr = {
    sizeof(struct discord_message),
    &discord_message_init_v,
    &discord_message_from_json_v,
    &discord_message_cleanup_v,
    (void *)ret,
  };

  discord_adapter_toggle_async(&client->adapter, &attr);
  return discord_create_message(client, channel_id, params, NULL);
}
