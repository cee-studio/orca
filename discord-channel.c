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
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_channel, ret);

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/channels/%" PRIu64, channel_id);
}

ORCAcode
discord_modify_channel(struct discord *client,
                       const u64_snowflake_t channel_id,
                       struct discord_modify_channel_params *params,
                       struct discord_channel *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_channel, ret);
  struct sized_buffer body;
  char buf[1024];

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);

  body.size = discord_modify_channel_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_PATCH,
                             "/channels/%" PRIu64, channel_id);
}

ORCAcode
discord_delete_channel(struct discord *client,
                       const u64_snowflake_t channel_id,
                       struct discord_channel *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_channel, ret);

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_DELETE,
                             "/channels/%" PRIu64, channel_id);
}

ORCAcode
discord_get_channel_messages(
  struct discord *client,
  const u64_snowflake_t channel_id,
  struct discord_get_channel_messages_params *params,
  struct discord_message ***ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_LIST_INIT(discord_message, ret);
  char query[1024] = "";

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

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

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/channels/%" PRIu64 "/messages%s%s", channel_id,
                             *query ? "?" : "", query);
}

ORCAcode
discord_get_channel_message(struct discord *client,
                            const u64_snowflake_t channel_id,
                            const u64_snowflake_t message_id,
                            struct discord_message *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_message, ret);

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, message_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/channels/%" PRIu64 "/messages/%" PRIu64,
                             channel_id, message_id);
}

ORCAcode
discord_create_message(struct discord *client,
                       const u64_snowflake_t channel_id,
                       struct discord_create_message_params *params,
                       struct discord_message *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_message, ret);
  struct sized_buffer body;
  enum http_method method;
  char buf[16384]; /**< @todo dynamic buffer */

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);

  body.size = discord_create_message_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  if (params->attachments) {
    method = HTTP_MIMEPOST;
    attr.attachments = params->attachments;
  }
  else {
    method = HTTP_POST;
  }

  return discord_adapter_run(&client->adapter, &attr, &body, method,
                             "/channels/%" PRIu64 "/messages", channel_id);
}

ORCAcode
discord_crosspost_message(struct discord *client,
                          const u64_snowflake_t channel_id,
                          const u64_snowflake_t message_id,
                          struct discord_message *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_message, ret);

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, message_id != 0, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_POST,
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

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, message_id != 0, ORCA_BAD_PARAMETER);

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

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, message_id != 0, ORCA_BAD_PARAMETER);

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

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, message_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, user_id != 0, ORCA_BAD_PARAMETER);

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
  struct discord_request_attr attr = REQUEST_ATTR_LIST_INIT(discord_user, ret);
  char query[1024] = "";
  char emoji_endpoint[256];
  char *pct_emoji_name;
  ORCAcode code;

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, message_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

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

  code = discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
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
  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, message_id != 0, ORCA_BAD_PARAMETER);

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

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, message_id != 0, ORCA_BAD_PARAMETER);

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
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_message, ret);
  struct sized_buffer body;
  char buf[16384]; /**< @todo dynamic buffer */

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, message_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);

  body.size = discord_edit_message_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_PATCH,
                             "/channels/%" PRIu64 "/messages/%" PRIu64,
                             channel_id, message_id);
}

ORCAcode
discord_delete_message(struct discord *client,
                       u64_snowflake_t channel_id,
                       u64_snowflake_t message_id)
{
  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, message_id != 0, ORCA_BAD_PARAMETER);

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

  ORCA_EXPECT(client, messages != NULL, ORCA_BAD_PARAMETER);

  count = ntl_length_max((ntl_t)messages, 101);
  ORCA_EXPECT(client, count >= 2 && count <= 100, ORCA_BAD_PARAMETER);

  for (i = 0; messages[i]; ++i) {
    u64_unix_ms_t timestamp = (*messages[i] >> 22) + 1420070400000;

    ORCA_EXPECT(client, now <= timestamp || now - timestamp <= 1209600000,
                ORCA_BAD_PARAMETER,
                "Messages should not be older than 2 weeks.");
  }

  body.size =
    json_ainject(&buf, "(messages):F", ja_u64_list_to_json, messages);
  body.start = buf;

  ORCA_EXPECT(client, buf != NULL, ORCA_BAD_JSON);

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

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, overwrite_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);

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
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_invite, ret);

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/channels/%" PRIu64 "/invites", channel_id);
}

ORCAcode
discord_create_channel_invite(
  struct discord *client,
  const u64_snowflake_t channel_id,
  struct discord_create_channel_invite_params *params,
  struct discord_invite *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_invite, ret);
  struct sized_buffer body;
  char buf[1024];
  size_t len;

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);

  if (params)
    len =
      discord_create_channel_invite_params_to_json(buf, sizeof(buf), params);
  else
    len = sprintf(buf, "{}");
  body.start = buf;
  body.size = len;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                             "/channels/%" PRIu64 "/invites", channel_id);
}

ORCAcode
discord_delete_channel_permission(struct discord *client,
                                  const u64_snowflake_t channel_id,
                                  const u64_snowflake_t overwrite_id)
{
  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, overwrite_id != 0, ORCA_BAD_PARAMETER);

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
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_channel, ret);
  struct sized_buffer body;
  char buf[256]; /* should be more than enough for this */

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params->webhook_channel_id != 0, ORCA_BAD_PARAMETER);

  body.size =
    discord_follow_news_channel_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                             "/channels/%" PRIu64 "/followers", channel_id);
}

ORCAcode
discord_trigger_typing_indicator(struct discord *client,
                                 u64_snowflake_t channel_id)
{
  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_POST,
                             "/channels/%" PRIu64 "/typing", channel_id);
}

ORCAcode
discord_get_pinned_messages(struct discord *client,
                            const u64_snowflake_t channel_id,
                            struct discord_message ***ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_LIST_INIT(discord_message, ret);

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/channels/%" PRIu64 "/pins", channel_id);
}

ORCAcode
discord_pin_message(struct discord *client,
                    const u64_snowflake_t channel_id,
                    const u64_snowflake_t message_id)
{
  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, message_id != 0, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_PUT,
                             "/channels/%" PRIu64 "/pins/%" PRIu64, channel_id,
                             message_id);
}

ORCAcode
discord_unpin_message(struct discord *client,
                      const u64_snowflake_t channel_id,
                      const u64_snowflake_t message_id)
{
  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, message_id != 0, ORCA_BAD_PARAMETER);

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

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, user_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);

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
  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, user_id != 0, ORCA_BAD_PARAMETER);

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
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_channel, ret);
  struct sized_buffer body;
  char buf[1024];

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, message_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);

  body.size =
    discord_start_thread_with_message_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
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
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_channel, ret);
  struct sized_buffer body;
  char buf[1024];

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);

  body.size = discord_start_thread_without_message_params_to_json(
    buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                             "/channels/%" PRIu64 "/threads", channel_id);
}

ORCAcode
discord_join_thread(struct discord *client, const u64_snowflake_t channel_id)
{
  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_PUT,
                             "/channels/%" PRIu64 "/thread-members/@me",
                             channel_id);
}

ORCAcode
discord_add_thread_member(struct discord *client,
                          const u64_snowflake_t channel_id,
                          const u64_snowflake_t user_id)
{
  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, user_id != 0, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_PUT,
                             "/channels/%" PRIu64 "/thread-members/" PRIu64,
                             channel_id, user_id);
}

ORCAcode
discord_leave_thread(struct discord *client, const u64_snowflake_t channel_id)
{
  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/channels/%" PRIu64 "/thread-members/@me",
                             channel_id);
}

ORCAcode
discord_remove_thread_member(struct discord *client,
                             const u64_snowflake_t channel_id,
                             const u64_snowflake_t user_id)
{
  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, user_id != 0, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/channels/%" PRIu64 "/thread-members/" PRIu64,
                             channel_id, user_id);
}

ORCAcode
discord_list_thread_members(struct discord *client,
                            const u64_snowflake_t channel_id,
                            struct discord_thread_member ***ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_LIST_INIT(discord_thread_member, ret);

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/channels/%" PRIu64 "/thread-members",
                             channel_id);
}

ORCAcode
discord_list_active_threads(struct discord *client,
                            const u64_snowflake_t channel_id,
                            struct discord_thread_response_body *body)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_INIT(discord_thread_response_body, body);

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, body != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
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
  struct discord_request_attr attr =
    REQUEST_ATTR_INIT(discord_thread_response_body, body);
  char query[1024] = "";
  size_t offset = 0;

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, body != NULL, ORCA_BAD_PARAMETER);

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

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
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
  struct discord_request_attr attr =
    REQUEST_ATTR_INIT(discord_thread_response_body, body);
  char query[1024] = "";
  size_t offset = 0;

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, body != NULL, ORCA_BAD_PARAMETER);

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

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
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
  struct discord_request_attr attr =
    REQUEST_ATTR_INIT(discord_thread_response_body, body);
  char query[1024] = "";
  size_t offset = 0;

  ORCA_EXPECT(client, channel_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, body != NULL, ORCA_BAD_PARAMETER);

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

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/channels/%" PRIu64
                             "/users/@me/threads/archived/private%s%s",
                             channel_id, *query ? "?" : "", query);
}

/* ASYNCHRONOUS WRAPPERS */

ORCAcode
discord_create_message_async(struct discord *client,
                             const u64_snowflake_t channel_id,
                             struct discord_create_message_params *params,
                             void (*done)(struct discord *client,
                                          const struct discord_message *ret))
{
  struct discord_async_attr attr = { (discord_done_cb)done };

  discord_adapter_set_async(&client->adapter, &attr);
  return discord_create_message(client, channel_id, params, NULL);
}
