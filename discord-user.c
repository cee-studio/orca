#define _GNU_SOURCE /* asprintf() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "discord.h"
#include "discord-internal.h"
#include "cee-utils.h"

ORCAcode
discord_get_current_user(struct discord *client, struct discord_user *p_user)
{
  struct ua_resp_handle handle = { &discord_user_from_json_v, p_user };

  if (!p_user) {
    logconf_error(&client->conf, "Missing 'p_user'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/users/@me");
}

ORCAcode
discord_get_user(struct discord *client,
                 const u64_snowflake_t user_id,
                 struct discord_user *p_user)
{
  struct ua_resp_handle handle = { &discord_user_from_json_v, p_user };

  if (!user_id) {
    logconf_error(&client->conf, "Missing 'user_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!p_user) {
    logconf_error(&client->conf, "Missing 'p_user'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/users/%" PRIu64, user_id);
}

ORCAcode
discord_modify_current_user(struct discord *client,
                            struct discord_modify_current_user_params *params,
                            struct discord_user *p_user)
{
  struct ua_resp_handle handle = { p_user ? &discord_user_from_json_v : NULL,
                                   p_user };
  struct sized_buffer body;
  char buf[1024];

  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size =
    discord_modify_current_user_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_PATCH,
                             "/users/@me");
}

/* @todo this is a temporary solution for wrapping with JS */
static void
sized_buffer_from_json(char *json, size_t len, void *data)
{
  struct sized_buffer *p = data;
  p->size = asprintf(&p->start, "%.*s", (int)len, json);
}

ORCAcode /* @todo this is a temporary solution for easily wrapping JS */
sb_discord_get_current_user(struct discord *client,
                            struct sized_buffer *p_sb_user)
{
  struct ua_resp_handle handle = { &sized_buffer_from_json, p_sb_user };

  if (!p_sb_user) {
    logconf_error(&client->conf, "Missing 'p_sb_user'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/users/@me");
}

ORCAcode
discord_get_current_user_guilds(struct discord *client,
                                NTL_T(struct discord_guild) * p_guilds)
{
  struct ua_resp_handle handle = { &discord_guild_list_from_json_v, p_guilds };

  if (!p_guilds) {
    logconf_error(&client->conf, "Missing 'p_guilds'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/users/@me/guilds");
}

ORCAcode
discord_leave_guild(struct discord *client, const u64_snowflake_t guild_id)
{
  struct sized_buffer body = { "{}", 2 };

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, &body, HTTP_DELETE,
                             "/users/@me/guilds/%" PRIu64, guild_id);
}

ORCAcode
discord_create_dm(struct discord *client,
                  struct discord_create_dm_params *params,
                  struct discord_channel *p_dm_channel)
{
  struct ua_resp_handle handle = { p_dm_channel ? &discord_channel_from_json_v
                                                : NULL,
                                   p_dm_channel };
  struct sized_buffer body;
  char buf[128];

  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_create_dm_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_POST,
                             "/users/@me/channels");
}

ORCAcode
discord_create_group_dm(struct discord *client,
                        struct discord_create_group_dm_params *params,
                        struct discord_channel *p_dm_channel)
{
  struct ua_resp_handle handle = { p_dm_channel ? &discord_channel_from_json_v
                                                : NULL,
                                   p_dm_channel };
  struct sized_buffer body;
  char buf[1024];

  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params->access_tokens) {
    logconf_error(&client->conf, "Missing 'params.access_tokens'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params->nicks) {
    logconf_error(&client->conf, "Missing 'params.nicks'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_create_group_dm_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_POST,
                             "/users/@me/channels");
}

ORCAcode
discord_get_user_connections(struct discord *client,
                             NTL_T(struct discord_connection) * p_connections)
{
  struct ua_resp_handle handle = { &discord_connection_list_from_json_v,
                                   p_connections };

  if (!p_connections) {
    logconf_error(&client->conf, "Missing 'p_connections'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/users/@me/connections");
}
