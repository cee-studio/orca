#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "discord.h"
#include "discord-internal.h"
#include "cee-utils.h"

ORCAcode
discord_create_guild(struct discord *client,
                     struct discord_create_guild_params *params,
                     struct discord_guild *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_guild, ret);
  struct sized_buffer body;
  char buf[4096];

  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_create_guild_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                             "/guilds");
}

ORCAcode
discord_get_guild(struct discord *client,
                  const u64_snowflake_t guild_id,
                  struct discord_guild *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_guild, ret);

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/guilds/%" PRIu64, guild_id);
}

ORCAcode
discord_get_guild_preview(struct discord *client,
                          const u64_snowflake_t guild_id,
                          struct discord_guild_preview *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_guild_preview, ret);

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/preview", guild_id);
}

ORCAcode
discord_modify_guild(struct discord *client,
                     const u64_snowflake_t guild_id,
                     struct discord_modify_guild_params *params,
                     struct discord_guild *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_guild, ret);
  struct sized_buffer body;
  char buf[4096];

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_modify_guild_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_PATCH,
                             "/guilds/%" PRIu64, guild_id);
}

ORCAcode
discord_delete_guild(struct discord *client, const u64_snowflake_t guild_id)
{
  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/guilds/%" PRIu64, guild_id);
}

ORCAcode
discord_get_guild_channels(struct discord *client,
                           const u64_snowflake_t guild_id,
                           struct discord_channel ***ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_LIST_INIT(discord_channel, ret);

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/channels", guild_id);
}

ORCAcode
discord_create_guild_channel(
  struct discord *client,
  const u64_snowflake_t guild_id,
  struct discord_create_guild_channel_params *params,
  struct discord_channel *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_channel, ret);
  struct sized_buffer body;
  char buf[2048];

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params");
    return ORCA_MISSING_PARAMETER;
  }

  body.size =
    discord_create_guild_channel_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                             "/guilds/%" PRIu64 "/channels", guild_id);
}

ORCAcode
discord_modify_guild_channel_positions(
  struct discord *client,
  const u64_snowflake_t guild_id,
  struct discord_modify_guild_channel_positions_params **params)
{
  struct sized_buffer body;
  char buf[4096];

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_modify_guild_channel_positions_params_list_to_json(
    buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, NULL, &body, HTTP_PATCH,
                             "/guilds/%" PRIu64 "/channels", guild_id);
}

ORCAcode
discord_get_guild_member(struct discord *client,
                         u64_snowflake_t guild_id,
                         u64_snowflake_t user_id,
                         struct discord_guild_member *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_guild_member, ret);

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!user_id) {
    logconf_error(&client->conf, "Missing 'user_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/members/%" PRIu64, guild_id,
                             user_id);
}

ORCAcode
discord_list_guild_members(struct discord *client,
                           const u64_snowflake_t guild_id,
                           struct discord_list_guild_members_params *params,
                           struct discord_guild_member ***ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_LIST_INIT(discord_guild_member, ret);
  char query[1024] = "";

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
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
    if (params->after) {
      offset += snprintf(query + offset, sizeof(query) - offset,
                         "%safter=%" PRIu64, *query ? "&" : "", params->after);
      ASSERT_S(offset < sizeof(query), "Out of bounds write attempt");
    }
  }

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/members%s%s", guild_id,
                             *query ? "?" : "", query);
}

ORCAcode
discord_search_guild_members(
  struct discord *client,
  const u64_snowflake_t guild_id,
  struct discord_search_guild_members_params *params,
  struct discord_guild_member ***ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_LIST_INIT(discord_guild_member, ret);
  char query[1024] = "";

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  if (params) {
    size_t offset = 0;
    if (params->query) {
      char *pe_query = url_encode(params->query);

      offset +=
        snprintf(query + offset, sizeof(query) - offset, "query=%s", pe_query);
      ASSERT_S(offset < sizeof(query), "Out of bounds write attempt");

      free(pe_query);
    }
    if (params->limit) {
      offset += snprintf(query + offset, sizeof(query) - offset, "%slimit=%d",
                         *query ? "&" : "", params->limit);
      ASSERT_S(offset < sizeof(query), "Out of bounds write attempt");
    }
  }

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/members/search%s%s",
                             guild_id, *query ? "?" : "", query);
}

ORCAcode
discord_add_guild_member(struct discord *client,
                         const u64_snowflake_t guild_id,
                         const u64_snowflake_t user_id,
                         struct discord_add_guild_member_params *params,
                         struct discord_guild_member *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_guild_member, ret);
  struct sized_buffer body;
  char buf[1024];

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!user_id) {
    logconf_error(&client->conf, "Missing 'user_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params || !params->access_token) {
    logconf_error(&client->conf, "Missing 'params.access_token'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size =
    discord_add_guild_member_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_PUT,
                             "/guilds/%" PRIu64 "/members/%" PRIu64, guild_id,
                             user_id);
}

ORCAcode
discord_modify_guild_member(struct discord *client,
                            const u64_snowflake_t guild_id,
                            const u64_snowflake_t user_id,
                            struct discord_modify_guild_member_params *params,
                            struct discord_guild_member *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_guild_member, ret);
  struct sized_buffer body;
  char buf[2048];

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
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
    discord_modify_guild_member_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_PATCH,
                             "/guilds/%" PRIu64 "/members/%" PRIu64, guild_id,
                             user_id);
}
ORCAcode
discord_modify_current_member(
  struct discord *client,
  const u64_snowflake_t guild_id,
  struct discord_modify_current_member_params *params,
  struct discord_guild_member *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_guild_member, ret);
  struct sized_buffer body;
  char buf[512];

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params->nick) {
    logconf_error(&client->conf, "Missing 'params.nick'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size =
    discord_modify_current_member_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_PATCH,
                             "/guilds/%" PRIu64 "/members/@me", guild_id);
}
ORCAcode
discord_modify_current_user_nick(
  struct discord *client,
  const u64_snowflake_t guild_id,
  struct discord_modify_current_user_nick_params *params,
  struct discord_guild_member *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_guild_member, ret);
  struct sized_buffer body;
  char buf[512];

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params->nick) {
    logconf_error(&client->conf, "Missing 'params.nick'");
    return ORCA_MISSING_PARAMETER;
  }

  logconf_warn(&client->conf,
               "This endpoint is now deprecated by Discord. Please use "
               "discord_modify_current_member instead");

  body.size =
    discord_modify_current_user_nick_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_PATCH,
                             "/guilds/%" PRIu64 "/members/@me/nick", guild_id);
}

ORCAcode
discord_add_guild_member_role(struct discord *client,
                              const u64_snowflake_t guild_id,
                              const u64_snowflake_t user_id,
                              const u64_snowflake_t role_id)
{
  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!user_id) {
    logconf_error(&client->conf, "Missing 'user_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!role_id) {
    logconf_error(&client->conf, "Missing 'role_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_PUT,
                             "/guilds/%" PRIu64 "/members/%" PRIu64
                             "/roles/%" PRIu64,
                             guild_id, user_id, role_id);
}

ORCAcode
discord_remove_guild_member_role(struct discord *client,
                                 const u64_snowflake_t guild_id,
                                 const u64_snowflake_t user_id,
                                 const u64_snowflake_t role_id)
{
  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!user_id) {
    logconf_error(&client->conf, "Missing 'user_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!role_id) {
    logconf_error(&client->conf, "Missing 'role_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/guilds/%" PRIu64 "/members/%" PRIu64
                             "/roles/%" PRIu64,
                             guild_id, user_id, role_id);
}

ORCAcode
discord_remove_guild_member(struct discord *client,
                            const u64_snowflake_t guild_id,
                            const u64_snowflake_t user_id)
{
  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!user_id) {
    logconf_error(&client->conf, "Missing 'user_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/guilds/%" PRIu64 "/members/%" PRIu64, guild_id,
                             user_id);
}

ORCAcode
discord_get_guild_bans(struct discord *client,
                       const u64_snowflake_t guild_id,
                       struct discord_ban ***ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_LIST_INIT(discord_ban, ret);

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/bans", guild_id);
}

ORCAcode
discord_get_guild_ban(struct discord *client,
                      const u64_snowflake_t guild_id,
                      const u64_snowflake_t user_id,
                      struct discord_ban *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_ban, ret);

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!user_id) {
    logconf_error(&client->conf, "Missing 'user_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/bans/%" PRIu64, guild_id,
                             user_id);
}

ORCAcode
discord_create_guild_ban(struct discord *client,
                         const u64_snowflake_t guild_id,
                         const u64_snowflake_t user_id,
                         struct discord_create_guild_ban_params *params)
{
  struct sized_buffer body;
  char buf[256];

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
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
  if (params->delete_message_days < 0 || params->delete_message_days > 7) {
    logconf_error(
      &client->conf,
      "'delete_message_days' is outside the interval (&client->conf, 0, 7)");
    return ORCA_BAD_PARAMETER;
  }

  body.size =
    discord_create_guild_ban_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, NULL, &body, HTTP_PUT,
                             "/guilds/%" PRIu64 "/bans/%" PRIu64, guild_id,
                             user_id);
}
ORCAcode
discord_remove_guild_ban(struct discord *client,
                         const u64_snowflake_t guild_id,
                         const u64_snowflake_t user_id)
{
  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!user_id) {
    logconf_error(&client->conf, "Missing 'user_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/guilds/%" PRIu64 "/bans/%" PRIu64, guild_id,
                             user_id);
}

ORCAcode
discord_get_guild_roles(struct discord *client,
                        const u64_snowflake_t guild_id,
                        struct discord_role ***ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_LIST_INIT(discord_role, ret);

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/roles", guild_id);
}

ORCAcode
discord_create_guild_role(struct discord *client,
                          const u64_snowflake_t guild_id,
                          struct discord_create_guild_role_params *params,
                          struct discord_role *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_role, ret);
  struct sized_buffer body;
  char buf[1024];

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size =
    discord_create_guild_role_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                             "/guilds/%" PRIu64 "/roles", guild_id);
}

ORCAcode
discord_modify_guild_role_positions(
  struct discord *client,
  const u64_snowflake_t guild_id,
  struct discord_modify_guild_role_positions_params **params,
  struct discord_role ***ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_LIST_INIT(discord_role, ret);
  struct sized_buffer body;
  char buf[4096];

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_modify_guild_role_positions_params_list_to_json(
    buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_PATCH,
                             "/guilds/%" PRIu64 "/roles", guild_id);
}

ORCAcode
discord_modify_guild_role(struct discord *client,
                          const u64_snowflake_t guild_id,
                          const u64_snowflake_t role_id,
                          struct discord_modify_guild_role_params *params,
                          struct discord_role *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_role, ret);
  struct sized_buffer body;
  char buf[2048] = "{}";
  size_t len;

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!role_id) {
    logconf_error(&client->conf, "Missing 'role_id'");
    return ORCA_MISSING_PARAMETER;
  }

  if (params)
    len = discord_modify_guild_role_params_to_json(buf, sizeof(buf), params);
  else
    len = sprintf(buf, "{}");
  body.size = len;
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_PATCH,
                             "/guilds/%" PRIu64 "/roles/%" PRIu64, guild_id,
                             role_id);
}

ORCAcode
discord_delete_guild_role(struct discord *client,
                          const u64_snowflake_t guild_id,
                          const u64_snowflake_t role_id)
{
  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!role_id) {
    logconf_error(&client->conf, "Missing 'role_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/guilds/%" PRIu64 "/roles/%" PRIu64, guild_id,
                             role_id);
}
ORCAcode
discord_begin_guild_prune(struct discord *client,
                          const u64_snowflake_t guild_id,
                          struct discord_begin_guild_prune_params *params)
{
  struct sized_buffer body;
  char buf[4096];
  size_t len;

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }

  if (params)
    len = discord_begin_guild_prune_params_to_json(buf, sizeof(buf), params);
  else
    len = sprintf(buf, "{}");
  body.size = len;
  body.start = buf;

  return discord_adapter_run(&client->adapter, NULL, &body, HTTP_POST,
                             "/guilds/%" PRIu64 "/prune", guild_id);
}

ORCAcode
discord_get_guild_invites(struct discord *client,
                          const u64_snowflake_t guild_id,
                          struct discord_invite ***ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_LIST_INIT(discord_invite, ret);

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/invites", guild_id);
}

ORCAcode
discord_delete_guild_integrations(struct discord *client,
                                  const u64_snowflake_t guild_id,
                                  const u64_snowflake_t integration_id)
{
  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!integration_id) {
    logconf_error(&client->conf, "Missing 'integration_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/guilds/%" PRIu64 "/integrations/%" PRIu64,
                             guild_id, integration_id);
}

ORCAcode
discord_get_guild_vanity_url(struct discord *client,
                             const u64_snowflake_t guild_id,
                             struct discord_invite *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_invite, ret);

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/vanity-url", guild_id);
}

ORCAcode
discord_get_guild_welcome_screen(struct discord *client,
                                 const u64_snowflake_t guild_id,
                                 struct discord_welcome_screen *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_welcome_screen, ret);

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/welcome-screen", guild_id);
}
