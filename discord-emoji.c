#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h> /* PRIu64 */

#include "discord.h"
#include "discord-internal.h"
#include "cee-utils.h"

ORCAcode
discord_list_guild_emojis(struct discord *client,
                          const u64_snowflake_t guild_id,
                          NTL_T(struct discord_emoji) * p_emojis)
{
  struct ua_resp_handle handle = { &discord_emoji_list_from_json_v, p_emojis };

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!p_emojis) {
    logconf_error(&client->conf, "Missing 'p_emojis'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/emojis", guild_id);
}

ORCAcode
discord_get_guild_emoji(struct discord *client,
                        const u64_snowflake_t guild_id,
                        const u64_snowflake_t emoji_id,
                        struct discord_emoji *p_emoji)
{
  struct ua_resp_handle handle = { &discord_emoji_from_json_v, p_emoji };

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!emoji_id) {
    logconf_error(&client->conf, "Missing 'emoji_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!p_emoji) {
    logconf_error(&client->conf, "Missing 'p_emoji'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/emojis/%" PRIu64, guild_id,
                             emoji_id);
}

ORCAcode
discord_create_guild_emoji(struct discord *client,
                           const u64_snowflake_t guild_id,
                           struct discord_create_guild_emoji_params *params,
                           struct discord_emoji *p_emoji)
{
  struct ua_resp_handle handle = { p_emoji ? &discord_emoji_from_json_v : NULL,
                                   p_emoji };
  struct sized_buffer body;
  char buf[2048];

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size =
    discord_create_guild_emoji_params_to_json(buf, sizeof(buf), &params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_POST,
                             "/guilds/%" PRIu64 "/emojis", guild_id);
}

ORCAcode
discord_modify_guild_emoji(struct discord *client,
                           const u64_snowflake_t guild_id,
                           const u64_snowflake_t emoji_id,
                           struct discord_modify_guild_emoji_params *params,
                           struct discord_emoji *p_emoji)
{
  struct ua_resp_handle handle = { p_emoji ? &discord_emoji_from_json_v : NULL,
                                   p_emoji };
  struct sized_buffer body;
  char buf[2048];

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!emoji_id) {
    logconf_error(&client->conf, "Missing 'emoji_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size =
    discord_modify_guild_emoji_params_to_json(buf, sizeof(buf), &params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_PATCH,
                             "/guilds/%" PRIu64 "/emojis/%" PRIu64, guild_id,
                             emoji_id);
}

ORCAcode
discord_delete_guild_emoji(struct discord *client,
                           const u64_snowflake_t guild_id,
                           const u64_snowflake_t emoji_id)
{
  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!emoji_id) {
    logconf_error(&client->conf, "Missing 'emoji_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/guilds/%" PRIu64 "/emojis/%" PRIu64, guild_id,
                             emoji_id);
}
