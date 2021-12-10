#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h> /* PRIu64 */

#include "discord.h"
#include "discord-internal.h"
#include "cee-utils.h"

ORCAcode
discord_list_guild_emojis(struct discord *client,
                          const u64_snowflake_t guild_id,
                          struct discord_emoji ***ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_LIST_INIT(discord_emoji, ret);

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/emojis", guild_id);
}

ORCAcode
discord_get_guild_emoji(struct discord *client,
                        const u64_snowflake_t guild_id,
                        const u64_snowflake_t emoji_id,
                        struct discord_emoji *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_emoji, ret);

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!emoji_id) {
    logconf_error(&client->conf, "Missing 'emoji_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/emojis/%" PRIu64, guild_id,
                             emoji_id);
}

ORCAcode
discord_create_guild_emoji(struct discord *client,
                           const u64_snowflake_t guild_id,
                           struct discord_create_guild_emoji_params *params,
                           struct discord_emoji *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_emoji, ret);
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
    discord_create_guild_emoji_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                             "/guilds/%" PRIu64 "/emojis", guild_id);
}

ORCAcode
discord_modify_guild_emoji(struct discord *client,
                           const u64_snowflake_t guild_id,
                           const u64_snowflake_t emoji_id,
                           struct discord_modify_guild_emoji_params *params,
                           struct discord_emoji *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_emoji, ret);
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
    discord_modify_guild_emoji_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_PATCH,
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
