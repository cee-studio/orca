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
    REQUEST_ATTR_LIST_INIT(discord_emoji, ret);

  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/emojis", guild_id);
}

ORCAcode
discord_get_guild_emoji(struct discord *client,
                        const u64_snowflake_t guild_id,
                        const u64_snowflake_t emoji_id,
                        struct discord_emoji *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_emoji, ret);

  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, emoji_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

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
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_emoji, ret);
  struct sized_buffer body;
  char buf[2048];

  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);

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
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_emoji, ret);
  struct sized_buffer body;
  char buf[2048];

  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, emoji_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);

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
  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, emoji_id != 0, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/guilds/%" PRIu64 "/emojis/%" PRIu64, guild_id,
                             emoji_id);
}
