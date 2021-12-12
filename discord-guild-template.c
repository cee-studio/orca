#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "discord.h"
#include "discord-internal.h"
#include "cee-utils.h"

ORCAcode
discord_get_guild_template(struct discord *client,
                           char *code,
                           struct discord_guild_template *ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_INIT(discord_guild_template, ret);

  ORCA_EXPECT(client, !IS_EMPTY_STRING(code), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/guilds/templates/%s", code);
}

ORCAcode
discord_create_guild_template(
  struct discord *client,
  u64_snowflake_t guild_id,
  struct discord_create_guild_template_params *params,
  struct discord_guild_template *ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_INIT(discord_guild_template, ret);
  struct sized_buffer body;
  char buf[256];

  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  body.size =
    discord_create_guild_template_params_to_json_v(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                             "/guilds/%" PRIu64 "/templates", guild_id);
}

ORCAcode
discord_sync_guild_template(struct discord *client,
                            u64_snowflake_t guild_id,
                            char *code,
                            struct discord_guild_template *ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_INIT(discord_guild_template, ret);

  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_PUT,
                             "/guilds/%" PRIu64 "/templates/%s", guild_id,
                             code);
}
