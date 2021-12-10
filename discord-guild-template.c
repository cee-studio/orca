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
    DISCORD_REQUEST_ATTR_INIT(discord_guild_template, ret);

  if (!code) {
    logconf_error(&client->conf, "Missing 'code'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

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
    DISCORD_REQUEST_ATTR_INIT(discord_guild_template, ret);
  struct sized_buffer body;
  char buf[256];

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

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
    DISCORD_REQUEST_ATTR_INIT(discord_guild_template, ret);

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_PUT,
                             "/guilds/%" PRIu64 "/templates/%s", guild_id,
                             code);
}
