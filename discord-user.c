#define _GNU_SOURCE /* asprintf() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "discord.h"
#include "discord-internal.h"
#include "cee-utils.h"

ORCAcode
discord_get_current_user(struct discord *client, struct discord_user *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_user, ret);

  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/users/@me");
}

ORCAcode
discord_get_user(struct discord *client,
                 const u64_snowflake_t user_id,
                 struct discord_user *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_user, ret);

  ORCA_EXPECT(client, user_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/users/%" PRIu64, user_id);
}

ORCAcode
discord_modify_current_user(struct discord *client,
                            struct discord_modify_current_user_params *params,
                            struct discord_user *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_user, ret);
  struct sized_buffer body;
  char buf[1024];

  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);

  body.size =
    discord_modify_current_user_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_PATCH,
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
sb_discord_get_current_user(struct discord *client, struct sized_buffer *ret)
{
  struct discord_request_attr attr = { ret, sizeof(struct sized_buffer), NULL,
                                       &sized_buffer_from_json };

  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/users/@me");
}

ORCAcode
discord_get_current_user_guilds(struct discord *client,
                                struct discord_guild ***ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_LIST_INIT(discord_guild, ret);

  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/users/@me/guilds");
}

ORCAcode
discord_leave_guild(struct discord *client, const u64_snowflake_t guild_id)
{
  struct sized_buffer body = { "{}", 2 };

  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, NULL, &body, HTTP_DELETE,
                             "/users/@me/guilds/%" PRIu64, guild_id);
}

ORCAcode
discord_create_dm(struct discord *client,
                  struct discord_create_dm_params *params,
                  struct discord_channel *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_channel, ret);
  struct sized_buffer body;
  char buf[128];

  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);

  body.size = discord_create_dm_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                             "/users/@me/channels");
}

ORCAcode
discord_create_group_dm(struct discord *client,
                        struct discord_create_group_dm_params *params,
                        struct discord_channel *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_channel, ret);
  struct sized_buffer body;
  char buf[1024];

  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params->access_tokens != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params->nicks != NULL, ORCA_BAD_PARAMETER);

  body.size = discord_create_group_dm_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                             "/users/@me/channels");
}

ORCAcode
discord_get_user_connections(struct discord *client,
                             struct discord_connection ***ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_LIST_INIT(discord_connection, ret);

  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/users/@me/connections");
}
