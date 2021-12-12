#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "discord.h"
#include "discord-internal.h"
#include "cee-utils.h"

ORCAcode
discord_get_global_application_commands(
  struct discord *client,
  const u64_snowflake_t application_id,
  struct discord_application_command ***ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_LIST_INIT(discord_application_command, ret);

  ORCA_EXPECT(client, application_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/applications/%" PRIu64 "/commands",
                             application_id);
}

ORCAcode
discord_create_global_application_command(
  struct discord *client,
  const u64_snowflake_t application_id,
  struct discord_create_global_application_command_params *params,
  struct discord_application_command *ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_INIT(discord_application_command, ret);
  struct sized_buffer body;
  char buf[4096];

  ORCA_EXPECT(client, application_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->name), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->description),
              ORCA_BAD_PARAMETER);

  body.size = discord_create_global_application_command_params_to_json(
    buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                             "/applications/%" PRIu64 "/commands",
                             application_id);
}

ORCAcode
discord_get_global_application_command(struct discord *client,
                                       const u64_snowflake_t application_id,
                                       const u64_snowflake_t command_id,
                                       struct discord_application_command *ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_INIT(discord_application_command, ret);

  ORCA_EXPECT(client, application_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, command_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/applications/%" PRIu64 "/commands/%" PRIu64,
                             application_id, command_id);
}

ORCAcode
discord_edit_global_application_command(
  struct discord *client,
  const u64_snowflake_t application_id,
  const u64_snowflake_t command_id,
  struct discord_edit_global_application_command_params *params,
  struct discord_application_command *ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_INIT(discord_application_command, ret);
  struct sized_buffer body;
  char buf[4096];

  ORCA_EXPECT(client, application_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, command_id != 0, ORCA_BAD_PARAMETER);

  body.size = discord_edit_global_application_command_params_to_json(
    buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_PATCH,
                             "/applications/%" PRIu64 "/commands/%" PRIu64,
                             application_id, command_id);
}

ORCAcode
discord_delete_global_application_command(struct discord *client,
                                          const u64_snowflake_t application_id,
                                          const u64_snowflake_t command_id)
{
  ORCA_EXPECT(client, application_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, command_id != 0, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/applications/%" PRIu64 "/commands/%" PRIu64,
                             application_id, command_id);
}

ORCAcode
discord_bulk_overwrite_global_application_command(
  struct discord *client,
  const u64_snowflake_t application_id,
  struct discord_application_command **params,
  struct discord_application_command ***ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_LIST_INIT(discord_application_command, ret);
  struct sized_buffer body;
  char buf[8192];

  ORCA_EXPECT(client, application_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);

  body.size =
    discord_application_command_list_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_PUT,
                             "/applications/%" PRIu64 "/commands",
                             application_id);
}

ORCAcode
discord_get_guild_application_commands(
  struct discord *client,
  const u64_snowflake_t application_id,
  const u64_snowflake_t guild_id,
  struct discord_application_command ***ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_LIST_INIT(discord_application_command, ret);

  ORCA_EXPECT(client, application_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/applications/%" PRIu64 "/guilds/%" PRIu64
                             "/commands",
                             application_id, guild_id);
}

ORCAcode
discord_create_guild_application_command(
  struct discord *client,
  const u64_snowflake_t application_id,
  const u64_snowflake_t guild_id,
  struct discord_create_guild_application_command_params *params,
  struct discord_application_command *ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_INIT(discord_application_command, ret);
  struct sized_buffer body;
  char buf[4096];

  ORCA_EXPECT(client, application_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->name), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->description),
              ORCA_BAD_PARAMETER);

  body.size = discord_create_guild_application_command_params_to_json(
    buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                             "/applications/%" PRIu64 "/guilds/%" PRIu64
                             "/commands",
                             application_id, guild_id);
}

ORCAcode
discord_get_guild_application_command(struct discord *client,
                                      const u64_snowflake_t application_id,
                                      const u64_snowflake_t guild_id,
                                      const u64_snowflake_t command_id,
                                      struct discord_application_command *ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_INIT(discord_application_command, ret);

  ORCA_EXPECT(client, application_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, command_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/applications/%" PRIu64 "/guilds/%" PRIu64
                             "/commands/%" PRIu64,
                             application_id, guild_id, command_id);
}

ORCAcode
discord_edit_guild_application_command(
  struct discord *client,
  const u64_snowflake_t application_id,
  const u64_snowflake_t guild_id,
  const u64_snowflake_t command_id,
  struct discord_edit_guild_application_command_params *params,
  struct discord_application_command *ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_INIT(discord_application_command, ret);
  struct sized_buffer body;
  char buf[4096];

  ORCA_EXPECT(client, application_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, command_id != 0, ORCA_BAD_PARAMETER);

  body.size = discord_edit_guild_application_command_params_to_json(
    buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_PATCH,
                             "/applications/%" PRIu64 "/guilds/%" PRIu64
                             "/commands/%" PRIu64,
                             application_id, guild_id, command_id);
}

ORCAcode
discord_delete_guild_application_command(struct discord *client,
                                         const u64_snowflake_t application_id,
                                         const u64_snowflake_t guild_id,
                                         const u64_snowflake_t command_id)
{
  ORCA_EXPECT(client, application_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, command_id != 0, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/applications/%" PRIu64 "/guilds/%" PRIu64
                             "/commands/%" PRIu64,
                             application_id, guild_id, command_id);
}

ORCAcode
discord_bulk_overwrite_guild_application_command(
  struct discord *client,
  const u64_snowflake_t application_id,
  const u64_snowflake_t guild_id,
  struct discord_application_command **params,
  struct discord_application_command ***ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_LIST_INIT(discord_application_command, ret);
  struct sized_buffer body;
  char buf[8192];

  ORCA_EXPECT(client, application_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);

  body.size =
    discord_application_command_list_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_PUT,
                             "/applications/%" PRIu64 "/guilds/%" PRIu64
                             "/commands",
                             application_id, guild_id);
}

ORCAcode
discord_get_guild_application_command_permissions(
  struct discord *client,
  const u64_snowflake_t application_id,
  const u64_snowflake_t guild_id,
  struct discord_guild_application_command_permissions ***ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_LIST_INIT(discord_application_command_permissions, ret);

  ORCA_EXPECT(client, application_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/applications/%" PRIu64 "/guilds/%" PRIu64
                             "/commands/permissions",
                             application_id, guild_id);
}

ORCAcode
discord_get_application_command_permissions(
  struct discord *client,
  const u64_snowflake_t application_id,
  const u64_snowflake_t guild_id,
  const u64_snowflake_t command_id,
  struct discord_guild_application_command_permissions *ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_INIT(discord_application_command_permissions, ret);

  ORCA_EXPECT(client, application_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, command_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/applications/%" PRIu64 "/guilds/%" PRIu64
                             "/commands/%" PRIu64 "/permissions",
                             application_id, guild_id, command_id);
}

ORCAcode
discord_edit_application_command_permissions(
  struct discord *client,
  const u64_snowflake_t application_id,
  const u64_snowflake_t guild_id,
  const u64_snowflake_t command_id,
  struct discord_edit_application_command_permissions_params *params,
  struct discord_guild_application_command_permissions *ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_INIT(discord_application_command_permissions, ret);
  struct sized_buffer body;
  char buf[8192];

  ORCA_EXPECT(client, application_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, command_id != 0, ORCA_BAD_PARAMETER);

  body.size = discord_edit_application_command_permissions_params_to_json(
    buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_PUT,
                             "/applications/%" PRIu64 "/guilds/%" PRIu64
                             "/commands/%" PRIu64 "/permissions",
                             application_id, guild_id, command_id);
}

ORCAcode
discord_batch_edit_application_command_permissions(
  struct discord *client,
  const u64_snowflake_t application_id,
  const u64_snowflake_t guild_id,
  struct discord_guild_application_command_permissions **params,
  struct discord_guild_application_command_permissions ***ret)
{
  struct discord_request_attr attr =
    REQUEST_ATTR_LIST_INIT(discord_application_command_permissions, ret);
  struct sized_buffer body;
  char buf[8192];

  ORCA_EXPECT(client, application_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);

  body.size = discord_guild_application_command_permissions_list_to_json(
    buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_PUT,
                             "/applications/%" PRIu64 "/guilds/%" PRIu64
                             "/commands/permissions",
                             application_id, guild_id);
}
