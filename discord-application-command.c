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
  NTL_T(struct discord_application_command) * p_app_cmds)
{
  struct ua_resp_handle handle = {
    &discord_application_command_list_from_json_v, p_app_cmds
  };

  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!p_app_cmds) {
    logconf_error(&client->conf, "Missing 'p_app_cmds'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/applications/%" PRIu64 "/commands",
                             application_id);
}

ORCAcode
discord_create_global_application_command(
  struct discord *client,
  const u64_snowflake_t application_id,
  struct discord_create_global_application_command_params *params,
  struct discord_application_command *p_app_cmd)
{
  struct ua_resp_handle handle = {
    p_app_cmd ? &discord_application_command_from_json_v : NULL,
    p_app_cmd,
  };
  struct sized_buffer body;
  char buf[4096];

  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(params->name)) {
    logconf_error(&client->conf, "Missing 'params.name'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(params->description)) {
    logconf_error(&client->conf, "Missing 'params.description'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_create_global_application_command_params_to_json(
    buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_POST,
                             "/applications/%" PRIu64 "/commands",
                             application_id);
}

ORCAcode
discord_get_global_application_command(
  struct discord *client,
  const u64_snowflake_t application_id,
  const u64_snowflake_t command_id,
  struct discord_application_command *p_app_cmd)
{
  struct ua_resp_handle handle = { &discord_application_command_from_json_v,
                                   p_app_cmd };

  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!command_id) {
    logconf_error(&client->conf, "Missing 'command_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!p_app_cmd) {
    logconf_error(&client->conf, "Missing 'p_app_cmd'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/applications/%" PRIu64 "/commands/%" PRIu64,
                             application_id, command_id);
}

ORCAcode
discord_edit_global_application_command(
  struct discord *client,
  const u64_snowflake_t application_id,
  const u64_snowflake_t command_id,
  struct discord_edit_global_application_command_params *params,
  struct discord_application_command *p_app_cmd)
{
  struct ua_resp_handle handle = {
    p_app_cmd ? &discord_application_command_from_json_v : NULL,
    p_app_cmd,
  };
  struct sized_buffer body;
  char buf[4096];

  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!command_id) {
    logconf_error(&client->conf, "Missing 'command_id'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_edit_global_application_command_params_to_json(
    buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_PATCH,
                             "/applications/%" PRIu64 "/commands/%" PRIu64,
                             application_id, command_id);
}

ORCAcode
discord_delete_global_application_command(struct discord *client,
                                          const u64_snowflake_t application_id,
                                          const u64_snowflake_t command_id)
{
  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!command_id) {
    logconf_error(&client->conf, "Missing 'command_id'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, NULL, NULL, HTTP_DELETE,
                             "/applications/%" PRIu64 "/commands/%" PRIu64,
                             application_id, command_id);
}

ORCAcode
discord_bulk_overwrite_global_application_command(
  struct discord *client,
  const u64_snowflake_t application_id,
  NTL_T(struct discord_application_command) params,
  NTL_T(struct discord_application_command) * p_app_cmds)
{
  struct ua_resp_handle handle = {
    p_app_cmds ? &discord_application_command_list_from_json_v : NULL,
    p_app_cmds
  };
  struct sized_buffer body;
  char buf[8192];

  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size =
    discord_application_command_list_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_PUT,
                             "/applications/%" PRIu64 "/commands",
                             application_id);
}

ORCAcode
discord_get_guild_application_commands(
  struct discord *client,
  const u64_snowflake_t application_id,
  const u64_snowflake_t guild_id,
  NTL_T(struct discord_application_command) * p_app_cmds)
{
  struct ua_resp_handle handle = {
    &discord_application_command_list_from_json_v, p_app_cmds
  };

  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!p_app_cmds) {
    logconf_error(&client->conf, "Missing 'p_app_cmds'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
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
  struct discord_application_command *p_app_cmd)
{
  struct ua_resp_handle handle = {
    p_app_cmd ? &discord_application_command_from_json_v : NULL,
    p_app_cmd,
  };
  struct sized_buffer body;
  char buf[4096];

  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(params->name)) {
    logconf_error(&client->conf, "Missing 'params.name'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(params->description)) {
    logconf_error(&client->conf, "Missing 'params.description'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_create_guild_application_command_params_to_json(
    buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_POST,
                             "/applications/%" PRIu64 "/guilds/%" PRIu64
                             "/commands",
                             application_id, guild_id);
}

ORCAcode
discord_get_guild_application_command(
  struct discord *client,
  const u64_snowflake_t application_id,
  const u64_snowflake_t guild_id,
  const u64_snowflake_t command_id,
  struct discord_application_command *p_app_cmd)
{
  struct ua_resp_handle handle = { &discord_application_command_from_json_v,
                                   p_app_cmd };

  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!command_id) {
    logconf_error(&client->conf, "Missing 'command_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!p_app_cmd) {
    logconf_error(&client->conf, "Missing 'p_app_cmd'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
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
  struct discord_application_command *p_app_cmd)
{
  struct ua_resp_handle handle = {
    p_app_cmd ? &discord_application_command_from_json_v : NULL,
    p_app_cmd,
  };
  struct sized_buffer body;
  char buf[4096];

  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!command_id) {
    logconf_error(&client->conf, "Missing 'command_id'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_edit_guild_application_command_params_to_json(
    buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_PATCH,
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
  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!command_id) {
    logconf_error(&client->conf, "Missing 'command_id'");
    return ORCA_MISSING_PARAMETER;
  }

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
  NTL_T(struct discord_application_command) params,
  NTL_T(struct discord_application_command) * p_app_cmds)
{
  struct ua_resp_handle handle = {
    p_app_cmds ? &discord_application_command_list_from_json_v : NULL,
    p_app_cmds
  };
  struct sized_buffer body;
  char buf[8192];

  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size =
    discord_application_command_list_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_PUT,
                             "/applications/%" PRIu64 "/guilds/%" PRIu64
                             "/commands",
                             application_id, guild_id);
}

ORCAcode
discord_get_guild_application_command_permissions(
  struct discord *client,
  const u64_snowflake_t application_id,
  const u64_snowflake_t guild_id,
  NTL_T(struct discord_guild_application_command_permissions) * p_permissions)
{
  struct ua_resp_handle handle = {
    &discord_guild_application_command_permissions_list_from_json_v,
    p_permissions
  };

  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!p_permissions) {
    logconf_error(&client->conf, "Missing 'p_permissions'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
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
  struct discord_guild_application_command_permissions *p_permissions)
{
  struct ua_resp_handle handle = {
    &discord_guild_application_command_permissions_from_json_v, p_permissions
  };

  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!command_id) {
    logconf_error(&client->conf, "Missing 'command_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!p_permissions) {
    logconf_error(&client->conf, "Missing 'p_permissions'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
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
  struct discord_guild_application_command_permissions *p_permissions)
{
  struct ua_resp_handle handle = {
    p_permissions ? &discord_guild_application_command_permissions_from_json_v
                  : NULL,
    p_permissions
  };
  struct sized_buffer body;
  char buf[8192];

  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!command_id) {
    logconf_error(&client->conf, "Missing 'command_id'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_edit_application_command_permissions_params_to_json(
    buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_PUT,
                             "/applications/%" PRIu64 "/guilds/%" PRIu64
                             "/commands/%" PRIu64 "/permissions",
                             application_id, guild_id, command_id);
}

ORCAcode
discord_batch_edit_application_command_permissions(
  struct discord *client,
  const u64_snowflake_t application_id,
  const u64_snowflake_t guild_id,
  NTL_T(struct discord_guild_application_command_permissions) params,
  NTL_T(struct discord_guild_application_command_permissions) * p_permissions)
{
  struct ua_resp_handle handle = {
    p_permissions
      ? &discord_guild_application_command_permissions_list_from_json_v
      : NULL,
    p_permissions
  };
  struct sized_buffer body;
  char buf[8192];

  if (!application_id) {
    logconf_error(&client->conf, "Missing 'application_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_guild_application_command_permissions_list_to_json(
    buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &handle, &body, HTTP_PUT,
                             "/applications/%" PRIu64 "/guilds/%" PRIu64
                             "/commands/permissions",
                             application_id, guild_id);
}
