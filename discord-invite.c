#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "discord.h"
#include "discord-internal.h"
#include "cee-utils.h"

ORCAcode
discord_get_invite(struct discord *client,
                   char *invite_code,
                   struct discord_get_invite_params *params,
                   struct discord_invite *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_invite, ret);
  struct sized_buffer body;
  char buf[1024];

  if (!invite_code) {
    logconf_error(&client->conf, "Missing 'invite_code'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params) {
    logconf_error(&client->conf, "Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  body.size = discord_get_invite_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return discord_adapter_run(&client->adapter, &attr, &body, HTTP_GET,
                             "/invites/%s", invite_code);
}

ORCAcode
discord_delete_invite(struct discord *client,
                      char *invite_code,
                      struct discord_invite *ret)
{
  struct discord_request_attr attr =
    DISCORD_REQUEST_ATTR_INIT(discord_invite, ret);

  if (!invite_code) {
    logconf_error(&client->conf, "Missing 'invite_code'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_DELETE,
                             "/invites/%s", invite_code);
}
