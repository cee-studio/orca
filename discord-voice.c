#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "discord.h"
#include "discord-internal.h"
#include "cee-utils.h"

ORCAcode
discord_list_voice_regions(struct discord *client,
                           struct discord_voice_region ***ret)
{
  struct ua_resp_handle handle = { &discord_voice_region_list_from_json_v,
                                   ret };
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/voice/regions");
}
