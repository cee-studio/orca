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
  struct discord_request_attr attr =
    REQUEST_ATTR_LIST_INIT(discord_voice_region, ret);

  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/voice/regions");
}
