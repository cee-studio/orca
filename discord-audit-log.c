#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h> /* PRIu64 */

#include "discord.h"
#include "discord-internal.h"
#include "cee-utils.h"

ORCAcode
discord_get_guild_audit_log(struct discord *client,
                            const u64_snowflake_t guild_id,
                            struct discord_get_guild_audit_log_params *params,
                            struct discord_audit_log *ret)
{
  struct discord_request_attr attr = REQUEST_ATTR_INIT(discord_audit_log, ret);
  char query[1024] = "";

  ORCA_EXPECT(client, guild_id != 0, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  if (params) {
    size_t offset = 0;

    if (params->user_id) {
      offset += snprintf(query + offset, sizeof(query) - offset,
                         "?user_id=%" PRIu64, params->user_id);
      ASSERT_S(offset < sizeof(query), "Out of bounds write attempt");
    }
    if (params->action_type) {
      offset +=
        snprintf(query + offset, sizeof(query) - offset, "%saction_type=%d",
                 *query ? "&" : "?", params->action_type);
      ASSERT_S(offset < sizeof(query), "Out of bounds write attempt");
    }
    if (params->before) {
      offset +=
        snprintf(query + offset, sizeof(query) - offset, "%sbefore=%" PRIu64,
                 *query ? "&" : "?", params->before);
      ASSERT_S(offset < sizeof(query), "Out of bounds write attempt");
    }
    if (params->limit) {
      offset += snprintf(query + offset, sizeof(query) - offset, "%slimit=%d",
                         *query ? "&" : "?", params->limit);
      ASSERT_S(offset < sizeof(query), "Out of bounds write attempt");
    }
  }

  return discord_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/audit-logs%s", guild_id,
                             query);
}
