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
  struct ua_resp_handle handle = { &discord_audit_log_from_json_v, ret };
  char query[1024] = "";

  if (!guild_id) {
    logconf_error(&client->conf, "Missing 'guild_id'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!ret) {
    logconf_error(&client->conf, "Missing 'ret'");
    return ORCA_MISSING_PARAMETER;
  }

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

  return discord_adapter_run(&client->adapter, &handle, NULL, HTTP_GET,
                             "/guilds/%" PRIu64 "/audit-logs%s", guild_id,
                             query);
}
