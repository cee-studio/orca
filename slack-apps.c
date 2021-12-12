#include <string.h>

#include "slack.h"
#include "slack-internal.h"

ORCAcode
slack_apps_connections_open(struct slack *client, struct sized_buffer *ret)
{
#if 0
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->bot_token.start), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->app_token.start), ORCA_BAD_PARAMETER);

  char auth[128] = "";
  size_t len;

  len = snprintf(auth, sizeof(auth), "Bearer %.*s",
                 (int)client->app_token.size, client->app_token.start);
  ASSERT_S(len < sizeof(auth), "Out of bounds write attempt");
  ua_reqheader_add(client->webapi.ua, "Authorization", auth);

  ORCAcode code;
  code = slack_webapi_run(&client->webapi, ret, NULL, HTTP_POST,
                          "/apps.connections.open");

  len = snprintf(auth, sizeof(auth), "Bearer %.*s",
                 (int)client->bot_token.size, client->bot_token.start);
  ASSERT_S(len < sizeof(auth), "Out of bounds write attempt");
  ua_reqheader_add(client->webapi.ua, "Authorization", auth);

  return code;
#else
  return -1;
#endif
}
