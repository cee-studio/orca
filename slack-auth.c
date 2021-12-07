#include "slack.h"
#include "slack-internal.h"

ORCAcode
slack_auth_test(struct slack *client, struct sized_buffer *ret)
{
  return slack_webapi_run(&client->webapi, ret, NULL, HTTP_POST,
                          "/auth.test");
}
