#include <string.h>

#include "slack.h"
#include "slack-internal.h"

ORCAcode
slack_users_info(struct slack *client,
                 struct slack_users_info_params *params,
                 struct sized_buffer *ret)
{
  if (!params) {
    log_error("Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }
  if (IS_EMPTY_STRING(params->user)) {
    log_error("Missing 'params.user'");
    return ORCA_MISSING_PARAMETER;
  }

  char query[4096];
  size_t len = 0;

  len += snprintf(query + len, sizeof(query) - len, "user=%s", params->user);
  ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  if (params->token) {
    len +=
      snprintf(query + len, sizeof(query) - len, "&token=%s", params->token);
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }
  if (params->include_locale) {
    len += snprintf(query + len, sizeof(query) - len, "&include_locale=true");
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }

  return slack_webapi_run(&client->webapi, ret,
                          &(struct sized_buffer){ query, len }, HTTP_POST,
                          "/users.info");
}
