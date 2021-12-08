#include <string.h>

#include "reddit.h"
#include "reddit-internal.h"

ORCAcode
reddit_access_token(struct reddit *client,
                    struct reddit_access_token_params *params,
                    struct sized_buffer *ret)
{
#if 0
  if (!params) {
    log_error("Missing 'params'");
    return ORCA_MISSING_PARAMETER;
  }
  if (!params->grant_type) {
    log_error("Missing 'params.grant_type'");
    return ORCA_MISSING_PARAMETER;
  }

  char query[1024];
  size_t len = 0;
  len += snprintf(query, sizeof(query), "grant_type=%s", params->grant_type);
  ASSERT_S(len < sizeof(query), "Out of bounds write attempt");

  if (STREQ(params->grant_type, "password")) { // script apps
    if (IS_EMPTY_STRING(params->username)) {
      if (!client->username.size) {
        log_error("Missing 'params.username'");
        return ORCA_MISSING_PARAMETER;
      }
      len += snprintf(query + len, sizeof(query) - len, "&username=%.*s",
                      (int)client->username.size, client->username.start);
    }
    else {
      len += snprintf(query + len, sizeof(query) - len, "&username=%s",
                      params->username);
    }

    if (IS_EMPTY_STRING(params->password)) {
      if (!client->password.size) {
        log_error("Missing 'params.password'");
        return ORCA_MISSING_PARAMETER;
      }
      len += snprintf(query + len, sizeof(query) - len, "&password=%.*s",
                      (int)client->password.size, client->password.start);
    }
    else {
      len += snprintf(query + len, sizeof(query) - len, "&password=%s",
                      params->password);
    }
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }
  else if (STREQ(params->grant_type, "authorization_code")) { // web apps
    if (IS_EMPTY_STRING(params->code)) {
      log_error("Missing 'params.code'");
      return ORCA_MISSING_PARAMETER;
    }
    if (IS_EMPTY_STRING(params->redirect_uri)) {
      log_error("Missing 'params.redirect_uri'");
      return ORCA_MISSING_PARAMETER;
    }
    len +=
      snprintf(query + len, sizeof(query) - len, "&code=%s&redirect_uri=%s",
               params->code, params->redirect_uri);
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }
  else if (!STREQ(params->grant_type, "refresh_token")) {
    log_error("Unknown 'grant_type' value (%s)", params->grant_type);
    return ORCA_BAD_PARAMETER;
  }

  ua_set_url(client->adapter.ua, BASE_API_URL);

  struct sized_buffer resp_body = { 0 };
  ORCAcode code;
  code = reddit_adapter_run(&client->adapter, &resp_body,
                            &(struct sized_buffer){ query, len }, HTTP_POST,
                            "/api/v1/access_token");

  char access_token[64], token_type[64];
  json_extract(resp_body.start, resp_body.size,
               "(access_token):.*s"
               "(token_type):.*s",
               sizeof(access_token), access_token, sizeof(token_type),
               token_type);

  char auth[256];
  len = snprintf(auth, sizeof(auth), "%s %s", token_type, access_token);
  ASSERT_S(len < sizeof(auth), "Out of bounds write attempt");

  ua_reqheader_add(client->adapter.ua, "Authorization", auth);
  ua_set_url(client->adapter.ua, BASE_OAUTH_URL);

  if (ret)
    memcpy(ret, &resp_body, sizeof(struct sized_buffer));
  else
    free(resp_body.start);

  return code;
#else
  return -1;
#endif
}
