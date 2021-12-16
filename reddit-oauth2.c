#include <string.h>

#include "reddit.h"
#include "reddit-internal.h"

ORCAcode
reddit_access_token(struct reddit *client,
                    struct reddit_access_token_params *params,
                    struct sized_buffer *ret)
{
  struct reddit_request_attr attr = {
    ret,  0,
    NULL, (void (*)(char *, size_t, void *)) & cee_sized_buffer_from_json,
    NULL, REDDIT_BASE_API_URL
  };
  struct sized_buffer body;
  char buf[1024];
  size_t len = 0;
  ORCAcode code;

  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->grant_type),
              ORCA_BAD_PARAMETER);

  len += snprintf(buf, sizeof(buf), "grant_type=%s", params->grant_type);
  ASSERT_S(len < sizeof(buf), "Out of bounds write attempt");

  if (STREQ(params->grant_type, "password")) { // script apps
    if (IS_EMPTY_STRING(params->username)) {
      ORCA_EXPECT(client, client->username.size != 0, ORCA_BAD_PARAMETER);

      len += snprintf(buf + len, sizeof(buf) - len, "&username=%.*s",
                      (int)client->username.size, client->username.start);
    }
    else {
      len += snprintf(buf + len, sizeof(buf) - len, "&username=%s",
                      params->username);
    }

    if (IS_EMPTY_STRING(params->password)) {
      ORCA_EXPECT(client, client->password.size != 0, ORCA_BAD_PARAMETER);

      len += snprintf(buf + len, sizeof(buf) - len, "&password=%.*s",
                      (int)client->password.size, client->password.start);
    }
    else {
      len += snprintf(buf + len, sizeof(buf) - len, "&password=%s",
                      params->password);
    }
    ASSERT_S(len < sizeof(buf), "Out of bounds write attempt");
  }
  else if (STREQ(params->grant_type, "authorization_code")) { // web apps
    ORCA_EXPECT(client, !IS_EMPTY_STRING(params->code), ORCA_BAD_PARAMETER);
    ORCA_EXPECT(client, !IS_EMPTY_STRING(params->redirect_uri),
                ORCA_BAD_PARAMETER);

    len += snprintf(buf + len, sizeof(buf) - len, "&code=%s&redirect_uri=%s",
                    params->code, params->redirect_uri);
    ASSERT_S(len < sizeof(buf), "Out of bounds write attempt");
  }
  else if (!STREQ(params->grant_type, "refresh_token")) {
    logconf_error(&client->conf, "Unknown 'grant_type' value (%s)",
                  params->grant_type);
    return ORCA_BAD_PARAMETER;
  }

  body.start = buf;
  body.size = len;

  code = reddit_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                            "/api/v1/access_token");

  if (ORCA_OK == code) {
    char access_token[64], token_type[64], auth[256];
    int len;

    json_extract(ret->start, ret->size,
                 "(access_token):.*s"
                 "(token_type):.*s",
                 sizeof(access_token), access_token, sizeof(token_type),
                 token_type);

    len = snprintf(auth, sizeof(auth), "%s %s", token_type, access_token);
    ASSERT_S(len < sizeof(auth), "Out of bounds write attempt");

    if (!client->adapter.auth) {
      client->adapter.auth = malloc(sizeof(auth));
    }
    memcpy(client->adapter.auth, auth, sizeof(auth));
    client->adapter.auth[len] = '\0';
  }

  return code;
}
