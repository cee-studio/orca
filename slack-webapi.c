#define _GNU_SOURCE /* asprintf() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "slack.h"
#include "slack-internal.h"

static void
setopt_cb(struct ua_conn *conn, void *p_token)
{
  struct sized_buffer *token = p_token;
  char auth[128];
  int ret;

  ret = snprintf(auth, sizeof(auth), "Bearer %.*s", (int)token->size,
                 token->start);
  ASSERT_S(ret < sizeof(auth), "Out of bounds write attempt");

  ua_conn_add_header(conn, "Authorization", auth);
  ua_conn_add_header(conn, "Content-type",
                     "application/x-www-form-urlencoded");

#if 0 /* enable for debugging */
  curl_easy_setopt(ua_conn_get_easy_handle(conn), CURLOPT_VERBOSE, 1L);
#endif
}

void
slack_webapi_init(struct slack_webapi *webapi,
                  struct logconf *conf,
                  struct sized_buffer *token)
{
  struct ua_attr attr = { 0 };

  attr.conf = conf;
  webapi->ua = ua_init(&attr);
  ua_set_url(webapi->ua, SLACK_BASE_API_URL);
  logconf_branch(&webapi->conf, conf, "SLACK_WEBAPI");

  if (STRNEQ("YOUR-BOT-TOKEN", token->start, token->size)) {
    token->start = NULL;
  }
  ASSERT_S(NULL != token->start, "Missing bot token");

  ua_set_opt(webapi->ua, token, &setopt_cb);
}

void
slack_webapi_cleanup(struct slack_webapi *webapi)
{
  ua_cleanup(webapi->ua);
}

/* template function for performing requests */
ORCAcode
slack_webapi_run(struct slack_webapi *webapi,
                 struct slack_request_attr *attr,
                 struct sized_buffer *body,
                 enum http_method method,
                 char endpoint_fmt[],
                 ...)
{
  char endpoint[2048];
  va_list args;
  size_t len;

  struct ua_resp_handle handle = { attr->obj, 0, NULL, attr->from_json };
  struct ua_conn_attr conn_attr = { method, body, endpoint };

  va_start(args, endpoint_fmt);

  len = vsnprintf(endpoint, sizeof(endpoint), endpoint_fmt, args);
  ASSERT_S(len < sizeof(endpoint), "Out of bounds write attempt");

  va_end(args);

  return ua_easy_run(webapi->ua, NULL, &handle, &conn_attr);
}

/******************************************************************************
 * Functions specific to Slack Apps
 ******************************************************************************/

ORCAcode
slack_apps_connections_open(struct slack *client, struct sized_buffer *ret)
{
  struct slack_request_attr attr = { ret, 0, NULL,
                                     (void (*)(char *, size_t, void *))
                                       & cee_sized_buffer_from_json };
  char auth[128] = "";
  size_t len;

  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->bot_token.start),
              ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->app_token.start),
              ORCA_BAD_PARAMETER);

  len = snprintf(auth, sizeof(auth), "Bearer %.*s",
                 (int)client->app_token.size, client->app_token.start);
  ASSERT_S(len < sizeof(auth), "Out of bounds write attempt");
  ua_reqheader_add(client->webapi.ua, "Authorization", auth);

  ORCAcode code;
  code = slack_webapi_run(&client->webapi, &attr, NULL, HTTP_POST,
                          "/apps.connections.open");

  len = snprintf(auth, sizeof(auth), "Bearer %.*s",
                 (int)client->bot_token.size, client->bot_token.start);
  ASSERT_S(len < sizeof(auth), "Out of bounds write attempt");
  ua_reqheader_add(client->webapi.ua, "Authorization", auth);

  return code;
}

/******************************************************************************
 * Functions specific to Slack Auth
 ******************************************************************************/

ORCAcode
slack_auth_test(struct slack *client, struct sized_buffer *ret)
{
  struct slack_request_attr attr = { ret, 0, NULL,
                                     (void (*)(char *, size_t, void *))
                                       & cee_sized_buffer_from_json };

  return slack_webapi_run(&client->webapi, &attr, NULL, HTTP_POST,
                          "/auth.test");
}

/******************************************************************************
 * Functions specific to Slack Chat
 ******************************************************************************/

ORCAcode
slack_chat_post_message(struct slack *client,
                        struct slack_chat_post_message_params *params,
                        struct sized_buffer *ret)
{
  struct slack_request_attr attr = {
    ret,  0,
    NULL, (void (*)(char *, size_t, void *)) & cee_sized_buffer_from_json,
    NULL, "application/json"
  };
  struct sized_buffer body;
  char buf[16384]; /**< @todo dynamic buffer */

  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->channel), ORCA_BAD_PARAMETER);

  body.size = slack_chat_post_message_params_to_json(buf, sizeof(buf), params);
  body.start = buf;

  return slack_webapi_run(&client->webapi, &attr, &body, HTTP_POST,
                          "/chat.postMessage");
}

/******************************************************************************
 * Functions specific to Slack Users
 ******************************************************************************/

ORCAcode
slack_users_info(struct slack *client,
                 struct slack_users_info_params *params,
                 struct sized_buffer *ret)
{
  struct slack_request_attr attr = { ret, 0, NULL,
                                     (void (*)(char *, size_t, void *))
                                       & cee_sized_buffer_from_json };
  struct sized_buffer body;
  char buf[4096];
  size_t len;

  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->user), ORCA_BAD_PARAMETER);

  len = snprintf(buf, sizeof(buf), "user=%s", params->user);
  ASSERT_S(len < sizeof(buf), "Out of bounds write attempt");

  if (params->token) {
    len += snprintf(buf + len, sizeof(buf) - len, "&token=%s", params->token);
    ASSERT_S(len < sizeof(buf), "Out of bounds write attempt");
  }
  if (params->include_locale) {
    len += snprintf(buf + len, sizeof(buf) - len, "&include_locale=true");
    ASSERT_S(len < sizeof(buf), "Out of bounds write attempt");
  }

  body.start = buf;
  body.size = len;

  return slack_webapi_run(&client->webapi, &attr, &body, HTTP_POST,
                          "/users.info");
}
