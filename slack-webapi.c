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
  ua_conn_add_header(webapi->ua, "Content-type",
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
  webapi->ua = ua_init(&(struct ua_attr){ .conf = conf });
  ua_set_url(webapi->ua, SLACK_BASE_API_URL);
  logconf_branch(&webapi->conf, conf, "SLACK_WEBAPI");

  if (STRNEQ("YOUR-BOT-TOKEN", token->start, token->size)) {
    token->start = NULL;
  }
  ASSERT_S(NULL != token->start, "Missing bot token");

  ua_set_opt(adapter->ua, token, &setopt_cb);
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

ORCAcode
slack_apps_connections_open(struct slack *client, struct sized_buffer *ret)
{
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
}

ORCAcode
slack_auth_test(struct slack *client, struct sized_buffer *ret)
{
  return slack_webapi_run(&client->webapi, ret, NULL, HTTP_POST,
                          "/auth.test");
}

ORCAcode
slack_chat_post_message(struct slack *client,
                        struct slack_chat_post_message_params *params,
                        struct sized_buffer *ret)
{
#if 0
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->channel), ORCA_BAD_PARAMETER);

  char *payload = NULL;
  size_t len = json_ainject(&payload,
                            "(token):s"
                            "(channel):s"
#if 0
                "(as_user):b"
#endif
                            "(icon_url):s"
                            "(icon_emoji):s"
                            "(text):s"
                            "(thread_ts):s"
                            "(username):s",
                            params->token, params->channel,
#if 0
                &params->as_user,
#endif
                            params->icon_url, params->icon_emoji, params->text,
                            params->thread_ts, params->username);

  if (!payload) {
    log_error("Couldn't create payload");
    return ORCA_BAD_PARAMETER;
  }

  ua_reqheader_add(client->webapi.ua, "Content-type", "application/json");

  ORCAcode code;
  code = slack_webapi_run(&client->webapi, ret,
                          &(struct sized_buffer){ payload, len }, HTTP_POST,
                          "/chat.postMessage");

  ua_reqheader_add(client->webapi.ua, "Content-type",
                   "application/x-www-form-urlencoded");

  free(payload);

  return code;
#else
  return -1;
#endif
}

ORCAcode
slack_users_info(struct slack *client,
                 struct slack_users_info_params *params,
                 struct sized_buffer *ret)
{
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->user), ORCA_BAD_PARAMETER);

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
