#define _GNU_SOURCE /* asprintf() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "slack.h"
#include "slack-internal.h"
#include "cee-utils.h"

#define SLACK_BASE_API_URL "https://slack.com/api"

void
slack_webapi_init(struct slack_webapi *webapi,
                  struct logconf *conf,
                  struct sized_buffer *token)
{
#if 0
  webapi->ua = ua_init(&(struct ua_attr){ .conf = conf });
  ua_set_url(webapi->ua, SLACK_BASE_API_URL);
  logconf_branch(&webapi->conf, conf, "SLACK_WEBAPI");

  if (STRNEQ("YOUR-BOT-TOKEN", token->start, token->size)) {
    token->start = NULL;
  }
  ASSERT_S(NULL != token->start, "Missing bot token");

  char auth[128];
  int ret = snprintf(auth, sizeof(auth), "Bearer %.*s", (int)token->size,
                     token->start);
  ASSERT_S(ret < sizeof(auth), "Out of bounds write attempt");

  ua_reqheader_add(webapi->ua, "Authorization", auth);
  ua_reqheader_add(webapi->ua, "Content-type",
                   "application/x-www-form-urlencoded");
#endif
}

void
slack_webapi_cleanup(struct slack_webapi *webapi)
{
  ua_cleanup(webapi->ua);
}

/* template function for performing requests */
ORCAcode
slack_webapi_run(struct slack_webapi *webapi,
                 struct sized_buffer *ret,
                 struct sized_buffer *body,
                 enum http_method method,
                 char endpoint_fmt[],
                 ...)
{
  struct ua_resp_handle handle = { ret
                                     ? (void (*)(char *, size_t, void *))
                                         & cee_sized_buffer_from_json
                                     : NULL,
                                   ret };
  struct ua_conn_attr conn_attr = { 0 };
  char endpoint[2048];
  va_list args;
  size_t len;

  va_start(args, endpoint_fmt);

  len = vsnprintf(endpoint, sizeof(endpoint), endpoint_fmt, args);
  ASSERT_S(len < sizeof(endpoint), "Out of bounds write attempt");

  va_end(args);

  conn_attr.method = method;
  conn_attr.body = body;
  conn_attr.endpoint = endpoint;

  return ua_easy_run(webapi->ua, NULL, &handle, &conn_attr);
}
