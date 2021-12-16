#define _GNU_SOURCE /* asprintf() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "reddit.h"
#include "reddit-internal.h"
#include "cee-utils.h"

static void
setopt_cb(struct ua_conn *conn, void *p_client)
{
  CURL *ehandle = ua_conn_get_easy_handle(conn);
  struct reddit *client = p_client;
  char client_id[512], client_secret[512], ua[512];
  int ret;

  ret = snprintf(client_id, sizeof(client_id), "%.*s",
                 (int)client->client_id.size, client->client_id.start);
  ASSERT_S(ret < sizeof(client_id), "Out of bounds write attempt");

  ret = snprintf(client_secret, sizeof(client_secret), "%.*s",
                 (int)client->client_secret.size, client->client_secret.start);
  ASSERT_S(ret < sizeof(client_secret), "Out of bounds write attempt");

  ret = snprintf(ua, sizeof(ua),
                 "orca:github.com/cee-studio/orca:v.0 (by /u/%.*s)",
                 (int)client->username.size, client->username.start);
  ASSERT_S(ret < sizeof(ua), "Out of bounds write attempt");

  ua_conn_add_header(conn, "User-Agent", ua);
  ua_conn_add_header(conn, "Content-Type",
                     "application/x-www-form-urlencoded");

  curl_easy_setopt(ehandle, CURLOPT_USERNAME, client_id);
  curl_easy_setopt(ehandle, CURLOPT_PASSWORD, client_secret);
}

void
reddit_adapter_init(struct reddit_adapter *adapter, struct logconf *conf)
{
  struct reddit *client = CONTAINEROF(adapter, struct reddit, adapter);
  struct ua_attr attr = { 0 };

  attr.conf = conf;
  adapter->ua = ua_init(&attr);

  logconf_branch(&adapter->conf, conf, "REDDIT_HTTP");
  ua_set_url(adapter->ua, REDDIT_BASE_OAUTH_URL);

  ua_set_opt(adapter->ua, client, &setopt_cb);
}

void
reddit_adapter_cleanup(struct reddit_adapter *adapter)
{
  if (adapter->auth) free(adapter->auth);
  ua_cleanup(adapter->ua);
}

static ORCAcode
_reddit_adapter_run_sync(struct reddit_adapter *adapter,
                         struct reddit_request_attr *attr,
                         struct sized_buffer *body,
                         enum http_method method,
                         char endpoint[])
{
  struct ua_conn_attr conn_attr = { method, body, endpoint, attr->base_url };
  struct ua_conn *conn = ua_conn_start(adapter->ua);
  ORCAcode code;
  bool retry;

  /* populate conn with parameters */
  ua_conn_setup(conn, &conn_attr);

  if (adapter->auth) {
    ua_conn_add_header(conn, "Authorization", adapter->auth);
  }

  do {
    /* perform blocking request, and check results */
    switch (code = ua_conn_perform(conn)) {
    case ORCA_OK: {
      struct ua_info info = { 0 };
      struct sized_buffer body;

      ua_info_extract(conn, &info);

      body = ua_info_get_body(&info);
      if (ORCA_OK == info.code && attr->obj) {
        if (attr->init) attr->init(attr->obj);

        attr->from_json(body.start, body.size, attr->obj);
      }

      ua_info_cleanup(&info);
    } break;
    case ORCA_CURLE_INTERNAL:
      logconf_error(&adapter->conf, "Curl internal error, will retry again");
      retry = true;
      break;
    default:
      logconf_error(&adapter->conf, "ORCA code: %d", code);
      retry = false;
      break;
    }

    ua_conn_reset(conn);
  } while (retry);

  ua_conn_stop(conn);

  return code;
}

/* template function for performing requests */
ORCAcode
reddit_adapter_run(struct reddit_adapter *adapter,
                   struct reddit_request_attr *attr,
                   struct sized_buffer *body,
                   enum http_method method,
                   char endpoint_fmt[],
                   ...)
{
  static struct reddit_request_attr blank_attr = { 0 };
  char endpoint[2048];
  va_list args;
  int ret;

  /* have it point somewhere */
  if (!attr) attr = &blank_attr;

  va_start(args, endpoint_fmt);

  ret = vsnprintf(endpoint, sizeof(endpoint), endpoint_fmt, args);
  ASSERT_S(ret < sizeof(endpoint), "Out of bounds write attempt");

  va_end(args);

  return _reddit_adapter_run_sync(adapter, attr, body, method, endpoint);
}
