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

  char client_id[512], client_secret[512], auth[512];
  int ret;

  ret = snprintf(client_id, sizeof(client_id), "%.*s",
                 (int)client->client_id.size, client->client_id.start);
  ASSERT_S(ret < sizeof(client_id), "Out of bounds write attempt");

  ret = snprintf(client_secret, sizeof(client_secret), "%.*s",
                 (int)client->client_secret.size, client->client_secret.start);
  ASSERT_S(ret < sizeof(client_secret), "Out of bounds write attempt");

  ret = snprintf(auth, sizeof(auth),
                 "orca:github.com/cee-studio/orca:v.0 (by /u/%.*s)",
                 (int)client->username.size, client->username.start);
  ASSERT_S(ret < sizeof(auth), "Out of bounds write attempt");

  ua_conn_add_header(conn, "User-Agent", auth);
  ua_conn_add_header(conn, "Content-Type",
                     "application/x-www-form-urlencoded");

  curl_easy_setopt(ehandle, CURLOPT_USERNAME, client_id);
  curl_easy_setopt(ehandle, CURLOPT_PASSWORD, client_secret);
}

void
reddit_adapter_init(struct reddit_adapter *adapter, struct logconf *conf)
{
  adapter->ua = ua_init(&(struct ua_attr){ .conf = conf });

  ua_set_url(adapter->ua, BASE_API_URL);
  logconf_branch(&adapter->conf, conf, "REDDIT_HTTP");

  ua_set_opt(adapter->ua, adapter->p_client, &setopt_cb);
}

void
reddit_adapter_cleanup(struct reddit_adapter *adapter)
{
  ua_cleanup(adapter->ua);
}

static void
sized_buffer_from_json(char *json, size_t len, void *data)
{
  struct sized_buffer *p = data;
  p->size = asprintf(&p->start, "%.*s", (int)len, json);
}

/* template function for performing requests */
ORCAcode
reddit_adapter_run(struct reddit_adapter *adapter,
                   struct sized_buffer *resp_body,
                   struct sized_buffer *req_body,
                   enum http_method http_method,
                   char endpoint_fmt[],
                   ...)
{
  va_list args;
  char endpoint[2048];

  va_start(args, endpoint_fmt);
  int ret = vsnprintf(endpoint, sizeof(endpoint), endpoint_fmt, args);
  ASSERT_S(ret < sizeof(endpoint), "Out of bounds write attempt");

  ORCAcode code;
  code = ua_run(adapter->ua, NULL,
                &(struct ua_resp_handle){
                  .ok_cb = resp_body ? &sized_buffer_from_json : NULL,
                  .ok_obj = resp_body },
                req_body, http_method, endpoint);

  va_end(args);

  return code;
}
