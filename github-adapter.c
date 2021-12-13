#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "github.h"
#include "github-internal.h"

#include "cee-utils.h"

#define GITHUB_BASE_API_URL "https://api.github.com"

static void
setopt_cb(struct ua_conn *conn, void *p_presets)
{
  struct github_presets *presets = p_presets;
  CURL *ehandle = ua_conn_get_easy_handle(conn);

  ua_conn_add_header(conn, "Accept", "application/vnd.github.v3+json");

  curl_easy_setopt(ehandle, CURLOPT_USERNAME, presets->username);
  curl_easy_setopt(ehandle, CURLOPT_USERPWD, presets->token);
}

void
github_adapter_init(struct github_adapter *adapter,
                    struct logconf *conf,
                    struct github_presets *presets)
{
  struct ua_attr attr = { 0 };

  attr.conf = conf;
  adapter->ua = ua_init(&attr);
  ua_set_url(adapter->ua, GITHUB_BASE_API_URL);

  logconf_branch(&adapter->conf, conf, "GITHUB_HTTP");

  ua_set_opt(adapter->ua, presets, &setopt_cb);
}

void
github_adapter_cleanup(struct github_adapter *adapter)
{
  ua_cleanup(adapter->ua);
}

static ORCAcode
_github_adapter_perform(struct github_adapter *adapter,
                       struct github_request_attr *attr,
                       struct sized_buffer *body,
                       enum http_method method,
                       char endpoint[])
{
  struct ua_conn *conn = ua_conn_start(adapter->ua);
  ORCAcode code;
  bool retry;

  /* populate conn with parameters */
  ua_conn_setup(conn, body, method, endpoint);

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
github_adapter_run(struct github_adapter *adapter,
                   struct github_request_attr *attr,
                   struct sized_buffer *body,
                   enum http_method method,
                   char endpoint_fmt[],
                   ...)
{
  static struct github_request_attr blank_attr = { 0 };
  char endpoint[2048];
  va_list args;
  int ret;

  /* have it point somewhere */
  if (!attr) attr = &blank_attr;

  /* build the endpoint string */
  va_start(args, endpoint_fmt);

  ret = vsnprintf(endpoint, sizeof(endpoint), endpoint_fmt, args);
  ASSERT_S(ret < sizeof(endpoint), "Out of bounds write attempt");

  va_end(args);

  return _github_adapter_perform(adapter, attr, body, method, endpoint);
}
