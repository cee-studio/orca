#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "discord.h"
#include "discord-internal.h"

static void
setopt_cb(struct ua_conn *conn, void *p_token)
{
  struct sized_buffer *token = p_token;
  char auth[128];
  int ret;

  ret =
    snprintf(auth, sizeof(auth), "Bot %.*s", (int)token->size, token->start);
  ASSERT_S(ret < sizeof(auth), "Out of bounds write attempt");

  ua_conn_add_header(conn, "Authorization", auth);
}

void
discord_adapter_init(struct discord_adapter *adapter,
                     struct logconf *conf,
                     struct sized_buffer *token)
{
  struct ua_attr attr = { 0 };

  attr.conf = conf;
  adapter->ua = ua_init(&attr);
  ua_set_url(adapter->ua, DISCORD_API_BASE_URL);

  if (!token->size) {
    /* no token means a webhook-only client */
    logconf_branch(&adapter->conf, conf, "DISCORD_WEBHOOK");
  }
  else {
    /* bot client */
    logconf_branch(&adapter->conf, conf, "DISCORD_HTTP");
    ua_set_opt(adapter->ua, token, &setopt_cb);
  }

  /* initialize ratelimit handler */
  discord_ratelimit_init(&adapter->rlimit, &adapter->conf);
}

void
discord_adapter_cleanup(struct discord_adapter *adapter)
{
  /* cleanup User-Agent handle */
  ua_cleanup(adapter->ua);

  /* cleanup ratelimit handle */
  discord_ratelimit_cleanup(&adapter->rlimit);
}

/* template function for performing requests */
ORCAcode
discord_adapter_run(struct discord_adapter *adapter,
                    struct discord_request_attr *attr,
                    struct sized_buffer *body,
                    enum http_method method,
                    char endpoint_fmt[],
                    ...)
{
  char endpoint[2048];
  va_list args;
  int ret;

  /* build the endpoint string */
  va_start(args, endpoint_fmt);

  ret = vsnprintf(endpoint, sizeof(endpoint), endpoint_fmt, args);
  ASSERT_S(ret < sizeof(endpoint), "Out of bounds write attempt");

  va_end(args);

  /* enqueue asynchronous request */
  if (true == adapter->async_enable) {
    adapter->async_enable = false;
    return discord_request_perform_async(&adapter->rlimit, attr, body, method,
                                         endpoint);
  }

  /* perform blocking request */
  return discord_request_perform(&adapter->rlimit, attr, body, method,
                                 endpoint);
}

void
discord_adapter_set_async(struct discord_adapter *adapter,
                          struct discord_async_attr *attr)
{
  adapter->async_enable = true;
  memcpy(&adapter->rlimit.async.attr, attr, sizeof(struct discord_async_attr));
}
