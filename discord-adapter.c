#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include "discord.h"
#include "discord-internal.h"

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
    char auth[128];
    int ret;

    /* bot client */
    logconf_branch(&adapter->conf, conf, "DISCORD_HTTP");

    ret =
      snprintf(auth, sizeof(auth), "Bot %.*s", (int)token->size, token->start);
    ASSERT_S(ret < sizeof(auth), "Out of bounds write attempt");

    ua_reqheader_add(adapter->ua, "Authorization", auth);
  }
  /* initialize ratelimit handler */
  discord_ratelimit_init(&adapter->rlimit, &adapter->conf);

  /* idleq is allocated to guarantee a client cloned by discord_clone() will
   * share the same queue */
  adapter->idleq = malloc(sizeof(QUEUE));
  QUEUE_INIT(adapter->idleq);
}

void
discord_adapter_cleanup(struct discord_adapter *adapter)
{
  struct discord_request *cxt;
  QUEUE queue;

  /* cleanup User-Agent handle */
  ua_cleanup(adapter->ua);
  /* cleanup request's informational handle */
  ua_info_cleanup(&adapter->err.info);
  /* cleanup ratelimit handle */
  discord_ratelimit_cleanup(&adapter->rlimit);
  /* cleanup idle requests queue */
  QUEUE_MOVE(adapter->idleq, &queue);
  while (!QUEUE_EMPTY(&queue)) {
    QUEUE *q = QUEUE_HEAD(&queue);
    cxt = QUEUE_DATA(q, struct discord_request, entry);
    QUEUE_REMOVE(&cxt->entry);
    discord_request_cleanup(cxt);
  }
  free(adapter->idleq);
}

/* template function for performing requests */
ORCAcode
discord_adapter_run(struct discord_adapter *adapter,
                    struct ua_resp_handle *resp_handle,
                    struct sized_buffer *req_body,
                    enum http_method method,
                    char endpoint_fmt[],
                    ...)
{
  /* fully-formed endpoint string */
  char endpoint[2048];
  /* variable arguments for endpoint formation */
  va_list args;
  /* vsnprintf OOB check */
  int ret;

  /* build the endpoint string */
  va_start(args, endpoint_fmt);
  ret = vsnprintf(endpoint, sizeof(endpoint), endpoint_fmt, args);
  ASSERT_S(ret < sizeof(endpoint), "Out of bounds write attempt");
  va_end(args);

  /* non-blocking request */
  if (true == adapter->async.enable) {
    struct discord_async_attr *attr = &adapter->async.attr;
    adapter->async.enable = false; /* reset */

    return discord_request_perform_async(adapter, attr, resp_handle, req_body,
                                         method, endpoint);
  }
  /* blocking request */
  return discord_request_perform(adapter, resp_handle, req_body, method,
                                 endpoint);
}

void
discord_adapter_set_async(struct discord_adapter *adapter,
                          struct discord_async_attr *attr)
{
  adapter->async.enable = true;

  if (attr)
    memcpy(&adapter->async.attr, attr, sizeof(struct discord_async_attr));
  else
    memset(&adapter->async.attr, 0, sizeof(struct discord_async_attr));
}
