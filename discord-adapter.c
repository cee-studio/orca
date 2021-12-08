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

  /* idleq is malloc'd to guarantee a client cloned by discord_clone() will
   * share the same queue with the original */
  adapter->idleq = malloc(sizeof(QUEUE));
  QUEUE_INIT(adapter->idleq);
}

void
discord_adapter_cleanup(struct discord_adapter *adapter)
{
  struct discord_request *cxt;
  QUEUE queue;
  QUEUE *q;

  /* cleanup User-Agent handle */
  ua_cleanup(adapter->ua);

  /* cleanup request's informational handle */
  ua_info_cleanup(&adapter->err.info);

  /* cleanup ratelimit handle */
  discord_ratelimit_cleanup(&adapter->rlimit);

  /* cleanup idle requests queue */
  QUEUE_MOVE(adapter->idleq, &queue);
  while (!QUEUE_EMPTY(&queue)) {
    q = QUEUE_HEAD(&queue);
    cxt = QUEUE_DATA(q, struct discord_request, entry);
    QUEUE_REMOVE(&cxt->entry);
    discord_request_cleanup(cxt);
  }

  if (adapter->obj.size) free(adapter->obj.buf);

  free(adapter->idleq);
}

/* template function for performing requests */
ORCAcode
discord_adapter_run(struct discord_adapter *adapter,
                    struct ua_resp_handle *handle,
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

  /* enqueue request */
  if (true == adapter->toggle_async) {
    struct discord_request_attr *attr = &adapter->attr;

    adapter->toggle_async = false; /* reset */
    return discord_request_perform_async(adapter, attr, handle, body, method,
                                         endpoint);
  }

  /* blocking request */
  return discord_request_perform(adapter, handle, body, method, endpoint);
}

void
discord_adapter_toggle_async(struct discord_adapter *adapter,
                             struct discord_request_attr *attr)
{
  adapter->toggle_async = true;

  if (attr)
    memcpy(&adapter->attr, attr, sizeof(struct discord_request_attr));
  else
    memset(&adapter->attr, 0, sizeof(struct discord_request_attr));
}
