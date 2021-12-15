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

#if 0 /* enable for debugging */
  curl_easy_setopt(ua_conn_get_easy_handle(conn), CURLOPT_VERBOSE, 1L);
#endif
}

void
discord_adapter_init(struct discord_adapter *adapter,
                     struct logconf *conf,
                     struct sized_buffer *token)
{
  const struct sized_buffer hash = { "null", 4 };
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

  adapter->mhandle = curl_multi_init();

  /* global ratelimiting resources */
  adapter->global = calloc(1, sizeof *adapter->global);
  if (pthread_rwlock_init(&adapter->global->rwlock, NULL))
    ERR("Couldn't initialize pthread rwlock");
  if (pthread_mutex_init(&adapter->global->lock, NULL))
    ERR("Couldn't initialize pthread mutex");

  /* for routes that still haven't discovered a bucket match */
  adapter->b_null = discord_bucket_init(adapter, "", &hash, 1L);

  /* idleq is malloc'd to guarantee a client cloned by discord_clone() will
   * share the same queue with the original */
  adapter->async.idleq = malloc(sizeof(QUEUE));
  QUEUE_INIT(adapter->async.idleq);
  /* initialize min-heap for handling request timeouts */
  heap_init(&adapter->async.timeouts);
}

static void
_discord_context_cleanup(struct discord_context *cxt)
{
  if (cxt->body.buf.start) free(cxt->body.buf.start);
  free(cxt);
}

void
discord_adapter_cleanup(struct discord_adapter *adapter)
{
  struct discord_context *cxt;
  QUEUE queue;
  QUEUE *q;

  /* cleanup User-Agent handle */
  ua_cleanup(adapter->ua);

  curl_multi_cleanup(adapter->mhandle);

  /* move pending requests to idle */
  discord_request_stop_all(adapter);

  discord_buckets_cleanup(adapter);

  /* cleanup global resources */
  pthread_rwlock_destroy(&adapter->global->rwlock);
  pthread_mutex_destroy(&adapter->global->lock);
  free(adapter->global);

  /* cleanup idle requests queue */
  QUEUE_MOVE(adapter->async.idleq, &queue);
  while (!QUEUE_EMPTY(&queue)) {
    q = QUEUE_HEAD(&queue);
    cxt = QUEUE_DATA(q, struct discord_context, entry);
    QUEUE_REMOVE(&cxt->entry);
    _discord_context_cleanup(cxt);
  }

  if (adapter->async.obj.size) free(adapter->async.obj.start);

  free(adapter->async.idleq);
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
  static struct discord_request_attr blank_attr = { 0 };
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

  /* enqueue asynchronous request */
  if (true == adapter->async_enable) {
    adapter->async_enable = false;
    return discord_request_run_async(adapter, attr, body, method, endpoint);
  }

  /* perform blocking request */
  return discord_request_run(adapter, attr, body, method, endpoint);
}

void
discord_adapter_set_async(struct discord_adapter *adapter,
                          struct discord_async_attr *attr)
{
  adapter->async_enable = true;
  memcpy(&adapter->async.attr, attr, sizeof(struct discord_async_attr));
}
