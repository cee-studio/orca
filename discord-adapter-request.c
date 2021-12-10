#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "discord.h"
#include "discord-internal.h"

#include "cee-utils.h"

/* get client from ratelimit pointer */
#define CLIENT(p_rlimit)                                                      \
  ((struct discord *)((int8_t *)(p_rlimit)-offsetof(struct discord,           \
                                                    adapter.rlimit)))

/* get request context from heap node */
#define CXT(p_node)                                                           \
  ((struct discord_request *)((int8_t *)(p_node)-offsetof(                    \
    struct discord_request, node)))

static int
timer_less_than(const struct heap_node *ha, const struct heap_node *hb)
{
  const struct discord_request *a = CXT(ha);
  const struct discord_request *b = CXT(hb);

  return a->timeout_ms <= b->timeout_ms;
}

static void
_discord_request_reset(struct discord_request *cxt)
{
  cxt->bucket = NULL;
  cxt->done = NULL;
  memset(&cxt->attr, 0, sizeof(struct discord_request_attr));
  *cxt->endpoint = '\0';
  cxt->conn = NULL;
}

void
discord_request_cleanup(struct discord_request *cxt)
{
  if (cxt->body.start) free(cxt->body.start);
  _discord_request_reset(cxt);
  free(cxt);
}

static void
_discord_request_populate(struct discord_request *cxt,
                          struct discord_adapter *adapter,
                          struct discord_request_attr *attr,
                          struct sized_buffer *body,
                          enum http_method method,
                          char endpoint[])
{
  cxt->method = method;
  cxt->done = adapter->async.attr.done;

  if (attr)
    memcpy(&cxt->attr, attr, sizeof(struct discord_request_attr));
  else
    memset(&cxt->attr, 0, sizeof(struct discord_request_attr));

  if (body) {
    /* copy request body */
    if (body->size > cxt->body.memsize) {
      /* needs to increase buffer size */
      void *tmp = realloc(cxt->body.start, body->size);
      ASSERT_S(tmp != NULL, "Out of memory");

      cxt->body.start = tmp;
      cxt->body.memsize = body->size;
    }
    memcpy(cxt->body.start, body->start, body->size);
    cxt->body.size = body->size;
  }

  /* copy endpoint over to cxt */
  memcpy(cxt->endpoint, endpoint, sizeof(cxt->endpoint));

  /* bucket pertaining to the request */
  cxt->bucket = discord_bucket_get(&adapter->rlimit, cxt->endpoint);
}

static void
_discord_request_set_timeout(struct discord_ratelimit *rlimit,
                             u64_unix_ms_t timeout,
                             struct discord_request *cxt)
{
  cxt->bucket->freeze = true;
  cxt->timeout_ms = timeout;
  heap_insert(&rlimit->timeouts, &cxt->node, &timer_less_than);
}

/* return true if there should be a retry attempt */
static bool
_discord_request_check_status(struct discord_adapter *adapter,
                              ORCAcode *code,
                              struct discord_request *cxt)
{
  if (*code != ORCA_HTTP_CODE) return false;

  switch (adapter->err.info.httpcode) {
  case HTTP_FORBIDDEN:
  case HTTP_NOT_FOUND:
  case HTTP_BAD_REQUEST:
    *code = ORCA_DISCORD_JSON_CODE;
    return false;
  case HTTP_UNAUTHORIZED:
    logconf_fatal(&adapter->conf,
                  "UNAUTHORIZED: Please provide a valid authentication token");
    *code = ORCA_DISCORD_BAD_AUTH;
    return false;
  case HTTP_METHOD_NOT_ALLOWED:
    logconf_fatal(&adapter->conf,
                  "METHOD_NOT_ALLOWED: The server couldn't recognize the "
                  "received HTTP method");
    return false;
  case HTTP_TOO_MANY_REQUESTS: {
    struct sized_buffer body = ua_info_get_body(&adapter->err.info);
    struct discord *client = CLIENT(&adapter->rlimit);
    double retry_after = 1.0;
    bool is_global = false;
    char message[256] = "";
    int64_t delay_ms = 0LL;

    json_extract(body.start, body.size,
                 "(global):b (message):.*s (retry_after):lf", &is_global,
                 sizeof(message), message, &retry_after);

    if (is_global) {
      u64_unix_ms_t global;

      global = discord_ratelimit_get_global_wait(&adapter->rlimit);
      delay_ms = (int64_t)(global - discord_timestamp(client));

      logconf_warn(&adapter->conf,
                   "429 GLOBAL RATELIMITING (wait: %" PRId64 " ms) : %s",
                   delay_ms, message);

      /* TODO: this blocks the event loop, which means Gateway's heartbeating
       * won't work */
      cee_sleep_ms(delay_ms);

      return true;
    }

    delay_ms = (int64_t)(1000 * retry_after);

    if (cxt) {
      /* non-blocking timeout */
      u64_unix_ms_t timeout = discord_timestamp(client) + delay_ms;

      logconf_warn(&adapter->conf,
                   "429 RATELIMITING (timeout: %" PRId64 " ms) : %s", delay_ms,
                   message);

      _discord_request_set_timeout(&adapter->rlimit, timeout, cxt);

      /* timed-out requests will be retried anyway */
      return false;
    }

    logconf_warn(&adapter->conf,
                 "429 RATELIMITING (wait: %" PRId64 " ms) : %s", delay_ms,
                 message);

    cee_sleep_ms(delay_ms);

    return true;
  }
  default:
    if (adapter->err.info.httpcode >= 500) {
      /* TODO: server error, implement retry up to X amount logic */
    }
    return true;
  }
}

/* true if a timeout has been set, false otherwise */
static bool
_discord_request_timeout(struct discord_ratelimit *rlimit,
                         struct discord_request *cxt)
{
  u64_unix_ms_t now = discord_timestamp(CLIENT(rlimit));
  u64_unix_ms_t timeout = discord_bucket_get_timeout(rlimit, cxt->bucket);

  if (now > timeout) return false;

  logconf_info(&rlimit->conf, "[%.4s] RATELIMITING (timeout %" PRId64 " ms)",
               cxt->bucket->hash, (int64_t)(timeout - now));

  _discord_request_set_timeout(rlimit, timeout, cxt);

  return true;
}

/* enqueue a request to be executed asynchronously */
ORCAcode
discord_request_perform_async(struct discord_adapter *adapter,
                              struct discord_request_attr *attr,
                              struct sized_buffer *body,
                              enum http_method method,
                              char endpoint[])
{
  struct discord_request *cxt;

  if (QUEUE_EMPTY(adapter->idleq)) {
    /* create new request handler */
    cxt = calloc(1, sizeof(struct discord_request));
  }
  else {
    /* get from idle requests queue */
    QUEUE *q = QUEUE_HEAD(adapter->idleq);
    QUEUE_REMOVE(q);

    cxt = QUEUE_DATA(q, struct discord_request, entry);
    _discord_request_reset(cxt);
  }
  QUEUE_INIT(&cxt->entry);

  _discord_request_populate(cxt, adapter, attr, body, method, endpoint);

  if (adapter->async.attr.high_p)
    QUEUE_INSERT_HEAD(&cxt->bucket->waitq, &cxt->entry);
  else
    QUEUE_INSERT_TAIL(&cxt->bucket->waitq, &cxt->entry);

  return ORCA_OK;
}

/* https://discord.com/developers/docs/topics/opcodes-and-status-codes#json-json-error-codes
 */
static void
json_error_cb(char *str, size_t len, void *p_adapter)
{
  struct discord_adapter *adapter = p_adapter;
  char message[256] = "";

  json_extract(str, len, "(message):.*s (code):d", sizeof(message), message,
               &adapter->err.jsoncode);
  logconf_error(
    &adapter->conf,
    ANSICOLOR("(JSON Error %d) %s",
              ANSI_BG_RED) " - See Discord's JSON Error Codes\n\t\t%.*s",
    adapter->err.jsoncode, message, (int)len, str);

  snprintf(adapter->err.jsonstr, sizeof(adapter->err.jsonstr), "%.*s",
           (int)len, str);
}

/* perform a blocking request */
ORCAcode
discord_request_perform(struct discord_adapter *adapter,
                        struct discord_request_attr *attr,
                        struct sized_buffer *body,
                        enum http_method method,
                        char endpoint[])
{
  /* bucket pertaining to the request */
  struct discord_bucket *b = discord_bucket_get(&adapter->rlimit, endpoint);
  /* connection handle to perform connection */
  struct ua_conn *conn;
  /* orca error status */
  ORCAcode code;
  /* in case of request failure, try again */
  bool retry;

  conn = ua_conn_start(adapter->ua);

  if (HTTP_MIMEPOST == method)
    ua_conn_add_header(conn, "Content-Type", "multipart/form-data");
  else
    ua_conn_add_header(conn, "Content-Type", "application/json");

  /* populate conn with parameters */
  ua_conn_setup(conn, body, method, endpoint);

  pthread_mutex_lock(&b->lock);
  do {
    ua_info_cleanup(&adapter->err.info);

    discord_bucket_cooldown(&adapter->rlimit, b);

    /* perform blocking request, and check results */
    if (ORCA_OK == (code = ua_conn_perform(conn))) {
      code = ua_info_extract(conn, &adapter->err.info);
    }

    if (attr->obj
        && (adapter->err.info.httpcode >= 200
            && adapter->err.info.httpcode < 300))
    {
      struct sized_buffer body = ua_info_get_body(&adapter->err.info);

      if (attr->init) attr->init(attr->obj);

      attr->from_json(body.start, body.size, attr->obj);
    }

    retry = _discord_request_check_status(adapter, &code, NULL);

    discord_bucket_build(&adapter->rlimit, b, endpoint, &adapter->err.info);
    ua_conn_reset(conn);
  } while (retry);
  pthread_mutex_unlock(&b->lock);

  /* reset conn and mark it as free to use */
  ua_conn_stop(conn);

  return code;
}

/* add a request to libcurl's multi handle */
static void
_discord_request_start_async(struct discord_ratelimit *rlimit,
                             struct discord_request *cxt)
{
  struct discord *client = CLIENT(rlimit);
  struct sized_buffer body;
  CURL *ehandle;

  cxt->conn = ua_conn_start(client->adapter.ua);

  if (HTTP_MIMEPOST == cxt->method)
    ua_conn_add_header(cxt->conn, "Content-Type", "multipart/form-data");
  else
    ua_conn_add_header(cxt->conn, "Content-Type", "application/json");

  ehandle = ua_conn_get_easy_handle(cxt->conn);

  body.start = cxt->body.start;
  body.size = cxt->body.size;

  ua_conn_setup(cxt->conn, &body, cxt->method, cxt->endpoint);

  /* link 'cxt' to 'ehandle' for easy retrieval */
  curl_easy_setopt(ehandle, CURLOPT_PRIVATE, cxt);

  /* initiate libcurl transfer */
  curl_multi_add_handle(client->mhandle, ehandle);

  QUEUE_INSERT_TAIL(&cxt->bucket->busyq, &cxt->entry);
}

/* check and enqueue requests that have been timed out */
void
discord_request_check_timeouts_async(struct discord_ratelimit *rlimit)
{
  struct discord_request *cxt;
  struct heap_node *node;

  while (1) {
    node = heap_min(&rlimit->timeouts);
    if (!node) break;

    cxt = CXT(node);
    if (cxt->timeout_ms > discord_timestamp(CLIENT(rlimit))) {
      /* current timestamp is lesser than lowest timeout */
      break;
    }

    heap_remove(&rlimit->timeouts, node, &timer_less_than);
    cxt->bucket->freeze = false;

    QUEUE_INSERT_HEAD(&cxt->bucket->waitq, &cxt->entry);
  }
}

/* send a standalone request to update stale bucket values */
static void
_discord_request_send_single(struct discord_ratelimit *rlimit,
                             struct discord_bucket *b)
{
  struct discord_request *cxt;
  QUEUE *q;

  q = QUEUE_HEAD(&b->waitq);
  QUEUE_REMOVE(q);
  QUEUE_INIT(q);

  cxt = QUEUE_DATA(q, struct discord_request, entry);

  _discord_request_start_async(rlimit, cxt);
}

/* send a batch of requests */
static void
_discord_request_send_batch(struct discord_ratelimit *rlimit,
                            struct discord_bucket *b)
{
  struct discord_request *cxt;
  QUEUE *q;
  long i;

  for (i = b->remaining; i > 0; --i) {
    if (QUEUE_EMPTY(&b->waitq)) break;

    q = QUEUE_HEAD(&b->waitq);
    QUEUE_REMOVE(q);
    QUEUE_INIT(q);

    cxt = QUEUE_DATA(q, struct discord_request, entry);

    /* timeout request if ratelimiting is necessary */
    if (_discord_request_timeout(rlimit, cxt)) {
      break;
    }

    _discord_request_start_async(rlimit, cxt);
  }
}

void
discord_request_check_pending_async(struct discord_ratelimit *rlimit)
{
  struct discord_bucket *b;

  /* iterate over buckets in search of pending requests */
  for (b = rlimit->buckets; b != NULL; b = b->hh.next) {
    /* skip timed-out, busy and non-pending buckets */
    if (b->freeze || !QUEUE_EMPTY(&b->busyq) || QUEUE_EMPTY(&b->waitq)) {
      continue;
    }

    /* if bucket is outdated then its necessary to send a single
     *      request to fetch updated values */
    if (b->reset_tstamp < discord_timestamp(CLIENT(rlimit))) {
      _discord_request_send_single(rlimit, b);
      continue;
    }

    /* send remainder or trigger timeout */
    _discord_request_send_batch(rlimit, b);
  }
}

static void
_discord_request_accept(struct discord_adapter *adapter,
                        ORCAcode code,
                        struct discord_request *cxt)
{
  /* increase buffer length if necessary */
  if (cxt->attr.size > adapter->obj.size) {
    void *tmp = realloc(adapter->obj.buf, cxt->attr.size);
    VASSERT_S(tmp != NULL, "Couldn't increase buffer %zu -> %zu (bytes)",
              adapter->obj.size, cxt->attr.size);

    adapter->obj.buf = tmp;
    adapter->obj.size = cxt->attr.size;
  }

  /* initialize obj */
  if (cxt->attr.init) cxt->attr.init(adapter->obj.buf);

  /* fill obj fields with JSON values */
  if (cxt->attr.from_json && ORCA_OK == code) {
    struct sized_buffer body = ua_info_get_body(&adapter->err.info);

    cxt->attr.from_json(body.start, body.size, adapter->obj.buf);
  }

  /* user callback */
  if (cxt->done) {
    struct discord *client = CLIENT(&adapter->rlimit);

    cxt->done(client, code, adapter->obj.buf);
  }

  /* cleanup obj fields */
  if (cxt->attr.cleanup) cxt->attr.cleanup(adapter->obj.buf);
}

void
discord_request_check_results_async(struct discord_ratelimit *rlimit)
{
  struct discord_adapter *adapter = &CLIENT(rlimit)->adapter;
  CURLM *mhandle = CLIENT(rlimit)->mhandle;
  struct discord_request *cxt;
  struct CURLMsg *curlmsg;
  CURL *ehandle;
  ORCAcode code;

  while (1) {
    int msgq = 0;
    bool retry;

    curlmsg = curl_multi_info_read(mhandle, &msgq);

    if (!curlmsg) break;
    if (CURLMSG_DONE != curlmsg->msg) continue;

    ehandle = curlmsg->easy_handle;
    curl_easy_getinfo(ehandle, CURLINFO_PRIVATE, &cxt);

    switch (curlmsg->data.result) {
    case CURLE_OK: {
      ua_info_cleanup(&adapter->err.info);

      /* check request results and call user-callbacks */
      code = ua_info_extract(cxt->conn, &adapter->err.info);

      retry = _discord_request_check_status(adapter, &code, cxt);

      discord_bucket_build(rlimit, cxt->bucket, cxt->endpoint,
                           &adapter->err.info);

      _discord_request_accept(adapter, code, cxt);
      break;
    }
    case CURLE_READ_ERROR:
      logconf_warn(&adapter->conf, "Read error, will retry again");
      retry = true;
      break;
    default:
      logconf_error(&adapter->conf, "(CURLE code: %d) %s",
                    curlmsg->data.result);
      retry = false;
      break;
    }

    /* remove from busy queue */
    curl_multi_remove_handle(mhandle, ehandle);
    QUEUE_REMOVE(&cxt->entry);

    /* enqueue request for retry or recycle */
    if (retry) {
      ua_conn_reset(cxt->conn);
      QUEUE_INSERT_HEAD(&cxt->bucket->waitq, &cxt->entry);
    }
    else {
      ua_conn_stop(cxt->conn);
      QUEUE_INSERT_TAIL(adapter->idleq, &cxt->entry);
    }
  }
}

void
discord_request_stop_all(struct discord_ratelimit *rlimit)
{
  struct discord *client = CLIENT(rlimit);
  struct discord_request *cxt;
  struct discord_bucket *b;
  struct heap_node *node;
  QUEUE *q;

  /* cancel pending timeouts */
  while ((node = heap_min(&rlimit->timeouts)) != NULL) {
    cxt = CXT(node);

    heap_remove(&rlimit->timeouts, node, &timer_less_than);
    cxt->bucket->freeze = false;

    QUEUE_INSERT_TAIL(client->adapter.idleq, &cxt->entry);
  }

  /* cancel bucket's on-going transfers */
  for (b = rlimit->buckets; b != NULL; b = b->hh.next) {
    CURL *ehandle;

    while (!QUEUE_EMPTY(&b->busyq)) {
      q = QUEUE_HEAD(&b->busyq);
      QUEUE_REMOVE(q);

      cxt = QUEUE_DATA(q, struct discord_request, entry);
      ehandle = ua_conn_get_easy_handle(cxt->conn);

      curl_multi_remove_handle(client->mhandle, ehandle);

      /* set for recycling */
      ua_conn_stop(cxt->conn);
      QUEUE_INSERT_TAIL(client->adapter.idleq, q);
    }

    /* cancel pending tranfers */
    QUEUE_ADD(client->adapter.idleq, &b->waitq);
    QUEUE_INIT(&b->waitq);
  }
}

/* in case of reconnect, we want to be able to resume connections */
void
discord_request_pause_all(struct discord_ratelimit *rlimit)
{
  struct discord *client = CLIENT(rlimit);
  struct discord_request *cxt;
  struct discord_bucket *b;
  struct heap_node *node;
  QUEUE *q;

  /* move pending timeouts to bucket's waitq */
  while ((node = heap_min(&rlimit->timeouts)) != NULL) {
    cxt = CXT(node);

    heap_remove(&rlimit->timeouts, node, &timer_less_than);
    cxt->bucket->freeze = false;

    QUEUE_INSERT_HEAD(&cxt->bucket->waitq, &cxt->entry);
  }

  /* cancel bucket's on-going transfers and move them to waitq for
   *        resuming */
  for (b = rlimit->buckets; b != NULL; b = b->hh.next) {
    CURL *ehandle;

    while (!QUEUE_EMPTY(&b->busyq)) {
      q = QUEUE_HEAD(&b->busyq);
      QUEUE_REMOVE(q);

      cxt = QUEUE_DATA(q, struct discord_request, entry);
      ehandle = ua_conn_get_easy_handle(cxt->conn);

      curl_multi_remove_handle(client->mhandle, ehandle);

      QUEUE_INSERT_HEAD(&b->waitq, q);
    }
  }
}
