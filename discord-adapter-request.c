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
  memset(&cxt->resp_handle, 0, sizeof(struct ua_resp_handle));
  *cxt->endpoint = '\0';
  cxt->conn = NULL;
}

void
discord_request_cleanup(struct discord_request *cxt)
{
  if (cxt->req_body.start) free(cxt->req_body.start);
  _discord_request_reset(cxt);
  free(cxt);
}

static void
_discord_request_populate(struct discord_request *cxt,
                          struct discord_adapter *adapter,
                          struct discord_async_attr *attr,
                          struct ua_resp_handle *resp_handle,
                          struct sized_buffer *req_body,
                          enum http_method method,
                          char endpoint[])
{
  cxt->method = method;

  if (attr)
    memcpy(&cxt->attr, attr, sizeof(struct discord_async_attr));
  else
    memset(&cxt->attr, 0, sizeof(struct discord_async_attr));

  if (resp_handle) {
    /* copy response handle */
    memcpy(&cxt->resp_handle, resp_handle, sizeof(cxt->resp_handle));
  }

  if (req_body) {
    /* copy request body */
    if (req_body->size > cxt->req_body.memsize) {
      /* needs to increase buffer size */
      void *tmp = realloc(cxt->req_body.start, req_body->size);
      ASSERT_S(tmp != NULL, "Out of memory");

      cxt->req_body.start = tmp;
      cxt->req_body.memsize = req_body->size;
    }
    memcpy(cxt->req_body.start, req_body->start, req_body->size);
    cxt->req_body.size = req_body->size;
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
_discord_request_status(struct discord_adapter *adapter,
                        ORCAcode *code,
                        struct discord_request *cxt)
{
  if (*code != ORCA_HTTP_CODE) {
    /* ORCA_OK or internal error */
    return false;
  }

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
    bool is_global = false;
    char message[256] = "";
    double retry_after = 1.0;
    long delay_ms = 0L;

    json_extract(body.start, body.size,
                 "(global):b (message):.*s (retry_after):lf", &is_global,
                 sizeof(message), message, &retry_after);

    if (is_global) {
      u64_unix_ms_t global;

      global = discord_ratelimit_get_global_wait(&adapter->rlimit);
      delay_ms = global - discord_timestamp(client);

      logconf_warn(&adapter->conf,
                   "429 GLOBAL RATELIMITING (wait: %ld ms) : %s", delay_ms,
                   message);

      /* TODO: this blocks the event loop, which means Gateway's heartbeating
       * won't work */
      cee_sleep_ms(delay_ms);

      return true;
    }

    delay_ms = 1000 * retry_after;

    if (cxt) {
      /* non-blocking timeout */
      u64_unix_ms_t timeout = discord_timestamp(client) + delay_ms;

      logconf_warn(&adapter->conf, "429 RATELIMITING (timeout: %ld ms) : %s",
                   delay_ms, message);

      _discord_request_set_timeout(&adapter->rlimit, timeout, cxt);

      /* timed-out requests will be retried anyway */
      return false;
    }

    logconf_warn(&adapter->conf, "429 RATELIMITING (wait: %ld ms) : %s",
                 delay_ms, message);

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

  logconf_info(&rlimit->conf, "[%.4s] RATELIMITING (timeout %ld ms)",
               cxt->bucket->hash, timeout - now);

  _discord_request_set_timeout(rlimit, timeout, cxt);

  return true;
}

/* enqueue a request to be executed asynchronously */
ORCAcode
discord_request_perform_async(struct discord_adapter *adapter,
                              struct discord_async_attr *attr,
                              struct ua_resp_handle *resp_handle,
                              struct sized_buffer *req_body,
                              enum http_method method,
                              char endpoint[])
{
  struct discord_request *cxt;

  if (QUEUE_EMPTY(&adapter->idleq)) {
    /* create new request handler */
    cxt = calloc(1, sizeof(struct discord_request));
  }
  else {
    /* get from idle requests queue */
    QUEUE *q = QUEUE_HEAD(&adapter->idleq);
    QUEUE_REMOVE(q);

    cxt = QUEUE_DATA(q, struct discord_request, entry);
    _discord_request_reset(cxt);
  }
  QUEUE_INIT(&cxt->entry);

  _discord_request_populate(cxt, adapter, attr, resp_handle, req_body, method,
                            endpoint);

  if (cxt->attr.high_priority)
    QUEUE_INSERT_HEAD(&cxt->bucket->waitq, &cxt->entry);
  else
    QUEUE_INSERT_TAIL(&cxt->bucket->waitq, &cxt->entry);

  return ORCA_OK;
}

/*
 * https://discord.com/developers/docs/topics/opcodes-and-status-codes#json-json-error-codes
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
                        struct ua_resp_handle *resp_handle,
                        struct sized_buffer *req_body,
                        enum http_method method,
                        char endpoint[])
{
  /* response callbacks */
  struct ua_resp_handle _resp_handle = {};
  /* bucket pertaining to the request */
  struct discord_bucket *b = discord_bucket_get(&adapter->rlimit, endpoint);
  /* orca error status */
  ORCAcode code;
  /* in case of request failure, try again */
  bool retry;

  _resp_handle.err_cb = &json_error_cb;
  _resp_handle.err_obj = adapter;
  if (resp_handle) {
    _resp_handle.ok_cb = resp_handle->ok_cb;
    _resp_handle.ok_obj = resp_handle->ok_obj;
  }

  pthread_mutex_lock(&b->lock);
  do {
    ua_info_cleanup(&adapter->err.info);

    discord_bucket_cooldown(&adapter->rlimit, b);

    code = ua_run(adapter->ua, &adapter->err.info, &_resp_handle, req_body,
                  method, endpoint);

    retry = _discord_request_status(adapter, &code, NULL);

    discord_bucket_build(&adapter->rlimit, b, endpoint, &adapter->err.info);
  } while (retry);
  pthread_mutex_unlock(&b->lock);

  return code;
}

/* add a request to libcurl's multi handle */
static void
_discord_request_start_async(struct discord_ratelimit *rlimit,
                             struct discord_request *cxt)
{
  struct discord *client = CLIENT(rlimit);
  struct sized_buffer req_body;
  CURL *ehandle;

  /* TODO: turn below into a user-agent.c function? */
  cxt->conn = ua_conn_start(client->adapter.ua);
  ehandle = ua_conn_curl_easy_get(cxt->conn);

  req_body.start = cxt->req_body.start;
  req_body.size = cxt->req_body.size;

  ua_conn_setup(client->adapter.ua, cxt->conn, &cxt->resp_handle, &req_body,
                cxt->method, cxt->endpoint);

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

  b->remaining = 1;

  _discord_request_start_async(rlimit, cxt);
}

/* send a batch of requests */
static void
_discord_request_send_batch(struct discord_ratelimit *rlimit,
                            struct discord_bucket *b)
{
  struct discord_request *cxt;
  QUEUE *q;
  int i;

  for (i = b->remaining; i > 0; --i) {
    if (QUEUE_EMPTY(&b->waitq)) break;

    q = QUEUE_HEAD(&b->waitq);
    QUEUE_REMOVE(q);
    QUEUE_INIT(q);

    cxt = QUEUE_DATA(q, struct discord_request, entry);

    /* timeout request if ratelimiting is necessary */
    if (_discord_request_timeout(rlimit, cxt)) break;

    _discord_request_start_async(rlimit, cxt);
  }
}

void
discord_request_check_pending_async(struct discord_ratelimit *rlimit)
{
  struct discord_bucket *b;

  /* iterate over buckets in search of pending requests */
  for (b = rlimit->buckets; b != NULL; b = b->hh.next) {
    if (b->freeze || !QUEUE_EMPTY(&b->busyq) || QUEUE_EMPTY(&b->waitq)) {
      /* skip timed-out, busy and non-pending buckets */
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

void
discord_request_check_results_async(struct discord_ratelimit *rlimit)
{
  struct discord *client = CLIENT(rlimit);
  struct CURLMsg *curlmsg;
  struct discord_request *cxt;
  CURL *ehandle;
  ORCAcode code;

  do {
    bool retry;
    int msgq = 0;
    curlmsg = curl_multi_info_read(client->mhandle, &msgq);

    if (!curlmsg) break;
    if (CURLMSG_DONE != curlmsg->msg) continue;

    ehandle = curlmsg->easy_handle;
    /* get request handler assigned to this easy handle */
    curl_easy_getinfo(ehandle, CURLINFO_PRIVATE, &cxt);
    ua_info_cleanup(&client->adapter.err.info);

    /* check request results and call user-callbacks accordingly */
    code = ua_conn_get_results(client->adapter.ua, cxt->conn,
                               &client->adapter.err.info);

    retry = _discord_request_status(&client->adapter, &code, cxt);

    discord_bucket_build(rlimit, cxt->bucket, cxt->endpoint,
                         &client->adapter.err.info);

    /* this easy handle is done polling */
    curl_multi_remove_handle(client->mhandle, ehandle);
    /* remove from 'busy' queue */
    QUEUE_REMOVE(&cxt->entry);

    if (retry) {
      /* reset conn for next iteration */
      ua_conn_reset(client->adapter.ua, cxt->conn);

      /* add request handler to 'waitq' queue for retry */
      QUEUE_INSERT_HEAD(&cxt->bucket->waitq, &cxt->entry);
    }
    else {
      if (cxt->attr.callback) {
        cxt->attr.callback(client, &client->gw.bot, NULL, code);
      }

      /* set conn as idle for recycling */
      ua_conn_stop(client->adapter.ua, cxt->conn);

      /* add request handler to 'idleq' queue for recycling */
      QUEUE_INSERT_TAIL(&client->adapter.idleq, &cxt->entry);
    }
  } while (1);
}

void
discord_request_stop_all(struct discord_ratelimit *rlimit)
{
  struct discord *client = CLIENT(rlimit);
  struct discord_request *cxt;
  struct discord_bucket *b;
  struct heap_node *node;
  QUEUE queue;
  QUEUE *q;

  /* cancel pending timeouts */
  while ((node = heap_min(&rlimit->timeouts)) != NULL) {
    heap_remove(&rlimit->timeouts, node, &timer_less_than);

    cxt = CXT(node);
    QUEUE_INSERT_TAIL(&client->adapter.idleq, &cxt->entry);
  }

  for (b = rlimit->buckets; b != NULL; b = b->hh.next) {
    /* cancel on-going transfers */
    QUEUE_MOVE(&b->busyq, &queue);
    while (!QUEUE_EMPTY(&queue)) {
      q = QUEUE_HEAD(&queue);
      QUEUE_REMOVE(q);

      cxt = QUEUE_DATA(q, struct discord_request, entry);
      curl_multi_remove_handle(client->mhandle,
                               ua_conn_curl_easy_get(cxt->conn));

      QUEUE_INSERT_TAIL(&client->adapter.idleq, q);
    }

    /* cancel pending tranfers */
    QUEUE_MOVE(&b->waitq, &queue);
    QUEUE_ADD(&client->adapter.idleq, &queue);
  }
}
