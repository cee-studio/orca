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
  struct discord *clone = CLIENT(&cxt->adapter->rlimit);

  discord_cleanup(clone);
  cxt->adapter = NULL;
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
                          struct ua_resp_handle *resp_handle,
                          struct sized_buffer *req_body,
                          enum http_method method,
                          char endpoint[])
{
  struct discord *client = CLIENT(&adapter->rlimit);

  cxt->method = method;
  cxt->callback = client->async.callback;
  cxt->adapter = &(discord_clone(client)->adapter);

  if (resp_handle) {
    /* copy response handle */
    memcpy(&cxt->resp_handle, resp_handle, sizeof(cxt->resp_handle));
  }
  if (req_body) {
    /* copy request body */
    if (req_body->size > cxt->req_body.size) {
      /* needs to increase buffer size */
      void *tmp = realloc(cxt->req_body.start, req_body->size);
      ASSERT_S(tmp != NULL, "Out of memory");

      cxt->req_body.start = tmp;
      cxt->req_body.size = req_body->size;
    }
    memcpy(cxt->req_body.start, req_body->start, req_body->size);
  }
  /* copy endpoint over to cxt */
  memcpy(cxt->endpoint, endpoint, sizeof(cxt->endpoint));

  /* bucket pertaining to the request */
  cxt->bucket = discord_bucket_get(&adapter->rlimit, cxt->endpoint);
}

/* return true if there should be a retry attempt */
static bool
_discord_request_status(struct discord_adapter *adapter, ORCAcode *code)
{
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
    bool is_global = false;
    char message[256] = "";
    double retry_after = 1.0;
    long delay_ms = 0L;

    json_extract(body.start, body.size,
                 "(global):b (message):.*s (retry_after):lf", &is_global,
                 sizeof(message), message, &retry_after);

    if (is_global) {
      struct discord *client = CLIENT(&adapter->rlimit);
      u64_unix_ms_t global;

      global = discord_ratelimit_get_global_wait(&adapter->rlimit);
      delay_ms = global - discord_timestamp(client);

      logconf_warn(&adapter->conf,
                   "429 GLOBAL RATELIMITING (wait: %ld ms) : %s", delay_ms,
                   message);
    }
    else {
      delay_ms = 1000 * retry_after;

      logconf_warn(&adapter->conf, "429 RATELIMITING (wait: %ld ms) : %s",
                   delay_ms, message);
    }

    /* TODO: this will block the event-loop even for non-global ratelimits */
    cee_sleep_ms(delay_ms);

    return true;
  }
  default:
    if (adapter->err.info.httpcode >= 500) {
      /* server related error, sleep for 5 seconds */
      /* TODO: implement retry up to X amount logic */
    }
    return true;
  }
}

void
discord_request_set_timeout(struct discord_ratelimit *rlimit,
                            u64_unix_ms_t timeout,
                            struct discord_request *cxt)
{
  cxt->timeout_ms = timeout;

  /* mark bucket as busy as we need to update its values before
   *        proceeding with the rest of requests */
  ++cxt->bucket->busy;

  heap_insert(&rlimit->timeouts, &cxt->node, &timer_less_than);
}

/* enqueue a request to be executed asynchronously */
ORCAcode
discord_request_perform_async(struct discord_adapter *adapter,
                              struct ua_resp_handle *resp_handle,
                              struct sized_buffer *req_body,
                              enum http_method method,
                              char endpoint[])
{
  struct discord_request *cxt;

  if (QUEUE_EMPTY(&adapter->idle)) {
    /* create new request handler */
    cxt = calloc(1, sizeof(struct discord_request));
    QUEUE_INIT(&cxt->entry);
  }
  else {
    /* recycle idle request handler */
    QUEUE *q = QUEUE_HEAD(&adapter->idle);
    cxt = QUEUE_DATA(q, struct discord_request, entry);
    QUEUE_REMOVE(&cxt->entry);

    _discord_request_reset(cxt);
  }

  /* populate request handler */
  _discord_request_populate(cxt, adapter, resp_handle, req_body, method,
                            endpoint);

  QUEUE_INSERT_TAIL(&cxt->bucket->pending, &cxt->entry);

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
  /* in case of request failure, try again */
  bool retry;
  /* orca error status */
  ORCAcode code;

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

    retry = (ORCA_HTTP_CODE == code) ? _discord_request_status(adapter, &code)
                                     : false;

    discord_bucket_build(&adapter->rlimit, b, endpoint, &adapter->err.info);
  } while (retry);
  pthread_mutex_unlock(&b->lock);

  return code;
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
      /* timeout haven't been reached yet */
      break;
    }

    heap_remove(&rlimit->timeouts, node, &timer_less_than);
    QUEUE_INSERT_HEAD(&cxt->bucket->pending, &cxt->entry);
  }
}

/* add a request to libcurl's multi handle */
static void
_discord_request_start_async(struct discord_ratelimit *rlimit,
                             struct discord_request *cxt)
{
  CURLM *mhandle = CLIENT(rlimit)->mhandle;
  CURL *ehandle;

  --cxt->bucket->remaining;
  ++cxt->bucket->busy;
  /* TODO: turn below into a user-agent.c function? */
  cxt->conn = ua_conn_start(cxt->adapter->ua);
  ehandle = ua_conn_curl_easy_get(cxt->conn);
  ua_conn_setup(cxt->adapter->ua, cxt->conn, &cxt->resp_handle, &cxt->req_body,
                cxt->method, cxt->endpoint);

  /* link 'cxt' to 'ehandle' for easy retrieval */
  curl_easy_setopt(ehandle, CURLOPT_PRIVATE, cxt);

  /* initiate libcurl transfer */
  curl_multi_add_handle(mhandle, ehandle);
}

/* send a standalone request to update stale bucket values */
static void
_discord_request_run_single(struct discord_ratelimit *rlimit,
                            struct discord_bucket *b)
{
  struct discord_request *cxt;
  QUEUE *q;

  q = QUEUE_HEAD(&b->pending);
  cxt = QUEUE_DATA(q, struct discord_request, entry);
  QUEUE_REMOVE(&cxt->entry);

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

  while (b->remaining > 0 && !QUEUE_EMPTY(&b->pending)) {
    q = QUEUE_HEAD(&b->pending);
    cxt = QUEUE_DATA(q, struct discord_request, entry);
    QUEUE_REMOVE(&cxt->entry);

    if (discord_bucket_timeout(rlimit, b, cxt)) {
      /* wait for timeout and bucket value update */
      break;
    }

    _discord_request_start_async(rlimit, cxt);
  };
}

void
discord_request_check_pending_async(struct discord_ratelimit *rlimit)
{
  struct discord_bucket *b;

  /* iterate over buckets in search of pending requests */
  for (b = rlimit->buckets; b != NULL; b = b->hh.next) {
    /* skip busy and idle buckets */
    if (b->busy || QUEUE_EMPTY(&b->pending)) continue;

    /* check if bucket is outdated */
    if (b->reset_tstamp < discord_timestamp(CLIENT(rlimit))) {
      /* perform a standalone request first and update bucket values */
      _discord_request_run_single(rlimit, b);
      continue;
    }

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
    ua_info_cleanup(&cxt->adapter->err.info);

    /* check request results and call user-callbacks accordingly */
    code = ua_conn_get_results(cxt->adapter->ua, cxt->conn,
                               &cxt->adapter->err.info);

    /* reset conn for next iteration */
    ua_conn_stop(client->adapter.ua, cxt->conn);

    retry = (ORCA_HTTP_CODE == code)
              ? _discord_request_status(cxt->adapter, &code)
              : false;

    discord_bucket_build(rlimit, cxt->bucket, cxt->endpoint,
                         &cxt->adapter->err.info);

    --cxt->bucket->busy;

    if (retry) {
      /* add request handler to 'pending' queue for retry */
      QUEUE_INSERT_HEAD(&cxt->bucket->pending, &cxt->entry);
    }
    else {
      if (cxt->callback) (*cxt->callback)(client, &client->gw.bot, NULL, code);
      /* add request handler to 'idle' queue for recycling */
      QUEUE_INSERT_TAIL(&client->adapter.idle, &cxt->entry);
    }

    /* this easy handle is done */
    curl_multi_remove_handle(client->mhandle, ehandle);

  } while (curlmsg);
}
