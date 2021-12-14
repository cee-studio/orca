#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "discord.h"
#include "discord-internal.h"

#include "cee-utils.h"

/* MT-Unsafe alternative to discord_timestamp() */
#define NOW(client) ((client)->gw.timer->now)

void
discord_request_init(struct discord_request *req, struct logconf *conf)
{
  const struct sized_buffer hash = { "null", 4 };

  logconf_branch(&req->conf, conf, "DISCORD_REQUEST");

  /* global resources */
  req->global = calloc(1, sizeof *req->global);
  if (pthread_rwlock_init(&req->global->rwlock, NULL))
    ERR("Couldn't initialize pthread rwlock");
  if (pthread_mutex_init(&req->global->lock, NULL))
    ERR("Couldn't initialize pthread mutex");

  /* for routes that still haven't discovered a bucket match */
  req->b_null = discord_bucket_init(req, "", &hash, 1L);

  /* idleq is malloc'd to guarantee a client cloned by discord_clone() will
   * share the same queue with the original */
  req->async.idleq = malloc(sizeof(QUEUE));
  QUEUE_INIT(req->async.idleq);
  /* initialize min-heap for handling request timeouts */
  heap_init(&req->async.timeouts);
}

static void
_discord_context_cleanup(struct discord_context *cxt)
{
  if (cxt->body.buf.start) free(cxt->body.buf.start);
  free(cxt);
}

/* cleanup routes and buckets */
void
discord_request_cleanup(struct discord_request *req)
{
  struct discord_context *cxt;
  QUEUE queue;
  QUEUE *q;

  /* move pending requests to idle */
  discord_request_stop_all(req);

  discord_buckets_cleanup(req);

  /* cleanup global resources */
  pthread_rwlock_destroy(&req->global->rwlock);
  pthread_mutex_destroy(&req->global->lock);
  free(req->global);

  /* cleanup idle requests queue */
  QUEUE_MOVE(req->async.idleq, &queue);
  while (!QUEUE_EMPTY(&queue)) {
    q = QUEUE_HEAD(&queue);
    cxt = QUEUE_DATA(q, struct discord_context, entry);
    QUEUE_REMOVE(&cxt->entry);
    _discord_context_cleanup(cxt);
  }

  if (req->async.obj.size) free(req->async.obj.start);

  free(req->async.idleq);
}

static void
_discord_context_to_mime(curl_mime *mime, void *p_cxt)
{
  struct discord_context *cxt = p_cxt;
  struct discord_attachment **atchs = cxt->attr.attachments;
  struct sized_buffer *body = &cxt->body.buf;
  curl_mimepart *part;
  char name[64];
  int i;

  /* json part */
  if (body->start && body->size) {
    part = curl_mime_addpart(mime);
    curl_mime_data(part, body->start, body->size);
    curl_mime_type(part, "application/json");
    curl_mime_name(part, "payload_json");
  }

  /* attachment part */
  for (i = 0; atchs[i]; ++i) {
    snprintf(name, sizeof(name), "files[%d]", i);
    if (atchs[i]->content) {
      part = curl_mime_addpart(mime);
      curl_mime_data(part, atchs[i]->content,
                     atchs[i]->size ? atchs[i]->size : CURL_ZERO_TERMINATED);
      curl_mime_filename(part, IS_EMPTY_STRING(atchs[i]->filename)
                                 ? "a.out"
                                 : atchs[i]->filename);
      curl_mime_type(part, IS_EMPTY_STRING(atchs[i]->content_type)
                             ? "application/octet-stream"
                             : atchs[i]->content_type);
      curl_mime_name(part, name);
    }
    else if (!IS_EMPTY_STRING(atchs[i]->filename)) {
      /* fetch local file by the filename */
      part = curl_mime_addpart(mime);
      curl_mime_filedata(part, atchs[i]->filename);
      curl_mime_type(part, IS_EMPTY_STRING(atchs[i]->content_type)
                             ? "application/octet-stream"
                             : atchs[i]->content_type);
      curl_mime_name(part, name);
    }
  }
}

/* TODO: make this kind of function specs generated (optional)
 *
 * Only the fields that are required at _discord_context_to_mime()
 *        are duplicated*/
static struct discord_attachment **
_discord_attachment_list_dup(struct discord_attachment **src)
{
  size_t i, len = ntl_length((ntl_t)src);
  struct discord_attachment **dest;

  dest = (struct discord_attachment **)ntl_calloc(len, sizeof **dest);

  for (i = 0; src[i]; ++i) {
    memcpy(dest[i], src[i], sizeof **dest);
    if (src[i]->content) {
      dest[i]->content = strdup(src[i]->content);
    }
    if (src[i]->filename) {
      dest[i]->filename = strdup(src[i]->filename);
    }
    if (src[i]->content_type) {
      dest[i]->content_type = strdup(src[i]->content_type);
    }
  }

  return dest;
}

static int
timer_less_than(const struct heap_node *ha, const struct heap_node *hb)
{
  const struct discord_context *a =
    CONTAINEROF(ha, struct discord_context, node);
  const struct discord_context *b =
    CONTAINEROF(hb, struct discord_context, node);

  return a->timeout_ms <= b->timeout_ms;
}

static void
_discord_context_stop(struct discord_context *cxt)
{
  ua_conn_stop(cxt->conn);

  cxt->bucket = NULL;
  cxt->done = NULL;
  *cxt->endpoint = '\0';
  cxt->conn = NULL;

  if (cxt->attr.attachments) {
    discord_attachment_list_free(cxt->attr.attachments);
  }
  memset(&cxt->attr, 0, sizeof(struct discord_request_attr));
}

static void
_discord_context_populate(struct discord_context *cxt,
                          struct discord_request *req,
                          struct discord_request_attr *attr,
                          struct sized_buffer *body,
                          enum http_method method,
                          char endpoint[])
{
  cxt->method = method;
  cxt->done = req->async.attr.done;

  memcpy(&cxt->attr, attr, sizeof(struct discord_request_attr));
  if (attr->attachments) {
    cxt->attr.attachments = _discord_attachment_list_dup(attr->attachments);
  }
  if (cxt->attr.size > req->async.obj.size) {
    void *tmp = realloc(req->async.obj.start, cxt->attr.size);
    VASSERT_S(tmp != NULL, "Couldn't increase buffer %zu -> %zu (bytes)",
              req->async.obj.size, cxt->attr.size);

    req->async.obj.start = tmp;
    req->async.obj.size = cxt->attr.size;
  }
  cxt->attr.obj = req->async.obj.start;

  if (body) {
    /* copy request body */
    if (body->size > cxt->body.memsize) {
      /* needs to increase buffer size */
      void *tmp = realloc(cxt->body.buf.start, body->size);
      ASSERT_S(tmp != NULL, "Out of memory");

      cxt->body.buf.start = tmp;
      cxt->body.memsize = body->size;
    }
    memcpy(cxt->body.buf.start, body->start, body->size);
    cxt->body.buf.size = body->size;
  }

  /* copy endpoint over to cxt */
  memcpy(cxt->endpoint, endpoint, sizeof(cxt->endpoint));

  /* bucket pertaining to the request */
  cxt->bucket = discord_bucket_get(req, cxt->endpoint);
}

static void
_discord_context_set_timeout(struct discord_request *req,
                             u64_unix_ms_t timeout,
                             struct discord_context *cxt)
{
  cxt->bucket->freeze = true;
  cxt->timeout_ms = timeout;

  heap_insert(&req->async.timeouts, &cxt->node, &timer_less_than);
}

/* return true if there should be a retry attempt */
static bool
_discord_request_get_info(struct discord_request *req,
                          struct discord_context *cxt,
                          struct ua_info *info)
{
  if (info->code != ORCA_HTTP_CODE) {
    /** ORCA_OK or internal error */
    return false;
  }

  switch (info->httpcode) {
  case HTTP_FORBIDDEN:
  case HTTP_NOT_FOUND:
  case HTTP_BAD_REQUEST:
    info->code = ORCA_DISCORD_JSON_CODE;
    return false;
  case HTTP_UNAUTHORIZED:
    logconf_fatal(&req->conf,
                  "UNAUTHORIZED: Please provide a valid authentication token");
    info->code = ORCA_DISCORD_BAD_AUTH;
    return false;
  case HTTP_METHOD_NOT_ALLOWED:
    logconf_fatal(&req->conf,
                  "METHOD_NOT_ALLOWED: The server couldn't recognize the "
                  "received HTTP method");
    return false;
  case HTTP_TOO_MANY_REQUESTS: {
    struct sized_buffer body = ua_info_get_body(info);
    struct discord *client = CLIENT(req, adapter.req);
    double retry_after = 1.0;
    bool is_global = false;
    char message[256] = "";
    int64_t delay_ms = 0LL;

    json_extract(body.start, body.size,
                 "(global):b (message):.*s (retry_after):lf", &is_global,
                 sizeof(message), message, &retry_after);

    if (is_global) {
      u64_unix_ms_t global;

      global = discord_request_get_global_wait(req);
      delay_ms = (int64_t)(global - discord_timestamp(client));

      logconf_warn(&req->conf,
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
      u64_unix_ms_t timeout = NOW(client) + delay_ms;

      logconf_warn(&req->conf,
                   "429 RATELIMITING (timeout: %" PRId64 " ms) : %s", delay_ms,
                   message);

      _discord_context_set_timeout(req, timeout, cxt);

      /* timed-out requests will be retried anyway */
      return false;
    }

    logconf_warn(&req->conf, "429 RATELIMITING (wait: %" PRId64 " ms) : %s",
                 delay_ms, message);

    cee_sleep_ms(delay_ms);

    return true;
  }
  default:
    if (info->httpcode >= 500) {
      /* TODO: server error, implement retry up to X amount logic */
    }
    return true;
  }
}

/* true if a timeout has been set, false otherwise */
static bool
_discord_context_timeout(struct discord_request *req,
                         struct discord_context *cxt)
{
  struct discord *client = CLIENT(req, adapter.req);
  u64_unix_ms_t now = NOW(client);
  u64_unix_ms_t timeout = discord_bucket_get_timeout(req, cxt->bucket);

  if (now > timeout) return false;

  logconf_info(&req->conf, "[%.4s] RATELIMITING (timeout %" PRId64 " ms)",
               cxt->bucket->hash, (int64_t)(timeout - now));

  _discord_context_set_timeout(req, timeout, cxt);

  return true;
}

/* enqueue a request to be executed asynchronously */
ORCAcode
discord_request_perform_async(struct discord_request *req,
                              struct discord_request_attr *attr,
                              struct sized_buffer *body,
                              enum http_method method,
                              char endpoint[])
{
  struct discord_context *cxt;

  if (QUEUE_EMPTY(req->async.idleq)) {
    /* create new request handler */
    cxt = calloc(1, sizeof(struct discord_context));
  }
  else {
    /* get from idle requests queue */
    QUEUE *q = QUEUE_HEAD(req->async.idleq);
    QUEUE_REMOVE(q);

    cxt = QUEUE_DATA(q, struct discord_context, entry);
  }
  QUEUE_INIT(&cxt->entry);

  _discord_context_populate(cxt, req, attr, body, method, endpoint);

  if (req->async.attr.high_p)
    QUEUE_INSERT_HEAD(&cxt->bucket->waitq, &cxt->entry);
  else
    QUEUE_INSERT_TAIL(&cxt->bucket->waitq, &cxt->entry);

  /* reset for next call */
  memset(&req->async.attr, 0, sizeof(struct discord_async_attr));

  return ORCA_OK;
}

/* perform a blocking request */
ORCAcode
discord_request_perform(struct discord_request *req,
                        struct discord_request_attr *attr,
                        struct sized_buffer *body,
                        enum http_method method,
                        char endpoint[])
{
  struct discord *client = CLIENT(req, adapter.req);
  /* bucket pertaining to the request */
  struct discord_bucket *b = discord_bucket_get(req, endpoint);
  /* throw-away for ua_conn_set_mime() */
  struct discord_context cxt = { 0 };
  struct ua_conn *conn;
  ORCAcode code;
  bool retry;

  conn = ua_conn_start(client->adapter.ua);

  if (HTTP_MIMEPOST == method) {
    cxt.attr.attachments = attr->attachments;
    cxt.body.buf = *body;

    ua_conn_add_header(conn, "Content-Type", "multipart/form-data");
    ua_conn_set_mime(conn, &cxt, &_discord_context_to_mime);
  }
  else {
    ua_conn_add_header(conn, "Content-Type", "application/json");
  }
  ua_conn_setup(conn, body, method, endpoint);

  pthread_mutex_lock(&b->lock);
  do {
    discord_bucket_cooldown(req, b);

    /* perform blocking request, and check results */
    switch (code = ua_conn_perform(conn)) {
    case ORCA_OK: {
      struct ua_info info = { 0 };
      struct sized_buffer body;

      ua_info_extract(conn, &info);
      retry = _discord_request_get_info(req, NULL, &info);

      body = ua_info_get_body(&info);
      if (ORCA_OK == info.code && attr->obj) {
        if (attr->init) attr->init(attr->obj);

        attr->from_json(body.start, body.size, attr->obj);
      }

      discord_bucket_build(req, b, endpoint, &info);
      ua_info_cleanup(&info);
    } break;
    case ORCA_CURLE_INTERNAL:
      logconf_error(&req->conf, "Curl internal error, will retry again");
      retry = true;
      break;
    default:
      logconf_error(&req->conf, "ORCA code: %d", code);
      retry = false;
      break;
    }

    /* in the off-chance of having consecutive blocking calls, update timestamp
     *        used for ratelimiting
     * TODO: create discord_timestamp_update() */
    ws_timestamp_update(client->gw.ws);

    ua_conn_reset(conn);
  } while (retry);
  pthread_mutex_unlock(&b->lock);

  /* reset conn and mark it as free to use */
  ua_conn_stop(conn);

  return code;
}

/* add a request to libcurl's multi handle */
static void
_discord_context_start_async(struct discord_request *req,
                             struct discord_context *cxt)
{
  struct discord *client = CLIENT(req, adapter.req);
  CURL *ehandle;

  cxt->conn = ua_conn_start(client->adapter.ua);

  ehandle = ua_conn_get_easy_handle(cxt->conn);

  if (HTTP_MIMEPOST == cxt->method) {
    ua_conn_add_header(cxt->conn, "Content-Type", "multipart/form-data");
    ua_conn_set_mime(cxt->conn, cxt, &_discord_context_to_mime);
  }
  else {
    ua_conn_add_header(cxt->conn, "Content-Type", "application/json");
  }
  ua_conn_setup(cxt->conn, &cxt->body.buf, cxt->method, cxt->endpoint);

  /* link 'cxt' to 'ehandle' for easy retrieval */
  curl_easy_setopt(ehandle, CURLOPT_PRIVATE, cxt);

  /* initiate libcurl transfer */
  curl_multi_add_handle(client->mhandle, ehandle);

  QUEUE_INSERT_TAIL(&cxt->bucket->busyq, &cxt->entry);
}

/* check and enqueue requests that have been timed out */
void
discord_request_check_timeouts_async(struct discord_request *req)
{
  struct discord *client = CLIENT(req, adapter.req);
  struct discord_context *cxt;
  struct heap_node *hmin;

  while (1) {
    hmin = heap_min(&req->async.timeouts);
    if (!hmin) break;

    cxt = CONTAINEROF(hmin, struct discord_context, node);
    if (cxt->timeout_ms > NOW(client)) {
      /* current timestamp is lesser than lowest timeout */
      break;
    }

    heap_remove(&req->async.timeouts, hmin, &timer_less_than);
    cxt->bucket->freeze = false;

    QUEUE_INSERT_HEAD(&cxt->bucket->waitq, &cxt->entry);
  }
}

/* send a standalone request to update stale bucket values */
static void
_discord_request_send_single(struct discord_request *req,
                             struct discord_bucket *b)
{
  struct discord_context *cxt;
  QUEUE *q;

  q = QUEUE_HEAD(&b->waitq);
  QUEUE_REMOVE(q);
  QUEUE_INIT(q);

  cxt = QUEUE_DATA(q, struct discord_context, entry);

  _discord_context_start_async(req, cxt);
}

/* send a batch of requests */
static void
_discord_request_send_batch(struct discord_request *req,
                            struct discord_bucket *b)
{
  struct discord_context *cxt;
  QUEUE *q;
  long i;

  for (i = b->remaining; i > 0; --i) {
    if (QUEUE_EMPTY(&b->waitq)) break;

    q = QUEUE_HEAD(&b->waitq);
    QUEUE_REMOVE(q);
    QUEUE_INIT(q);

    cxt = QUEUE_DATA(q, struct discord_context, entry);

    /* timeout request if ratelimiting is necessary */
    if (_discord_context_timeout(req, cxt)) break;

    _discord_context_start_async(req, cxt);
  }
}

void
discord_request_check_pending_async(struct discord_request *req)
{
  struct discord *client = CLIENT(req, adapter.req);
  struct discord_bucket *b;

  /* iterate over buckets in search of pending requests */
  for (b = req->buckets; b != NULL; b = b->hh.next) {
    /* skip timed-out, busy and non-pending buckets */
    if (b->freeze || !QUEUE_EMPTY(&b->busyq) || QUEUE_EMPTY(&b->waitq)) {
      continue;
    }

    /* if bucket is outdated then its necessary to send a single
     *      request to fetch updated values */
    if (b->reset_tstamp < NOW(client)) {
      _discord_request_send_single(req, b);
      continue;
    }

    /* send remainder or trigger timeout */
    _discord_request_send_batch(req, b);
  }
}

void
discord_request_check_action(struct discord_request *req, struct CURLMsg *msg)
{
  struct discord_context *cxt;
  bool retry;

  curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &cxt);
  switch (msg->data.result) {
  case CURLE_OK: {
    struct ua_info info = { 0 };
    struct sized_buffer body;

    ua_info_extract(cxt->conn, &info);
    retry = _discord_request_get_info(req, cxt, &info);

    body = ua_info_get_body(&info);
    if (info.code != ORCA_OK) {
      /* TODO: failure callback */
    }
    else if (cxt->done) {
      struct discord *client = CLIENT(req, adapter.req);

      if (cxt->attr.init) cxt->attr.init(cxt->attr.obj);

      /* fill obj fields with JSON values */
      if (cxt->attr.from_json) {
        cxt->attr.from_json(body.start, body.size, cxt->attr.obj);
      }

      cxt->done(client, cxt->attr.obj);

      /* cleanup obj fields */
      if (cxt->attr.cleanup) cxt->attr.cleanup(cxt->attr.obj);
    }

    discord_bucket_build(req, cxt->bucket, cxt->endpoint, &info);
    ua_info_cleanup(&info);
  } break;
  case CURLE_READ_ERROR:
    logconf_warn(&req->conf, "Read error, will retry again");
    retry = true;
    break;
  default:
    logconf_error(&req->conf, "(CURLE code: %d)", msg->data.result);
    retry = false;
    break;
  }

  /* remove from busy queue */
  QUEUE_REMOVE(&cxt->entry);

  /* enqueue request for retry or recycle */
  if (retry) {
    ua_conn_reset(cxt->conn);
    QUEUE_INSERT_HEAD(&cxt->bucket->waitq, &cxt->entry);
  }
  else {
    _discord_context_stop(cxt);
    QUEUE_INSERT_TAIL(req->async.idleq, &cxt->entry);
  }
}

void
discord_request_stop_all(struct discord_request *req)
{
  struct discord *client = CLIENT(req, adapter.req);
  struct discord_context *cxt;
  struct discord_bucket *b;
  struct heap_node *hmin;
  QUEUE *q;

  /* cancel pending timeouts */
  while ((hmin = heap_min(&req->async.timeouts)) != NULL) {
    cxt = CONTAINEROF(hmin, struct discord_context, node);

    heap_remove(&req->async.timeouts, hmin, &timer_less_than);
    cxt->bucket->freeze = false;

    QUEUE_INSERT_TAIL(req->async.idleq, &cxt->entry);
  }

  /* cancel bucket's on-going transfers */
  for (b = req->buckets; b != NULL; b = b->hh.next) {
    CURL *ehandle;

    while (!QUEUE_EMPTY(&b->busyq)) {
      q = QUEUE_HEAD(&b->busyq);
      QUEUE_REMOVE(q);

      cxt = QUEUE_DATA(q, struct discord_context, entry);
      ehandle = ua_conn_get_easy_handle(cxt->conn);

      /* TODO: UB if calling inside of libcurl's callbacks */
      curl_multi_remove_handle(client->mhandle, ehandle);

      /* set for recycling */
      ua_conn_stop(cxt->conn);
      QUEUE_INSERT_TAIL(req->async.idleq, q);
    }

    /* cancel pending tranfers */
    QUEUE_ADD(req->async.idleq, &b->waitq);
    QUEUE_INIT(&b->waitq);
  }
}

/* in case of reconnect, we want to be able to resume connections */
void
discord_request_pause_all(struct discord_request *req)
{
  struct discord *client = CLIENT(req, adapter.req);
  struct discord_context *cxt;
  struct discord_bucket *b;
  struct heap_node *hmin;
  QUEUE *q;

  /* move pending timeouts to bucket's waitq */
  while ((hmin = heap_min(&req->async.timeouts)) != NULL) {
    cxt = CONTAINEROF(hmin, struct discord_context, node);

    heap_remove(&req->async.timeouts, hmin, &timer_less_than);
    cxt->bucket->freeze = false;

    QUEUE_INSERT_HEAD(&cxt->bucket->waitq, &cxt->entry);
  }

  /* cancel bucket's on-going transfers and move them to waitq for
   *        resuming */
  for (b = req->buckets; b != NULL; b = b->hh.next) {
    CURL *ehandle;

    while (!QUEUE_EMPTY(&b->busyq)) {
      q = QUEUE_HEAD(&b->busyq);
      QUEUE_REMOVE(q);

      cxt = QUEUE_DATA(q, struct discord_context, entry);
      ehandle = ua_conn_get_easy_handle(cxt->conn);

      /* TODO: UB if calling inside of libcurl's callbacks */
      curl_multi_remove_handle(client->mhandle, ehandle);

      QUEUE_INSERT_HEAD(&b->waitq, q);
    }
  }
}
