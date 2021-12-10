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

static void
_discord_request_to_mime(curl_mime *mime, void *p_cxt)
{
  struct discord_request *cxt = p_cxt;
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
 * Only the fields that are required at _discord_request_to_mime()
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
  const struct discord_request *a = CXT(ha);
  const struct discord_request *b = CXT(hb);

  return a->timeout_ms <= b->timeout_ms;
}

static void
_discord_request_stop(struct discord_request *cxt)
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
_discord_request_populate(struct discord_request *cxt,
                          struct discord_ratelimit *rlimit,
                          struct discord_request_attr *attr,
                          struct sized_buffer *body,
                          enum http_method method,
                          char endpoint[])
{
  cxt->method = method;
  cxt->done = rlimit->async.attr.done;

  memcpy(&cxt->attr, attr, sizeof(struct discord_request_attr));

  if (attr->attachments) {
    cxt->attr.attachments = _discord_attachment_list_dup(attr->attachments);
  }

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
  cxt->bucket = discord_bucket_get(rlimit, cxt->endpoint);
}

static void
_discord_request_set_timeout(struct discord_ratelimit *rlimit,
                             u64_unix_ms_t timeout,
                             struct discord_request *cxt)
{
  cxt->bucket->freeze = true;
  cxt->timeout_ms = timeout;
  heap_insert(&rlimit->async.timeouts, &cxt->node, &timer_less_than);
}

/* return true if there should be a retry attempt */
static bool
_discord_request_check_status(struct discord_ratelimit *rlimit,
                              struct discord_request *cxt,
                              struct ua_info *info)
{
  if (info->code != ORCA_HTTP_CODE) return false;

  switch (info->httpcode) {
  case HTTP_FORBIDDEN:
  case HTTP_NOT_FOUND:
  case HTTP_BAD_REQUEST:
    info->code = ORCA_DISCORD_JSON_CODE;
    return false;
  case HTTP_UNAUTHORIZED:
    logconf_fatal(&rlimit->conf,
                  "UNAUTHORIZED: Please provide a valid authentication token");
    info->code = ORCA_DISCORD_BAD_AUTH;
    return false;
  case HTTP_METHOD_NOT_ALLOWED:
    logconf_fatal(&rlimit->conf,
                  "METHOD_NOT_ALLOWED: The server couldn't recognize the "
                  "received HTTP method");
    return false;
  case HTTP_TOO_MANY_REQUESTS: {
    struct sized_buffer body = ua_info_get_body(info);
    struct discord *client = CLIENT(rlimit);
    double retry_after = 1.0;
    bool is_global = false;
    char message[256] = "";
    int64_t delay_ms = 0LL;

    json_extract(body.start, body.size,
                 "(global):b (message):.*s (retry_after):lf", &is_global,
                 sizeof(message), message, &retry_after);

    if (is_global) {
      u64_unix_ms_t global;

      global = discord_ratelimit_get_global_wait(rlimit);
      delay_ms = (int64_t)(global - discord_timestamp(client));

      logconf_warn(&rlimit->conf,
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

      logconf_warn(&rlimit->conf,
                   "429 RATELIMITING (timeout: %" PRId64 " ms) : %s", delay_ms,
                   message);

      _discord_request_set_timeout(rlimit, timeout, cxt);

      /* timed-out requests will be retried anyway */
      return false;
    }

    logconf_warn(&rlimit->conf, "429 RATELIMITING (wait: %" PRId64 " ms) : %s",
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
discord_request_perform_async(struct discord_ratelimit *rlimit,
                              struct discord_request_attr *attr,
                              struct sized_buffer *body,
                              enum http_method method,
                              char endpoint[])
{
  struct discord_request *cxt;

  if (QUEUE_EMPTY(rlimit->async.idleq)) {
    /* create new request handler */
    cxt = calloc(1, sizeof(struct discord_request));
  }
  else {
    /* get from idle requests queue */
    QUEUE *q = QUEUE_HEAD(rlimit->async.idleq);
    QUEUE_REMOVE(q);

    cxt = QUEUE_DATA(q, struct discord_request, entry);
  }
  QUEUE_INIT(&cxt->entry);

  _discord_request_populate(cxt, rlimit, attr, body, method, endpoint);

  if (rlimit->async.attr.high_p)
    QUEUE_INSERT_HEAD(&cxt->bucket->waitq, &cxt->entry);
  else
    QUEUE_INSERT_TAIL(&cxt->bucket->waitq, &cxt->entry);

  /* reset for next call */
  memset(&rlimit->async.attr, 0, sizeof(struct discord_async_attr));

  return ORCA_OK;
}

/* perform a blocking request */
ORCAcode
discord_request_perform(struct discord_ratelimit *rlimit,
                        struct discord_request_attr *attr,
                        struct sized_buffer *body,
                        enum http_method method,
                        char endpoint[])
{
  struct discord *client = CLIENT(rlimit);
  /* bucket pertaining to the request */
  struct discord_bucket *b = discord_bucket_get(rlimit, endpoint);
  /* throw-away for ua_conn_set_mime() */
  struct discord_request cxt = { 0 };
  struct ua_conn *conn;
  ORCAcode code;
  bool retry;

  conn = ua_conn_start(client->adapter.ua);

  if (HTTP_MIMEPOST == method) {
    cxt.attr.attachments = attr->attachments;
    cxt.body.buf = *body;

    ua_conn_add_header(conn, "Content-Type", "multipart/form-data");
    ua_conn_set_mime(conn, &cxt, &_discord_request_to_mime);
  }
  else {
    ua_conn_add_header(conn, "Content-Type", "application/json");
  }
  ua_conn_setup(conn, body, method, endpoint);

  pthread_mutex_lock(&b->lock);
  do {
    discord_bucket_cooldown(rlimit, b);

    /* perform blocking request, and check results */
    code = ua_conn_perform(conn);
    switch (code) {
    case ORCA_OK: {
      struct ua_info info = { 0 };
      struct sized_buffer body = ua_info_get_body(&info);

      code = ua_info_extract(conn, &info);

      retry = _discord_request_check_status(rlimit, NULL, &info);

      discord_bucket_build(rlimit, b, endpoint, &info);

      if (ORCA_OK == info.code && attr->obj) {
        body = ua_info_get_body(&info);

        if (attr->init) attr->init(attr->obj);

        attr->from_json(body.start, body.size, attr->obj);
      }

      ua_info_cleanup(&info);
    } break;
    case ORCA_CURLE_INTERNAL:
      logconf_error(&rlimit->conf, "Curl internal error, will retry again");
      retry = true;
      break;
    default:
      logconf_error(&rlimit->conf, "ORCA code: %d", code);
      retry = false;
      break;
    }

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
  CURL *ehandle;

  cxt->conn = ua_conn_start(client->adapter.ua);

  ehandle = ua_conn_get_easy_handle(cxt->conn);

  if (HTTP_MIMEPOST == cxt->method) {
    ua_conn_add_header(cxt->conn, "Content-Type", "multipart/form-data");
    ua_conn_set_mime(cxt->conn, cxt, &_discord_request_to_mime);
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
discord_request_check_timeouts_async(struct discord_ratelimit *rlimit)
{
  struct discord_request *cxt;
  struct heap_node *node;

  while (1) {
    node = heap_min(&rlimit->async.timeouts);
    if (!node) break;

    cxt = CXT(node);
    if (cxt->timeout_ms > discord_timestamp(CLIENT(rlimit))) {
      /* current timestamp is lesser than lowest timeout */
      break;
    }

    heap_remove(&rlimit->async.timeouts, node, &timer_less_than);
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
_discord_request_accept_async(struct discord_ratelimit *rlimit,
                              struct discord_request *cxt,
                              struct ua_info *info)
{
  /* increase buffer length if necessary */
  if (cxt->attr.size > rlimit->async.obj.size) {
    void *tmp = realloc(rlimit->async.obj.start, cxt->attr.size);
    VASSERT_S(tmp != NULL, "Couldn't increase buffer %zu -> %zu (bytes)",
              rlimit->async.obj.size, cxt->attr.size);

    rlimit->async.obj.start = tmp;
    rlimit->async.obj.size = cxt->attr.size;
  }

  /* initialize obj */
  if (cxt->attr.init) cxt->attr.init(rlimit->async.obj.start);

  /* fill obj fields with JSON values */
  if (cxt->attr.from_json && ORCA_OK == info->code) {
    struct sized_buffer body = ua_info_get_body(info);

    cxt->attr.from_json(body.start, body.size, rlimit->async.obj.start);
  }

  /* user callback */
  if (cxt->done)
    cxt->done(CLIENT(rlimit), info->code, rlimit->async.obj.start);

  /* cleanup obj fields */
  if (cxt->attr.cleanup) cxt->attr.cleanup(rlimit->async.obj.start);
}

void
discord_request_check_results_async(struct discord_ratelimit *rlimit)
{
  struct discord *client = CLIENT(rlimit);
  struct discord_request *cxt;
  struct CURLMsg *curlmsg;
  CURL *ehandle;
  ORCAcode code;

  while (1) {
    int msgq = 0;
    bool retry;

    curlmsg = curl_multi_info_read(client->mhandle, &msgq);

    if (!curlmsg) break;
    if (CURLMSG_DONE != curlmsg->msg) continue;

    ehandle = curlmsg->easy_handle;
    curl_easy_getinfo(ehandle, CURLINFO_PRIVATE, &cxt);

    switch (curlmsg->data.result) {
    case CURLE_OK: {
      struct ua_info info = { 0 };

      code = ua_info_extract(cxt->conn, &info);

      retry = _discord_request_check_status(rlimit, cxt, &info);

      discord_bucket_build(rlimit, cxt->bucket, cxt->endpoint, &info);

      if (ORCA_OK == info.code) {
        _discord_request_accept_async(rlimit, cxt, &info);
      }

      ua_info_cleanup(&info);
    } break;
    case CURLE_READ_ERROR:
      logconf_warn(&rlimit->conf, "Read error, will retry again");
      retry = true;
      break;
    default:
      logconf_error(&rlimit->conf, "CURLE code: %d", curlmsg->data.result);
      retry = false;
      break;
    }

    /* remove from busy queue */
    curl_multi_remove_handle(client->mhandle, ehandle);
    QUEUE_REMOVE(&cxt->entry);

    /* enqueue request for retry or recycle */
    if (retry) {
      ua_conn_reset(cxt->conn);

      QUEUE_INSERT_HEAD(&cxt->bucket->waitq, &cxt->entry);
    }
    else {
      _discord_request_stop(cxt);

      QUEUE_INSERT_TAIL(rlimit->async.idleq, &cxt->entry);
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
  while ((node = heap_min(&rlimit->async.timeouts)) != NULL) {
    cxt = CXT(node);

    heap_remove(&rlimit->async.timeouts, node, &timer_less_than);
    cxt->bucket->freeze = false;

    QUEUE_INSERT_TAIL(rlimit->async.idleq, &cxt->entry);
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
      QUEUE_INSERT_TAIL(rlimit->async.idleq, q);
    }

    /* cancel pending tranfers */
    QUEUE_ADD(rlimit->async.idleq, &b->waitq);
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
  while ((node = heap_min(&rlimit->async.timeouts)) != NULL) {
    cxt = CXT(node);

    heap_remove(&rlimit->async.timeouts, node, &timer_less_than);
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
