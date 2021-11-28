#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include "discord.h"
#include "discord-internal.h"

#include "cee-utils.h"

/* get client from adapter pointer */
#define CLIENT(p_adapter)                                                     \
  ((struct discord *)((int8_t *)(p_adapter)-offsetof(struct discord, adapter)))

/**
 * JSON ERROR CODES
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

void
discord_adapter_init(struct discord_adapter *adapter,
                     struct logconf *conf,
                     struct sized_buffer *token)
{
  adapter->ua = ua_init(&(struct ua_attr){ .conf = conf });
  ua_set_url(adapter->ua, DISCORD_API_BASE_URL);

  if (!token->size) {
    /* no token means a webhook-only client */
    logconf_branch(&adapter->conf, conf, "DISCORD_WEBHOOK");
  }
  else {
    /* bot client */
    logconf_branch(&adapter->conf, conf, "DISCORD_HTTP");

    char auth[128];
    int ret =
      snprintf(auth, sizeof(auth), "Bot %.*s", (int)token->size, token->start);
    ASSERT_S(ret < sizeof(auth), "Out of bounds write attempt");

    ua_reqheader_add(adapter->ua, "Authorization", auth);
  }
  /* initialize ratelimit handler */
  adapter->ratelimit = discord_ratelimit_init(&adapter->conf);
  /* initialize request queues (for async purposes) */
  QUEUE_INIT(&adapter->queue.hold);
  QUEUE_INIT(&adapter->queue.idle);
}

void
discord_adapter_cleanup(struct discord_adapter *adapter)
{
  /* cleanup User-Agent handle */
  ua_cleanup(adapter->ua);
  /* cleanup request's informational handle */
  ua_info_cleanup(&adapter->err.info);
  /* cleanup ratelimit handle */
  discord_ratelimit_cleanup(adapter->ratelimit);
}

/* in case 'endpoint' has a major param, it will be written into 'buf' */
static const char *
_discord_adapter_get_route(const char endpoint[], char buf[32])
{
  /* determine which ratelimit group (aka bucket) a request belongs to
   * by checking its route.
   * see:  https://discord.com/developers/docs/topics/rate-limits */
  if (STRNEQ(endpoint, "/channels/", sizeof("/channels/") - 1)
      || STRNEQ(endpoint, "/guilds/", sizeof("/guilds/") - 1)
      || STRNEQ(endpoint, "/webhooks/", sizeof("/webhooks/") - 1))
  {
    /* safe to assume strchr() won't return NULL */
    char *start = 1 + strchr(1 + endpoint, '/'), *end = strchr(start, '/');
    ptrdiff_t len = end - start;

    /* copy snowflake id over to buf */
    memcpy(buf, start, len);
    buf[len] = '\0';
    return buf;
  }
  return endpoint;
}

static void
_discord_request_cxt_reset(struct discord_request_cxt *cxt)
{
  cxt->p_adapter = NULL;
  cxt->route = NULL;
  memset(&cxt->resp_handle, 0, sizeof(struct ua_resp_handle));
  *cxt->endpoint = '\0';
}

static void
_discord_request_cxt_populate(struct discord_request_cxt *cxt,
                              struct discord_adapter *adapter,
                              struct ua_resp_handle *resp_handle,
                              struct sized_buffer *req_body,
                              enum http_method http_method,
                              char endpoint[])
{
  /* pass to _discord_adapter_get_route() for reentrancy */
  char buf[32];
  /* bucket key, pointer to either 'endpoint' or 'buf' */
  const char *route = _discord_adapter_get_route(endpoint, buf);
  /* route pertaining to the request */
  struct discord_route *r = discord_route_get(adapter->ratelimit, route);

  cxt->p_adapter = &(discord_clone(CLIENT(adapter))->adapter);
  cxt->route = r;
  if (resp_handle) {
    cxt->resp_handle = *resp_handle;
  }
  if (req_body) {
    if (req_body->size > cxt->req_body.size) {
      void *tmp = realloc(cxt->req_body.start, req_body->size);
      ASSERT_S(tmp != NULL, "Out of memory");

      cxt->req_body.start = tmp;
      cxt->req_body.size = req_body->size;
    }
    memcpy(cxt->req_body.start, req_body->start, req_body->size);
  }
  memcpy(cxt->endpoint, endpoint, sizeof(cxt->endpoint));
}

/* return true if there should be a retry attempt */
static bool
_discord_adapter_get_status(struct discord_adapter *adapter, ORCAcode *code)
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
    bool is_global = false;
    char message[256] = "";
    double retry_after = 1.0;
    long delay_ms = 0L;

    struct sized_buffer body = ua_info_get_body(&adapter->err.info);
    json_extract(body.start, body.size,
                 "(global):b (message):.*s (retry_after):lf", &is_global,
                 sizeof(message), message, &retry_after);

    if (is_global) {
      u64_unix_ms_t global;

      pthread_rwlock_rdlock(&adapter->ratelimit->rwlock);
      global = adapter->ratelimit->global;
      pthread_rwlock_unlock(&adapter->ratelimit->rwlock);

      delay_ms = global - cee_timestamp_ms();

      logconf_warn(&adapter->conf,
                   "429 GLOBAL RATELIMITING (wait: %ld ms) : %s", delay_ms,
                   message);
    }
    else {
      delay_ms = 1000 * retry_after;

      logconf_warn(&adapter->conf, "429 RATELIMITING (wait: %ld ms) : %s",
                   delay_ms, message);
    }

    cee_sleep_ms(delay_ms);

    return true;
  }
  default:
    if (adapter->err.info.httpcode >= 500) {
      /* server related error, sleep for 5 seconds */
      cee_sleep_ms(5000);
    }
    return true;
  }
}

void
discord_adapter_enqueue(struct discord_adapter *adapter,
                        struct ua_resp_handle *resp_handle,
                        struct sized_buffer *req_body,
                        enum http_method http_method,
                        char endpoint[])
{
  /* request context to be enqueued */
  struct discord_request_cxt *cxt;

  if (QUEUE_EMPTY(&adapter->queue.idle)) {
    /* create new request handler */
    cxt = calloc(1, sizeof(struct discord_request_cxt));
  }
  else {
    /* recycle idle request handler */
    QUEUE *q = QUEUE_HEAD(&adapter->queue.idle);
    cxt = QUEUE_DATA(q, struct discord_request_cxt, entry);
    _discord_request_cxt_reset(cxt);
  }
  /* populate request handler */
  _discord_request_cxt_populate(cxt, adapter, resp_handle, req_body,
                                http_method, endpoint);
  /* enqueue request handler */
  QUEUE_INIT(&cxt->entry);
  QUEUE_INSERT_TAIL(&adapter->queue.hold, &cxt->entry);
}

void
discord_adapter_prepare(struct discord_adapter *adapter)
{
  long delay_ms;
  struct discord_request_cxt *cxt;
  struct ua_conn *conn;
  CURL *ehandle;

  if (QUEUE_EMPTY(&adapter->queue.hold)) return;

  while (!QUEUE_EMPTY(&adapter->queue.hold)) {
    QUEUE *q = QUEUE_HEAD(&adapter->queue.hold);
    cxt = QUEUE_DATA(q, struct discord_request_cxt, entry);
    QUEUE_REMOVE(q);

    delay_ms =
      discord_bucket_get_cooldown(adapter->ratelimit, cxt->route->bucket);
    if (delay_ms > 0) {
      logconf_info(&adapter->ratelimit->conf,
                   "[%.4s] RATELIMITING (timeout %ld ms)",
                   cxt->route->bucket->hash, delay_ms);
      /* TODO: register timeout callback for 'cxt' */
      continue;
    }
    conn = ua_conn_get(adapter->ua);
    ehandle = ua_conn_curl_easy_get(conn);
    ua_conn_setup(cxt->p_adapter->ua, conn, &cxt->resp_handle, &cxt->req_body,
                  cxt->http_method, cxt->endpoint);
    /* link 'cxt' to 'ehandle' for easy retrieval */
    curl_easy_setopt(ehandle, CURLOPT_PRIVATE, cxt);
    /* let curl begin transfer */
    curl_multi_add_handle(CLIENT(adapter)->mhandle, ehandle);
  }
}

void
discord_adapter_check(struct discord_adapter *adapter)
{
  int msgq;
  struct CURLMsg *curlmsg;
  struct discord_request_cxt *cxt;
  CURLM *mhandle = CLIENT(adapter)->mhandle;
  CURL *ehandle;
  ORCAcode code;

  do {
    msgq = 0;
    curlmsg = curl_multi_info_read(mhandle, &msgq);
    if (curlmsg && (CURLMSG_DONE == curlmsg->msg)) {
      code = ORCA_OK;
      ehandle = curlmsg->easy_handle;
      /* get request handler assigned to this easy handle */
      curl_easy_getinfo(ehandle, CURLINFO_PRIVATE, &cxt);
      /* TODO: trigger cxt callback here */
      curl_multi_remove_handle(mhandle, ehandle);
      if (_discord_adapter_get_status(adapter, &code)) {
        /* TODO: set retry transfer callback */
        QUEUE_INSERT_HEAD(&adapter->queue.hold, &cxt->entry);
      }
      else {
        /* insert request handler into idle queue for recycling */
        QUEUE_INSERT_TAIL(&adapter->queue.idle, &cxt->entry);
      }
      discord_bucket_build(adapter->ratelimit, cxt->route->bucket,
                           cxt->route->route, code, &cxt->p_adapter->err.info);
    }
  } while (curlmsg);
}

static ORCAcode
_discord_adapter_request(struct discord_adapter *adapter,
                         struct ua_resp_handle *resp_handle,
                         struct sized_buffer *req_body,
                         enum http_method http_method,
                         char endpoint[])
{
  /* pass to _discord_adapter_get_route() for reentrancy */
  char buf[32];
  /* bucket key, pointer to either 'endpoint' or 'major' */
  const char *route = _discord_adapter_get_route(endpoint, buf);
  /* response callbacks */
  struct ua_resp_handle _resp_handle = {};
  /* bucket pertaining to the request */
  struct discord_bucket *b = discord_bucket_get(adapter->ratelimit, route);
  /* in case of request failure, try again */
  bool keepalive = true;
  /* bucket ratelimit cooldown (in milliseconds) */
  long delay_ms;
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
    delay_ms = discord_bucket_get_cooldown(adapter->ratelimit, b);
    if (delay_ms > 0) {
      logconf_info(&adapter->ratelimit->conf,
                   "[%.4s] RATELIMITING (wait %ld ms)", b->hash, delay_ms);
      cee_sleep_ms(delay_ms);
    }

    code = ua_run(adapter->ua, &adapter->err.info, &_resp_handle, req_body,
                  http_method, endpoint);

    if (code != ORCA_HTTP_CODE) {
      keepalive = false;
    }
    else {
      keepalive = _discord_adapter_get_status(adapter, &code);
    }
    discord_bucket_build(adapter->ratelimit, b, route, code,
                         &adapter->err.info);
  } while (keepalive);
  pthread_mutex_unlock(&b->lock);

  return code;
}

/* template function for performing requests */
ORCAcode
discord_adapter_run(struct discord_adapter *adapter,
                    struct ua_resp_handle *resp_handle,
                    struct sized_buffer *req_body,
                    enum http_method http_method,
                    char endpoint_fmt[],
                    ...)
{
  /* fully-formed endpoint string */
  char endpoint[2048];
  /* variable arguments for endpoint formation */
  va_list args;
  /* snprintf OOB check */
  int ret;

  /* build the endpoint string */
  va_start(args, endpoint_fmt);
  ret = vsnprintf(endpoint, sizeof(endpoint), endpoint_fmt, args);
  ASSERT_S(ret < sizeof(endpoint), "Out of bounds write attempt");
  va_end(args);

  return _discord_adapter_request(adapter, resp_handle, req_body, http_method,
                                  endpoint);
}
