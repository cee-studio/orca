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
  /* initialize request queues (for async purposes) */
  QUEUE_INIT(&adapter->idle);
}

static void _discord_request_cleanup(struct discord_request *cxt);

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
  QUEUE_MOVE(&adapter->idle, &queue);
  while (!QUEUE_EMPTY(&queue)) {
    QUEUE *q = QUEUE_HEAD(&queue);
    cxt = QUEUE_DATA(q, struct discord_request, entry);
    QUEUE_REMOVE(&cxt->entry);
    _discord_request_cleanup(cxt);
  }
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
_discord_request_reset(struct discord_request *cxt)
{
  discord_cleanup(CLIENT(cxt->adapter));
  cxt->adapter = NULL;
  cxt->bucket = NULL;
  memset(&cxt->resp_handle, 0, sizeof(struct ua_resp_handle));
  *cxt->endpoint = '\0';
  cxt->conn = NULL;
}

static void
_discord_request_cleanup(struct discord_request *cxt)
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
  cxt->method = method;
  cxt->callback = CLIENT(adapter)->async.callback;
  cxt->adapter = &(discord_clone(CLIENT(adapter))->adapter);
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
  /* bucket key, pointer to either 'endpoint' or 'buf' */
  cxt->route = _discord_adapter_get_route(cxt->endpoint, cxt->_buf);
  /* bucket pertaining to the request */
  cxt->bucket = discord_bucket_get(&adapter->rlimit, cxt->route);
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
    struct sized_buffer body = ua_info_get_body(&adapter->err.info);
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
      delay_ms = global - discord_timestamp(CLIENT(adapter));

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

/* enqueue a request to be executed asynchronously */
static ORCAcode
_discord_adapter_enqueue(struct discord_adapter *adapter,
                         struct ua_resp_handle *resp_handle,
                         struct sized_buffer *req_body,
                         enum http_method method,
                         char endpoint[])
{
  /* request context to be enqueued */
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
  /* put request handler on hold */
  QUEUE_INSERT_TAIL(&cxt->bucket->pending, &cxt->entry);

  return ORCA_OK;
}

void
discord_adapter_check_requests(struct discord_adapter *adapter)
{
  struct CURLMsg *curlmsg;
  struct discord_request *cxt;
  CURLM *mhandle = CLIENT(adapter)->mhandle;
  CURL *ehandle;
  ORCAcode code;

  do {
    bool retry;
    int msgq = 0;
    curlmsg = curl_multi_info_read(mhandle, &msgq);

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
    ua_conn_stop(adapter->ua, cxt->conn);

    retry = (ORCA_HTTP_CODE == code)
              ? _discord_adapter_get_status(cxt->adapter, &code)
              : false;

    discord_bucket_build(&adapter->rlimit, cxt->bucket, cxt->route,
                         &cxt->adapter->err.info);

    --cxt->bucket->busy;

    if (retry) {
      /* add request handler to 'pending' queue for retry */
      QUEUE_INSERT_HEAD(&cxt->bucket->pending, &cxt->entry);
    }
    else {
      if (cxt->callback) {
        (*cxt->callback)(CLIENT(adapter), &CLIENT(adapter)->gw.bot, NULL,
                         code);
      }
      /* add request handler to 'idle' queue for recycling */
      QUEUE_INSERT_TAIL(&adapter->idle, &cxt->entry);
    }
    /* this easy handle is done polling for IO */
    curl_multi_remove_handle(mhandle, ehandle);
  } while (curlmsg);
}

static ORCAcode
_discord_adapter_request(struct discord_adapter *adapter,
                         struct ua_resp_handle *resp_handle,
                         struct sized_buffer *req_body,
                         enum http_method method,
                         char endpoint[])
{
  /* pass to _discord_adapter_get_route() for reentrancy */
  char buf[32];
  /* bucket key, pointer to either 'endpoint' or 'major' */
  const char *route = _discord_adapter_get_route(endpoint, buf);
  /* response callbacks */
  struct ua_resp_handle _resp_handle = {};
  /* bucket pertaining to the request */
  struct discord_bucket *b = discord_bucket_get(&adapter->rlimit, route);
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

    retry = (ORCA_HTTP_CODE == code)
              ? _discord_adapter_get_status(adapter, &code)
              : false;

    discord_bucket_build(&adapter->rlimit, b, route, &adapter->err.info);
  } while (retry);
  pthread_mutex_unlock(&b->lock);

  return code;
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

  if (true == CLIENT(adapter)->async.enable) {
    /* disable async for next request */
    CLIENT(adapter)->async.enable = false;
    /* enqueue request */
    return _discord_adapter_enqueue(adapter, resp_handle, req_body, method,
                                    endpoint);
  }
  return _discord_adapter_request(adapter, resp_handle, req_body, method,
                                  endpoint);
}
