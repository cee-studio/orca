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

void
discord_adapter_enqueue(struct discord_adapter *adapter,
                        struct ua_resp_handle *resp_handle,
                        struct sized_buffer *req_body,
                        enum http_method http_method,
                        char endpoint[])
{
  /* pass to _discord_adapter_get_route() for reentrancy */
  char buf[32];
  /* bucket key, pointer to either 'endpoint' or 'major' */
  const char *route = _discord_adapter_get_route(endpoint, buf);
  /* bucket pertaining to the request */
  struct discord_bucket *bucket =
    discord_bucket_get(adapter->ratelimit, route);
  /* request context to be enqueued */
  struct discord_request_cxt *cxt;

  if (!QUEUE_EMPTY(&bucket->idle_requests)) {
    /* recycle and enqueue idle request */
    QUEUE *q;

    q = QUEUE_HEAD(&bucket->idle_requests);
    cxt = QUEUE_DATA(q, struct discord_request_cxt, entry);
    memset(cxt, 0, sizeof(struct discord_request_cxt));
  }
  else {
    /* create new request handler */
    cxt = calloc(1, sizeof *cxt);
  }
  /* populate request handler */
  cxt->p_adapter = &(discord_clone(CLIENT(adapter))->adapter);
  cxt->bucket = bucket;
  if (resp_handle) cxt->resp_handle = *resp_handle;
  if (req_body) cxt->req_body = *req_body;
  memcpy(cxt->endpoint, endpoint, sizeof(cxt->endpoint));

  /* enqueue request */
  QUEUE_INIT(&cxt->entry);
  QUEUE_INSERT_TAIL(&bucket->pending_requests, &cxt->entry);
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
  struct discord_bucket *bucket =
    discord_bucket_get(adapter->ratelimit, route);
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

  pthread_mutex_lock(&bucket->lock);
  do {
    ua_info_cleanup(&adapter->err.info);
    delay_ms = discord_bucket_get_cooldown(adapter->ratelimit, bucket);
    if (delay_ms > 0) {
      logconf_info(&adapter->ratelimit->conf,
                   "[%.4s] RATELIMITING (wait %ld ms)", bucket->hash,
                   delay_ms);
      /* @todo emit timer for async requests */
      cee_sleep_ms(delay_ms);
    }

    code = ua_run(adapter->ua, &adapter->err.info, &_resp_handle, req_body,
                  http_method, endpoint);

    if (code != ORCA_HTTP_CODE) {
      keepalive = false;
    }
    else {
      switch (adapter->err.info.httpcode) {
      case HTTP_FORBIDDEN:
      case HTTP_NOT_FOUND:
      case HTTP_BAD_REQUEST:
        keepalive = false;
        code = ORCA_DISCORD_JSON_CODE;
        break;
      case HTTP_UNAUTHORIZED:
        keepalive = false;
        logconf_fatal(
          &adapter->conf,
          "UNAUTHORIZED: Please provide a valid authentication token");
        code = ORCA_DISCORD_BAD_AUTH;
        break;
      case HTTP_METHOD_NOT_ALLOWED:
        keepalive = false;
        logconf_fatal(&adapter->conf,
                      "METHOD_NOT_ALLOWED: The server couldn't recognize the "
                      "received HTTP method");
        break;
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

        /* @todo emit timer for async requests */
        cee_sleep_ms(delay_ms);

        break;
      }
      default:
        if (adapter->err.info.httpcode >= 500) {
          /* server related error, sleep for 5 seconds
           * @todo emit timer for async requests */
          cee_sleep_ms(5000);
        }
        break;
      }
    }
    discord_bucket_build(adapter->ratelimit, bucket, route, code,
                         &adapter->err.info);
  } while (keepalive);
  pthread_mutex_unlock(&bucket->lock);

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
