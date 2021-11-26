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
  ua_cleanup(adapter->ua);
  discord_ratelimit_cleanup(adapter->ratelimit);
  pthread_rwlock_destroy(&adapter->ratelimit->rwlock);
  pthread_mutex_destroy(&adapter->ratelimit->lock);
  free(adapter->ratelimit);
  ua_info_cleanup(&adapter->err.info);
}

static ORCAcode
_discord_adapter_request(struct discord_adapter *adapter,
                         struct ua_resp_handle *resp_handle,
                         struct sized_buffer *req_body,
                         enum http_method http_method,
                         char endpoint[],
                         const char route[])
{
  bool keepalive = true;
  long delay_ms;
  ORCAcode code;
  struct discord_bucket *bucket =
    discord_bucket_get(adapter->ratelimit, route);
  /* assign JSON error callback */
  struct ua_resp_handle _resp_handle = { .err_cb = &json_error_cb,
                                         .err_obj = adapter };
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
  /* check endpoint for these major parameters
   * see:  https://discord.com/developers/docs/topics/rate-limits */
  static const char CHANNEL_END[] = "/channels/%";
  static const char GUILD_END[] = "/guilds/%";
  static const char WEBHOOK_END[] = "/webhooks/%";
  /* fully-formed endpoint string */
  char endpoint[2048];
  /* in case endpoint has a major param */
  char major[32];
  /* bucket key, pointer to either 'endpoint' or 'major' */
  const char *route;
  /* variable arguments for endpoint formation */
  va_list args;
  /* snprintf OOB check */
  int ret;

  /* build the endpoint string */
  va_start(args, endpoint_fmt);
  ret = vsnprintf(endpoint, sizeof(endpoint), endpoint_fmt, args);
  ASSERT_S(ret < sizeof(endpoint), "Out of bounds write attempt");
  va_end(args);

  /* determine which ratelimit group (aka bucket) a request belongs to
   * by checking its route. */
  if (STRNEQ(endpoint_fmt, CHANNEL_END, sizeof(CHANNEL_END) - 1)
      || STRNEQ(endpoint_fmt, GUILD_END, sizeof(GUILD_END) - 1)
      || STRNEQ(endpoint_fmt, WEBHOOK_END, sizeof(WEBHOOK_END) - 1))
  {
    /* safe to assume strchr() won't return NULL */
    char *start = 1 + strchr(1 + endpoint, '/'), *end = strchr(start, '/');
    ptrdiff_t len = end - start;

    /* copy snowflake id over to 'major' */
    memcpy(major, start, len);
    major[len] = '\0';
    route = major;
  }
  else {
    route = endpoint;
  }

  return _discord_adapter_request(adapter, resp_handle, req_body, http_method,
                                  endpoint, route);
}
