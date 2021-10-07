#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "discord.h"
#include "discord-internal.h"

#include "cee-utils.h"


void
discord_adapter_init(struct discord_adapter *adapter, struct logconf *conf, struct sized_buffer *token)
{
  adapter->ua = ua_init(conf);
  ua_set_url(adapter->ua, DISCORD_API_BASE_URL);

  adapter->ratelimit = calloc(1, sizeof *adapter->ratelimit);
  if (pthread_mutex_init(&adapter->ratelimit->lock, NULL))
    ERR("Couldn't initialize pthread mutex");

  logconf_branch(&adapter->ratelimit->conf, conf, "DISCORD_RATELIMIT");
  if (!token->size) { /* no token means a webhook-only client */
    logconf_branch(&adapter->conf, conf, "DISCORD_WEBHOOK");
  }
  else {
    logconf_branch(&adapter->conf, conf, "DISCORD_HTTP");

    char auth[128];
    int ret = snprintf(auth, sizeof(auth), "Bot %.*s", (int)token->size, token->start);
    ASSERT_S(ret < sizeof(auth), "Out of bounds write attempt");

    ua_reqheader_add(adapter->ua, "Authorization", auth);
  }
}

void
discord_adapter_cleanup(struct discord_adapter *adapter)
{
  ua_cleanup(adapter->ua);
  discord_buckets_cleanup(adapter);
  pthread_mutex_destroy(&adapter->ratelimit->lock);
  free(adapter->ratelimit);
  ua_info_cleanup(&adapter->err.info);
}

/**
 * JSON ERROR CODES
 * https://discord.com/developers/docs/topics/opcodes-and-status-codes#json-json-error-codes 
 */
static void
json_error_cb(char *str, size_t len, void *p_adapter)
{
  struct discord_adapter *adapter = p_adapter;
  char message[256]="";

  json_extract(str, len, "(message):.*s (code):d", 
      sizeof(message), message, &adapter->err.jsoncode);
  logconf_error(&adapter->conf, ANSICOLOR("(JSON Error %d) %s", ANSI_BG_RED)
            " - See Discord's JSON Error Codes\n\t\t%.*s",
            adapter->err.jsoncode, message, (int)len, str);

  snprintf(adapter->err.jsonstr, sizeof(adapter->err.jsonstr), 
      "%.*s", (int)len, str);
}

/* template function for performing requests */
ORCAcode
discord_adapter_run(
  struct discord_adapter *adapter, 
  struct ua_resp_handle *resp_handle,
  struct sized_buffer *req_body,
  enum http_method http_method, char endpoint[], ...)
{
  va_list args;
  va_start(args, endpoint);

  /* IF UNSET, SET TO DEFAULT ERROR HANDLING CALLBACKS */
  if (resp_handle && !resp_handle->err_cb) {
    resp_handle->err_cb = &json_error_cb;
    resp_handle->err_obj = adapter;
  }

  /* Check if endpoint contain a major param */
  const char *route;
  if (strstr(endpoint, "/channels/%")) 
    route = "@channel";
  else if (strstr(endpoint, "/guilds/%"))   
    route = "@guild";
  else if (strstr(endpoint, "/webhook/%"))  
    route = "@webhook";
  else
    route = endpoint;

  struct discord_bucket *bucket;
  pthread_mutex_lock(&adapter->ratelimit->lock);
  bucket = discord_bucket_try_get(adapter, route);
  pthread_mutex_unlock(&adapter->ratelimit->lock);

  ORCAcode code;
  bool keepalive=true;
  do {
    ua_info_cleanup(&adapter->err.info);

    discord_bucket_try_cooldown(adapter, bucket);

    code = ua_vrun(
      adapter->ua,
      &adapter->err.info,
      resp_handle,
      req_body,
      http_method, endpoint, args);
    
    if (code != ORCA_HTTP_CODE)
    {
        keepalive = false;
    }
    else 
    {
        const int httpcode = adapter->err.info.httpcode;
        switch (httpcode) {
        case HTTP_FORBIDDEN:
        case HTTP_NOT_FOUND:
        case HTTP_BAD_REQUEST:
            keepalive = false; 
            code = ORCA_DISCORD_JSON_CODE;
            break;
        case HTTP_UNAUTHORIZED:
            keepalive = false;
            logconf_fatal(&adapter->conf, "UNAUTHORIZED: Please provide a valid authentication token");
            code = ORCA_DISCORD_BAD_AUTH;
            break;
        case HTTP_METHOD_NOT_ALLOWED:
            keepalive = false;
            logconf_fatal(&adapter->conf, "METHOD_NOT_ALLOWED: The server couldn't recognize the received HTTP method");
            break;
        case HTTP_TOO_MANY_REQUESTS: {
            bool is_global     = false;
            char message[256]  = "";
            double retry_after = -1; /* seconds */

            struct sized_buffer body = ua_info_get_resp_body(&adapter->err.info);
            json_extract(body.start, body.size,
                        "(global):b (message):s (retry_after):lf",
                        &is_global, message, &retry_after);
            VASSERT_S(retry_after != -1, "(NO RETRY-AFTER INCLUDED) %s", message);

            if (is_global) {
              logconf_warn(&adapter->conf, "429 GLOBAL RATELIMITING (wait: %.2lf ms) : %s", 1000*retry_after, message);
              ua_block_ms(adapter->ua, (uint64_t)(1000*retry_after));
            }
            else {
              logconf_warn(&adapter->conf, "429 RATELIMITING (wait: %.2lf ms) : %s", 1000*retry_after, message);
              cee_sleep_ms((int64_t)(1000*retry_after));
            }
           break; }
        default:
            if (httpcode >= 500) /* server related error, retry */
              ua_block_ms(adapter->ua, 5000); /* wait for 5 seconds */
            break;
        }
    }

    pthread_mutex_lock(&adapter->ratelimit->lock);
    discord_bucket_build(adapter, bucket, route, code, &adapter->err.info);
    pthread_mutex_unlock(&adapter->ratelimit->lock);
  } while (keepalive);

  va_end(args);

  return code;
}
