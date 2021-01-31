#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h> //for usleep
#include <stdarg.h>

#include <libdiscord.h>
#include "orka-utils.h"

#define BASE_API_URL "https://discord.com/api"

namespace discord {
namespace user_agent {

/* initialize curl_slist's request header utility
 * @todo create distinction between bot and bearer token */
static struct curl_slist*
reqheader_init(char token[])
{
  char auth[MAX_HEADER_LEN];
  int ret = snprintf(auth, MAX_HEADER_LEN, "Authorization: Bot %s", token);
  ASSERT_S(ret < (int)sizeof(auth), "Out of bounds write attempt");

  struct curl_slist *new_header = NULL;
  void *tmp; //for checking potential allocation error

  new_header = curl_slist_append(new_header,"X-RateLimit-Precision: millisecond");
  ASSERT_S(NULL != new_header, "Out of memory");

  tmp = curl_slist_append(new_header,"Accept: application/json");
  ASSERT_S(NULL != tmp, "Out of memory");

  tmp = curl_slist_append(new_header, auth);
  ASSERT_S(NULL != tmp, "Out of memory");

  tmp = curl_slist_append(new_header,"User-Agent: orca (http://github.com/cee-studio/orca, v" LIBDISCORD_VERSION ")");
  ASSERT_S(NULL != tmp, "Out of memory");

  tmp = curl_slist_append(new_header,"Content-Type: application/json");
  ASSERT_S(NULL != tmp, "Out of memory");

  return new_header;
}

void
init(dati *ua, char token[])
{
  ua->req_header = reqheader_init(token);
  ua->ehandle = custom_easy_init(
                  &ua->p_client->settings,
                  ua->req_header,
                  &ua->pairs,
                  &ua->body);
}

void
cleanup(dati *ua)
{
  bucket::cleanup(ua);

  curl_slist_free_all(ua->req_header);
  curl_easy_cleanup(ua->ehandle); 

  if (ua->body.start) {
    free(ua->body.start);
  }
}

struct ratelimit {
  dati *ua;
  bucket::dati *bucket;
  char *endpoint;
  struct resp_handle *resp_handle;
};

//attempt to fetch a bucket handling connections from this endpoint
static void
start_cb(void *p_data)
{
  struct ratelimit *data = (struct ratelimit*)p_data;
  data->bucket = bucket::try_get(data->ua, data->endpoint);
}

static void
before_perform_cb(void *p_data)
{
  struct ratelimit *data = (struct ratelimit*)p_data;
  bucket::try_cooldown(data->bucket);
}

static perform_action
on_success_cb(
  void *p_data,
  enum http_code code,
  struct sized_buffer *body,
  struct api_header_s *pairs)
{
  D_NOTOP_PRINT("(%d)%s - %s", 
      code,
      http_code_print(code),
      http_reason_print(code));

  struct ratelimit *data = (struct ratelimit*)p_data;

  if (HTTP_OK == code) {
    if (data->resp_handle && data->resp_handle->ok_cb) {
      (*data->resp_handle->ok_cb)(
          body->start,
          body->size, 
          data->resp_handle->ok_obj);
    }
  }

  bucket::build(data->ua, data->bucket, data->endpoint);

  return ACTION_SUCCESS;
}

static perform_action
on_failure_cb(
  void *p_data,
  enum http_code code,
  struct sized_buffer *body,
  struct api_header_s *pairs)
{
  if (code >= 500) { // server related error, retry
    D_NOTOP_PRINT("(%d)%s - %s", 
        code,
        http_code_print(code),
        http_reason_print(code));

    orka_sleep_ms(5000); // wait a bit before retrying

    return ACTION_RETRY; // RETRY
  }

  switch (code) {
  case HTTP_BAD_REQUEST:
  case HTTP_UNAUTHORIZED:
  case HTTP_FORBIDDEN:
  case HTTP_NOT_FOUND:
  case HTTP_METHOD_NOT_ALLOWED:
  default:
      ERR("(%d)%s - %s",  //print error and abort
          code,
          http_code_print(code),
          http_reason_print(code));

      return ACTION_ABORT;
  case HTTP_TOO_MANY_REQUESTS:
   {
      D_NOTOP_PRINT("(%d)%s - %s", 
          code,
          http_code_print(code),
          http_reason_print(code));

      char message[256];
      long long retry_after_ms = 0;

      json_scanf(body->start, body->size,
                  "[message]%s [retry_after]%lld",
                  message, &retry_after_ms);

      if (retry_after_ms) { // retry after attribute received
        D_NOTOP_PRINT("RATELIMIT MESSAGE:\n\t%s (wait: %lld ms)", message, retry_after_ms);

        orka_sleep_ms(retry_after_ms); // wait a bit before retrying

        return ACTION_RETRY;
      }
      
      // no retry after included, we should abort

      ERR("RATELIMIT MESSAGE:\n\t%s", message);
      return ACTION_ABORT;
   }
  }
}

/* template function for performing requests */
void
run(
  dati *ua, 
  struct resp_handle *resp_handle,
  struct sized_buffer *body,
  enum http_method http_method,
  char endpoint[],
  ...)
{
  va_list args;
  va_start (args, endpoint);

  set_url(ua->ehandle, BASE_API_URL, endpoint, &args); //set the request URL

  va_end(args);

  set_method(ua->ehandle, http_method, body); //set the request method

  struct ratelimit ratelimit = {
    .ua = ua, 
    .bucket = NULL, 
    .endpoint = endpoint,
    .resp_handle = resp_handle
  };

  struct perform_cbs cbs = {
    .p_data = (void*)&ratelimit,
    .start = &start_cb,
    .before_perform = &before_perform_cb,
    .on_1xx = NULL,
    .on_2xx = &on_success_cb,
    .on_3xx = &on_success_cb,
    .on_4xx = &on_failure_cb,
    .on_5xx = &on_failure_cb,
  };

  perform_request(
    &ua->body,
    &ua->pairs,
    ua->ehandle,
    &cbs);
}

} // namespace user_agent
} // namespace discord
