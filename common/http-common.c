#include <stdio.h>
#include <stdlib.h>
#include <ctype.h> //for isspace()
#include <string.h>

#include "http-common.h"
#include "orka-utils.h"

/* attempt to get value from matching response header field */
char*
get_respheader_value(struct ua_conn_s *conn, char field[])
{
  for (int i=0; i < conn->pairs.size; ++i) {
    if (0 == strcasecmp(field, conn->pairs.field[i])) {
      return conn->pairs.value[i]; //found header field, return its value
    }
  }

  return NULL; //couldn't find header field
}

void
add_reqheader_pair(struct ua_handle_s *handle, char field[],  char value[])
{
  char buf[MAX_HEADER_LEN];
  int ret = snprintf(buf, sizeof(buf), "%s: %s", field, value);
  ASSERT_S(ret < MAX_HEADER_LEN, "Out of bounds write attempt");

  if (NULL == handle->reqheader) 
    handle->reqheader = curl_slist_append(NULL, buf);
  else
    curl_slist_append(handle->reqheader, buf);
}

void
edit_reqheader_pair(struct ua_handle_s *handle, char field[],  char new_value[])
{
  size_t len = strlen(field);
  struct curl_slist *node = handle->reqheader;
  while (strncasecmp(node->data, field, len)) {
    node = node->next;
    if (NULL == node) {
      D_PRINT("Couldn't find field '%s' in existing request header", field);
      return; /* EARLY EXIT */
    }
  }

  free(node->data);
  asprintf(&node->data, "%s: %s", field, new_value);
}

// @todo this needs some testing
void
del_reqheader_pair(struct ua_handle_s *handle, char field[])
{
  struct curl_slist *node = handle->reqheader;
  size_t len = strlen(field);
  if (strncasecmp(node->data, field, len)) {
    free(node->data);
    free(node);
    handle->reqheader = NULL;

    return; /* EARLY EXIT */
  }

  do { // iterate linked list to try and find field match
    if (node->next && strncasecmp(node->next->data, field, len)) {
      free(node->next->data);
      free(node->next);
      node->next = NULL;

      return; /* EARLY EXIT */
    }
    node = node->next;
  } while (node != NULL);

  D_PRINT("Couldn't find field '%s' in existing request header", field);
}

char*
http_code_print(int httpcode)
{
  switch (httpcode) {
      CASE_RETURN_STR(HTTP_OK);
      CASE_RETURN_STR(HTTP_CREATED);
      CASE_RETURN_STR(HTTP_NO_CONTENT);
      CASE_RETURN_STR(HTTP_NOT_MODIFIED);
      CASE_RETURN_STR(HTTP_BAD_REQUEST);
      CASE_RETURN_STR(HTTP_UNAUTHORIZED);
      CASE_RETURN_STR(HTTP_FORBIDDEN);
      CASE_RETURN_STR(HTTP_NOT_FOUND);
      CASE_RETURN_STR(HTTP_METHOD_NOT_ALLOWED);
      CASE_RETURN_STR(HTTP_UNPROCESSABLE_ENTITY);
      CASE_RETURN_STR(HTTP_TOO_MANY_REQUESTS);
      CASE_RETURN_STR(HTTP_GATEWAY_UNAVAILABLE);
  default:
      if (httpcode >= 500) return "5xx SERVER ERROR";
      if (httpcode >= 400) return "4xx CLIENT ERROR";
      if (httpcode >= 300) return "3xx REDIRECTING";
      if (httpcode >= 200) return "2xx SUCCESS";
      if (httpcode >= 100) return "1xx INFO";
  }

  return "UNUSUAL HTTP CODE";
}

char*
http_reason_print(int httpcode)
{
  switch (httpcode) {
  case HTTP_OK:
      return "The request was completed succesfully.";
  case HTTP_CREATED:
      return "The entity was created succesfully.";
  case HTTP_NO_CONTENT:
      return "The request completed succesfully but returned no content.";
  case HTTP_NOT_MODIFIED:
      return "The entity was not modified (no action was taken).";
  case HTTP_BAD_REQUEST:
      return "The request was improperly formatted, or the server couldn't understand it.";
  case HTTP_UNAUTHORIZED:
      return "The Authorization header was missing or invalid.";
  case HTTP_FORBIDDEN:
      return "The Authorization token you passed did not have permission to the resource.";
  case HTTP_NOT_FOUND:
      return "The resource at the location specified doesn't exist.";
  case HTTP_METHOD_NOT_ALLOWED:
      return "The HTTP method used is not valid for the location specified.";
  case HTTP_TOO_MANY_REQUESTS:
      return "You got ratelimited.";
  case HTTP_GATEWAY_UNAVAILABLE:
      return "There was not a gateway available to process your request. Wait a bit and retry.";
  case CURL_NO_RESPONSE:
      return "Curl couldn't fetch a HTTP response.";
  default:
      if (httpcode >= 500) 
        return "The server had an error processing your request.";
      if (httpcode >= 400)
        return "Client side error, request couldn't be processed.";
      if (httpcode >= 300)
        return "Client requires taking additional action to complete the request";
      if (httpcode >= 200)
        return "The action request was received, understood and accepted.";
      if (httpcode >= 100)
        return "The request was received and understood. The client must wait for a final response.";

      return "Unusual HTTP method.";
  }
}

char*
http_method_print(enum http_method method)
{
  switch(method) {
      CASE_RETURN_STR(HTTP_DELETE);
      CASE_RETURN_STR(HTTP_GET);
      CASE_RETURN_STR(HTTP_POST);
      CASE_RETURN_STR(HTTP_MIMEPOST);
      CASE_RETURN_STR(HTTP_PATCH);
      CASE_RETURN_STR(HTTP_PUT);
  default:
      ERR("Invalid HTTP method (code: %d)", method);
  }
}

/* set specific http method used for the request */
void
ua_set_method(struct ua_conn_s *conn, enum http_method method, struct sized_buffer *req_body)
{
  // resets any preexisting CUSTOMREQUEST
  curl_easy_setopt(conn->ehandle, CURLOPT_CUSTOMREQUEST, NULL);

  CURLcode ecode;
  switch (method) {
  case HTTP_DELETE:
      ecode = curl_easy_setopt(conn->ehandle, CURLOPT_CUSTOMREQUEST, "DELETE");
      ASSERT_S(CURLE_OK == ecode, curl_easy_strerror(ecode));
      break;
  case HTTP_GET:
      ecode = curl_easy_setopt(conn->ehandle, CURLOPT_HTTPGET, 1L);
      ASSERT_S(CURLE_OK == ecode, curl_easy_strerror(ecode));
      return; /* EARLY RETURN */
  case HTTP_POST:
      curl_easy_setopt(conn->ehandle, CURLOPT_POST, 1L);
      break;
  case HTTP_MIMEPOST:
      curl_easy_setopt(conn->ehandle, CURLOPT_MIMEPOST, req_body->start);
      return; /* EARLY RETURN */
  case HTTP_PATCH:
      curl_easy_setopt(conn->ehandle, CURLOPT_CUSTOMREQUEST, "PATCH");
      break;
  case HTTP_PUT:
      curl_easy_setopt(conn->ehandle, CURLOPT_CUSTOMREQUEST, "PUT");
      break;
  default:
      ERR("Unknown http method (code: %d)", method);
  }
  
  if (req_body && req_body->start) {
    //set ptr to payload that will be sent via POST/PUT
    curl_easy_setopt(conn->ehandle, CURLOPT_POSTFIELDS, req_body->start);
    curl_easy_setopt(conn->ehandle, CURLOPT_POSTFIELDSIZE, req_body->size);
  }
}

void
ua_set_url(struct ua_conn_s *conn, char base_api_url[], char endpoint[], va_list args)
{
  //create the url route
  char url_route[MAX_URL_LEN];
  int ret = vsnprintf(url_route, sizeof(url_route), endpoint, args);
  ASSERT_S(ret < (int)sizeof(url_route), "oob write of url_route");

  char base_url[MAX_URL_LEN];
  ret = snprintf(base_url, sizeof(base_url), "%s%s", base_api_url, url_route);
  ASSERT_S(ret < (int)sizeof(base_url), "Out of bounds write attempt");

  CURLcode ecode = curl_easy_setopt(conn->ehandle, CURLOPT_URL, base_url);
  ASSERT_S(CURLE_OK == ecode, curl_easy_strerror(ecode));
}

static void
noop_cb(void *data)
{ 
  (void)data; 
  return; 
}

static perform_action
noop_success_cb(
  void *p_data,
  int httpcode,
  struct ua_conn_s *conn)
{ 
  (void)p_data; (void)httpcode; (void)conn;
  return ACTION_SUCCESS;
}

static perform_action
noop_retry_cb(
  void *p_data,
  int httpcode,
  struct ua_conn_s *conn)
{
  (void)p_data; (void)httpcode; (void)conn;
  return ACTION_RETRY;
}

static perform_action 
noop_abort_cb(
  void *p_data,
  int httpcode,
  struct ua_conn_s *conn)
{ 
  (void)p_data; (void)httpcode; (void)conn;
  return ACTION_ABORT; 
}

int
ua_send_request(struct ua_conn_s *conn)
{
  CURLcode ecode;

  //@todo shouldn't abort on error
  ecode = curl_easy_perform(conn->ehandle);
  ASSERT_S(CURLE_OK == ecode, curl_easy_strerror(ecode));

  //get response's code
  int httpcode;
  ecode = curl_easy_getinfo(conn->ehandle, CURLINFO_RESPONSE_CODE, &httpcode);
  ASSERT_S(CURLE_OK == ecode, curl_easy_strerror(ecode));

  ecode = curl_easy_getinfo(conn->ehandle, CURLINFO_EFFECTIVE_URL, &conn->resp_url);
  ASSERT_S(CURLE_OK == ecode, curl_easy_strerror(ecode));
  DS_PRINT("Request URL: %s", &conn->resp_url);

  return httpcode;
}

void
ua_perform_request(
  struct ua_conn_s *conn, 
  struct resp_handle *resp_handle,
  struct perform_cbs *p_cbs)
{
  struct perform_cbs cbs;
  if (p_cbs)
    memcpy(&cbs, p_cbs, sizeof(struct perform_cbs));
  else
    memset(&cbs, 0, sizeof(struct perform_cbs));

  /* SET DEFAULT CALLBACKS */
  if (!cbs.before_perform) cbs.before_perform = &noop_cb;
  if (!cbs.on_1xx) cbs.on_1xx = &noop_success_cb;
  if (!cbs.on_2xx) cbs.on_2xx = &noop_success_cb;
  if (!cbs.on_3xx) cbs.on_3xx = &noop_success_cb;
  if (!cbs.on_4xx) cbs.on_4xx = &noop_abort_cb;
  if (!cbs.on_5xx) cbs.on_5xx = &noop_retry_cb;

  perform_action action;
  do {
    /* triggers on every start of loop iteration */
    (*cbs.before_perform)(cbs.p_data);
  
    int httpcode = ua_send_request(conn);

    /* triggers response related callbacks */
    if (httpcode >= 500) { // SERVER ERROR
      action = (*cbs.on_5xx)(cbs.p_data, httpcode, conn);

      if (resp_handle && resp_handle->err_cb) {
        (*resp_handle->err_cb)(
            conn->resp_body.start,
            conn->resp_body.size, 
            resp_handle->err_obj);
      }
    }
    else if (httpcode >= 400) { // CLIENT ERROR
      action = (*cbs.on_4xx)(cbs.p_data, httpcode, conn);

      if (resp_handle && resp_handle->err_cb) {
        (*resp_handle->err_cb)(
            conn->resp_body.start,
            conn->resp_body.size, 
            resp_handle->err_obj);
      }
    }
    else if (httpcode >= 300) { // REDIRECTING
      action = (*cbs.on_3xx)(cbs.p_data, httpcode, conn);
    }
    else if (httpcode >= 200) { // SUCCESS RESPONSES
      action = (*cbs.on_2xx)(cbs.p_data, httpcode, conn);

      if (resp_handle && resp_handle->ok_cb) {
        (*resp_handle->ok_cb)(
            conn->resp_body.start,
            conn->resp_body.size, 
            resp_handle->ok_obj);
      }
    }
    else if (httpcode >= 100) { // INFO RESPONSE
      action = (*cbs.on_1xx)(cbs.p_data, httpcode, conn);
    }

    // reset body and header for next possible iteration
    conn->resp_body.size = 0;
    conn->pairs.size = 0;

    switch (action) {
    case ACTION_SUCCESS:
    case ACTION_FAILURE:
        D_PRINT("FINISHED REQUEST AT %s", conn->resp_url);
        conn->is_available = 1;
        return;
    case ACTION_RETRY:
        D_PRINT("RETRYING TO PERFORM REQUEST AT %s", conn->resp_url);
        break;
    case ACTION_ABORT:
    default:
        ERR("COULDN'T PERFORM REQUEST AT %s", conn->resp_url);
    }

  } while (ACTION_RETRY == action);
}

static size_t
curl_resheader_cb(char *str, size_t size, size_t nmemb, void *p_userdata)
{
  size_t realsize = size * nmemb;
  struct api_header_s *pairs = (struct api_header_s *)p_userdata;

  char *ptr;
  if (!(ptr = strchr(str, ':'))) { //returns if can't find ':' token match
    return realsize;
  }

  *ptr = '\0'; //replace ':' with '\0' to separate field from value

  int ret = snprintf(pairs->field[pairs->size], MAX_HEADER_LEN, "%s", str);
  ASSERT_S(ret < MAX_HEADER_LEN, "oob of paris->field");

  if (!(ptr = strstr(ptr + 1, "\r\n"))) {//returns if can't find CRLF match
    return realsize;
  }

  *ptr = '\0'; //replace CRLF with '\0' to isolate field

  //adjust offset to start of value
  int offset = 1; //offset starts after '\0' separator token
  while (isspace(str[strlen(str) + offset])) {
    ++offset;
  }

  //get the value part from string
  ret = snprintf(pairs->value[pairs->size], MAX_HEADER_LEN, "%s",
                 &str[strlen(str) + offset]);
  ASSERT_S(ret < MAX_HEADER_LEN, "oob write attempt");

  ++pairs->size; //update header amount of field/value pairs
  ASSERT_S(pairs->size < MAX_HEADER_SIZE, "oob write of pairs");

  return realsize;
}

/* get api response body string
* see: https://curl.se/libcurl/c/CURLOPT_WRITEFUNCTION.html */
static size_t
curl_resbody_cb(char *str, size_t size, size_t nmemb, void *p_userdata)
{
  size_t realsize = size * nmemb;
  struct sized_buffer *resp_body = (struct sized_buffer *)p_userdata;

  //update response body string size
  resp_body->start = realloc(resp_body->start, resp_body->size + realsize + 1);
  memcpy(resp_body->start + resp_body->size, str, realsize);
  resp_body->size += realsize;
  resp_body->start[resp_body->size] = '\0';
  return realsize;
}

void
json_dump(const char *text, struct _settings_s *settings, const char *data)
{
  if (NULL == settings->f_json_dump) return;
  FILE *f_dump = settings->f_json_dump;

  char timestr[64] = {0};
  orka_timestamp_str(timestr, sizeof(timestr));

  fprintf(f_dump, "\r\r\r\r%s - %s\n%s\n", text, timestr, data);
  fflush(f_dump);
}

static void
curl_dump(const char *text, FILE *f_dump, unsigned char *ptr, size_t size)
{
  const unsigned int WIDTH = 0x10;

  char timestr[64] = {0};
  orka_timestamp_str(timestr, sizeof(timestr));

  fprintf(f_dump, "\r\r\r\r%s %10.10ld bytes (0x%8.8lx) - %s\n%s\n",
          text, (long)size, (long)size, timestr, ptr);

  for(size_t i=0; i < size; i += WIDTH)
  {
    fprintf(f_dump, "%4.4lx: ", (long)i);

    //show hex to the left
    for(size_t c = 0; c < WIDTH; c++) {
      if(i+c < size)
        fprintf(f_dump, "%02x ", ptr[i+c]);
      else
        fputs("   ", f_dump);
    }

    //show data on the right
    for(size_t c = 0; (c < WIDTH) && (i+c < size); c++) {
      char x = (ptr[i+c] >= 0x20 && ptr[i+c] < 0x80) ? ptr[i+c] : '.';
      fputc(x, f_dump);
    }

    fputc('\n', f_dump); //newline
  }

  fflush(f_dump);
}

int
curl_debug_cb(
  CURL *ehandle,
  curl_infotype type,
  char *data,
  size_t size,
  void *p_userdata)
{
  struct _settings_s *settings = (struct _settings_s *)p_userdata;
  if (NULL == settings->f_curl_dump) return 0;

  FILE *f_dump = settings->f_curl_dump;

  const char *text = NULL;
  switch (type) {
  case CURLINFO_TEXT:
    {
      char timestr[64] = {0};
      orka_timestamp_str(timestr, sizeof(timestr));

      fprintf(f_dump, "\r\r\r\rCURL INFO - %s\n%s\n", timestr, data);
      fflush(f_dump);
    }
  /* fallthrough */
  default:
      return 0;
  case CURLINFO_HEADER_OUT:
      text = "SEND HEADER";
      break;
  case CURLINFO_DATA_OUT:
      text = "SEND DATA";
      break;
  case CURLINFO_SSL_DATA_OUT:
      text = "SEND SSL DATA";
      break;
  case CURLINFO_HEADER_IN:
      text = "RECEIVE HEADER";
      break;
  case CURLINFO_DATA_IN:
      text = "RECEIVE DATA";
      break;
  case CURLINFO_SSL_DATA_IN:
      text = "RECEIVE SSL DATA";
      break;
  }

  curl_dump(text, f_dump, (unsigned char*)data, size);

  return 0;

  (void)ehandle;
}

void
ua_easy_setopt(struct ua_handle_s *handle, void *data, void (setopt_cb)(CURL *ehandle, void *data)) {
  handle->setopt_cb = setopt_cb;
  handle->data = data;
}

static void
ua_conn_easy_init(struct ua_handle_s *handle, struct ua_conn_s *conn)
{
  CURL *new_ehandle = curl_easy_init();

  CURLcode ecode;
  /* DEBUG ONLY FUNCTIONS */
  //set debug callback
  D_ONLY(ecode = curl_easy_setopt(new_ehandle, CURLOPT_DEBUGFUNCTION, &curl_debug_cb));
  D_ASSERT_S(CURLE_OK == ecode, curl_easy_strerror(ecode));

  //set ptr to settings containing dump files
  D_ONLY(ecode = curl_easy_setopt(new_ehandle, CURLOPT_DEBUGDATA, &handle->settings));
  D_ASSERT_S(CURLE_OK == ecode, curl_easy_strerror(ecode));

  //enable verbose
  D_ONLY(ecode = curl_easy_setopt(new_ehandle, CURLOPT_VERBOSE, 1L));
  D_ASSERT_S(CURLE_OK == ecode, curl_easy_strerror(ecode));
  /* * * * * * * * * * * */

  //set ptr to request header we will be using for API communication
  ecode = curl_easy_setopt(new_ehandle, CURLOPT_HTTPHEADER, handle->reqheader);
  ASSERT_S(CURLE_OK == ecode, curl_easy_strerror(ecode));

  //enable follow redirections
  ecode = curl_easy_setopt(new_ehandle, CURLOPT_FOLLOWLOCATION, 1L);
  ASSERT_S(CURLE_OK == ecode, curl_easy_strerror(ecode));

  //set response body callback
  ecode = curl_easy_setopt(new_ehandle, CURLOPT_WRITEFUNCTION, &curl_resbody_cb);
  ASSERT_S(CURLE_OK == ecode, curl_easy_strerror(ecode));

  //set ptr to response body to be filled at callback
  ecode = curl_easy_setopt(new_ehandle, CURLOPT_WRITEDATA, &conn->resp_body);
  ASSERT_S(CURLE_OK == ecode, curl_easy_strerror(ecode));

  //set response header callback
  ecode = curl_easy_setopt(new_ehandle, CURLOPT_HEADERFUNCTION, &curl_resheader_cb);
  ASSERT_S(CURLE_OK == ecode, curl_easy_strerror(ecode));

  //set ptr to response header to be filled at callback
  ecode = curl_easy_setopt(new_ehandle, CURLOPT_HEADERDATA, &conn->pairs);
  ASSERT_S(CURLE_OK == ecode, curl_easy_strerror(ecode));

  conn->ehandle = new_ehandle;
}

static void
ua_conn_init(struct ua_handle_s *handle, struct ua_conn_s *conn) 
{
  memset(conn, 0, sizeof(struct ua_conn_s));
  ua_conn_easy_init(handle, conn);
}

static void
ua_conn_cleanup(struct ua_conn_s *conn)
{
  curl_easy_cleanup(conn->ehandle);
  if (conn->resp_body.start) {
    free(conn->resp_body.start);
  }
}

struct ua_conn_s*
ua_get_conn(struct ua_handle_s *handle)
{
  if (!handle->num_available) { // no available conn, create new
    struct ua_conn_s *new_conn = realloc(handle->conns, (1 + handle->size) * sizeof(struct ua_conn_s));

    ua_conn_init(handle, &new_conn[handle->size]);
    handle->conns = new_conn;

    ++handle->size;

    return &handle->conns[handle->size-1];
  }
  else {
    for (size_t i=0; i < handle->size; ++i) {
      if (handle->conns[i].is_available) {
        handle->conns[i].is_available = 0;
        --handle->num_available;
        return &handle->conns[i];
      }
    }
    ERR("There were no available connections (internal error)");
  }
}

void
ua_handle_init(struct ua_handle_s *handle, char base_url[]) 
{
  memset(handle, 0, sizeof(struct ua_handle_s));
  handle->base_url = base_url;
}

void
ua_handle_cleanup(struct ua_handle_s *handle)
{
  curl_slist_free_all(handle->reqheader);
  for (size_t i=0; handle->size; ++i) {
    ua_conn_cleanup(&handle->conns[i]);
  }
}
