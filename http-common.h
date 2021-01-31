#ifndef HTTP_COMMON_H
#define HTTP_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <curl/curl.h>
#include "orka-debug.h"
#include "ntl.h"


/* UTILITY MACROS */
#define STREQ(str1, str2) (0 == strcmp(str1, str2))
#define STRNEQ(str1, str2, n) (0 == strncmp(str1, str2, n))
//check if string is empty
#define IS_EMPTY_STRING(str) (!(str) || !*(str))
//if case matches return token as string
#define CASE_RETURN_STR(opcode) case opcode: return #opcode

//possible http methods
enum http_method {
  HTTP_DELETE, HTTP_GET, HTTP_POST, HTTP_PATCH, HTTP_PUT
};


/* HTTP RESPONSE CODES
https://discord.com/developers/docs/topics/opcodes-and-status-codes#http-http-response-codes */
enum http_code {
  HTTP_OK                       = 200,
  HTTP_CREATED                  = 201,
  HTTP_NO_CONTENT               = 204,
  HTTP_NOT_MODIFIED             = 304,
  HTTP_BAD_REQUEST              = 400,
  HTTP_UNAUTHORIZED             = 401,
  HTTP_FORBIDDEN                = 403,
  HTTP_NOT_FOUND                = 404,
  HTTP_METHOD_NOT_ALLOWED       = 405,
  HTTP_UNPROCESSABLE_ENTITY     = 422,
  HTTP_TOO_MANY_REQUESTS        = 429,
  HTTP_GATEWAY_UNAVAILABLE      = 502,

  CURL_NO_RESPONSE              = 0,
};

#define MAX_HEADER_SIZE 100
#define MAX_URL_LEN     512
#define MAX_HEADER_LEN  512

struct api_header_s {
  char field[MAX_HEADER_SIZE][MAX_HEADER_LEN];
  char value[MAX_HEADER_SIZE][MAX_HEADER_LEN];
  int size;
};

struct _settings_s { //@todo this whole struct is temporary
  char *token;
  FILE *f_json_dump;
  FILE *f_curl_dump;
};

//callback for object to be loaded by api response
typedef void (load_obj_cb)(char *str, size_t len, void *p_obj);

// response handle
struct resp_handle {
  load_obj_cb *ok_cb;
  void *ok_obj; // the pointer to be passed to ok_cb

  load_obj_cb *err_cb;
  void *err_obj; // the pointer to be passed to err_cb
};

char* get_header_value(struct api_header_s *pairs, char header_field[]);
char* http_code_print(enum http_code code);
char* http_reason_print(enum http_code code);
char* http_method_print(enum http_method method);

/* set url to be used for the request */
void set_url(CURL *ehandle, char base_api_url[], char endpoint[], va_list *args);
/* set specific http method used for the request */
void set_method(CURL *ehandle, enum http_method method, struct sized_buffer *body);

typedef enum {ACTION_SUCCESS, ACTION_RETRY, ACTION_ABORT} perform_action;
typedef perform_action (http_response_cb)(
    void *data,
    enum http_code code, 
    struct sized_buffer *body,
    struct api_header_s *pairs);

struct perform_cbs {
  void *p_data; // data to be received by callbacks

  void (*start)(void*); // trigger once at function start
  void (*before_perform)(void*); // trigger before perform attempt

  http_response_cb *on_1xx; // trigger at 1xx code
  http_response_cb *on_2xx; // trigger every 2xx code
  http_response_cb *on_3xx; // trigger every 3xx code
  http_response_cb *on_4xx; // trigger every 4xx code
  http_response_cb *on_5xx; // trigger every 5xx code
};

void perform_request(
  struct sized_buffer *body,
  struct api_header_s *pairs,
  CURL *ehandle,
  struct perform_cbs *cbs);

CURL* custom_easy_init(struct _settings_s *settings,
                 struct curl_slist *req_header,
                 struct api_header_s *pairs,
                 struct sized_buffer *body);

void json_dump(const char *text, struct _settings_s *settings, const char *data);
int curl_debug_cb(CURL *ehandle, curl_infotype type, char *data, size_t size, void *p_userdata);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HTTP_COMMON_H
