/**
 * @file user-agent.h
 */

#ifndef USER_AGENT_H
#define USER_AGENT_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <curl/curl.h>
#include "ntl.h" /* struct sized_buffer */
#include "types.h" /* ORCAcode */
#include "logconf.h" /* logging facilities */

/* forward declaration */
struct user_agent;
struct ua_conn;

/** @brief User-Agent handle initialization attributes */
struct ua_attr {
  /** pre-initialized logging module */
  struct logconf *conf;
};

/** @brief HTTP methods */
enum http_method {
  HTTP_INVALID = -1,
  HTTP_DELETE,
  HTTP_GET,
  HTTP_POST,
  HTTP_MIMEPOST,
  HTTP_PATCH,
  HTTP_PUT
};

/* COMMON HTTP RESPONSE CODES
https://en.wikipedia.org/wiki/List_of_HTTP_status_codes */
#define HTTP_OK                   200
#define HTTP_CREATED              201
#define HTTP_NO_CONTENT           204
#define HTTP_NOT_MODIFIED         304
#define HTTP_BAD_REQUEST          400
#define HTTP_UNAUTHORIZED         401
#define HTTP_FORBIDDEN            403
#define HTTP_NOT_FOUND            404
#define HTTP_METHOD_NOT_ALLOWED   405
#define HTTP_UNPROCESSABLE_ENTITY 422
#define HTTP_TOO_MANY_REQUESTS    429
#define HTTP_GATEWAY_UNAVAILABLE  502

/** Maximum amount of header pairs */
#define UA_MAX_HEADER_PAIRS 100 + 1

/** @brief Callback for object to be loaded by api response */
typedef void (*ua_load_obj_cb)(char *str, size_t len, void *p_obj);

/** @brief User callback to be called on request completion */
struct ua_resp_handle {
  /** callback called when a successful transfer occurs */
  ua_load_obj_cb ok_cb;
  /** the pointer to be passed to ok_cb */
  void *ok_obj;
  /** callback called when a failed transfer occurs */
  ua_load_obj_cb err_cb;
  /** the pointer to be passed to err_cb */
  void *err_obj;
};

/** @brief Structure for storing the request's response header */
struct ua_resp_header {
  /** response header buffer */
  char *buf;
  /** response header string length */
  size_t len;
  /** real size occupied in memory by buffer */
  size_t bufsize;
  /** array of header field/value pairs */
  struct {
    struct {
      /** offset index of 'buf' for the start of field or value */
      uintptr_t idx;
      /** length of individual field or value */
      size_t size;
    } field, value;
  } pairs[UA_MAX_HEADER_PAIRS];
  /** amount of pairs initialized */
  int n_pairs;
};

/** @brief Structure for storing the request's response body */
struct ua_resp_body {
  /** response body buffer */
  char *buf;
  /** response body string length */
  size_t len;
  /** real size occupied in memory by buffer */
  size_t bufsize;
};

/** @brief Informational handle received on request's completion */
struct ua_info {
  /** logging informational */
  struct loginfo loginfo;
  /** last used HTTP method */
  enum http_method method;
  /** the HTTP response code */
  int httpcode;
  /** total elapsed time for request completion (in micro-seconds) */
  curl_off_t time_us;
  /** the response header */
  struct ua_resp_header header;
  /** the response body */
  struct ua_resp_body body;
};

const char *http_code_print(int httpcode);
const char *http_reason_print(int httpcode);
const char *http_method_print(enum http_method method);
enum http_method http_method_eval(char method[]);

/**
 * @brief Add a field/value pair to the request header
 *
 * @param ua the User-Agent handle created with ua_init()
 * @param field header's field to be added
 * @param value field's value
 */
void ua_reqheader_add(struct user_agent *ua,
                      const char field[],
                      const char value[]);

/**
 * @brief Delete a field from the request header
 *
 * @param ua the User-Agent handle created with ua_init()
 * @param field header's field to be deleted
 */
void ua_reqheader_del(struct user_agent *ua, const char field[]);

/**
 * @brief Get the request header as a linear string
 *
 * @param ua the User-Agent handle created with ua_init()
 * @param buf the user buffer to be filled
 * @param bufsize the user buffer size in bytes
 * @return the user buffer
 */
char *ua_reqheader_str(struct user_agent *ua, char *buf, size_t bufsize);

/**
 * @brief Set a setup callback to be called by each libcurl's connection during
 * initial setup
 *
 * @param ua the User-Handle created with ua_init()
 * @param data user data to be passed along to setopt_cb
 * @param setopt_cb the user callback
 */
void ua_curl_easy_setopt(struct user_agent *ua,
                         void *data,
                         void (*setopt_cb)(CURL *ehandle, void *data));
/**
 * @brief Set a MIME creation callback to be called by each libcurl's
 * connection
 *
 * This sets a user-defined callback for creating multipart types, needed
 *        if `Content-Type: multipart/form-data` is set
 * @param ua the User-Handle created with ua_init()
 * @param data user data to be passed along to `mime_cb`
 * @param mime_cb the user callback
 */
void ua_curl_mime_setopt(struct user_agent *ua,
                         void *data,
                         void (*mime_cb)(curl_mime *mime, void *data));

/**
 * @brief Initialize User-Agent handle
 *
 * @param attr optional attributes to override defaults
 * @return the user agent handle
 */
struct user_agent *ua_init(struct ua_attr *attr);

/**
 * @brief Clone a User-Agent handle
 *
 * Should be called before entering a thread, to ensure each thread
 *        has its own `user-agent` instance with unique buffers, url and
 * headers. The clone will share connections with the original, but will have
 *        its own unique set of URL and headers
 * @param orig_ua the original User-Agent handle
 * @return the User-Agent handle clone
 * @note should call ua_cleanup() after done being used
 */
struct user_agent *ua_clone(struct user_agent *orig_ua);

/**
 * @brief Cleanup User-Agent handle resources
 *
 * @param ua the User-Agent handle created with ua_init()
 */
void ua_cleanup(struct user_agent *ua);

/**
 * @brief Set the request url
 *
 * @param ua the User-Agent handle created with ua_init()
 * @param base_url the base request url
 */
void ua_set_url(struct user_agent *ua, const char *base_url);

/**
 * @brief Get the request url
 *
 * @param ua the User-Agent handle created with ua_init()
 * @return the request url set with ua_set_url()
 */
const char *ua_get_url(struct user_agent *ua);

/**
 * @brief Run a REST transfer
 *
 * @param ua the User-Agent handle created with ua_init()
 * @param info optional informational handle on how the request went
 * @param handle the optional response callbacks, can be NULL
 * @param body the optional request body, can be NULL
 * @param method the HTTP method of this transfer (GET, POST, ...)
 * @param endpoint the endpoint to be appended to the URL set at ua_set_url()
 * @return ORCAcode for how the transfer went, ORCA_OK means success.
 */
ORCAcode ua_run(struct user_agent *ua,
                struct ua_info *info,
                struct ua_resp_handle *handle,
                struct sized_buffer *body,
                enum http_method method,
                char endpoint[]);

/**
 * @brief Get a connection handle and mark it as running
 *
 * @param ua the User-Agent handle created with ua_init()
 * @return a connection handle
 */
struct ua_conn *ua_conn_start(struct user_agent *ua);

/**
 * @brief Reset a connection handle fields
 *
 * @param ua the User-Agent handle created with ua_init()
 * @param conn connection handle to be reset
 * @warning this won't deactivate the handle, for that purpose check
 *        ua_conn_stop()
 */
void ua_conn_reset(struct user_agent *ua, struct ua_conn *conn);

/**
 * @brief Stop a connection handle and mark it as idle
 *
 * @param ua the User-Agent handle created with ua_init()
 * @param conn connection handle to be deactivated
 */
void ua_conn_stop(struct user_agent *ua, struct ua_conn *conn);

/**
 * @brief Setup a connection handle
 *
 * @param ua the User-Agent handle created with ua_init()
 * @param conn the connection handle to be modified
 * @param handle the optional response callbacks, can be NULL
 * @param body the optional request body, can be NULL
 * @param method the HTTP method of this transfer (GET, POST, ...)
 * @param endpoint the endpoint to be appended to the URL set at ua_set_url()
 */
void ua_conn_setup(struct user_agent *ua,
                   struct ua_conn *conn,
                   struct ua_resp_handle *handle,
                   struct sized_buffer *body,
                   enum http_method method,
                   char endpoint[]);

/**
 * @brief Fetch information about previous request
 *
 * @param ua the User-Agent handle created with ua_init()
 * @param conn the connection that performed a request
 * @param info handle containing information on previous request
 * @return ORCAcode for how the transfer went, ORCA_OK means success.
 */
ORCAcode ua_conn_get_results(struct user_agent *ua,
                             struct ua_conn *conn,
                             struct ua_info *info);

/**
 * @brief Get libcurl's easy handle assigned to `conn`
 *
 * @param conn the connection handle
 * @return the libcurl's easy handle
 */
CURL *ua_conn_curl_easy_get(struct ua_conn *conn);

/**
 * @brief Cleanup informational handle
 *
 * @param info handle containing information on previous request
 */
void ua_info_cleanup(struct ua_info *info);

/**
 * @brief Get a value's from the response header
 *
 * @param info handle containing information on previous request
 * @param field the header field to fetch the value
 * @return a sized_buffer containing the field's value
 */
const struct sized_buffer ua_info_header_get(struct ua_info *info,
                                             char field[]);

/**
 * @brief Get the response body
 *
 * @param info handle containing information on previous request
 * @return a sized_buffer containing the response body
 */
const struct sized_buffer ua_info_get_body(struct ua_info *info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* USER_AGENT_H */
