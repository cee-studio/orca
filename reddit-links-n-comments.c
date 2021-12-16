#define _GNU_SOURCE /* asprintf() */
#include <string.h>

#include "reddit.h"
#include "reddit-internal.h"

ORCAcode
reddit_comment(struct reddit *client,
               struct reddit_comment_params *params,
               struct sized_buffer *ret)
{
  struct reddit_request_attr attr = { ret, 0, NULL,
                                      (void (*)(char *, size_t, void *))
                                        & cee_sized_buffer_from_json };
  struct sized_buffer body;
  char *text_url_encoded;
  char buf[4096];
  size_t len = 0;

  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->text), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->thing_id), ORCA_BAD_PARAMETER);

  text_url_encoded = url_encode(params->text);

  len += snprintf(buf, sizeof(buf), "text=%s", text_url_encoded);
  ASSERT_S(len < sizeof(buf), "Out of bounds write attempt");

  free(text_url_encoded);

  len +=
    snprintf(buf + len, sizeof(buf) - len, "&thing_id=%s", params->thing_id);
  ASSERT_S(len < sizeof(buf), "Out of bounds write attempt");

  if (params->api_type) {
    len +=
      snprintf(buf + len, sizeof(buf) - len, "&api_type=%s", params->api_type);
    ASSERT_S(len < sizeof(buf), "Out of bounds write attempt");
  }
  if (params->return_rtjson) {
    len += snprintf(buf + len, sizeof(buf) - len, "&return_rtjson=%d",
                    params->return_rtjson);
    ASSERT_S(len < sizeof(buf), "Out of bounds write attempt");
  }
  if (params->richtext_json) {
    len += snprintf(buf + len, sizeof(buf) - len, "&richtext_json=%s",
                    params->richtext_json);
    ASSERT_S(len < sizeof(buf), "Out of bounds write attempt");
  }
  if (params->uh) {
    len += snprintf(buf + len, sizeof(buf) - len, "&uh=%s", params->uh);
    ASSERT_S(len < sizeof(buf), "Out of bounds write attempt");
  }

  body.start = buf;
  body.size = len;

  return reddit_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                            "/api/comment");
}
