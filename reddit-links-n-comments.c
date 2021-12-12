#define _GNU_SOURCE /* asprintf() */
#include <string.h>

#include "reddit.h"
#include "reddit-internal.h"

ORCAcode reddit_comment(struct reddit *client,
                        struct reddit_comment_params *params,
                        struct sized_buffer *ret)
{
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->text), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->thing_id), ORCA_BAD_PARAMETER);

  char query[4096];
  size_t len = 0;

  char *text_url_encoded = url_encode(params->text);
  len += snprintf(query, sizeof(query), "text=%s", text_url_encoded);
  ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  free(text_url_encoded);

  len += snprintf(query + len, sizeof(query) - len, "&thing_id=%s",
                  params->thing_id);
  ASSERT_S(len < sizeof(query), "Out of bounds write attempt");

  if (params->api_type) {
    len += snprintf(query + len, sizeof(query) - len, "&api_type=%s",
                    params->api_type);
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }
  if (params->return_rtjson) {
    len += snprintf(query + len, sizeof(query) - len, "&return_rtjson=%d",
                    params->return_rtjson);
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }
  if (params->richtext_json) {
    len += snprintf(query + len, sizeof(query) - len, "&richtext_json=%s",
                    params->richtext_json);
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }
  if (params->uh) {
    len += snprintf(query + len, sizeof(query) - len, "&uh=%s", params->uh);
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }

  return reddit_adapter_run(&client->adapter, ret,
                            &(struct sized_buffer){ query, len }, HTTP_POST,
                            "/api/comment");
}
