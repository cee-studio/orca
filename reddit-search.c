#include <string.h>

#include "reddit.h"
#include "reddit-internal.h"

ORCAcode
reddit_search(struct reddit *client,
              struct reddit_search_params *params,
              char subreddit[],
              struct sized_buffer *ret)
{
  struct reddit_request_attr attr = { ret, 0, NULL,
                                      (void (*)(char *, size_t, void *))
                                        & cee_sized_buffer_from_json };
  char *q_url_encoded;
  char query[1024];
  size_t len = 0;

  ORCA_EXPECT(client, !IS_EMPTY_STRING(subreddit), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, cee_str_bounds_check(params->category, 5) != 0,
              ORCA_BAD_PARAMETER,
              "Category should be no longer than 5 characters");
  ORCA_EXPECT(client, cee_str_bounds_check(params->q, 512) > 0,
              ORCA_BAD_PARAMETER,
              "Keywords should be no longer than 512 characters");
  ORCA_EXPECT(client,
              IS_EMPTY_STRING(params->show) || STREQ(params->show, "all"),
              ORCA_BAD_PARAMETER, "'show' should be NULL or \"all\"");
  ORCA_EXPECT(client,
              IS_EMPTY_STRING(params->type)
                || strstr("sr,link,user", params->type),
              ORCA_BAD_PARAMETER);

  if (!params->limit) // default is 25
    params->limit = 25;
  else if (params->limit > 100)
    params->limit = 100;

  len += snprintf(query, sizeof(query), "limit=%d", params->limit);
  ASSERT_S(len < sizeof(query), "Out of bounds write attempt");

  q_url_encoded = url_encode(params->q);

  len += snprintf(query + len, sizeof(query) - len, "&q=%s", q_url_encoded);
  ASSERT_S(len < sizeof(query), "Out of bounds write attempt");

  free(q_url_encoded);

  if (true == params->restrict_sr) {
    len += snprintf(query + len, sizeof(query) - len, "&restrict_sr=1");
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }
  if (!IS_EMPTY_STRING(params->t)) {
    ORCA_EXPECT(client, strstr("hour,day,week,month,year,all", params->t),
                ORCA_BAD_PARAMETER);

    len += snprintf(query + len, sizeof(query) - len, "&t=%s", params->t);
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }
  if (!IS_EMPTY_STRING(params->sort)) {
    ORCA_EXPECT(client, strstr("relevance,hot,top,new,comments", params->sort),
                ORCA_BAD_PARAMETER);

    len +=
      snprintf(query + len, sizeof(query) - len, "&sort=%s", params->sort);
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }
  if (params->before) {
    ORCA_EXPECT(client, IS_EMPTY_STRING(params->after), ORCA_BAD_PARAMETER,
                "Can't have 'after' and 'before' set at the same time");

    len +=
      snprintf(query + len, sizeof(query) - len, "&before=%s", params->before);
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }
  if (params->after) {
    ORCA_EXPECT(client, IS_EMPTY_STRING(params->before), ORCA_BAD_PARAMETER,
                "Can't have 'after' and 'before' set at the same time");

    len +=
      snprintf(query + len, sizeof(query) - len, "&after=%s", params->after);
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }

  return reddit_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                            "/r/%s/search.json?raw_json=1%s", subreddit,
                            query);
}
