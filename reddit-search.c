#include <string.h>

#include "reddit.h"
#include "reddit-internal.h"

ORCAcode reddit_search(struct reddit *client,
                       struct reddit_search_params *params,
                       char subreddit[],
                       struct sized_buffer *ret)
{
  ORCA_EXPECT(client, !IS_EMPTY_STRING(subreddit), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, (!params->after) != (!params->before), ORCA_BAD_PARAMETER, "Can't have 'after' and 'before' at the same time");
  ORCA_EXPECT(client, cee_str_bounds_check(params->category, 5) != 0, ORCA_BAD_PARAMETER, "Should be no longer than 5 characters");
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->q), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, cee_str_bounds_check(params->q, 512) != 0, ORCA_BAD_PARAMETER, "Should be no longer than 512 characters");
  ORCA_EXPECT(client, IS_EMPTY_STRING(params->show) || STREQ(params->show, "all"), ORCA_BAD_PARAMETER, "'show' should be NULL or \"all\"");
  if (!IS_EMPTY_STRING(params->sort))
    ORCA_EXPECT(client, strstr(params->sort, "relevance,hot,top,new,comments"), ORCA_BAD_PARAMETER);
  if (!IS_EMPTY_STRING(params->t))
    ORCA_EXPECT(client, strstr(params->t, "hour,day,week.month,year,all"), ORCA_BAD_PARAMETER);
  if (!IS_EMPTY_STRING(params->type))
    ORCA_EXPECT(client, strstr(params->type, "sr,link,user"), ORCA_BAD_PARAMETER);

  if (!params->limit) // default is 25
    params->limit = 25;
  else if (params->limit > 100)
    params->limit = 100;

  char query[1024];
  size_t len = 0;
  len += snprintf(query, sizeof(query), "limit=%d", params->limit);
  ASSERT_S(len < sizeof(query), "Out of bounds write attempt");

  char *q_url_encoded = url_encode(params->q);
  len += snprintf(query + len, sizeof(query) - len, "&q=%s", q_url_encoded);
  ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  free(q_url_encoded);

  if (true == params->restrict_sr) {
    len += snprintf(query + len, sizeof(query) - len, "&restrict_sr=1");
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }
  if (params->t) {
    len += snprintf(query + len, sizeof(query) - len, "&t=%s", params->t);
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }
  if (params->sort) {
    len +=
      snprintf(query + len, sizeof(query) - len, "&sort=%s", params->sort);
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }
  if (params->before) {
    len +=
      snprintf(query + len, sizeof(query) - len, "&before=%s", params->before);
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }
  if (params->after) {
    len +=
      snprintf(query + len, sizeof(query) - len, "&after=%s", params->after);
    ASSERT_S(len < sizeof(query), "Out of bounds write attempt");
  }

  return reddit_adapter_run(&client->adapter, ret, NULL, HTTP_GET,
                            "/r/%s/search.json?raw_json=1%s", subreddit,
                            query);
}
