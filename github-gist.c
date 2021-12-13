#define _GNU_SOURCE /* asprintf() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "cee-utils.h"
#include "cee-utils/ntl.h"
#include "json-actor.h"

#include "github.h"
#include "github-internal.h"

ORCAcode
github_create_gist(struct github *client,
                   struct github_gist_create_params *params,
                   struct github_gist *ret)
{
  struct github_request_attr attr = { ret, sizeof *ret, &github_gist_init_v,
                                      &github_gist_from_json_v,
                                      &github_gist_cleanup_v };
  struct sized_buffer body;
  char buf[4096];
  char fmt[2048];

  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->description),
              ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->title), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->contents), ORCA_BAD_PARAMETER);

  /* Create the format string for the buf
   * TODO: Allocate buffer big enough, then free it after the request is made
   */
  snprintf(fmt, sizeof(fmt),
           "(public): \"%s\", (description): \"%s\", (files): { (%s): { "
           "(content): \"%s\" }}",
           params->public, params->description, params->title,
           params->contents);

  body.size = json_inject(buf, sizeof(buf), fmt);
  body.start = buf;

  return github_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                            "/gists");
}

ORCAcode
github_get_gist(struct github *client, char *id, struct github_gist *ret)
{
  struct github_request_attr attr = { ret, sizeof *ret, &github_gist_init_v,
                                      &github_gist_from_json_v,
                                      &github_gist_cleanup_v };

  ORCA_EXPECT(client, !IS_EMPTY_STRING(id), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return github_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                            "/gists/%s", id);
}

ORCAcode
github_gist_is_starred(struct github *client, char *id)
{
  ORCA_EXPECT(client, !IS_EMPTY_STRING(id), ORCA_BAD_PARAMETER);

  return github_adapter_run(&client->adapter, NULL, NULL, HTTP_GET,
                            "/gists/%s/star", id);
}
