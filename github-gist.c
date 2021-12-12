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
  log_info("===create-gist===");

  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->description), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->title), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->contents), ORCA_BAD_PARAMETER);

  char payload[4096];
  char fmt[2048];

  /* Create the format string for the payload
   * TODO:
   * Allocate buffer big enough, then free it after the request is made
   * */
  snprintf(fmt, sizeof(fmt),
           "(public): \"%s\", (description): \"%s\", (files): { (%s): { "
           "(content): \"%s\" }}",
           params->public, params->description, params->title,
           params->contents);

  size_t len = json_inject(payload, sizeof(payload), fmt);

  return github_adapter_run(
    &client->adapter,
    &(struct ua_resp_handle){ .ok_cb = &github_gist_from_json_v,
                              .ok_obj = ret },
    &(struct sized_buffer){ payload, len }, HTTP_POST, "/gists");
}

ORCAcode
github_get_gist(struct github *client, char *id, struct github_gist *ret)
{
  log_info("===get-a-gist===");

  ORCA_EXPECT(client, !IS_EMPTY_STRING(id), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return github_adapter_run(
    &client->adapter,
    &(struct ua_resp_handle){ .ok_cb = &github_gist_from_json_v,
                              .ok_obj = ret },
    NULL, HTTP_GET, "/gists/%s", id);
}

ORCAcode
github_gist_is_starred(struct github *client, char *id)
{
  log_info("===gist-is-starred===");

  ORCA_EXPECT(client, !IS_EMPTY_STRING(id), ORCA_BAD_PARAMETER);

  return github_adapter_run(&client->adapter, NULL, NULL, HTTP_GET,
                            "/gists/%s/star", id);
}
