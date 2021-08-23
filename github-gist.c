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
github_create_gist(struct github *client, struct github_gist_create_params *params, struct github_gist *gist)
{
  log_info("===create-gist===");

  if (!params->description) {
    log_error("Missing 'description'");
  }
  if (!params->title) {
    log_error("Missing 'title'");
  }
  if (!params->contents) {
    log_error("Missing 'contents'");
  }

  char payload[4096];
  char fmt[1024];

  /* Create the format string for the payload */
  snprintf(fmt, sizeof(fmt), "(description): \"%s\", (files): { (%s): { (content): \"%s\" }}", params->description,
                                                                                               params->title,
                                                                                               params->contents);
  size_t ret = json_inject(payload, sizeof(payload), fmt);

  return github_adapter_run(
          &client->adapter,
          &(struct ua_resp_handle){
            .ok_cb = &github_gist_from_json_v,
            .ok_obj = &gist
          },
          &(struct sized_buffer){ payload, ret },
          HTTP_POST,
          "/gists");
}
