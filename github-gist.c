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
github_create_gist(struct github *client, char* description, char* title, char* contents, struct github_gist* gist)
{
  log_info("===create-gist===");

  if(!description) {
    log_error("Missing 'description'");
  }
  if(!title) {
    log_error("Missing 'title'");
  }
  if(!contents) {
    log_error("Missing 'contents'");
  }

  char payload[4096];
  char fmt[1024];

  /* Create the format string for the payload */
  snprintf(fmt, sizeof(fmt), "(files): { (%s): { (content): \"%s\" }}", title, contents);

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
