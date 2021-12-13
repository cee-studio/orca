#include <stdio.h>
#include <stdlib.h>

#include "github.h"
#include "github-internal.h"

#include "cee-utils.h"

ORCAcode
github_create_fork(struct github *client, char *owner, char *repo)
{
  ORCA_EXPECT(client, !IS_EMPTY_STRING(owner), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(repo), ORCA_BAD_PARAMETER);

  return github_adapter_run(&client->adapter, NULL, NULL, HTTP_POST,
                            "/repos/%s/%s/forks", owner, repo);
}
