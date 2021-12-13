#define _GNU_SOURCE /* asprintf() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <errno.h>

#include "cee-utils.h"
#include "cee-utils/ntl.h"
#include "json-actor.h"

#include "github.h"
#include "github-internal.h"

static void
_github_presets_init(struct github_presets *presets,
                     const struct sized_buffer *username,
                     const struct sized_buffer *token,
                     const char *repo_config)
{

  presets->owner = NULL;
  presets->repo = NULL;
  presets->default_branch = NULL;

  /* Optionally fill in the repo_config. Can be
   * done later with github_fill_repo_config. */
  if (repo_config) {
    size_t len = 0;
    char *json = cee_load_whole_file(repo_config, &len);

    json_extract(json, len, "(owner):?s,(repo):?s,(default_branch):?s",
                 &presets->owner, &presets->repo, &presets->default_branch);

    free(json);
  }

  asprintf(&presets->username, "%.*s", (int)username->size, username->start);
  asprintf(&presets->token, "%.*s", (int)token->size, token->start);
}

void
github_write_json(char *json, size_t len, void *user_obj)
{
  struct sized_buffer *new_user_obj = user_obj;

  new_user_obj->size = asprintf(&new_user_obj->start, "%.*s", (int)len, json);
}

ORCAcode
github_fill_repo_config(struct github *client, char *repo_config)
{
  size_t len = 0;
  char *json;

  ORCA_EXPECT(client, !IS_EMPTY_STRING(repo_config), ORCA_BAD_PARAMETER);

  json = cee_load_whole_file(repo_config, &len);

  json_extract(json, len, "(owner):?s,(repo):?s,(default_branch):?s",
               &client->presets.owner, &client->presets.repo,
               &client->presets.default_branch);

  free(json);

  return ORCA_OK;
}

static void
object_sha_from_json(char *str, size_t len, void *pp)
{
  json_extract(str, len, "(object.sha):?s", (char **)pp);
}

static void
sha_from_json(char *json, size_t len, void *pp)
{
  json_extract(json, len, "(sha):?s", (char **)pp);
}

struct github *
github_init(const char username[],
            const char token[],
            const char repo_config[])
{
  const struct sized_buffer _username = { (char *)username, strlen(username) };
  const struct sized_buffer _token = { (char *)token, strlen(token) };
  struct github *new_client;

  new_client = calloc(1, sizeof *new_client);
  logconf_setup(&new_client->conf, "GITHUB", NULL);

  _github_presets_init(&new_client->presets, &_username, &_token, repo_config);

  github_adapter_init(&new_client->adapter, &new_client->conf,
                      &new_client->presets);

  return new_client;
}

struct github *
github_config_init(const char config_file[], const char repo_config[])
{
  struct sized_buffer username, token;
  struct github *new_client;
  FILE *fp;

  fp = fopen(config_file, "rb");
  VASSERT_S(fp != NULL, "Couldn't open '%s': %s", config_file,
            strerror(errno));

  new_client = calloc(1, sizeof *new_client);
  logconf_setup(&new_client->conf, "GITHUB", fp);

  fclose(fp);

  username = logconf_get_field(&new_client->conf, "github.username");
  token = logconf_get_field(&new_client->conf, "github.token");

  _github_presets_init(&new_client->presets, &username, &token, repo_config);

  github_adapter_init(&new_client->adapter, &new_client->conf,
                      &new_client->presets);

  return new_client;
}

ORCAcode
github_update_my_fork(struct github *client, char **ret)
{
  struct github_request_attr attr = { &ret, 0, NULL, &object_sha_from_json };
  struct sized_buffer body;
  char *sha = NULL;
  char buf[2048];
  ORCAcode code;

  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->presets.username),
              ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->presets.default_branch),
              ORCA_BAD_PARAMETER);

  code =
    github_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                       "/repos/%s/%s/git/refs/heads/%s", client->presets.owner,
                       client->presets.repo, client->presets.default_branch);

  ORCA_EXPECT(client, ORCA_OK == code, code, "Couldn't fetch sha");

  body.size = json_inject(buf, sizeof(buf), "(sha):s", sha);
  body.start = buf;

  if (ret)
    *ret = sha;
  else
    free(sha);

  return github_adapter_run(&client->adapter, NULL, &body, HTTP_PATCH,
                            "/repos/%s/%s/git/refs/heads/%s",
                            client->presets.username, client->presets.repo,
                            client->presets.default_branch);
}

ORCAcode
github_get_head_commit(struct github *client, char **ret)
{
  struct github_request_attr attr = { ret, 0, NULL, &object_sha_from_json };

  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->presets.username),
              ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->presets.default_branch),
              ORCA_BAD_PARAMETER);

  return github_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                            "/repos/%s/%s/git/refs/heads/%s",
                            client->presets.username, client->presets.repo,
                            client->presets.default_branch);
}

ORCAcode
github_get_tree_sha(struct github *client, char *commit_sha, char **ret)
{
  struct github_request_attr attr = { ret, 0, NULL, &sha_from_json };

  ORCA_EXPECT(client, !IS_EMPTY_STRING(commit_sha), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->presets.username),
              ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->presets.repo),
              ORCA_BAD_PARAMETER);

  return github_adapter_run(
    &client->adapter, &attr, NULL, HTTP_GET, "/repos/%s/%s/git/trees/%s",
    client->presets.username, client->presets.repo, commit_sha);
}

ORCAcode
github_create_blobs(struct github *client, struct github_file **files)
{
  struct github_request_attr attr = { NULL, 0, NULL, &sha_from_json };
  struct sized_buffer body;
  ORCAcode code;
  char *buf;
  int i;

  ORCA_EXPECT(client, files != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->presets.username),
              ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->presets.repo),
              ORCA_BAD_PARAMETER);

  for (i = 0; files[i]; ++i) {
    char *f_content;
    size_t f_len;

    f_content = cee_load_whole_file(files[i]->path, &f_len);
    ORCA_EXPECT(client, f_content != NULL, ORCA_BAD_PARAMETER,
                "File path doesn't exist");

    buf = NULL;

    body.size = json_ainject(&buf,
                             "(content):.*s"
                             "(encoding):|utf-8|",
                             f_len, f_content);
    body.start = buf;
    free(f_content);

    ORCA_EXPECT(client, buf != NULL, ORCA_BAD_JSON);

    attr.obj = &files[i]->sha;

    code = github_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                              "/repos/%s/%s/git/blobs",
                              client->presets.username, client->presets.repo);

    free(buf);
  }

  return code;
}

static size_t
node_to_json(char *str, size_t size, void *p)
{
  struct github_file *f = p;

  return json_inject(str, size,
                     "(path):s"
                     "(mode):|100644|"
                     "(type):|blob|"
                     "(sha):s",
                     f->path, f->sha);
}

static int
node_list_to_json(char *buf, size_t size, void *p)
{
  return ntl_to_buf(buf, size, (void **)p, NULL, &node_to_json);
}

ORCAcode
github_create_tree(struct github *client,
                   char *base_tree_sha,
                   struct github_file **files,
                   char **ret)
{
  struct github_request_attr attr = { ret, 0, NULL, &sha_from_json };
  struct sized_buffer body;
  char buf[2048];

  ORCA_EXPECT(client, !IS_EMPTY_STRING(base_tree_sha), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, files != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->presets.username),
              ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->presets.repo),
              ORCA_BAD_PARAMETER);

  body.size = json_inject(buf, sizeof(buf),
                          "(tree):F"
                          "(base_tree):s",
                          &node_list_to_json, files, base_tree_sha);
  body.start = buf;

  return github_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                            "/repos/%s/%s/git/trees", client->presets.username,
                            client->presets.repo);
}

ORCAcode
github_create_a_commit(struct github *client,
                       char *tree_sha,
                       char *parent_commit_sha,
                       char *commit_msg,
                       char **ret)
{
  struct github_request_attr attr = { ret, 0, NULL, &sha_from_json };
  struct sized_buffer body;
  char buf[4096];

  ORCA_EXPECT(client, !IS_EMPTY_STRING(tree_sha), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(parent_commit_sha), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(commit_msg), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->presets.username),
              ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->presets.repo),
              ORCA_BAD_PARAMETER);

  body.size = json_inject(buf, sizeof(buf),
                          "(message):s"
                          "(tree):s"
                          "(parents):[s]",
                          commit_msg, tree_sha, parent_commit_sha);
  body.start = buf;

  return github_adapter_run(&client->adapter, &attr, &body, HTTP_POST,
                            "/repos/%s/%s/git/commits",
                            client->presets.username, client->presets.repo);
}

ORCAcode
github_create_a_branch(struct github *client,
                       char *head_commit_sha,
                       char *branch)
{
  struct sized_buffer body;
  char buf[4096];

  ORCA_EXPECT(client, !IS_EMPTY_STRING(head_commit_sha), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(branch), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->presets.username),
              ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->presets.repo),
              ORCA_BAD_PARAMETER);

  body.size = json_inject(buf, sizeof(buf),
                          "(ref):|refs/heads/%s|"
                          "(sha):s",
                          branch, head_commit_sha);
  body.start = buf;

  return github_adapter_run(&client->adapter, NULL, &body, HTTP_POST,
                            "/repos/%s/%s/git/refs", client->presets.username,
                            client->presets.repo);
}

ORCAcode
github_update_a_commit(struct github *client, char *branch, char *commit_sha)
{
  struct sized_buffer body;
  char buf[512];

  ORCA_EXPECT(client, !IS_EMPTY_STRING(branch), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(commit_sha), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->presets.username),
              ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->presets.repo),
              ORCA_BAD_PARAMETER);

  body.size = json_inject(buf, sizeof(buf), "(sha):s", commit_sha);
  body.start = buf;

  return github_adapter_run(
    &client->adapter, NULL, NULL, HTTP_PATCH, "/repos/%s/%s/git/refs/heads/%s",
    client->presets.username, client->presets.repo, branch);
}

ORCAcode
github_create_a_pull_request(struct github *client,
                             char *branch,
                             char *pull_msg)
{
  struct sized_buffer body;
  char buf[4096];

  ORCA_EXPECT(client, !IS_EMPTY_STRING(branch), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(pull_msg), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->presets.username),
              ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(client->presets.default_branch),
              ORCA_BAD_PARAMETER);

  body.size = json_inject(buf, sizeof(buf),
                          "(title):s"
                          "(body):s"
                          "(head):|%s:%s|"
                          "(base):s",
                          branch, pull_msg, client->presets.username, branch,
                          client->presets.default_branch);
  body.start = buf;

  return github_adapter_run(&client->adapter, NULL, &body, HTTP_POST,
                            "/repos/%s/%s/pulls", client->presets.owner,
                            client->presets.repo);
}

ORCAcode
github_get_user(struct github *client, char *username, struct github_user *ret)
{
  struct github_request_attr attr = {
    ret,
    sizeof *ret,
    &github_user_init_v,
    &github_user_from_json_v,
    &github_user_cleanup_v,
  };

  ORCA_EXPECT(client, !IS_EMPTY_STRING(username), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return github_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                            "/users/%s", username);
}

ORCAcode
github_get_repository(struct github *client,
                      char *owner,
                      char *repo,
                      struct sized_buffer *ret)
{
  struct github_request_attr attr = { ret, 0, NULL, &github_write_json };

  ORCA_EXPECT(client, !IS_EMPTY_STRING(repo), ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, ret != NULL, ORCA_BAD_PARAMETER);

  return github_adapter_run(&client->adapter, &attr, NULL, HTTP_GET,
                            "/repos/%s/%s", owner, repo);
}
