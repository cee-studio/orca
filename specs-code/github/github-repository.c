/* This file is generated from specs/github/github-repository.json, Please don't edit it. */
/**
 * @file specs-code/github/github-repository.c
 * @see https://docs.github.com/en/rest/reference/repos#get-a-repository
 */

#include "specs.h"

void github_repository_from_json(char *json, size_t len, struct github_repository **pp)
{
  static size_t ret=0; // used for debugging
  size_t r=0;
  if (!*pp) *pp = calloc(1, sizeof **pp);
  struct github_repository *p = *pp;
  r=json_extract(json, len, 
  /* specs/github/github-repository.json:12:28
     '{ "name": "id", "type":{ "base":"int"}}' */
                "(id):d,"
  /* specs/github/github-repository.json:13:28
     '{ "name": "node_id", "type":{ "base":"char", "dec":"*"}}' */
                "(node_id):?s,"
  /* specs/github/github-repository.json:14:28
     '{ "name": "name", "type":{ "base":"char", "dec":"*"}}' */
                "(name):?s,"
  /* specs/github/github-repository.json:15:28
     '{ "name": "full_name", "type":{ "base":"char", "dec":"*"}}' */
                "(full_name):?s,"
  /* specs/github/github-repository.json:16:28
     '{ "name": "private", "type":{ "base":"bool"}}' */
                "(private):b,"
  /* specs/github/github-repository.json:17:77
     '{ "type": {"base":"struct github_user", "dec":"*"}, "name":"owner"}' */
                "(owner):F,"
                "@arg_switches:b"
                "@record_defined"
                "@record_null",
  /* specs/github/github-repository.json:12:28
     '{ "name": "id", "type":{ "base":"int"}}' */
                &p->id,
  /* specs/github/github-repository.json:13:28
     '{ "name": "node_id", "type":{ "base":"char", "dec":"*"}}' */
                &p->node_id,
  /* specs/github/github-repository.json:14:28
     '{ "name": "name", "type":{ "base":"char", "dec":"*"}}' */
                &p->name,
  /* specs/github/github-repository.json:15:28
     '{ "name": "full_name", "type":{ "base":"char", "dec":"*"}}' */
                &p->full_name,
  /* specs/github/github-repository.json:16:28
     '{ "name": "private", "type":{ "base":"bool"}}' */
                &p->private,
  /* specs/github/github-repository.json:17:77
     '{ "type": {"base":"struct github_user", "dec":"*"}, "name":"owner"}' */
                github_user_from_json, &p->owner,
                p->__M.arg_switches, sizeof(p->__M.arg_switches), p->__M.enable_arg_switches,
                p->__M.record_defined, sizeof(p->__M.record_defined),
                p->__M.record_null, sizeof(p->__M.record_null));
  ret = r;
}

static void github_repository_use_default_inject_settings(struct github_repository *p)
{
  p->__M.enable_arg_switches = true;
  /* specs/github/github-repository.json:12:28
     '{ "name": "id", "type":{ "base":"int"}}' */
  p->__M.arg_switches[0] = &p->id;

  /* specs/github/github-repository.json:13:28
     '{ "name": "node_id", "type":{ "base":"char", "dec":"*"}}' */
  p->__M.arg_switches[1] = p->node_id;

  /* specs/github/github-repository.json:14:28
     '{ "name": "name", "type":{ "base":"char", "dec":"*"}}' */
  p->__M.arg_switches[2] = p->name;

  /* specs/github/github-repository.json:15:28
     '{ "name": "full_name", "type":{ "base":"char", "dec":"*"}}' */
  p->__M.arg_switches[3] = p->full_name;

  /* specs/github/github-repository.json:16:28
     '{ "name": "private", "type":{ "base":"bool"}}' */
  p->__M.arg_switches[4] = &p->private;

  /* specs/github/github-repository.json:17:77
     '{ "type": {"base":"struct github_user", "dec":"*"}, "name":"owner"}' */
  p->__M.arg_switches[5] = p->owner;

}

size_t github_repository_to_json(char *json, size_t len, struct github_repository *p)
{
  size_t r;
  github_repository_use_default_inject_settings(p);
  r=json_inject(json, len, 
  /* specs/github/github-repository.json:12:28
     '{ "name": "id", "type":{ "base":"int"}}' */
                "(id):d,"
  /* specs/github/github-repository.json:13:28
     '{ "name": "node_id", "type":{ "base":"char", "dec":"*"}}' */
                "(node_id):s,"
  /* specs/github/github-repository.json:14:28
     '{ "name": "name", "type":{ "base":"char", "dec":"*"}}' */
                "(name):s,"
  /* specs/github/github-repository.json:15:28
     '{ "name": "full_name", "type":{ "base":"char", "dec":"*"}}' */
                "(full_name):s,"
  /* specs/github/github-repository.json:16:28
     '{ "name": "private", "type":{ "base":"bool"}}' */
                "(private):b,"
  /* specs/github/github-repository.json:17:77
     '{ "type": {"base":"struct github_user", "dec":"*"}, "name":"owner"}' */
                "(owner):F,"
                "@arg_switches:b",
  /* specs/github/github-repository.json:12:28
     '{ "name": "id", "type":{ "base":"int"}}' */
                &p->id,
  /* specs/github/github-repository.json:13:28
     '{ "name": "node_id", "type":{ "base":"char", "dec":"*"}}' */
                p->node_id,
  /* specs/github/github-repository.json:14:28
     '{ "name": "name", "type":{ "base":"char", "dec":"*"}}' */
                p->name,
  /* specs/github/github-repository.json:15:28
     '{ "name": "full_name", "type":{ "base":"char", "dec":"*"}}' */
                p->full_name,
  /* specs/github/github-repository.json:16:28
     '{ "name": "private", "type":{ "base":"bool"}}' */
                &p->private,
  /* specs/github/github-repository.json:17:77
     '{ "type": {"base":"struct github_user", "dec":"*"}, "name":"owner"}' */
                github_user_to_json, p->owner,
                p->__M.arg_switches, sizeof(p->__M.arg_switches), p->__M.enable_arg_switches);
  return r;
}


typedef void (*vfvp)(void *);
typedef void (*vfcpsvp)(char *, size_t, void *);
typedef size_t (*sfcpsvp)(char *, size_t, void *);
void github_repository_cleanup_v(void *p) {
  github_repository_cleanup((struct github_repository *)p);
}

void github_repository_init_v(void *p) {
  github_repository_init((struct github_repository *)p);
}

void github_repository_from_json_v(char *json, size_t len, void *pp) {
 github_repository_from_json(json, len, (struct github_repository**)pp);
}

size_t github_repository_to_json_v(char *json, size_t len, void *p) {
  return github_repository_to_json(json, len, (struct github_repository*)p);
}

void github_repository_list_free_v(void **p) {
  github_repository_list_free((struct github_repository**)p);
}

void github_repository_list_from_json_v(char *str, size_t len, void *p) {
  github_repository_list_from_json(str, len, (struct github_repository ***)p);
}

size_t github_repository_list_to_json_v(char *str, size_t len, void *p){
  return github_repository_list_to_json(str, len, (struct github_repository **)p);
}


void github_repository_cleanup(struct github_repository *d) {
  /* specs/github/github-repository.json:12:28
     '{ "name": "id", "type":{ "base":"int"}}' */
  // p->id is a scalar
  /* specs/github/github-repository.json:13:28
     '{ "name": "node_id", "type":{ "base":"char", "dec":"*"}}' */
  if (d->node_id)
    free(d->node_id);
  /* specs/github/github-repository.json:14:28
     '{ "name": "name", "type":{ "base":"char", "dec":"*"}}' */
  if (d->name)
    free(d->name);
  /* specs/github/github-repository.json:15:28
     '{ "name": "full_name", "type":{ "base":"char", "dec":"*"}}' */
  if (d->full_name)
    free(d->full_name);
  /* specs/github/github-repository.json:16:28
     '{ "name": "private", "type":{ "base":"bool"}}' */
  // p->private is a scalar
  /* specs/github/github-repository.json:17:77
     '{ "type": {"base":"struct github_user", "dec":"*"}, "name":"owner"}' */
  if (d->owner) {
    github_user_cleanup(d->owner);
    free(d->owner);
  }
}

void github_repository_init(struct github_repository *p) {
  memset(p, 0, sizeof(struct github_repository));
  /* specs/github/github-repository.json:12:28
     '{ "name": "id", "type":{ "base":"int"}}' */

  /* specs/github/github-repository.json:13:28
     '{ "name": "node_id", "type":{ "base":"char", "dec":"*"}}' */

  /* specs/github/github-repository.json:14:28
     '{ "name": "name", "type":{ "base":"char", "dec":"*"}}' */

  /* specs/github/github-repository.json:15:28
     '{ "name": "full_name", "type":{ "base":"char", "dec":"*"}}' */

  /* specs/github/github-repository.json:16:28
     '{ "name": "private", "type":{ "base":"bool"}}' */

  /* specs/github/github-repository.json:17:77
     '{ "type": {"base":"struct github_user", "dec":"*"}, "name":"owner"}' */
  p->owner = malloc(sizeof *p->owner);
  github_user_init(p->owner);

}
void github_repository_list_free(struct github_repository **p) {
  ntl_free((void**)p, (vfvp)github_repository_cleanup);
}

void github_repository_list_from_json(char *str, size_t len, struct github_repository ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct github_repository);
  d.init_elem = NULL;
  d.elem_from_buf = github_repository_from_json_v;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t github_repository_list_to_json(char *str, size_t len, struct github_repository **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, github_repository_to_json_v);
}

