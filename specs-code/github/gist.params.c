/* This file is generated from github/gist.params.json, Please don't edit it. */
/**
 * @file specs-code/github/gist.params.c
 * @see https://docs.github.com/en/rest/reference/gists
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "json-actor.h"
#include "json-actor-boxed.h"
#include "cee-utils.h"
#include "github.h"

void github_gist_create_params_from_json_p(char *json, size_t len, struct github_gist_create_params **pp)
{
  if (!*pp) *pp = malloc(sizeof **pp);
  github_gist_create_params_from_json(json, len, *pp);
}
void github_gist_create_params_from_json(char *json, size_t len, struct github_gist_create_params *p)
{
  github_gist_create_params_init(p);
  json_extract(json, len, 
  /* github/gist.params.json:13:28
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }}' */
                "(description):?s,"
  /* github/gist.params.json:14:28
     '{ "name": "title", "type":{ "base":"char", "dec":"*" }}' */
                "(title):?s,"
  /* github/gist.params.json:15:28
     '{ "name": "contents", "type":{ "base":"char", "dec":"*" }}' */
                "(contents):?s,"
  /* github/gist.params.json:16:28
     '{ "name": "public", "type":{ "base":"char", "dec":"*" }}' */
                "(public):?s,",
  /* github/gist.params.json:13:28
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }}' */
                &p->description,
  /* github/gist.params.json:14:28
     '{ "name": "title", "type":{ "base":"char", "dec":"*" }}' */
                &p->title,
  /* github/gist.params.json:15:28
     '{ "name": "contents", "type":{ "base":"char", "dec":"*" }}' */
                &p->contents,
  /* github/gist.params.json:16:28
     '{ "name": "public", "type":{ "base":"char", "dec":"*" }}' */
                &p->public);
}

size_t github_gist_create_params_to_json(char *json, size_t len, struct github_gist_create_params *p)
{
  size_t r;
  void *arg_switches[4]={NULL};
  /* github/gist.params.json:13:28
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }}' */
  arg_switches[0] = p->description;

  /* github/gist.params.json:14:28
     '{ "name": "title", "type":{ "base":"char", "dec":"*" }}' */
  arg_switches[1] = p->title;

  /* github/gist.params.json:15:28
     '{ "name": "contents", "type":{ "base":"char", "dec":"*" }}' */
  arg_switches[2] = p->contents;

  /* github/gist.params.json:16:28
     '{ "name": "public", "type":{ "base":"char", "dec":"*" }}' */
  arg_switches[3] = p->public;

  r=json_inject(json, len, 
  /* github/gist.params.json:13:28
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }}' */
                "(description):s,"
  /* github/gist.params.json:14:28
     '{ "name": "title", "type":{ "base":"char", "dec":"*" }}' */
                "(title):s,"
  /* github/gist.params.json:15:28
     '{ "name": "contents", "type":{ "base":"char", "dec":"*" }}' */
                "(contents):s,"
  /* github/gist.params.json:16:28
     '{ "name": "public", "type":{ "base":"char", "dec":"*" }}' */
                "(public):s,"
                "@arg_switches:b",
  /* github/gist.params.json:13:28
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }}' */
                p->description,
  /* github/gist.params.json:14:28
     '{ "name": "title", "type":{ "base":"char", "dec":"*" }}' */
                p->title,
  /* github/gist.params.json:15:28
     '{ "name": "contents", "type":{ "base":"char", "dec":"*" }}' */
                p->contents,
  /* github/gist.params.json:16:28
     '{ "name": "public", "type":{ "base":"char", "dec":"*" }}' */
                p->public,
                arg_switches, sizeof(arg_switches), true);
  return r;
}


void github_gist_create_params_cleanup_v(void *p) {
  github_gist_create_params_cleanup((struct github_gist_create_params *)p);
}

void github_gist_create_params_init_v(void *p) {
  github_gist_create_params_init((struct github_gist_create_params *)p);
}

void github_gist_create_params_from_json_v(char *json, size_t len, void *p) {
 github_gist_create_params_from_json(json, len, (struct github_gist_create_params*)p);
}

size_t github_gist_create_params_to_json_v(char *json, size_t len, void *p) {
  return github_gist_create_params_to_json(json, len, (struct github_gist_create_params*)p);
}

void github_gist_create_params_list_free_v(void **p) {
  github_gist_create_params_list_free((struct github_gist_create_params**)p);
}

void github_gist_create_params_list_from_json_v(char *str, size_t len, void *p) {
  github_gist_create_params_list_from_json(str, len, (struct github_gist_create_params ***)p);
}

size_t github_gist_create_params_list_to_json_v(char *str, size_t len, void *p){
  return github_gist_create_params_list_to_json(str, len, (struct github_gist_create_params **)p);
}


void github_gist_create_params_cleanup(struct github_gist_create_params *d) {
  /* github/gist.params.json:13:28
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }}' */
  if (d->description)
    free(d->description);
  /* github/gist.params.json:14:28
     '{ "name": "title", "type":{ "base":"char", "dec":"*" }}' */
  if (d->title)
    free(d->title);
  /* github/gist.params.json:15:28
     '{ "name": "contents", "type":{ "base":"char", "dec":"*" }}' */
  if (d->contents)
    free(d->contents);
  /* github/gist.params.json:16:28
     '{ "name": "public", "type":{ "base":"char", "dec":"*" }}' */
  if (d->public)
    free(d->public);
}

void github_gist_create_params_init(struct github_gist_create_params *p) {
  memset(p, 0, sizeof(struct github_gist_create_params));
  /* github/gist.params.json:13:28
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }}' */

  /* github/gist.params.json:14:28
     '{ "name": "title", "type":{ "base":"char", "dec":"*" }}' */

  /* github/gist.params.json:15:28
     '{ "name": "contents", "type":{ "base":"char", "dec":"*" }}' */

  /* github/gist.params.json:16:28
     '{ "name": "public", "type":{ "base":"char", "dec":"*" }}' */

}
void github_gist_create_params_list_free(struct github_gist_create_params **p) {
  ntl_free((void**)p, (void(*)(void*))github_gist_create_params_cleanup);
}

void github_gist_create_params_list_from_json(char *str, size_t len, struct github_gist_create_params ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct github_gist_create_params);
  d.init_elem = NULL;
  d.elem_from_buf = (void(*)(char*,size_t,void*))github_gist_create_params_from_json_p;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t github_gist_create_params_list_to_json(char *str, size_t len, struct github_gist_create_params **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, (size_t(*)(char*,size_t,void*))github_gist_create_params_to_json);
}

