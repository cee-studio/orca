/* This file is generated from reddit/links_n_comments.json, Please don't edit it. */
/**
 * @file specs-code/reddit/links_n_comments.c
 * @see 
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "json-actor.h"
#include "json-actor-boxed.h"
#include "cee-utils.h"
#include "reddit.h"

void reddit_comment_params_from_json_p(char *json, size_t len, struct reddit_comment_params **pp)
{
  if (!*pp) *pp = malloc(sizeof **pp);
  reddit_comment_params_from_json(json, len, *pp);
}
void reddit_comment_params_from_json(char *json, size_t len, struct reddit_comment_params *p)
{
  reddit_comment_params_init(p);
  json_extract(json, len, 
  /* reddit/links_n_comments.json:13:20
     '{ "name": "api_type", "type":{ "base":"char", "dec":"*" }, "comment":"the string json" }' */
                "(api_type):?s,"
  /* reddit/links_n_comments.json:14:20
     '{ "name": "return_rtjson", "type":{ "base":"bool" }, "comment":"boolean value" }' */
                "(return_rtjson):b,"
  /* reddit/links_n_comments.json:15:20
     '{ "name": "richtext_json", "type":{ "base":"char", "dec":"*" }, "comment":"JSON data" }' */
                "(richtext_json):?s,"
  /* reddit/links_n_comments.json:16:20
     '{ "name": "text", "type":{ "base":"char", "dec":"*" }, "comment":"raw markdown text" }' */
                "(text):?s,"
  /* reddit/links_n_comments.json:17:20
     '{ "name": "thing_id", "type":{ "base":"char", "dec":"*" }, "comment":"fullname of parent thing" }' */
                "(thing_id):?s,"
  /* reddit/links_n_comments.json:18:20
     '{ "name": "uh", "type":{ "base":"char", "dec":"*" }, "comment":"a modhash" }' */
                "(uh):?s,",
  /* reddit/links_n_comments.json:13:20
     '{ "name": "api_type", "type":{ "base":"char", "dec":"*" }, "comment":"the string json" }' */
                &p->api_type,
  /* reddit/links_n_comments.json:14:20
     '{ "name": "return_rtjson", "type":{ "base":"bool" }, "comment":"boolean value" }' */
                &p->return_rtjson,
  /* reddit/links_n_comments.json:15:20
     '{ "name": "richtext_json", "type":{ "base":"char", "dec":"*" }, "comment":"JSON data" }' */
                &p->richtext_json,
  /* reddit/links_n_comments.json:16:20
     '{ "name": "text", "type":{ "base":"char", "dec":"*" }, "comment":"raw markdown text" }' */
                &p->text,
  /* reddit/links_n_comments.json:17:20
     '{ "name": "thing_id", "type":{ "base":"char", "dec":"*" }, "comment":"fullname of parent thing" }' */
                &p->thing_id,
  /* reddit/links_n_comments.json:18:20
     '{ "name": "uh", "type":{ "base":"char", "dec":"*" }, "comment":"a modhash" }' */
                &p->uh);
}

size_t reddit_comment_params_to_json(char *json, size_t len, struct reddit_comment_params *p)
{
  size_t r;
  void *arg_switches[6]={NULL};
  /* reddit/links_n_comments.json:13:20
     '{ "name": "api_type", "type":{ "base":"char", "dec":"*" }, "comment":"the string json" }' */
  arg_switches[0] = p->api_type;

  /* reddit/links_n_comments.json:14:20
     '{ "name": "return_rtjson", "type":{ "base":"bool" }, "comment":"boolean value" }' */
  arg_switches[1] = &p->return_rtjson;

  /* reddit/links_n_comments.json:15:20
     '{ "name": "richtext_json", "type":{ "base":"char", "dec":"*" }, "comment":"JSON data" }' */
  arg_switches[2] = p->richtext_json;

  /* reddit/links_n_comments.json:16:20
     '{ "name": "text", "type":{ "base":"char", "dec":"*" }, "comment":"raw markdown text" }' */
  arg_switches[3] = p->text;

  /* reddit/links_n_comments.json:17:20
     '{ "name": "thing_id", "type":{ "base":"char", "dec":"*" }, "comment":"fullname of parent thing" }' */
  arg_switches[4] = p->thing_id;

  /* reddit/links_n_comments.json:18:20
     '{ "name": "uh", "type":{ "base":"char", "dec":"*" }, "comment":"a modhash" }' */
  arg_switches[5] = p->uh;

  r=json_inject(json, len, 
  /* reddit/links_n_comments.json:13:20
     '{ "name": "api_type", "type":{ "base":"char", "dec":"*" }, "comment":"the string json" }' */
                "(api_type):s,"
  /* reddit/links_n_comments.json:14:20
     '{ "name": "return_rtjson", "type":{ "base":"bool" }, "comment":"boolean value" }' */
                "(return_rtjson):b,"
  /* reddit/links_n_comments.json:15:20
     '{ "name": "richtext_json", "type":{ "base":"char", "dec":"*" }, "comment":"JSON data" }' */
                "(richtext_json):s,"
  /* reddit/links_n_comments.json:16:20
     '{ "name": "text", "type":{ "base":"char", "dec":"*" }, "comment":"raw markdown text" }' */
                "(text):s,"
  /* reddit/links_n_comments.json:17:20
     '{ "name": "thing_id", "type":{ "base":"char", "dec":"*" }, "comment":"fullname of parent thing" }' */
                "(thing_id):s,"
  /* reddit/links_n_comments.json:18:20
     '{ "name": "uh", "type":{ "base":"char", "dec":"*" }, "comment":"a modhash" }' */
                "(uh):s,"
                "@arg_switches:b",
  /* reddit/links_n_comments.json:13:20
     '{ "name": "api_type", "type":{ "base":"char", "dec":"*" }, "comment":"the string json" }' */
                p->api_type,
  /* reddit/links_n_comments.json:14:20
     '{ "name": "return_rtjson", "type":{ "base":"bool" }, "comment":"boolean value" }' */
                &p->return_rtjson,
  /* reddit/links_n_comments.json:15:20
     '{ "name": "richtext_json", "type":{ "base":"char", "dec":"*" }, "comment":"JSON data" }' */
                p->richtext_json,
  /* reddit/links_n_comments.json:16:20
     '{ "name": "text", "type":{ "base":"char", "dec":"*" }, "comment":"raw markdown text" }' */
                p->text,
  /* reddit/links_n_comments.json:17:20
     '{ "name": "thing_id", "type":{ "base":"char", "dec":"*" }, "comment":"fullname of parent thing" }' */
                p->thing_id,
  /* reddit/links_n_comments.json:18:20
     '{ "name": "uh", "type":{ "base":"char", "dec":"*" }, "comment":"a modhash" }' */
                p->uh,
                arg_switches, sizeof(arg_switches), true);
  return r;
}


void reddit_comment_params_cleanup_v(void *p) {
  reddit_comment_params_cleanup((struct reddit_comment_params *)p);
}

void reddit_comment_params_init_v(void *p) {
  reddit_comment_params_init((struct reddit_comment_params *)p);
}

void reddit_comment_params_from_json_v(char *json, size_t len, void *p) {
 reddit_comment_params_from_json(json, len, (struct reddit_comment_params*)p);
}

size_t reddit_comment_params_to_json_v(char *json, size_t len, void *p) {
  return reddit_comment_params_to_json(json, len, (struct reddit_comment_params*)p);
}

void reddit_comment_params_list_free_v(void **p) {
  reddit_comment_params_list_free((struct reddit_comment_params**)p);
}

void reddit_comment_params_list_from_json_v(char *str, size_t len, void *p) {
  reddit_comment_params_list_from_json(str, len, (struct reddit_comment_params ***)p);
}

size_t reddit_comment_params_list_to_json_v(char *str, size_t len, void *p){
  return reddit_comment_params_list_to_json(str, len, (struct reddit_comment_params **)p);
}


void reddit_comment_params_cleanup(struct reddit_comment_params *d) {
  /* reddit/links_n_comments.json:13:20
     '{ "name": "api_type", "type":{ "base":"char", "dec":"*" }, "comment":"the string json" }' */
  if (d->api_type)
    free(d->api_type);
  /* reddit/links_n_comments.json:14:20
     '{ "name": "return_rtjson", "type":{ "base":"bool" }, "comment":"boolean value" }' */
  (void)d->return_rtjson;
  /* reddit/links_n_comments.json:15:20
     '{ "name": "richtext_json", "type":{ "base":"char", "dec":"*" }, "comment":"JSON data" }' */
  if (d->richtext_json)
    free(d->richtext_json);
  /* reddit/links_n_comments.json:16:20
     '{ "name": "text", "type":{ "base":"char", "dec":"*" }, "comment":"raw markdown text" }' */
  if (d->text)
    free(d->text);
  /* reddit/links_n_comments.json:17:20
     '{ "name": "thing_id", "type":{ "base":"char", "dec":"*" }, "comment":"fullname of parent thing" }' */
  if (d->thing_id)
    free(d->thing_id);
  /* reddit/links_n_comments.json:18:20
     '{ "name": "uh", "type":{ "base":"char", "dec":"*" }, "comment":"a modhash" }' */
  if (d->uh)
    free(d->uh);
}

void reddit_comment_params_init(struct reddit_comment_params *p) {
  memset(p, 0, sizeof(struct reddit_comment_params));
  /* reddit/links_n_comments.json:13:20
     '{ "name": "api_type", "type":{ "base":"char", "dec":"*" }, "comment":"the string json" }' */

  /* reddit/links_n_comments.json:14:20
     '{ "name": "return_rtjson", "type":{ "base":"bool" }, "comment":"boolean value" }' */

  /* reddit/links_n_comments.json:15:20
     '{ "name": "richtext_json", "type":{ "base":"char", "dec":"*" }, "comment":"JSON data" }' */

  /* reddit/links_n_comments.json:16:20
     '{ "name": "text", "type":{ "base":"char", "dec":"*" }, "comment":"raw markdown text" }' */

  /* reddit/links_n_comments.json:17:20
     '{ "name": "thing_id", "type":{ "base":"char", "dec":"*" }, "comment":"fullname of parent thing" }' */

  /* reddit/links_n_comments.json:18:20
     '{ "name": "uh", "type":{ "base":"char", "dec":"*" }, "comment":"a modhash" }' */

}
void reddit_comment_params_list_free(struct reddit_comment_params **p) {
  ntl_free((void**)p, (void(*)(void*))reddit_comment_params_cleanup);
}

void reddit_comment_params_list_from_json(char *str, size_t len, struct reddit_comment_params ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct reddit_comment_params);
  d.init_elem = NULL;
  d.elem_from_buf = (void(*)(char*,size_t,void*))reddit_comment_params_from_json_p;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t reddit_comment_params_list_to_json(char *str, size_t len, struct reddit_comment_params **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, (size_t(*)(char*,size_t,void*))reddit_comment_params_to_json);
}

