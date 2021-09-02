/* This file is generated from specs/discord/webhook.json, Please don't edit it. */
/**
 * @file specs-code/discord/webhook.c
 * @see https://discord.com/developers/docs/resources/webhook
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "json-actor.h"
#include "json-actor-boxed.h"
#include "cee-utils.h"
#include "discord.h"

void discord_webhook_from_json(char *json, size_t len, struct discord_webhook **pp)
{
  static size_t ret=0; // used for debugging
  size_t r=0;
  if (!*pp) *pp = calloc(1, sizeof **pp);
  struct discord_webhook *p = *pp;
  r=json_extract(json, len, 
  /* specs/discord/webhook.json:12:20
     '{ "name": "id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                "(id):F,"
  /* specs/discord/webhook.json:13:20
     '{ "name": "type", "type":{ "base":"int", "int_alias":"enum discord_webhook_types" }}' */
                "(type):d,"
  /* specs/discord/webhook.json:14:20
     '{ "name": "guild_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                "(guild_id):F,"
  /* specs/discord/webhook.json:15:20
     '{ "name": "channel_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                "(channel_id):F,"
  /* specs/discord/webhook.json:16:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*" }}' */
                "(user):F,"
  /* specs/discord/webhook.json:17:20
     '{ "name": "name", "type":{ "base":"char", "dec":"[DISCORD_WEBHOOK_NAME_LEN]" }}' */
                "(name):s,"
  /* specs/discord/webhook.json:18:20
     '{ "name": "avatar", "type":{ "base":"char", "dec":"*" }, "comment":"@todo fixed size limit"}' */
                "(avatar):?s,"
  /* specs/discord/webhook.json:19:20
     '{ "name": "token", "type":{ "base":"char", "dec":"*" }, "comment":"@todo fixed size limit"}' */
                "(token):?s,"
  /* specs/discord/webhook.json:20:20
     '{ "name": "application_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                "(application_id):F,"
                "@arg_switches:b"
                "@record_defined"
                "@record_null",
  /* specs/discord/webhook.json:12:20
     '{ "name": "id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                cee_strtoull, &p->id,
  /* specs/discord/webhook.json:13:20
     '{ "name": "type", "type":{ "base":"int", "int_alias":"enum discord_webhook_types" }}' */
                &p->type,
  /* specs/discord/webhook.json:14:20
     '{ "name": "guild_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                cee_strtoull, &p->guild_id,
  /* specs/discord/webhook.json:15:20
     '{ "name": "channel_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                cee_strtoull, &p->channel_id,
  /* specs/discord/webhook.json:16:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*" }}' */
                discord_user_from_json, &p->user,
  /* specs/discord/webhook.json:17:20
     '{ "name": "name", "type":{ "base":"char", "dec":"[DISCORD_WEBHOOK_NAME_LEN]" }}' */
                p->name,
  /* specs/discord/webhook.json:18:20
     '{ "name": "avatar", "type":{ "base":"char", "dec":"*" }, "comment":"@todo fixed size limit"}' */
                &p->avatar,
  /* specs/discord/webhook.json:19:20
     '{ "name": "token", "type":{ "base":"char", "dec":"*" }, "comment":"@todo fixed size limit"}' */
                &p->token,
  /* specs/discord/webhook.json:20:20
     '{ "name": "application_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                cee_strtoull, &p->application_id,
                p->__M.arg_switches, sizeof(p->__M.arg_switches), p->__M.enable_arg_switches,
                p->__M.record_defined, sizeof(p->__M.record_defined),
                p->__M.record_null, sizeof(p->__M.record_null));
  ret = r;
}

static void discord_webhook_use_default_inject_settings(struct discord_webhook *p)
{
  p->__M.enable_arg_switches = true;
  /* specs/discord/webhook.json:12:20
     '{ "name": "id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  p->__M.arg_switches[0] = &p->id;

  /* specs/discord/webhook.json:13:20
     '{ "name": "type", "type":{ "base":"int", "int_alias":"enum discord_webhook_types" }}' */
  p->__M.arg_switches[1] = &p->type;

  /* specs/discord/webhook.json:14:20
     '{ "name": "guild_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  p->__M.arg_switches[2] = &p->guild_id;

  /* specs/discord/webhook.json:15:20
     '{ "name": "channel_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  p->__M.arg_switches[3] = &p->channel_id;

  /* specs/discord/webhook.json:16:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*" }}' */
  p->__M.arg_switches[4] = p->user;

  /* specs/discord/webhook.json:17:20
     '{ "name": "name", "type":{ "base":"char", "dec":"[DISCORD_WEBHOOK_NAME_LEN]" }}' */
  p->__M.arg_switches[5] = p->name;

  /* specs/discord/webhook.json:18:20
     '{ "name": "avatar", "type":{ "base":"char", "dec":"*" }, "comment":"@todo fixed size limit"}' */
  p->__M.arg_switches[6] = p->avatar;

  /* specs/discord/webhook.json:19:20
     '{ "name": "token", "type":{ "base":"char", "dec":"*" }, "comment":"@todo fixed size limit"}' */
  p->__M.arg_switches[7] = p->token;

  /* specs/discord/webhook.json:20:20
     '{ "name": "application_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  p->__M.arg_switches[8] = &p->application_id;

}

size_t discord_webhook_to_json(char *json, size_t len, struct discord_webhook *p)
{
  size_t r;
  discord_webhook_use_default_inject_settings(p);
  r=json_inject(json, len, 
  /* specs/discord/webhook.json:12:20
     '{ "name": "id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                "(id):|F|,"
  /* specs/discord/webhook.json:13:20
     '{ "name": "type", "type":{ "base":"int", "int_alias":"enum discord_webhook_types" }}' */
                "(type):d,"
  /* specs/discord/webhook.json:14:20
     '{ "name": "guild_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                "(guild_id):|F|,"
  /* specs/discord/webhook.json:15:20
     '{ "name": "channel_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                "(channel_id):|F|,"
  /* specs/discord/webhook.json:16:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*" }}' */
                "(user):F,"
  /* specs/discord/webhook.json:17:20
     '{ "name": "name", "type":{ "base":"char", "dec":"[DISCORD_WEBHOOK_NAME_LEN]" }}' */
                "(name):s,"
  /* specs/discord/webhook.json:18:20
     '{ "name": "avatar", "type":{ "base":"char", "dec":"*" }, "comment":"@todo fixed size limit"}' */
                "(avatar):s,"
  /* specs/discord/webhook.json:19:20
     '{ "name": "token", "type":{ "base":"char", "dec":"*" }, "comment":"@todo fixed size limit"}' */
                "(token):s,"
  /* specs/discord/webhook.json:20:20
     '{ "name": "application_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                "(application_id):|F|,"
                "@arg_switches:b",
  /* specs/discord/webhook.json:12:20
     '{ "name": "id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                cee_ulltostr, &p->id,
  /* specs/discord/webhook.json:13:20
     '{ "name": "type", "type":{ "base":"int", "int_alias":"enum discord_webhook_types" }}' */
                &p->type,
  /* specs/discord/webhook.json:14:20
     '{ "name": "guild_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                cee_ulltostr, &p->guild_id,
  /* specs/discord/webhook.json:15:20
     '{ "name": "channel_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                cee_ulltostr, &p->channel_id,
  /* specs/discord/webhook.json:16:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*" }}' */
                discord_user_to_json, p->user,
  /* specs/discord/webhook.json:17:20
     '{ "name": "name", "type":{ "base":"char", "dec":"[DISCORD_WEBHOOK_NAME_LEN]" }}' */
                p->name,
  /* specs/discord/webhook.json:18:20
     '{ "name": "avatar", "type":{ "base":"char", "dec":"*" }, "comment":"@todo fixed size limit"}' */
                p->avatar,
  /* specs/discord/webhook.json:19:20
     '{ "name": "token", "type":{ "base":"char", "dec":"*" }, "comment":"@todo fixed size limit"}' */
                p->token,
  /* specs/discord/webhook.json:20:20
     '{ "name": "application_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                cee_ulltostr, &p->application_id,
                p->__M.arg_switches, sizeof(p->__M.arg_switches), p->__M.enable_arg_switches);
  return r;
}


typedef void (*vfvp)(void *);
typedef void (*vfcpsvp)(char *, size_t, void *);
typedef size_t (*sfcpsvp)(char *, size_t, void *);
void discord_webhook_cleanup_v(void *p) {
  discord_webhook_cleanup((struct discord_webhook *)p);
}

void discord_webhook_init_v(void *p) {
  discord_webhook_init((struct discord_webhook *)p);
}

void discord_webhook_from_json_v(char *json, size_t len, void *pp) {
 discord_webhook_from_json(json, len, (struct discord_webhook**)pp);
}

size_t discord_webhook_to_json_v(char *json, size_t len, void *p) {
  return discord_webhook_to_json(json, len, (struct discord_webhook*)p);
}

void discord_webhook_list_free_v(void **p) {
  discord_webhook_list_free((struct discord_webhook**)p);
}

void discord_webhook_list_from_json_v(char *str, size_t len, void *p) {
  discord_webhook_list_from_json(str, len, (struct discord_webhook ***)p);
}

size_t discord_webhook_list_to_json_v(char *str, size_t len, void *p){
  return discord_webhook_list_to_json(str, len, (struct discord_webhook **)p);
}


void discord_webhook_cleanup(struct discord_webhook *d) {
  /* specs/discord/webhook.json:12:20
     '{ "name": "id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  // p->id is a scalar
  /* specs/discord/webhook.json:13:20
     '{ "name": "type", "type":{ "base":"int", "int_alias":"enum discord_webhook_types" }}' */
  // p->type is a scalar
  /* specs/discord/webhook.json:14:20
     '{ "name": "guild_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  // p->guild_id is a scalar
  /* specs/discord/webhook.json:15:20
     '{ "name": "channel_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  // p->channel_id is a scalar
  /* specs/discord/webhook.json:16:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*" }}' */
  if (d->user) {
    discord_user_cleanup(d->user);
    free(d->user);
  }
  /* specs/discord/webhook.json:17:20
     '{ "name": "name", "type":{ "base":"char", "dec":"[DISCORD_WEBHOOK_NAME_LEN]" }}' */
  // p->name is a scalar
  /* specs/discord/webhook.json:18:20
     '{ "name": "avatar", "type":{ "base":"char", "dec":"*" }, "comment":"@todo fixed size limit"}' */
  if (d->avatar)
    free(d->avatar);
  /* specs/discord/webhook.json:19:20
     '{ "name": "token", "type":{ "base":"char", "dec":"*" }, "comment":"@todo fixed size limit"}' */
  if (d->token)
    free(d->token);
  /* specs/discord/webhook.json:20:20
     '{ "name": "application_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  // p->application_id is a scalar
}

void discord_webhook_init(struct discord_webhook *p) {
  memset(p, 0, sizeof(struct discord_webhook));
  /* specs/discord/webhook.json:12:20
     '{ "name": "id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */

  /* specs/discord/webhook.json:13:20
     '{ "name": "type", "type":{ "base":"int", "int_alias":"enum discord_webhook_types" }}' */

  /* specs/discord/webhook.json:14:20
     '{ "name": "guild_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */

  /* specs/discord/webhook.json:15:20
     '{ "name": "channel_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */

  /* specs/discord/webhook.json:16:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*" }}' */
  p->user = malloc(sizeof *p->user);
  discord_user_init(p->user);

  /* specs/discord/webhook.json:17:20
     '{ "name": "name", "type":{ "base":"char", "dec":"[DISCORD_WEBHOOK_NAME_LEN]" }}' */

  /* specs/discord/webhook.json:18:20
     '{ "name": "avatar", "type":{ "base":"char", "dec":"*" }, "comment":"@todo fixed size limit"}' */

  /* specs/discord/webhook.json:19:20
     '{ "name": "token", "type":{ "base":"char", "dec":"*" }, "comment":"@todo fixed size limit"}' */

  /* specs/discord/webhook.json:20:20
     '{ "name": "application_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */

}
void discord_webhook_list_free(struct discord_webhook **p) {
  ntl_free((void**)p, (vfvp)discord_webhook_cleanup);
}

void discord_webhook_list_from_json(char *str, size_t len, struct discord_webhook ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct discord_webhook);
  d.init_elem = NULL;
  d.elem_from_buf = discord_webhook_from_json_v;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_webhook_list_to_json(char *str, size_t len, struct discord_webhook **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, discord_webhook_to_json_v);
}



enum discord_webhook_types discord_webhook_types_eval(char *s){
  if(strcasecmp("INCOMING", s) == 0) return DISCORD_WEBHOOK_INCOMING;
  if(strcasecmp("CHANNEL_FOLLOWER", s) == 0) return DISCORD_WEBHOOK_CHANNEL_FOLLOWER;
  ERR("'%s' doesn't match any known enumerator.", s);
}
char* discord_webhook_types_print(enum discord_webhook_types v){

  switch (v) {
  case DISCORD_WEBHOOK_INCOMING: return "INCOMING";
  case DISCORD_WEBHOOK_CHANNEL_FOLLOWER: return "CHANNEL_FOLLOWER";
  }

  return NULL;
}
