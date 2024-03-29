/* This file is generated from discord/invite.json, Please don't edit it. */
/**
 * @file specs-code/discord/invite.c
 * @see https://discord.com/developers/docs/resources/invite
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "json-actor.h"
#include "json-actor-boxed.h"
#include "cee-utils.h"
#include "discord.h"


void discord_invite_target_user_types_list_free_v(void **p) {
  discord_invite_target_user_types_list_free((enum discord_invite_target_user_types**)p);
}

void discord_invite_target_user_types_list_from_json_v(char *str, size_t len, void *p) {
  discord_invite_target_user_types_list_from_json(str, len, (enum discord_invite_target_user_types ***)p);
}

size_t discord_invite_target_user_types_list_to_json_v(char *str, size_t len, void *p){
  return discord_invite_target_user_types_list_to_json(str, len, (enum discord_invite_target_user_types **)p);
}

enum discord_invite_target_user_types discord_invite_target_user_types_eval(char *s){
  if(strcasecmp("STREAM", s) == 0) return DISCORD_INVITE_STREAM;
  ERR("'%s' doesn't match any known enumerator.", s);
  return -1;
}

char* discord_invite_target_user_types_print(enum discord_invite_target_user_types v){

  switch (v) {
  case DISCORD_INVITE_STREAM: return "STREAM";
  }

  return NULL;
}

void discord_invite_target_user_types_list_free(enum discord_invite_target_user_types **p) {
  ntl_free((void**)p, NULL);
}

void discord_invite_target_user_types_list_from_json(char *str, size_t len, enum discord_invite_target_user_types ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(enum discord_invite_target_user_types);
  d.init_elem = NULL;
  d.elem_from_buf = ja_u64_from_json_v;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_invite_target_user_types_list_to_json(char *str, size_t len, enum discord_invite_target_user_types **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, ja_u64_to_json_v);
}


void discord_invite_from_json_p(char *json, size_t len, struct discord_invite **pp)
{
  if (!*pp) *pp = malloc(sizeof **pp);
  discord_invite_from_json(json, len, *pp);
}
void discord_invite_from_json(char *json, size_t len, struct discord_invite *p)
{
  discord_invite_init(p);
  json_extract(json, len, 
  /* discord/invite.json:22:20
     '{ "name": "code", "type":{ "base":"char", "dec":"*" }}' */
                "(code):?s,"
  /* discord/invite.json:23:20
     '{ "name": "guild", "type":{ "base":"struct discord_guild", "dec":"*"}, "comment":"partial guild object"}' */
                "(guild):F,"
  /* discord/invite.json:24:20
     '{ "name": "channel", "type":{ "base":"struct discord_channel", "dec":"*"}, "comment":"partial channel object"}' */
                "(channel):F,"
  /* discord/invite.json:25:20
     '{ "name": "inviter", "type":{ "base":"struct discord_user", "dec":"*"}}' */
                "(inviter):F,"
  /* discord/invite.json:26:20
     '{ "name": "target_user", "type":{ "base":"struct discord_user", "dec":"*"}, "comment":"partial user object"}' */
                "(target_user):F,"
  /* discord/invite.json:27:20
     '{ "name": "target_user_type", "type":{ "base":"int", "int_alias":"enum discord_invite_target_user_types" }}' */
                "(target_user_type):d,"
  /* discord/invite.json:28:20
     '{ "name": "approximate_presence_count", "type":{ "base":"int" }}' */
                "(approximate_presence_count):d,"
  /* discord/invite.json:29:20
     '{ "name": "approximate_member_count", "type":{ "base":"int" }}' */
                "(approximate_member_count):d,",
  /* discord/invite.json:22:20
     '{ "name": "code", "type":{ "base":"char", "dec":"*" }}' */
                &p->code,
  /* discord/invite.json:23:20
     '{ "name": "guild", "type":{ "base":"struct discord_guild", "dec":"*"}, "comment":"partial guild object"}' */
                discord_guild_from_json_p, &p->guild,
  /* discord/invite.json:24:20
     '{ "name": "channel", "type":{ "base":"struct discord_channel", "dec":"*"}, "comment":"partial channel object"}' */
                discord_channel_from_json_p, &p->channel,
  /* discord/invite.json:25:20
     '{ "name": "inviter", "type":{ "base":"struct discord_user", "dec":"*"}}' */
                discord_user_from_json_p, &p->inviter,
  /* discord/invite.json:26:20
     '{ "name": "target_user", "type":{ "base":"struct discord_user", "dec":"*"}, "comment":"partial user object"}' */
                discord_user_from_json_p, &p->target_user,
  /* discord/invite.json:27:20
     '{ "name": "target_user_type", "type":{ "base":"int", "int_alias":"enum discord_invite_target_user_types" }}' */
                &p->target_user_type,
  /* discord/invite.json:28:20
     '{ "name": "approximate_presence_count", "type":{ "base":"int" }}' */
                &p->approximate_presence_count,
  /* discord/invite.json:29:20
     '{ "name": "approximate_member_count", "type":{ "base":"int" }}' */
                &p->approximate_member_count);
}

size_t discord_invite_to_json(char *json, size_t len, struct discord_invite *p)
{
  size_t r;
  void *arg_switches[8]={NULL};
  /* discord/invite.json:22:20
     '{ "name": "code", "type":{ "base":"char", "dec":"*" }}' */
  arg_switches[0] = p->code;

  /* discord/invite.json:23:20
     '{ "name": "guild", "type":{ "base":"struct discord_guild", "dec":"*"}, "comment":"partial guild object"}' */
  arg_switches[1] = p->guild;

  /* discord/invite.json:24:20
     '{ "name": "channel", "type":{ "base":"struct discord_channel", "dec":"*"}, "comment":"partial channel object"}' */
  arg_switches[2] = p->channel;

  /* discord/invite.json:25:20
     '{ "name": "inviter", "type":{ "base":"struct discord_user", "dec":"*"}}' */
  arg_switches[3] = p->inviter;

  /* discord/invite.json:26:20
     '{ "name": "target_user", "type":{ "base":"struct discord_user", "dec":"*"}, "comment":"partial user object"}' */
  arg_switches[4] = p->target_user;

  /* discord/invite.json:27:20
     '{ "name": "target_user_type", "type":{ "base":"int", "int_alias":"enum discord_invite_target_user_types" }}' */
  arg_switches[5] = &p->target_user_type;

  /* discord/invite.json:28:20
     '{ "name": "approximate_presence_count", "type":{ "base":"int" }}' */
  arg_switches[6] = &p->approximate_presence_count;

  /* discord/invite.json:29:20
     '{ "name": "approximate_member_count", "type":{ "base":"int" }}' */
  arg_switches[7] = &p->approximate_member_count;

  r=json_inject(json, len, 
  /* discord/invite.json:22:20
     '{ "name": "code", "type":{ "base":"char", "dec":"*" }}' */
                "(code):s,"
  /* discord/invite.json:23:20
     '{ "name": "guild", "type":{ "base":"struct discord_guild", "dec":"*"}, "comment":"partial guild object"}' */
                "(guild):F,"
  /* discord/invite.json:24:20
     '{ "name": "channel", "type":{ "base":"struct discord_channel", "dec":"*"}, "comment":"partial channel object"}' */
                "(channel):F,"
  /* discord/invite.json:25:20
     '{ "name": "inviter", "type":{ "base":"struct discord_user", "dec":"*"}}' */
                "(inviter):F,"
  /* discord/invite.json:26:20
     '{ "name": "target_user", "type":{ "base":"struct discord_user", "dec":"*"}, "comment":"partial user object"}' */
                "(target_user):F,"
  /* discord/invite.json:27:20
     '{ "name": "target_user_type", "type":{ "base":"int", "int_alias":"enum discord_invite_target_user_types" }}' */
                "(target_user_type):d,"
  /* discord/invite.json:28:20
     '{ "name": "approximate_presence_count", "type":{ "base":"int" }}' */
                "(approximate_presence_count):d,"
  /* discord/invite.json:29:20
     '{ "name": "approximate_member_count", "type":{ "base":"int" }}' */
                "(approximate_member_count):d,"
                "@arg_switches:b",
  /* discord/invite.json:22:20
     '{ "name": "code", "type":{ "base":"char", "dec":"*" }}' */
                p->code,
  /* discord/invite.json:23:20
     '{ "name": "guild", "type":{ "base":"struct discord_guild", "dec":"*"}, "comment":"partial guild object"}' */
                discord_guild_to_json, p->guild,
  /* discord/invite.json:24:20
     '{ "name": "channel", "type":{ "base":"struct discord_channel", "dec":"*"}, "comment":"partial channel object"}' */
                discord_channel_to_json, p->channel,
  /* discord/invite.json:25:20
     '{ "name": "inviter", "type":{ "base":"struct discord_user", "dec":"*"}}' */
                discord_user_to_json, p->inviter,
  /* discord/invite.json:26:20
     '{ "name": "target_user", "type":{ "base":"struct discord_user", "dec":"*"}, "comment":"partial user object"}' */
                discord_user_to_json, p->target_user,
  /* discord/invite.json:27:20
     '{ "name": "target_user_type", "type":{ "base":"int", "int_alias":"enum discord_invite_target_user_types" }}' */
                &p->target_user_type,
  /* discord/invite.json:28:20
     '{ "name": "approximate_presence_count", "type":{ "base":"int" }}' */
                &p->approximate_presence_count,
  /* discord/invite.json:29:20
     '{ "name": "approximate_member_count", "type":{ "base":"int" }}' */
                &p->approximate_member_count,
                arg_switches, sizeof(arg_switches), true);
  return r;
}


void discord_invite_cleanup_v(void *p) {
  discord_invite_cleanup((struct discord_invite *)p);
}

void discord_invite_init_v(void *p) {
  discord_invite_init((struct discord_invite *)p);
}

void discord_invite_from_json_v(char *json, size_t len, void *p) {
 discord_invite_from_json(json, len, (struct discord_invite*)p);
}

size_t discord_invite_to_json_v(char *json, size_t len, void *p) {
  return discord_invite_to_json(json, len, (struct discord_invite*)p);
}

void discord_invite_list_free_v(void **p) {
  discord_invite_list_free((struct discord_invite**)p);
}

void discord_invite_list_from_json_v(char *str, size_t len, void *p) {
  discord_invite_list_from_json(str, len, (struct discord_invite ***)p);
}

size_t discord_invite_list_to_json_v(char *str, size_t len, void *p){
  return discord_invite_list_to_json(str, len, (struct discord_invite **)p);
}


void discord_invite_cleanup(struct discord_invite *d) {
  /* discord/invite.json:22:20
     '{ "name": "code", "type":{ "base":"char", "dec":"*" }}' */
  if (d->code)
    free(d->code);
  /* discord/invite.json:23:20
     '{ "name": "guild", "type":{ "base":"struct discord_guild", "dec":"*"}, "comment":"partial guild object"}' */
  if (d->guild) {
    discord_guild_cleanup(d->guild);
    free(d->guild);
  }
  /* discord/invite.json:24:20
     '{ "name": "channel", "type":{ "base":"struct discord_channel", "dec":"*"}, "comment":"partial channel object"}' */
  if (d->channel) {
    discord_channel_cleanup(d->channel);
    free(d->channel);
  }
  /* discord/invite.json:25:20
     '{ "name": "inviter", "type":{ "base":"struct discord_user", "dec":"*"}}' */
  if (d->inviter) {
    discord_user_cleanup(d->inviter);
    free(d->inviter);
  }
  /* discord/invite.json:26:20
     '{ "name": "target_user", "type":{ "base":"struct discord_user", "dec":"*"}, "comment":"partial user object"}' */
  if (d->target_user) {
    discord_user_cleanup(d->target_user);
    free(d->target_user);
  }
  /* discord/invite.json:27:20
     '{ "name": "target_user_type", "type":{ "base":"int", "int_alias":"enum discord_invite_target_user_types" }}' */
  (void)d->target_user_type;
  /* discord/invite.json:28:20
     '{ "name": "approximate_presence_count", "type":{ "base":"int" }}' */
  (void)d->approximate_presence_count;
  /* discord/invite.json:29:20
     '{ "name": "approximate_member_count", "type":{ "base":"int" }}' */
  (void)d->approximate_member_count;
}

void discord_invite_init(struct discord_invite *p) {
  memset(p, 0, sizeof(struct discord_invite));
  /* discord/invite.json:22:20
     '{ "name": "code", "type":{ "base":"char", "dec":"*" }}' */

  /* discord/invite.json:23:20
     '{ "name": "guild", "type":{ "base":"struct discord_guild", "dec":"*"}, "comment":"partial guild object"}' */

  /* discord/invite.json:24:20
     '{ "name": "channel", "type":{ "base":"struct discord_channel", "dec":"*"}, "comment":"partial channel object"}' */

  /* discord/invite.json:25:20
     '{ "name": "inviter", "type":{ "base":"struct discord_user", "dec":"*"}}' */

  /* discord/invite.json:26:20
     '{ "name": "target_user", "type":{ "base":"struct discord_user", "dec":"*"}, "comment":"partial user object"}' */

  /* discord/invite.json:27:20
     '{ "name": "target_user_type", "type":{ "base":"int", "int_alias":"enum discord_invite_target_user_types" }}' */

  /* discord/invite.json:28:20
     '{ "name": "approximate_presence_count", "type":{ "base":"int" }}' */

  /* discord/invite.json:29:20
     '{ "name": "approximate_member_count", "type":{ "base":"int" }}' */

}
void discord_invite_list_free(struct discord_invite **p) {
  ntl_free((void**)p, (void(*)(void*))discord_invite_cleanup);
}

void discord_invite_list_from_json(char *str, size_t len, struct discord_invite ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct discord_invite);
  d.init_elem = NULL;
  d.elem_from_buf = (void(*)(char*,size_t,void*))discord_invite_from_json_p;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_invite_list_to_json(char *str, size_t len, struct discord_invite **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, (size_t(*)(char*,size_t,void*))discord_invite_to_json);
}


void discord_invite_metadata_from_json_p(char *json, size_t len, struct discord_invite_metadata **pp)
{
  if (!*pp) *pp = malloc(sizeof **pp);
  discord_invite_metadata_from_json(json, len, *pp);
}
void discord_invite_metadata_from_json(char *json, size_t len, struct discord_invite_metadata *p)
{
  discord_invite_metadata_init(p);
  json_extract(json, len, 
  /* discord/invite.json:39:20
     '{ "name": "user", "type":{ "base":"int" }}' */
                "(user):d,"
  /* discord/invite.json:40:20
     '{ "name": "max_uses", "type":{ "base":"int" }}' */
                "(max_uses):d,"
  /* discord/invite.json:41:20
     '{ "name": "max_age", "type":{ "base":"int" }}' */
                "(max_age):d,"
  /* discord/invite.json:42:20
     '{ "name": "temporary", "type":{ "base":"int" }}' */
                "(temporary):d,"
  /* discord/invite.json:43:20
     '{ "name": "created_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601"}}' */
                "(created_at):F,",
  /* discord/invite.json:39:20
     '{ "name": "user", "type":{ "base":"int" }}' */
                &p->user,
  /* discord/invite.json:40:20
     '{ "name": "max_uses", "type":{ "base":"int" }}' */
                &p->max_uses,
  /* discord/invite.json:41:20
     '{ "name": "max_age", "type":{ "base":"int" }}' */
                &p->max_age,
  /* discord/invite.json:42:20
     '{ "name": "temporary", "type":{ "base":"int" }}' */
                &p->temporary,
  /* discord/invite.json:43:20
     '{ "name": "created_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601"}}' */
                cee_iso8601_to_unix_ms, &p->created_at);
}

size_t discord_invite_metadata_to_json(char *json, size_t len, struct discord_invite_metadata *p)
{
  size_t r;
  void *arg_switches[5]={NULL};
  /* discord/invite.json:39:20
     '{ "name": "user", "type":{ "base":"int" }}' */
  arg_switches[0] = &p->user;

  /* discord/invite.json:40:20
     '{ "name": "max_uses", "type":{ "base":"int" }}' */
  arg_switches[1] = &p->max_uses;

  /* discord/invite.json:41:20
     '{ "name": "max_age", "type":{ "base":"int" }}' */
  arg_switches[2] = &p->max_age;

  /* discord/invite.json:42:20
     '{ "name": "temporary", "type":{ "base":"int" }}' */
  arg_switches[3] = &p->temporary;

  /* discord/invite.json:43:20
     '{ "name": "created_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601"}}' */
  arg_switches[4] = &p->created_at;

  r=json_inject(json, len, 
  /* discord/invite.json:39:20
     '{ "name": "user", "type":{ "base":"int" }}' */
                "(user):d,"
  /* discord/invite.json:40:20
     '{ "name": "max_uses", "type":{ "base":"int" }}' */
                "(max_uses):d,"
  /* discord/invite.json:41:20
     '{ "name": "max_age", "type":{ "base":"int" }}' */
                "(max_age):d,"
  /* discord/invite.json:42:20
     '{ "name": "temporary", "type":{ "base":"int" }}' */
                "(temporary):d,"
  /* discord/invite.json:43:20
     '{ "name": "created_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601"}}' */
                "(created_at):|F|,"
                "@arg_switches:b",
  /* discord/invite.json:39:20
     '{ "name": "user", "type":{ "base":"int" }}' */
                &p->user,
  /* discord/invite.json:40:20
     '{ "name": "max_uses", "type":{ "base":"int" }}' */
                &p->max_uses,
  /* discord/invite.json:41:20
     '{ "name": "max_age", "type":{ "base":"int" }}' */
                &p->max_age,
  /* discord/invite.json:42:20
     '{ "name": "temporary", "type":{ "base":"int" }}' */
                &p->temporary,
  /* discord/invite.json:43:20
     '{ "name": "created_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601"}}' */
                cee_unix_ms_to_iso8601, &p->created_at,
                arg_switches, sizeof(arg_switches), true);
  return r;
}


void discord_invite_metadata_cleanup_v(void *p) {
  discord_invite_metadata_cleanup((struct discord_invite_metadata *)p);
}

void discord_invite_metadata_init_v(void *p) {
  discord_invite_metadata_init((struct discord_invite_metadata *)p);
}

void discord_invite_metadata_from_json_v(char *json, size_t len, void *p) {
 discord_invite_metadata_from_json(json, len, (struct discord_invite_metadata*)p);
}

size_t discord_invite_metadata_to_json_v(char *json, size_t len, void *p) {
  return discord_invite_metadata_to_json(json, len, (struct discord_invite_metadata*)p);
}

void discord_invite_metadata_list_free_v(void **p) {
  discord_invite_metadata_list_free((struct discord_invite_metadata**)p);
}

void discord_invite_metadata_list_from_json_v(char *str, size_t len, void *p) {
  discord_invite_metadata_list_from_json(str, len, (struct discord_invite_metadata ***)p);
}

size_t discord_invite_metadata_list_to_json_v(char *str, size_t len, void *p){
  return discord_invite_metadata_list_to_json(str, len, (struct discord_invite_metadata **)p);
}


void discord_invite_metadata_cleanup(struct discord_invite_metadata *d) {
  /* discord/invite.json:39:20
     '{ "name": "user", "type":{ "base":"int" }}' */
  (void)d->user;
  /* discord/invite.json:40:20
     '{ "name": "max_uses", "type":{ "base":"int" }}' */
  (void)d->max_uses;
  /* discord/invite.json:41:20
     '{ "name": "max_age", "type":{ "base":"int" }}' */
  (void)d->max_age;
  /* discord/invite.json:42:20
     '{ "name": "temporary", "type":{ "base":"int" }}' */
  (void)d->temporary;
  /* discord/invite.json:43:20
     '{ "name": "created_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601"}}' */
  (void)d->created_at;
}

void discord_invite_metadata_init(struct discord_invite_metadata *p) {
  memset(p, 0, sizeof(struct discord_invite_metadata));
  /* discord/invite.json:39:20
     '{ "name": "user", "type":{ "base":"int" }}' */

  /* discord/invite.json:40:20
     '{ "name": "max_uses", "type":{ "base":"int" }}' */

  /* discord/invite.json:41:20
     '{ "name": "max_age", "type":{ "base":"int" }}' */

  /* discord/invite.json:42:20
     '{ "name": "temporary", "type":{ "base":"int" }}' */

  /* discord/invite.json:43:20
     '{ "name": "created_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601"}}' */

}
void discord_invite_metadata_list_free(struct discord_invite_metadata **p) {
  ntl_free((void**)p, (void(*)(void*))discord_invite_metadata_cleanup);
}

void discord_invite_metadata_list_from_json(char *str, size_t len, struct discord_invite_metadata ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct discord_invite_metadata);
  d.init_elem = NULL;
  d.elem_from_buf = (void(*)(char*,size_t,void*))discord_invite_metadata_from_json_p;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_invite_metadata_list_to_json(char *str, size_t len, struct discord_invite_metadata **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, (size_t(*)(char*,size_t,void*))discord_invite_metadata_to_json);
}

