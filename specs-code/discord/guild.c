/* This file is generated from discord/guild.json, Please don't edit it. */
/**
 * @file specs-code/discord/guild.c
 * @see https://discord.com/developers/docs/resources/guild
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "json-actor.h"
#include "json-actor-boxed.h"
#include "cee-utils.h"
#include "discord.h"

void discord_guild_from_json_p(char *json, size_t len, struct discord_guild **pp)
{
  if (!*pp) *pp = malloc(sizeof **pp);
  discord_guild_from_json(json, len, *pp);
}
void discord_guild_from_json(char *json, size_t len, struct discord_guild *p)
{
  discord_guild_init(p);
  json_extract(json, len, 
  /* discord/guild.json:12:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"id"}' */
                "(id):F,"
  /* discord/guild.json:13:53
     '{"type":{"base":"char", "dec":"*"}, "name":"name"}' */
                "(name):?s,"
  /* discord/guild.json:14:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"icon"}' */
                "(icon):?s,"
  /* discord/guild.json:15:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"icon_hash"}' */
                "(icon_hash):?s,"
  /* discord/guild.json:16:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"splash"}' */
                "(splash):?s,"
  /* discord/guild.json:17:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"discovery_splash"}' */
                "(discovery_splash):?s,"
  /* discord/guild.json:18:42
     '{"type":{"base":"bool"}, "name":"owner", "option":true}' */
                "(owner):b,"
  /* discord/guild.json:19:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"owner_id"}' */
                "(owner_id):F,"
  /* discord/guild.json:20:41
     '{"type":{"base":"int"}, "name":"permissions", "option":true}' */
                "(permissions):d,"
  /* discord/guild.json:21:53
     '{"type":{"base":"char", "dec":"*"}, "name":"region"}' */
                "(region):?s,"
  /* discord/guild.json:22:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"afk_channel_id"}' */
                "(afk_channel_id):F,"
  /* discord/guild.json:23:41
     '{"type":{"base":"int"}, "name":"afk_timeout"}' */
                "(afk_timeout):d,"
  /* discord/guild.json:24:42
     '{"type":{"base":"bool"}, "name":"widget_enabled", "option":true}' */
                "(widget_enabled):b,"
  /* discord/guild.json:25:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"widget_channel_id", "option":true}' */
                "(widget_channel_id):F,"
  /* discord/guild.json:26:88
     '{"type":{"base":"int", "int_alias":"enum discord_verification_level"}, "name":"verification_level"}' */
                "(verification_level):d,"
  /* discord/guild.json:28:32
     '{"type":{"base":"int", "int_alias":"enum discord_default_message_notification_level"}, 
              "name":"default_message_notifications"}' */
                "(default_message_notifications):d,"
  /* discord/guild.json:30:32
     '{"type":{"base":"int", "int_alias":"enum discord_explicit_content_filter_level"},
              "name":"explicit_content_filter"}' */
                "(explicit_content_filter):d,"
  /* discord/guild.json:31:70
     '{"type":{"base":"struct discord_role", "dec":"ntl"}, "name":"roles", "comment":"array of role objects", "inject_if_not":null }' */
                "(roles):F,"
  /* discord/guild.json:32:71
     '{"type":{"base":"struct discord_emoji", "dec":"ntl"}, "name":"emojis"}' */
                "(emojis):F,"
  /* discord/guild.json:33:57
     '{"type":{"base":"ja_str", "dec":"ntl"}, "name":"features", "comment":"array of guild feature strings", "inject_if_not":null }' */
                "(features):F,"
  /* discord/guild.json:34:79
     '{"type":{"base":"int", "int_alias":"enum discord_mfa_level"}, "name":"mfa_level"}' */
                "(mfa_level):d,"
  /* discord/guild.json:35:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"application_id"}' */
                "(application_id):F,"
  /* discord/guild.json:36:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"system_channel_id"}' */
                "(system_channel_id):F,"
  /* discord/guild.json:37:90
     '{"type":{"base":"int", "int_alias":"enum discord_system_channel_flags"}, "name":"system_channel_flags"}' */
                "(system_channel_flags):d,"
  /* discord/guild.json:38:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"rules_channel_id"}' */
                "(rules_channel_id):F,"
  /* discord/guild.json:39:76
     '{"type":{"base":"char", "dec":"*", "converter":"iso8601"}, "name":"joined_at", "option":true}' */
                "(joined_at):F,"
  /* discord/guild.json:40:42
     '{"type":{"base":"bool"}, "name":"large", "option":true}' */
                "(large):b,"
  /* discord/guild.json:41:42
     '{"type":{"base":"bool"}, "name":"unavailable", "option":true}' */
                "(unavailable):b,"
  /* discord/guild.json:42:41
     '{"type":{"base":"int"}, "name":"member_count", "option":true}' */
                "(member_count):d,"
  /* discord/guild.json:43:77
     '{"type":{"base":"struct discord_voice_state", "dec":"ntl"}, "name":"voice_states", "comment":"array of partial voice state objects", "inject_if_not":null }' */
                "(voice_states):F,"
  /* discord/guild.json:44:78
     '{"type":{"base":"struct discord_guild_member", "dec":"ntl"}, "name":"members", "option":true}' */
                "(members):F,"
  /* discord/guild.json:45:73
     '{"type":{"base":"struct discord_channel", "dec":"ntl"}, "name":"channels", "option":true,
         "comment":"array of channel objects"}' */
                "(channels):F,"
  /* discord/guild.json:47:81
     '{"type":{"base":"struct discord_presence_status", "dec":"ntl"}, "name":"presences", "option":true, "comment":"array of partial presence update objects", "inject_if_not":null }' */
                "(presences):F,"
  /* discord/guild.json:48:41
     '{"type":{"base":"int"}, "name":"max_presences", "option":true}' */
                "(max_presences):d,"
  /* discord/guild.json:49:41
     '{"type":{"base":"int"}, "name":"max_members", "option":true}' */
                "(max_members):d,"
  /* discord/guild.json:50:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"vanity_url"}' */
                "(vanity_url):?s,"
  /* discord/guild.json:51:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"description"}' */
                "(description):?s,"
  /* discord/guild.json:52:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"banner"}' */
                "(banner):?s,"
  /* discord/guild.json:53:82
     '{"type":{"base":"int", "int_alias":"enum discord_premium_tier"}, "name":"premium_tier"}' */
                "(premium_tier):d,"
  /* discord/guild.json:54:41
     '{"type":{"base":"int"}, "name":"premium_subscription_count", "option":true}' */
                "(premium_subscription_count):d,"
  /* discord/guild.json:55:53
     '{"type":{"base":"char", "dec":"*"}, "name":"preferred_locale"}' */
                "(preferred_locale):?s,"
  /* discord/guild.json:57:27
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, 
         "name":"public_updates_channel_id"}' */
                "(public_updates_channel_id):F,"
  /* discord/guild.json:58:41
     '{"type":{"base":"int"}, "name":"max_video_channel_users", "option":true}' */
                "(max_video_channel_users):d,"
  /* discord/guild.json:59:41
     '{"type":{"base":"int"}, "name":"approximate_member_count", "option":true}' */
                "(approximate_member_count):d,"
  /* discord/guild.json:60:41
     '{"type":{"base":"int"}, "name":"approximate_presence_count", "option":true}' */
                "(approximate_presence_count):d,"
  /* discord/guild.json:61:78
     '{"type":{"base":"struct discord_welcome_screen", "dec":"*"}, "name":"welcome_screen", "option":true}' */
                "(welcome_screen):F,",
  /* discord/guild.json:12:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"id"}' */
                cee_strtou64, &p->id,
  /* discord/guild.json:13:53
     '{"type":{"base":"char", "dec":"*"}, "name":"name"}' */
                &p->name,
  /* discord/guild.json:14:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"icon"}' */
                &p->icon,
  /* discord/guild.json:15:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"icon_hash"}' */
                &p->icon_hash,
  /* discord/guild.json:16:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"splash"}' */
                &p->splash,
  /* discord/guild.json:17:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"discovery_splash"}' */
                &p->discovery_splash,
  /* discord/guild.json:18:42
     '{"type":{"base":"bool"}, "name":"owner", "option":true}' */
                &p->owner,
  /* discord/guild.json:19:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"owner_id"}' */
                cee_strtou64, &p->owner_id,
  /* discord/guild.json:20:41
     '{"type":{"base":"int"}, "name":"permissions", "option":true}' */
                &p->permissions,
  /* discord/guild.json:21:53
     '{"type":{"base":"char", "dec":"*"}, "name":"region"}' */
                &p->region,
  /* discord/guild.json:22:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"afk_channel_id"}' */
                cee_strtou64, &p->afk_channel_id,
  /* discord/guild.json:23:41
     '{"type":{"base":"int"}, "name":"afk_timeout"}' */
                &p->afk_timeout,
  /* discord/guild.json:24:42
     '{"type":{"base":"bool"}, "name":"widget_enabled", "option":true}' */
                &p->widget_enabled,
  /* discord/guild.json:25:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"widget_channel_id", "option":true}' */
                cee_strtou64, &p->widget_channel_id,
  /* discord/guild.json:26:88
     '{"type":{"base":"int", "int_alias":"enum discord_verification_level"}, "name":"verification_level"}' */
                &p->verification_level,
  /* discord/guild.json:28:32
     '{"type":{"base":"int", "int_alias":"enum discord_default_message_notification_level"}, 
              "name":"default_message_notifications"}' */
                &p->default_message_notifications,
  /* discord/guild.json:30:32
     '{"type":{"base":"int", "int_alias":"enum discord_explicit_content_filter_level"},
              "name":"explicit_content_filter"}' */
                &p->explicit_content_filter,
  /* discord/guild.json:31:70
     '{"type":{"base":"struct discord_role", "dec":"ntl"}, "name":"roles", "comment":"array of role objects", "inject_if_not":null }' */
                discord_role_list_from_json, &p->roles,
  /* discord/guild.json:32:71
     '{"type":{"base":"struct discord_emoji", "dec":"ntl"}, "name":"emojis"}' */
                discord_emoji_list_from_json, &p->emojis,
  /* discord/guild.json:33:57
     '{"type":{"base":"ja_str", "dec":"ntl"}, "name":"features", "comment":"array of guild feature strings", "inject_if_not":null }' */
                ja_str_list_from_json, &p->features,
  /* discord/guild.json:34:79
     '{"type":{"base":"int", "int_alias":"enum discord_mfa_level"}, "name":"mfa_level"}' */
                &p->mfa_level,
  /* discord/guild.json:35:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"application_id"}' */
                cee_strtou64, &p->application_id,
  /* discord/guild.json:36:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"system_channel_id"}' */
                cee_strtou64, &p->system_channel_id,
  /* discord/guild.json:37:90
     '{"type":{"base":"int", "int_alias":"enum discord_system_channel_flags"}, "name":"system_channel_flags"}' */
                &p->system_channel_flags,
  /* discord/guild.json:38:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"rules_channel_id"}' */
                cee_strtou64, &p->rules_channel_id,
  /* discord/guild.json:39:76
     '{"type":{"base":"char", "dec":"*", "converter":"iso8601"}, "name":"joined_at", "option":true}' */
                cee_iso8601_to_unix_ms, &p->joined_at,
  /* discord/guild.json:40:42
     '{"type":{"base":"bool"}, "name":"large", "option":true}' */
                &p->large,
  /* discord/guild.json:41:42
     '{"type":{"base":"bool"}, "name":"unavailable", "option":true}' */
                &p->unavailable,
  /* discord/guild.json:42:41
     '{"type":{"base":"int"}, "name":"member_count", "option":true}' */
                &p->member_count,
  /* discord/guild.json:43:77
     '{"type":{"base":"struct discord_voice_state", "dec":"ntl"}, "name":"voice_states", "comment":"array of partial voice state objects", "inject_if_not":null }' */
                discord_voice_state_list_from_json, &p->voice_states,
  /* discord/guild.json:44:78
     '{"type":{"base":"struct discord_guild_member", "dec":"ntl"}, "name":"members", "option":true}' */
                discord_guild_member_list_from_json, &p->members,
  /* discord/guild.json:45:73
     '{"type":{"base":"struct discord_channel", "dec":"ntl"}, "name":"channels", "option":true,
         "comment":"array of channel objects"}' */
                discord_channel_list_from_json, &p->channels,
  /* discord/guild.json:47:81
     '{"type":{"base":"struct discord_presence_status", "dec":"ntl"}, "name":"presences", "option":true, "comment":"array of partial presence update objects", "inject_if_not":null }' */
                discord_presence_status_list_from_json, &p->presences,
  /* discord/guild.json:48:41
     '{"type":{"base":"int"}, "name":"max_presences", "option":true}' */
                &p->max_presences,
  /* discord/guild.json:49:41
     '{"type":{"base":"int"}, "name":"max_members", "option":true}' */
                &p->max_members,
  /* discord/guild.json:50:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"vanity_url"}' */
                &p->vanity_url,
  /* discord/guild.json:51:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"description"}' */
                &p->description,
  /* discord/guild.json:52:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"banner"}' */
                &p->banner,
  /* discord/guild.json:53:82
     '{"type":{"base":"int", "int_alias":"enum discord_premium_tier"}, "name":"premium_tier"}' */
                &p->premium_tier,
  /* discord/guild.json:54:41
     '{"type":{"base":"int"}, "name":"premium_subscription_count", "option":true}' */
                &p->premium_subscription_count,
  /* discord/guild.json:55:53
     '{"type":{"base":"char", "dec":"*"}, "name":"preferred_locale"}' */
                &p->preferred_locale,
  /* discord/guild.json:57:27
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, 
         "name":"public_updates_channel_id"}' */
                cee_strtou64, &p->public_updates_channel_id,
  /* discord/guild.json:58:41
     '{"type":{"base":"int"}, "name":"max_video_channel_users", "option":true}' */
                &p->max_video_channel_users,
  /* discord/guild.json:59:41
     '{"type":{"base":"int"}, "name":"approximate_member_count", "option":true}' */
                &p->approximate_member_count,
  /* discord/guild.json:60:41
     '{"type":{"base":"int"}, "name":"approximate_presence_count", "option":true}' */
                &p->approximate_presence_count,
  /* discord/guild.json:61:78
     '{"type":{"base":"struct discord_welcome_screen", "dec":"*"}, "name":"welcome_screen", "option":true}' */
                discord_welcome_screen_from_json_p, &p->welcome_screen);
}

size_t discord_guild_to_json(char *json, size_t len, struct discord_guild *p)
{
  size_t r;
  void *arg_switches[46]={NULL};
  /* discord/guild.json:12:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"id"}' */
  arg_switches[0] = &p->id;

  /* discord/guild.json:13:53
     '{"type":{"base":"char", "dec":"*"}, "name":"name"}' */
  arg_switches[1] = p->name;

  /* discord/guild.json:14:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"icon"}' */
  arg_switches[2] = p->icon;

  /* discord/guild.json:15:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"icon_hash"}' */
  arg_switches[3] = p->icon_hash;

  /* discord/guild.json:16:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"splash"}' */
  arg_switches[4] = p->splash;

  /* discord/guild.json:17:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"discovery_splash"}' */
  arg_switches[5] = p->discovery_splash;

  /* discord/guild.json:18:42
     '{"type":{"base":"bool"}, "name":"owner", "option":true}' */
  arg_switches[6] = &p->owner;

  /* discord/guild.json:19:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"owner_id"}' */
  arg_switches[7] = &p->owner_id;

  /* discord/guild.json:20:41
     '{"type":{"base":"int"}, "name":"permissions", "option":true}' */
  arg_switches[8] = &p->permissions;

  /* discord/guild.json:21:53
     '{"type":{"base":"char", "dec":"*"}, "name":"region"}' */
  arg_switches[9] = p->region;

  /* discord/guild.json:22:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"afk_channel_id"}' */
  arg_switches[10] = &p->afk_channel_id;

  /* discord/guild.json:23:41
     '{"type":{"base":"int"}, "name":"afk_timeout"}' */
  arg_switches[11] = &p->afk_timeout;

  /* discord/guild.json:24:42
     '{"type":{"base":"bool"}, "name":"widget_enabled", "option":true}' */
  arg_switches[12] = &p->widget_enabled;

  /* discord/guild.json:25:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"widget_channel_id", "option":true}' */
  arg_switches[13] = &p->widget_channel_id;

  /* discord/guild.json:26:88
     '{"type":{"base":"int", "int_alias":"enum discord_verification_level"}, "name":"verification_level"}' */
  arg_switches[14] = &p->verification_level;

  /* discord/guild.json:28:32
     '{"type":{"base":"int", "int_alias":"enum discord_default_message_notification_level"}, 
              "name":"default_message_notifications"}' */
  arg_switches[15] = &p->default_message_notifications;

  /* discord/guild.json:30:32
     '{"type":{"base":"int", "int_alias":"enum discord_explicit_content_filter_level"},
              "name":"explicit_content_filter"}' */
  arg_switches[16] = &p->explicit_content_filter;

  /* discord/guild.json:31:70
     '{"type":{"base":"struct discord_role", "dec":"ntl"}, "name":"roles", "comment":"array of role objects", "inject_if_not":null }' */
  if (p->roles != NULL)
    arg_switches[17] = p->roles;

  /* discord/guild.json:32:71
     '{"type":{"base":"struct discord_emoji", "dec":"ntl"}, "name":"emojis"}' */
  arg_switches[18] = p->emojis;

  /* discord/guild.json:33:57
     '{"type":{"base":"ja_str", "dec":"ntl"}, "name":"features", "comment":"array of guild feature strings", "inject_if_not":null }' */
  if (p->features != NULL)
    arg_switches[19] = p->features;

  /* discord/guild.json:34:79
     '{"type":{"base":"int", "int_alias":"enum discord_mfa_level"}, "name":"mfa_level"}' */
  arg_switches[20] = &p->mfa_level;

  /* discord/guild.json:35:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"application_id"}' */
  arg_switches[21] = &p->application_id;

  /* discord/guild.json:36:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"system_channel_id"}' */
  arg_switches[22] = &p->system_channel_id;

  /* discord/guild.json:37:90
     '{"type":{"base":"int", "int_alias":"enum discord_system_channel_flags"}, "name":"system_channel_flags"}' */
  arg_switches[23] = &p->system_channel_flags;

  /* discord/guild.json:38:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"rules_channel_id"}' */
  arg_switches[24] = &p->rules_channel_id;

  /* discord/guild.json:39:76
     '{"type":{"base":"char", "dec":"*", "converter":"iso8601"}, "name":"joined_at", "option":true}' */
  arg_switches[25] = &p->joined_at;

  /* discord/guild.json:40:42
     '{"type":{"base":"bool"}, "name":"large", "option":true}' */
  arg_switches[26] = &p->large;

  /* discord/guild.json:41:42
     '{"type":{"base":"bool"}, "name":"unavailable", "option":true}' */
  arg_switches[27] = &p->unavailable;

  /* discord/guild.json:42:41
     '{"type":{"base":"int"}, "name":"member_count", "option":true}' */
  arg_switches[28] = &p->member_count;

  /* discord/guild.json:43:77
     '{"type":{"base":"struct discord_voice_state", "dec":"ntl"}, "name":"voice_states", "comment":"array of partial voice state objects", "inject_if_not":null }' */
  if (p->voice_states != NULL)
    arg_switches[29] = p->voice_states;

  /* discord/guild.json:44:78
     '{"type":{"base":"struct discord_guild_member", "dec":"ntl"}, "name":"members", "option":true}' */
  arg_switches[30] = p->members;

  /* discord/guild.json:45:73
     '{"type":{"base":"struct discord_channel", "dec":"ntl"}, "name":"channels", "option":true,
         "comment":"array of channel objects"}' */
  arg_switches[31] = p->channels;

  /* discord/guild.json:47:81
     '{"type":{"base":"struct discord_presence_status", "dec":"ntl"}, "name":"presences", "option":true, "comment":"array of partial presence update objects", "inject_if_not":null }' */
  if (p->presences != NULL)
    arg_switches[32] = p->presences;

  /* discord/guild.json:48:41
     '{"type":{"base":"int"}, "name":"max_presences", "option":true}' */
  arg_switches[33] = &p->max_presences;

  /* discord/guild.json:49:41
     '{"type":{"base":"int"}, "name":"max_members", "option":true}' */
  arg_switches[34] = &p->max_members;

  /* discord/guild.json:50:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"vanity_url"}' */
  arg_switches[35] = p->vanity_url;

  /* discord/guild.json:51:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"description"}' */
  arg_switches[36] = p->description;

  /* discord/guild.json:52:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"banner"}' */
  arg_switches[37] = p->banner;

  /* discord/guild.json:53:82
     '{"type":{"base":"int", "int_alias":"enum discord_premium_tier"}, "name":"premium_tier"}' */
  arg_switches[38] = &p->premium_tier;

  /* discord/guild.json:54:41
     '{"type":{"base":"int"}, "name":"premium_subscription_count", "option":true}' */
  arg_switches[39] = &p->premium_subscription_count;

  /* discord/guild.json:55:53
     '{"type":{"base":"char", "dec":"*"}, "name":"preferred_locale"}' */
  arg_switches[40] = p->preferred_locale;

  /* discord/guild.json:57:27
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, 
         "name":"public_updates_channel_id"}' */
  arg_switches[41] = &p->public_updates_channel_id;

  /* discord/guild.json:58:41
     '{"type":{"base":"int"}, "name":"max_video_channel_users", "option":true}' */
  arg_switches[42] = &p->max_video_channel_users;

  /* discord/guild.json:59:41
     '{"type":{"base":"int"}, "name":"approximate_member_count", "option":true}' */
  arg_switches[43] = &p->approximate_member_count;

  /* discord/guild.json:60:41
     '{"type":{"base":"int"}, "name":"approximate_presence_count", "option":true}' */
  arg_switches[44] = &p->approximate_presence_count;

  /* discord/guild.json:61:78
     '{"type":{"base":"struct discord_welcome_screen", "dec":"*"}, "name":"welcome_screen", "option":true}' */
  arg_switches[45] = p->welcome_screen;

  r=json_inject(json, len, 
  /* discord/guild.json:12:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"id"}' */
                "(id):|F|,"
  /* discord/guild.json:13:53
     '{"type":{"base":"char", "dec":"*"}, "name":"name"}' */
                "(name):s,"
  /* discord/guild.json:14:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"icon"}' */
                "(icon):s,"
  /* discord/guild.json:15:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"icon_hash"}' */
                "(icon_hash):s,"
  /* discord/guild.json:16:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"splash"}' */
                "(splash):s,"
  /* discord/guild.json:17:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"discovery_splash"}' */
                "(discovery_splash):s,"
  /* discord/guild.json:18:42
     '{"type":{"base":"bool"}, "name":"owner", "option":true}' */
                "(owner):b,"
  /* discord/guild.json:19:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"owner_id"}' */
                "(owner_id):|F|,"
  /* discord/guild.json:20:41
     '{"type":{"base":"int"}, "name":"permissions", "option":true}' */
                "(permissions):d,"
  /* discord/guild.json:21:53
     '{"type":{"base":"char", "dec":"*"}, "name":"region"}' */
                "(region):s,"
  /* discord/guild.json:22:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"afk_channel_id"}' */
                "(afk_channel_id):|F|,"
  /* discord/guild.json:23:41
     '{"type":{"base":"int"}, "name":"afk_timeout"}' */
                "(afk_timeout):d,"
  /* discord/guild.json:24:42
     '{"type":{"base":"bool"}, "name":"widget_enabled", "option":true}' */
                "(widget_enabled):b,"
  /* discord/guild.json:25:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"widget_channel_id", "option":true}' */
                "(widget_channel_id):|F|,"
  /* discord/guild.json:26:88
     '{"type":{"base":"int", "int_alias":"enum discord_verification_level"}, "name":"verification_level"}' */
                "(verification_level):d,"
  /* discord/guild.json:28:32
     '{"type":{"base":"int", "int_alias":"enum discord_default_message_notification_level"}, 
              "name":"default_message_notifications"}' */
                "(default_message_notifications):d,"
  /* discord/guild.json:30:32
     '{"type":{"base":"int", "int_alias":"enum discord_explicit_content_filter_level"},
              "name":"explicit_content_filter"}' */
                "(explicit_content_filter):d,"
  /* discord/guild.json:31:70
     '{"type":{"base":"struct discord_role", "dec":"ntl"}, "name":"roles", "comment":"array of role objects", "inject_if_not":null }' */
                "(roles):F,"
  /* discord/guild.json:32:71
     '{"type":{"base":"struct discord_emoji", "dec":"ntl"}, "name":"emojis"}' */
                "(emojis):F,"
  /* discord/guild.json:33:57
     '{"type":{"base":"ja_str", "dec":"ntl"}, "name":"features", "comment":"array of guild feature strings", "inject_if_not":null }' */
                "(features):F,"
  /* discord/guild.json:34:79
     '{"type":{"base":"int", "int_alias":"enum discord_mfa_level"}, "name":"mfa_level"}' */
                "(mfa_level):d,"
  /* discord/guild.json:35:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"application_id"}' */
                "(application_id):|F|,"
  /* discord/guild.json:36:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"system_channel_id"}' */
                "(system_channel_id):|F|,"
  /* discord/guild.json:37:90
     '{"type":{"base":"int", "int_alias":"enum discord_system_channel_flags"}, "name":"system_channel_flags"}' */
                "(system_channel_flags):d,"
  /* discord/guild.json:38:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"rules_channel_id"}' */
                "(rules_channel_id):|F|,"
  /* discord/guild.json:39:76
     '{"type":{"base":"char", "dec":"*", "converter":"iso8601"}, "name":"joined_at", "option":true}' */
                "(joined_at):|F|,"
  /* discord/guild.json:40:42
     '{"type":{"base":"bool"}, "name":"large", "option":true}' */
                "(large):b,"
  /* discord/guild.json:41:42
     '{"type":{"base":"bool"}, "name":"unavailable", "option":true}' */
                "(unavailable):b,"
  /* discord/guild.json:42:41
     '{"type":{"base":"int"}, "name":"member_count", "option":true}' */
                "(member_count):d,"
  /* discord/guild.json:43:77
     '{"type":{"base":"struct discord_voice_state", "dec":"ntl"}, "name":"voice_states", "comment":"array of partial voice state objects", "inject_if_not":null }' */
                "(voice_states):F,"
  /* discord/guild.json:44:78
     '{"type":{"base":"struct discord_guild_member", "dec":"ntl"}, "name":"members", "option":true}' */
                "(members):F,"
  /* discord/guild.json:45:73
     '{"type":{"base":"struct discord_channel", "dec":"ntl"}, "name":"channels", "option":true,
         "comment":"array of channel objects"}' */
                "(channels):F,"
  /* discord/guild.json:47:81
     '{"type":{"base":"struct discord_presence_status", "dec":"ntl"}, "name":"presences", "option":true, "comment":"array of partial presence update objects", "inject_if_not":null }' */
                "(presences):F,"
  /* discord/guild.json:48:41
     '{"type":{"base":"int"}, "name":"max_presences", "option":true}' */
                "(max_presences):d,"
  /* discord/guild.json:49:41
     '{"type":{"base":"int"}, "name":"max_members", "option":true}' */
                "(max_members):d,"
  /* discord/guild.json:50:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"vanity_url"}' */
                "(vanity_url):s,"
  /* discord/guild.json:51:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"description"}' */
                "(description):s,"
  /* discord/guild.json:52:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"banner"}' */
                "(banner):s,"
  /* discord/guild.json:53:82
     '{"type":{"base":"int", "int_alias":"enum discord_premium_tier"}, "name":"premium_tier"}' */
                "(premium_tier):d,"
  /* discord/guild.json:54:41
     '{"type":{"base":"int"}, "name":"premium_subscription_count", "option":true}' */
                "(premium_subscription_count):d,"
  /* discord/guild.json:55:53
     '{"type":{"base":"char", "dec":"*"}, "name":"preferred_locale"}' */
                "(preferred_locale):s,"
  /* discord/guild.json:57:27
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, 
         "name":"public_updates_channel_id"}' */
                "(public_updates_channel_id):|F|,"
  /* discord/guild.json:58:41
     '{"type":{"base":"int"}, "name":"max_video_channel_users", "option":true}' */
                "(max_video_channel_users):d,"
  /* discord/guild.json:59:41
     '{"type":{"base":"int"}, "name":"approximate_member_count", "option":true}' */
                "(approximate_member_count):d,"
  /* discord/guild.json:60:41
     '{"type":{"base":"int"}, "name":"approximate_presence_count", "option":true}' */
                "(approximate_presence_count):d,"
  /* discord/guild.json:61:78
     '{"type":{"base":"struct discord_welcome_screen", "dec":"*"}, "name":"welcome_screen", "option":true}' */
                "(welcome_screen):F,"
                "@arg_switches:b",
  /* discord/guild.json:12:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"id"}' */
                cee_u64tostr, &p->id,
  /* discord/guild.json:13:53
     '{"type":{"base":"char", "dec":"*"}, "name":"name"}' */
                p->name,
  /* discord/guild.json:14:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"icon"}' */
                p->icon,
  /* discord/guild.json:15:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"icon_hash"}' */
                p->icon_hash,
  /* discord/guild.json:16:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"splash"}' */
                p->splash,
  /* discord/guild.json:17:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"discovery_splash"}' */
                p->discovery_splash,
  /* discord/guild.json:18:42
     '{"type":{"base":"bool"}, "name":"owner", "option":true}' */
                &p->owner,
  /* discord/guild.json:19:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"owner_id"}' */
                cee_u64tostr, &p->owner_id,
  /* discord/guild.json:20:41
     '{"type":{"base":"int"}, "name":"permissions", "option":true}' */
                &p->permissions,
  /* discord/guild.json:21:53
     '{"type":{"base":"char", "dec":"*"}, "name":"region"}' */
                p->region,
  /* discord/guild.json:22:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"afk_channel_id"}' */
                cee_u64tostr, &p->afk_channel_id,
  /* discord/guild.json:23:41
     '{"type":{"base":"int"}, "name":"afk_timeout"}' */
                &p->afk_timeout,
  /* discord/guild.json:24:42
     '{"type":{"base":"bool"}, "name":"widget_enabled", "option":true}' */
                &p->widget_enabled,
  /* discord/guild.json:25:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"widget_channel_id", "option":true}' */
                cee_u64tostr, &p->widget_channel_id,
  /* discord/guild.json:26:88
     '{"type":{"base":"int", "int_alias":"enum discord_verification_level"}, "name":"verification_level"}' */
                &p->verification_level,
  /* discord/guild.json:28:32
     '{"type":{"base":"int", "int_alias":"enum discord_default_message_notification_level"}, 
              "name":"default_message_notifications"}' */
                &p->default_message_notifications,
  /* discord/guild.json:30:32
     '{"type":{"base":"int", "int_alias":"enum discord_explicit_content_filter_level"},
              "name":"explicit_content_filter"}' */
                &p->explicit_content_filter,
  /* discord/guild.json:31:70
     '{"type":{"base":"struct discord_role", "dec":"ntl"}, "name":"roles", "comment":"array of role objects", "inject_if_not":null }' */
                discord_role_list_to_json, p->roles,
  /* discord/guild.json:32:71
     '{"type":{"base":"struct discord_emoji", "dec":"ntl"}, "name":"emojis"}' */
                discord_emoji_list_to_json, p->emojis,
  /* discord/guild.json:33:57
     '{"type":{"base":"ja_str", "dec":"ntl"}, "name":"features", "comment":"array of guild feature strings", "inject_if_not":null }' */
                ja_str_list_to_json, p->features,
  /* discord/guild.json:34:79
     '{"type":{"base":"int", "int_alias":"enum discord_mfa_level"}, "name":"mfa_level"}' */
                &p->mfa_level,
  /* discord/guild.json:35:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"application_id"}' */
                cee_u64tostr, &p->application_id,
  /* discord/guild.json:36:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"system_channel_id"}' */
                cee_u64tostr, &p->system_channel_id,
  /* discord/guild.json:37:90
     '{"type":{"base":"int", "int_alias":"enum discord_system_channel_flags"}, "name":"system_channel_flags"}' */
                &p->system_channel_flags,
  /* discord/guild.json:38:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"rules_channel_id"}' */
                cee_u64tostr, &p->rules_channel_id,
  /* discord/guild.json:39:76
     '{"type":{"base":"char", "dec":"*", "converter":"iso8601"}, "name":"joined_at", "option":true}' */
                cee_unix_ms_to_iso8601, &p->joined_at,
  /* discord/guild.json:40:42
     '{"type":{"base":"bool"}, "name":"large", "option":true}' */
                &p->large,
  /* discord/guild.json:41:42
     '{"type":{"base":"bool"}, "name":"unavailable", "option":true}' */
                &p->unavailable,
  /* discord/guild.json:42:41
     '{"type":{"base":"int"}, "name":"member_count", "option":true}' */
                &p->member_count,
  /* discord/guild.json:43:77
     '{"type":{"base":"struct discord_voice_state", "dec":"ntl"}, "name":"voice_states", "comment":"array of partial voice state objects", "inject_if_not":null }' */
                discord_voice_state_list_to_json, p->voice_states,
  /* discord/guild.json:44:78
     '{"type":{"base":"struct discord_guild_member", "dec":"ntl"}, "name":"members", "option":true}' */
                discord_guild_member_list_to_json, p->members,
  /* discord/guild.json:45:73
     '{"type":{"base":"struct discord_channel", "dec":"ntl"}, "name":"channels", "option":true,
         "comment":"array of channel objects"}' */
                discord_channel_list_to_json, p->channels,
  /* discord/guild.json:47:81
     '{"type":{"base":"struct discord_presence_status", "dec":"ntl"}, "name":"presences", "option":true, "comment":"array of partial presence update objects", "inject_if_not":null }' */
                discord_presence_status_list_to_json, p->presences,
  /* discord/guild.json:48:41
     '{"type":{"base":"int"}, "name":"max_presences", "option":true}' */
                &p->max_presences,
  /* discord/guild.json:49:41
     '{"type":{"base":"int"}, "name":"max_members", "option":true}' */
                &p->max_members,
  /* discord/guild.json:50:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"vanity_url"}' */
                p->vanity_url,
  /* discord/guild.json:51:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"description"}' */
                p->description,
  /* discord/guild.json:52:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"banner"}' */
                p->banner,
  /* discord/guild.json:53:82
     '{"type":{"base":"int", "int_alias":"enum discord_premium_tier"}, "name":"premium_tier"}' */
                &p->premium_tier,
  /* discord/guild.json:54:41
     '{"type":{"base":"int"}, "name":"premium_subscription_count", "option":true}' */
                &p->premium_subscription_count,
  /* discord/guild.json:55:53
     '{"type":{"base":"char", "dec":"*"}, "name":"preferred_locale"}' */
                p->preferred_locale,
  /* discord/guild.json:57:27
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, 
         "name":"public_updates_channel_id"}' */
                cee_u64tostr, &p->public_updates_channel_id,
  /* discord/guild.json:58:41
     '{"type":{"base":"int"}, "name":"max_video_channel_users", "option":true}' */
                &p->max_video_channel_users,
  /* discord/guild.json:59:41
     '{"type":{"base":"int"}, "name":"approximate_member_count", "option":true}' */
                &p->approximate_member_count,
  /* discord/guild.json:60:41
     '{"type":{"base":"int"}, "name":"approximate_presence_count", "option":true}' */
                &p->approximate_presence_count,
  /* discord/guild.json:61:78
     '{"type":{"base":"struct discord_welcome_screen", "dec":"*"}, "name":"welcome_screen", "option":true}' */
                discord_welcome_screen_to_json, p->welcome_screen,
                arg_switches, sizeof(arg_switches), true);
  return r;
}


void discord_guild_cleanup_v(void *p) {
  discord_guild_cleanup((struct discord_guild *)p);
}

void discord_guild_init_v(void *p) {
  discord_guild_init((struct discord_guild *)p);
}

void discord_guild_from_json_v(char *json, size_t len, void *p) {
 discord_guild_from_json(json, len, (struct discord_guild*)p);
}

size_t discord_guild_to_json_v(char *json, size_t len, void *p) {
  return discord_guild_to_json(json, len, (struct discord_guild*)p);
}

void discord_guild_list_free_v(void **p) {
  discord_guild_list_free((struct discord_guild**)p);
}

void discord_guild_list_from_json_v(char *str, size_t len, void *p) {
  discord_guild_list_from_json(str, len, (struct discord_guild ***)p);
}

size_t discord_guild_list_to_json_v(char *str, size_t len, void *p){
  return discord_guild_list_to_json(str, len, (struct discord_guild **)p);
}


void discord_guild_cleanup(struct discord_guild *d) {
  /* discord/guild.json:12:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"id"}' */
  (void)d->id;
  /* discord/guild.json:13:53
     '{"type":{"base":"char", "dec":"*"}, "name":"name"}' */
  if (d->name)
    free(d->name);
  /* discord/guild.json:14:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"icon"}' */
  if (d->icon)
    free(d->icon);
  /* discord/guild.json:15:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"icon_hash"}' */
  if (d->icon_hash)
    free(d->icon_hash);
  /* discord/guild.json:16:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"splash"}' */
  if (d->splash)
    free(d->splash);
  /* discord/guild.json:17:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"discovery_splash"}' */
  if (d->discovery_splash)
    free(d->discovery_splash);
  /* discord/guild.json:18:42
     '{"type":{"base":"bool"}, "name":"owner", "option":true}' */
  (void)d->owner;
  /* discord/guild.json:19:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"owner_id"}' */
  (void)d->owner_id;
  /* discord/guild.json:20:41
     '{"type":{"base":"int"}, "name":"permissions", "option":true}' */
  (void)d->permissions;
  /* discord/guild.json:21:53
     '{"type":{"base":"char", "dec":"*"}, "name":"region"}' */
  if (d->region)
    free(d->region);
  /* discord/guild.json:22:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"afk_channel_id"}' */
  (void)d->afk_channel_id;
  /* discord/guild.json:23:41
     '{"type":{"base":"int"}, "name":"afk_timeout"}' */
  (void)d->afk_timeout;
  /* discord/guild.json:24:42
     '{"type":{"base":"bool"}, "name":"widget_enabled", "option":true}' */
  (void)d->widget_enabled;
  /* discord/guild.json:25:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"widget_channel_id", "option":true}' */
  (void)d->widget_channel_id;
  /* discord/guild.json:26:88
     '{"type":{"base":"int", "int_alias":"enum discord_verification_level"}, "name":"verification_level"}' */
  (void)d->verification_level;
  /* discord/guild.json:28:32
     '{"type":{"base":"int", "int_alias":"enum discord_default_message_notification_level"}, 
              "name":"default_message_notifications"}' */
  (void)d->default_message_notifications;
  /* discord/guild.json:30:32
     '{"type":{"base":"int", "int_alias":"enum discord_explicit_content_filter_level"},
              "name":"explicit_content_filter"}' */
  (void)d->explicit_content_filter;
  /* discord/guild.json:31:70
     '{"type":{"base":"struct discord_role", "dec":"ntl"}, "name":"roles", "comment":"array of role objects", "inject_if_not":null }' */
  if (d->roles)
    discord_role_list_free(d->roles);
  /* discord/guild.json:32:71
     '{"type":{"base":"struct discord_emoji", "dec":"ntl"}, "name":"emojis"}' */
  if (d->emojis)
    discord_emoji_list_free(d->emojis);
  /* discord/guild.json:33:57
     '{"type":{"base":"ja_str", "dec":"ntl"}, "name":"features", "comment":"array of guild feature strings", "inject_if_not":null }' */
  if (d->features)
    ja_str_list_free(d->features);
  /* discord/guild.json:34:79
     '{"type":{"base":"int", "int_alias":"enum discord_mfa_level"}, "name":"mfa_level"}' */
  (void)d->mfa_level;
  /* discord/guild.json:35:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"application_id"}' */
  (void)d->application_id;
  /* discord/guild.json:36:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"system_channel_id"}' */
  (void)d->system_channel_id;
  /* discord/guild.json:37:90
     '{"type":{"base":"int", "int_alias":"enum discord_system_channel_flags"}, "name":"system_channel_flags"}' */
  (void)d->system_channel_flags;
  /* discord/guild.json:38:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"rules_channel_id"}' */
  (void)d->rules_channel_id;
  /* discord/guild.json:39:76
     '{"type":{"base":"char", "dec":"*", "converter":"iso8601"}, "name":"joined_at", "option":true}' */
  (void)d->joined_at;
  /* discord/guild.json:40:42
     '{"type":{"base":"bool"}, "name":"large", "option":true}' */
  (void)d->large;
  /* discord/guild.json:41:42
     '{"type":{"base":"bool"}, "name":"unavailable", "option":true}' */
  (void)d->unavailable;
  /* discord/guild.json:42:41
     '{"type":{"base":"int"}, "name":"member_count", "option":true}' */
  (void)d->member_count;
  /* discord/guild.json:43:77
     '{"type":{"base":"struct discord_voice_state", "dec":"ntl"}, "name":"voice_states", "comment":"array of partial voice state objects", "inject_if_not":null }' */
  if (d->voice_states)
    discord_voice_state_list_free(d->voice_states);
  /* discord/guild.json:44:78
     '{"type":{"base":"struct discord_guild_member", "dec":"ntl"}, "name":"members", "option":true}' */
  if (d->members)
    discord_guild_member_list_free(d->members);
  /* discord/guild.json:45:73
     '{"type":{"base":"struct discord_channel", "dec":"ntl"}, "name":"channels", "option":true,
         "comment":"array of channel objects"}' */
  if (d->channels)
    discord_channel_list_free(d->channels);
  /* discord/guild.json:47:81
     '{"type":{"base":"struct discord_presence_status", "dec":"ntl"}, "name":"presences", "option":true, "comment":"array of partial presence update objects", "inject_if_not":null }' */
  if (d->presences)
    discord_presence_status_list_free(d->presences);
  /* discord/guild.json:48:41
     '{"type":{"base":"int"}, "name":"max_presences", "option":true}' */
  (void)d->max_presences;
  /* discord/guild.json:49:41
     '{"type":{"base":"int"}, "name":"max_members", "option":true}' */
  (void)d->max_members;
  /* discord/guild.json:50:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"vanity_url"}' */
  if (d->vanity_url)
    free(d->vanity_url);
  /* discord/guild.json:51:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"description"}' */
  if (d->description)
    free(d->description);
  /* discord/guild.json:52:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"banner"}' */
  if (d->banner)
    free(d->banner);
  /* discord/guild.json:53:82
     '{"type":{"base":"int", "int_alias":"enum discord_premium_tier"}, "name":"premium_tier"}' */
  (void)d->premium_tier;
  /* discord/guild.json:54:41
     '{"type":{"base":"int"}, "name":"premium_subscription_count", "option":true}' */
  (void)d->premium_subscription_count;
  /* discord/guild.json:55:53
     '{"type":{"base":"char", "dec":"*"}, "name":"preferred_locale"}' */
  if (d->preferred_locale)
    free(d->preferred_locale);
  /* discord/guild.json:57:27
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, 
         "name":"public_updates_channel_id"}' */
  (void)d->public_updates_channel_id;
  /* discord/guild.json:58:41
     '{"type":{"base":"int"}, "name":"max_video_channel_users", "option":true}' */
  (void)d->max_video_channel_users;
  /* discord/guild.json:59:41
     '{"type":{"base":"int"}, "name":"approximate_member_count", "option":true}' */
  (void)d->approximate_member_count;
  /* discord/guild.json:60:41
     '{"type":{"base":"int"}, "name":"approximate_presence_count", "option":true}' */
  (void)d->approximate_presence_count;
  /* discord/guild.json:61:78
     '{"type":{"base":"struct discord_welcome_screen", "dec":"*"}, "name":"welcome_screen", "option":true}' */
  if (d->welcome_screen) {
    discord_welcome_screen_cleanup(d->welcome_screen);
    free(d->welcome_screen);
  }
}

void discord_guild_init(struct discord_guild *p) {
  memset(p, 0, sizeof(struct discord_guild));
  /* discord/guild.json:12:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"id"}' */

  /* discord/guild.json:13:53
     '{"type":{"base":"char", "dec":"*"}, "name":"name"}' */

  /* discord/guild.json:14:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"icon"}' */

  /* discord/guild.json:15:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"icon_hash"}' */

  /* discord/guild.json:16:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"splash"}' */

  /* discord/guild.json:17:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"discovery_splash"}' */

  /* discord/guild.json:18:42
     '{"type":{"base":"bool"}, "name":"owner", "option":true}' */

  /* discord/guild.json:19:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"owner_id"}' */

  /* discord/guild.json:20:41
     '{"type":{"base":"int"}, "name":"permissions", "option":true}' */

  /* discord/guild.json:21:53
     '{"type":{"base":"char", "dec":"*"}, "name":"region"}' */

  /* discord/guild.json:22:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"afk_channel_id"}' */

  /* discord/guild.json:23:41
     '{"type":{"base":"int"}, "name":"afk_timeout"}' */

  /* discord/guild.json:24:42
     '{"type":{"base":"bool"}, "name":"widget_enabled", "option":true}' */

  /* discord/guild.json:25:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"widget_channel_id", "option":true}' */

  /* discord/guild.json:26:88
     '{"type":{"base":"int", "int_alias":"enum discord_verification_level"}, "name":"verification_level"}' */

  /* discord/guild.json:28:32
     '{"type":{"base":"int", "int_alias":"enum discord_default_message_notification_level"}, 
              "name":"default_message_notifications"}' */

  /* discord/guild.json:30:32
     '{"type":{"base":"int", "int_alias":"enum discord_explicit_content_filter_level"},
              "name":"explicit_content_filter"}' */

  /* discord/guild.json:31:70
     '{"type":{"base":"struct discord_role", "dec":"ntl"}, "name":"roles", "comment":"array of role objects", "inject_if_not":null }' */

  /* discord/guild.json:32:71
     '{"type":{"base":"struct discord_emoji", "dec":"ntl"}, "name":"emojis"}' */

  /* discord/guild.json:33:57
     '{"type":{"base":"ja_str", "dec":"ntl"}, "name":"features", "comment":"array of guild feature strings", "inject_if_not":null }' */

  /* discord/guild.json:34:79
     '{"type":{"base":"int", "int_alias":"enum discord_mfa_level"}, "name":"mfa_level"}' */

  /* discord/guild.json:35:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"application_id"}' */

  /* discord/guild.json:36:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"system_channel_id"}' */

  /* discord/guild.json:37:90
     '{"type":{"base":"int", "int_alias":"enum discord_system_channel_flags"}, "name":"system_channel_flags"}' */

  /* discord/guild.json:38:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"rules_channel_id"}' */

  /* discord/guild.json:39:76
     '{"type":{"base":"char", "dec":"*", "converter":"iso8601"}, "name":"joined_at", "option":true}' */

  /* discord/guild.json:40:42
     '{"type":{"base":"bool"}, "name":"large", "option":true}' */

  /* discord/guild.json:41:42
     '{"type":{"base":"bool"}, "name":"unavailable", "option":true}' */

  /* discord/guild.json:42:41
     '{"type":{"base":"int"}, "name":"member_count", "option":true}' */

  /* discord/guild.json:43:77
     '{"type":{"base":"struct discord_voice_state", "dec":"ntl"}, "name":"voice_states", "comment":"array of partial voice state objects", "inject_if_not":null }' */

  /* discord/guild.json:44:78
     '{"type":{"base":"struct discord_guild_member", "dec":"ntl"}, "name":"members", "option":true}' */

  /* discord/guild.json:45:73
     '{"type":{"base":"struct discord_channel", "dec":"ntl"}, "name":"channels", "option":true,
         "comment":"array of channel objects"}' */

  /* discord/guild.json:47:81
     '{"type":{"base":"struct discord_presence_status", "dec":"ntl"}, "name":"presences", "option":true, "comment":"array of partial presence update objects", "inject_if_not":null }' */

  /* discord/guild.json:48:41
     '{"type":{"base":"int"}, "name":"max_presences", "option":true}' */

  /* discord/guild.json:49:41
     '{"type":{"base":"int"}, "name":"max_members", "option":true}' */

  /* discord/guild.json:50:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"vanity_url"}' */

  /* discord/guild.json:51:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"description"}' */

  /* discord/guild.json:52:70
     '{"type":{"base":"char", "dec":"*", "nullable":true}, "name":"banner"}' */

  /* discord/guild.json:53:82
     '{"type":{"base":"int", "int_alias":"enum discord_premium_tier"}, "name":"premium_tier"}' */

  /* discord/guild.json:54:41
     '{"type":{"base":"int"}, "name":"premium_subscription_count", "option":true}' */

  /* discord/guild.json:55:53
     '{"type":{"base":"char", "dec":"*"}, "name":"preferred_locale"}' */

  /* discord/guild.json:57:27
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, 
         "name":"public_updates_channel_id"}' */

  /* discord/guild.json:58:41
     '{"type":{"base":"int"}, "name":"max_video_channel_users", "option":true}' */

  /* discord/guild.json:59:41
     '{"type":{"base":"int"}, "name":"approximate_member_count", "option":true}' */

  /* discord/guild.json:60:41
     '{"type":{"base":"int"}, "name":"approximate_presence_count", "option":true}' */

  /* discord/guild.json:61:78
     '{"type":{"base":"struct discord_welcome_screen", "dec":"*"}, "name":"welcome_screen", "option":true}' */

}
void discord_guild_list_free(struct discord_guild **p) {
  ntl_free((void**)p, (void(*)(void*))discord_guild_cleanup);
}

void discord_guild_list_from_json(char *str, size_t len, struct discord_guild ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct discord_guild);
  d.init_elem = NULL;
  d.elem_from_buf = (void(*)(char*,size_t,void*))discord_guild_from_json_p;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_guild_list_to_json(char *str, size_t len, struct discord_guild **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, (size_t(*)(char*,size_t,void*))discord_guild_to_json);
}



void discord_default_message_notification_level_list_free_v(void **p) {
  discord_default_message_notification_level_list_free((enum discord_default_message_notification_level**)p);
}

void discord_default_message_notification_level_list_from_json_v(char *str, size_t len, void *p) {
  discord_default_message_notification_level_list_from_json(str, len, (enum discord_default_message_notification_level ***)p);
}

size_t discord_default_message_notification_level_list_to_json_v(char *str, size_t len, void *p){
  return discord_default_message_notification_level_list_to_json(str, len, (enum discord_default_message_notification_level **)p);
}

enum discord_default_message_notification_level discord_default_message_notification_level_eval(char *s){
  if(strcasecmp("ALL_MESSAGES", s) == 0) return DISCORD_ALL_MESSAGES;
  if(strcasecmp("ONLY_MENTIONS", s) == 0) return DISCORD_ONLY_MENTIONS;
  ERR("'%s' doesn't match any known enumerator.", s);
  return -1;
}

char* discord_default_message_notification_level_print(enum discord_default_message_notification_level v){

  switch (v) {
  case DISCORD_ALL_MESSAGES: return "ALL_MESSAGES";
  case DISCORD_ONLY_MENTIONS: return "ONLY_MENTIONS";
  }

  return NULL;
}

void discord_default_message_notification_level_list_free(enum discord_default_message_notification_level **p) {
  ntl_free((void**)p, NULL);
}

void discord_default_message_notification_level_list_from_json(char *str, size_t len, enum discord_default_message_notification_level ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(enum discord_default_message_notification_level);
  d.init_elem = NULL;
  d.elem_from_buf = ja_u64_from_json_v;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_default_message_notification_level_list_to_json(char *str, size_t len, enum discord_default_message_notification_level **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, ja_u64_to_json_v);
}



void discord_explicit_content_filter_level_list_free_v(void **p) {
  discord_explicit_content_filter_level_list_free((enum discord_explicit_content_filter_level**)p);
}

void discord_explicit_content_filter_level_list_from_json_v(char *str, size_t len, void *p) {
  discord_explicit_content_filter_level_list_from_json(str, len, (enum discord_explicit_content_filter_level ***)p);
}

size_t discord_explicit_content_filter_level_list_to_json_v(char *str, size_t len, void *p){
  return discord_explicit_content_filter_level_list_to_json(str, len, (enum discord_explicit_content_filter_level **)p);
}

enum discord_explicit_content_filter_level discord_explicit_content_filter_level_eval(char *s){
  if(strcasecmp("DISABLED", s) == 0) return DISCORD_DISABLED;
  if(strcasecmp("MEMBERS_WITHOUT_ROLES", s) == 0) return DISCORD_MEMBERS_WITHOUT_ROLES;
  if(strcasecmp("ALL_MEMBERS", s) == 0) return DISCORD_ALL_MEMBERS;
  ERR("'%s' doesn't match any known enumerator.", s);
  return -1;
}

char* discord_explicit_content_filter_level_print(enum discord_explicit_content_filter_level v){

  switch (v) {
  case DISCORD_DISABLED: return "DISABLED";
  case DISCORD_MEMBERS_WITHOUT_ROLES: return "MEMBERS_WITHOUT_ROLES";
  case DISCORD_ALL_MEMBERS: return "ALL_MEMBERS";
  }

  return NULL;
}

void discord_explicit_content_filter_level_list_free(enum discord_explicit_content_filter_level **p) {
  ntl_free((void**)p, NULL);
}

void discord_explicit_content_filter_level_list_from_json(char *str, size_t len, enum discord_explicit_content_filter_level ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(enum discord_explicit_content_filter_level);
  d.init_elem = NULL;
  d.elem_from_buf = ja_u64_from_json_v;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_explicit_content_filter_level_list_to_json(char *str, size_t len, enum discord_explicit_content_filter_level **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, ja_u64_to_json_v);
}



void discord_mfa_level_list_free_v(void **p) {
  discord_mfa_level_list_free((enum discord_mfa_level**)p);
}

void discord_mfa_level_list_from_json_v(char *str, size_t len, void *p) {
  discord_mfa_level_list_from_json(str, len, (enum discord_mfa_level ***)p);
}

size_t discord_mfa_level_list_to_json_v(char *str, size_t len, void *p){
  return discord_mfa_level_list_to_json(str, len, (enum discord_mfa_level **)p);
}

enum discord_mfa_level discord_mfa_level_eval(char *s){
  if(strcasecmp("DISCORD_MFA_NONE", s) == 0) return DISCORD_DISCORD_MFA_NONE;
  if(strcasecmp("ELEVATED", s) == 0) return DISCORD_ELEVATED;
  ERR("'%s' doesn't match any known enumerator.", s);
  return -1;
}

char* discord_mfa_level_print(enum discord_mfa_level v){

  switch (v) {
  case DISCORD_DISCORD_MFA_NONE: return "DISCORD_MFA_NONE";
  case DISCORD_ELEVATED: return "ELEVATED";
  }

  return NULL;
}

void discord_mfa_level_list_free(enum discord_mfa_level **p) {
  ntl_free((void**)p, NULL);
}

void discord_mfa_level_list_from_json(char *str, size_t len, enum discord_mfa_level ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(enum discord_mfa_level);
  d.init_elem = NULL;
  d.elem_from_buf = ja_u64_from_json_v;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_mfa_level_list_to_json(char *str, size_t len, enum discord_mfa_level **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, ja_u64_to_json_v);
}



void discord_verification_level_list_free_v(void **p) {
  discord_verification_level_list_free((enum discord_verification_level**)p);
}

void discord_verification_level_list_from_json_v(char *str, size_t len, void *p) {
  discord_verification_level_list_from_json(str, len, (enum discord_verification_level ***)p);
}

size_t discord_verification_level_list_to_json_v(char *str, size_t len, void *p){
  return discord_verification_level_list_to_json(str, len, (enum discord_verification_level **)p);
}

enum discord_verification_level discord_verification_level_eval(char *s){
  if(strcasecmp("DISCORD_VL_NONE", s) == 0) return DISCORD_DISCORD_VL_NONE;
  if(strcasecmp("LOW", s) == 0) return DISCORD_LOW;
  if(strcasecmp("MEDIUM", s) == 0) return DISCORD_MEDIUM;
  if(strcasecmp("HIGH", s) == 0) return DISCORD_HIGH;
  if(strcasecmp("VERY_HIGH", s) == 0) return DISCORD_VERY_HIGH;
  ERR("'%s' doesn't match any known enumerator.", s);
  return -1;
}

char* discord_verification_level_print(enum discord_verification_level v){

  switch (v) {
  case DISCORD_DISCORD_VL_NONE: return "DISCORD_VL_NONE";
  case DISCORD_LOW: return "LOW";
  case DISCORD_MEDIUM: return "MEDIUM";
  case DISCORD_HIGH: return "HIGH";
  case DISCORD_VERY_HIGH: return "VERY_HIGH";
  }

  return NULL;
}

void discord_verification_level_list_free(enum discord_verification_level **p) {
  ntl_free((void**)p, NULL);
}

void discord_verification_level_list_from_json(char *str, size_t len, enum discord_verification_level ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(enum discord_verification_level);
  d.init_elem = NULL;
  d.elem_from_buf = ja_u64_from_json_v;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_verification_level_list_to_json(char *str, size_t len, enum discord_verification_level **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, ja_u64_to_json_v);
}



void discord_premium_tier_list_free_v(void **p) {
  discord_premium_tier_list_free((enum discord_premium_tier**)p);
}

void discord_premium_tier_list_from_json_v(char *str, size_t len, void *p) {
  discord_premium_tier_list_from_json(str, len, (enum discord_premium_tier ***)p);
}

size_t discord_premium_tier_list_to_json_v(char *str, size_t len, void *p){
  return discord_premium_tier_list_to_json(str, len, (enum discord_premium_tier **)p);
}

enum discord_premium_tier discord_premium_tier_eval(char *s){
  if(strcasecmp("DISCORD_PREMIUM_NONE", s) == 0) return DISCORD_DISCORD_PREMIUM_NONE;
  if(strcasecmp("TIER_1", s) == 0) return DISCORD_TIER_1;
  if(strcasecmp("TIER_2", s) == 0) return DISCORD_TIER_2;
  if(strcasecmp("TIER_3", s) == 0) return DISCORD_TIER_3;
  ERR("'%s' doesn't match any known enumerator.", s);
  return -1;
}

char* discord_premium_tier_print(enum discord_premium_tier v){

  switch (v) {
  case DISCORD_DISCORD_PREMIUM_NONE: return "DISCORD_PREMIUM_NONE";
  case DISCORD_TIER_1: return "TIER_1";
  case DISCORD_TIER_2: return "TIER_2";
  case DISCORD_TIER_3: return "TIER_3";
  }

  return NULL;
}

void discord_premium_tier_list_free(enum discord_premium_tier **p) {
  ntl_free((void**)p, NULL);
}

void discord_premium_tier_list_from_json(char *str, size_t len, enum discord_premium_tier ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(enum discord_premium_tier);
  d.init_elem = NULL;
  d.elem_from_buf = ja_u64_from_json_v;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_premium_tier_list_to_json(char *str, size_t len, enum discord_premium_tier **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, ja_u64_to_json_v);
}



void discord_system_channel_flags_list_free_v(void **p) {
  discord_system_channel_flags_list_free((enum discord_system_channel_flags**)p);
}

void discord_system_channel_flags_list_from_json_v(char *str, size_t len, void *p) {
  discord_system_channel_flags_list_from_json(str, len, (enum discord_system_channel_flags ***)p);
}

size_t discord_system_channel_flags_list_to_json_v(char *str, size_t len, void *p){
  return discord_system_channel_flags_list_to_json(str, len, (enum discord_system_channel_flags **)p);
}

enum discord_system_channel_flags discord_system_channel_flags_eval(char *s){
  if(strcasecmp("SUPRESS_JOIN_NOTIFICATIONS", s) == 0) return DISCORD_SUPRESS_JOIN_NOTIFICATIONS;
  if(strcasecmp("SUPRESS_PREMIUM_SUBSCRIPTIONS", s) == 0) return DISCORD_SUPRESS_PREMIUM_SUBSCRIPTIONS;
  ERR("'%s' doesn't match any known enumerator.", s);
  return -1;
}

char* discord_system_channel_flags_print(enum discord_system_channel_flags v){

  switch (v) {
  case DISCORD_SUPRESS_JOIN_NOTIFICATIONS: return "SUPRESS_JOIN_NOTIFICATIONS";
  case DISCORD_SUPRESS_PREMIUM_SUBSCRIPTIONS: return "SUPRESS_PREMIUM_SUBSCRIPTIONS";
  }

  return NULL;
}

void discord_system_channel_flags_list_free(enum discord_system_channel_flags **p) {
  ntl_free((void**)p, NULL);
}

void discord_system_channel_flags_list_from_json(char *str, size_t len, enum discord_system_channel_flags ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(enum discord_system_channel_flags);
  d.init_elem = NULL;
  d.elem_from_buf = ja_u64_from_json_v;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_system_channel_flags_list_to_json(char *str, size_t len, enum discord_system_channel_flags **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, ja_u64_to_json_v);
}



void discord_guild_features_list_free_v(void **p) {
  discord_guild_features_list_free((enum discord_guild_features**)p);
}

void discord_guild_features_list_from_json_v(char *str, size_t len, void *p) {
  discord_guild_features_list_from_json(str, len, (enum discord_guild_features ***)p);
}

size_t discord_guild_features_list_to_json_v(char *str, size_t len, void *p){
  return discord_guild_features_list_to_json(str, len, (enum discord_guild_features **)p);
}

enum discord_guild_features discord_guild_features_eval(char *s){
  if(strcasecmp("INVITE_SPLASH", s) == 0) return DISCORD_GUILD_INVITE_SPLASH;
  if(strcasecmp("VIP_REGIONS", s) == 0) return DISCORD_GUILD_VIP_REGIONS;
  if(strcasecmp("VANITY_URL", s) == 0) return DISCORD_GUILD_VANITY_URL;
  if(strcasecmp("VERIFIED", s) == 0) return DISCORD_GUILD_VERIFIED;
  if(strcasecmp("PARTNERED", s) == 0) return DISCORD_GUILD_PARTNERED;
  if(strcasecmp("COMMUNITY", s) == 0) return DISCORD_GUILD_COMMUNITY;
  if(strcasecmp("COMMERCE", s) == 0) return DISCORD_GUILD_COMMERCE;
  if(strcasecmp("NEWS", s) == 0) return DISCORD_GUILD_NEWS;
  if(strcasecmp("DISCOVERABLE", s) == 0) return DISCORD_GUILD_DISCOVERABLE;
  if(strcasecmp("FEATURABLE", s) == 0) return DISCORD_GUILD_FEATURABLE;
  if(strcasecmp("ANIMATED_ICON", s) == 0) return DISCORD_GUILD_ANIMATED_ICON;
  if(strcasecmp("BANNER", s) == 0) return DISCORD_GUILD_BANNER;
  if(strcasecmp("WELCOME_SCREEN_ENABLED", s) == 0) return DISCORD_GUILD_WELCOME_SCREEN_ENABLED;
  if(strcasecmp("MEMBER_VERIFICATION_GATE_ENABLED", s) == 0) return DISCORD_GUILD_MEMBER_VERIFICATION_GATE_ENABLED;
  if(strcasecmp("PREVIEW_ENABLED", s) == 0) return DISCORD_GUILD_PREVIEW_ENABLED;
  ERR("'%s' doesn't match any known enumerator.", s);
  return -1;
}

char* discord_guild_features_print(enum discord_guild_features v){

  switch (v) {
  case DISCORD_GUILD_INVITE_SPLASH: return "INVITE_SPLASH";
  case DISCORD_GUILD_VIP_REGIONS: return "VIP_REGIONS";
  case DISCORD_GUILD_VANITY_URL: return "VANITY_URL";
  case DISCORD_GUILD_VERIFIED: return "VERIFIED";
  case DISCORD_GUILD_PARTNERED: return "PARTNERED";
  case DISCORD_GUILD_COMMUNITY: return "COMMUNITY";
  case DISCORD_GUILD_COMMERCE: return "COMMERCE";
  case DISCORD_GUILD_NEWS: return "NEWS";
  case DISCORD_GUILD_DISCOVERABLE: return "DISCOVERABLE";
  case DISCORD_GUILD_FEATURABLE: return "FEATURABLE";
  case DISCORD_GUILD_ANIMATED_ICON: return "ANIMATED_ICON";
  case DISCORD_GUILD_BANNER: return "BANNER";
  case DISCORD_GUILD_WELCOME_SCREEN_ENABLED: return "WELCOME_SCREEN_ENABLED";
  case DISCORD_GUILD_MEMBER_VERIFICATION_GATE_ENABLED: return "MEMBER_VERIFICATION_GATE_ENABLED";
  case DISCORD_GUILD_PREVIEW_ENABLED: return "PREVIEW_ENABLED";
  }

  return NULL;
}

void discord_guild_features_list_free(enum discord_guild_features **p) {
  ntl_free((void**)p, NULL);
}

void discord_guild_features_list_from_json(char *str, size_t len, enum discord_guild_features ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(enum discord_guild_features);
  d.init_elem = NULL;
  d.elem_from_buf = ja_u64_from_json_v;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_guild_features_list_to_json(char *str, size_t len, enum discord_guild_features **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, ja_u64_to_json_v);
}


void discord_unavailable_guild_from_json_p(char *json, size_t len, struct discord_unavailable_guild **pp)
{
  if (!*pp) *pp = malloc(sizeof **pp);
  discord_unavailable_guild_from_json(json, len, *pp);
}
void discord_unavailable_guild_from_json(char *json, size_t len, struct discord_unavailable_guild *p)
{
  discord_unavailable_guild_init(p);
  json_extract(json, len, 
  /* discord/guild.json:152:18
     '{"name":"id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}}' */
                "(id):F,"
  /* discord/guild.json:153:18
     '{"name":"unavailable", "type":{"base":"bool"}}' */
                "(unavailable):b,",
  /* discord/guild.json:152:18
     '{"name":"id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}}' */
                cee_strtou64, &p->id,
  /* discord/guild.json:153:18
     '{"name":"unavailable", "type":{"base":"bool"}}' */
                &p->unavailable);
}

size_t discord_unavailable_guild_to_json(char *json, size_t len, struct discord_unavailable_guild *p)
{
  size_t r;
  void *arg_switches[2]={NULL};
  /* discord/guild.json:152:18
     '{"name":"id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}}' */
  arg_switches[0] = &p->id;

  /* discord/guild.json:153:18
     '{"name":"unavailable", "type":{"base":"bool"}}' */
  arg_switches[1] = &p->unavailable;

  r=json_inject(json, len, 
  /* discord/guild.json:152:18
     '{"name":"id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}}' */
                "(id):|F|,"
  /* discord/guild.json:153:18
     '{"name":"unavailable", "type":{"base":"bool"}}' */
                "(unavailable):b,"
                "@arg_switches:b",
  /* discord/guild.json:152:18
     '{"name":"id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}}' */
                cee_u64tostr, &p->id,
  /* discord/guild.json:153:18
     '{"name":"unavailable", "type":{"base":"bool"}}' */
                &p->unavailable,
                arg_switches, sizeof(arg_switches), true);
  return r;
}


void discord_unavailable_guild_cleanup_v(void *p) {
  discord_unavailable_guild_cleanup((struct discord_unavailable_guild *)p);
}

void discord_unavailable_guild_init_v(void *p) {
  discord_unavailable_guild_init((struct discord_unavailable_guild *)p);
}

void discord_unavailable_guild_from_json_v(char *json, size_t len, void *p) {
 discord_unavailable_guild_from_json(json, len, (struct discord_unavailable_guild*)p);
}

size_t discord_unavailable_guild_to_json_v(char *json, size_t len, void *p) {
  return discord_unavailable_guild_to_json(json, len, (struct discord_unavailable_guild*)p);
}

void discord_unavailable_guild_list_free_v(void **p) {
  discord_unavailable_guild_list_free((struct discord_unavailable_guild**)p);
}

void discord_unavailable_guild_list_from_json_v(char *str, size_t len, void *p) {
  discord_unavailable_guild_list_from_json(str, len, (struct discord_unavailable_guild ***)p);
}

size_t discord_unavailable_guild_list_to_json_v(char *str, size_t len, void *p){
  return discord_unavailable_guild_list_to_json(str, len, (struct discord_unavailable_guild **)p);
}


void discord_unavailable_guild_cleanup(struct discord_unavailable_guild *d) {
  /* discord/guild.json:152:18
     '{"name":"id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}}' */
  (void)d->id;
  /* discord/guild.json:153:18
     '{"name":"unavailable", "type":{"base":"bool"}}' */
  (void)d->unavailable;
}

void discord_unavailable_guild_init(struct discord_unavailable_guild *p) {
  memset(p, 0, sizeof(struct discord_unavailable_guild));
  /* discord/guild.json:152:18
     '{"name":"id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}}' */

  /* discord/guild.json:153:18
     '{"name":"unavailable", "type":{"base":"bool"}}' */

}
void discord_unavailable_guild_list_free(struct discord_unavailable_guild **p) {
  ntl_free((void**)p, (void(*)(void*))discord_unavailable_guild_cleanup);
}

void discord_unavailable_guild_list_from_json(char *str, size_t len, struct discord_unavailable_guild ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct discord_unavailable_guild);
  d.init_elem = NULL;
  d.elem_from_buf = (void(*)(char*,size_t,void*))discord_unavailable_guild_from_json_p;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_unavailable_guild_list_to_json(char *str, size_t len, struct discord_unavailable_guild **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, (size_t(*)(char*,size_t,void*))discord_unavailable_guild_to_json);
}


void discord_guild_preview_from_json_p(char *json, size_t len, struct discord_guild_preview **pp)
{
  if (!*pp) *pp = malloc(sizeof **pp);
  discord_guild_preview_from_json(json, len, *pp);
}
void discord_guild_preview_from_json(char *json, size_t len, struct discord_guild_preview *p)
{
  discord_guild_preview_init(p);
  json_extract(json, len, 
  /* discord/guild.json:162:18
     '{"name":"id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}}' */
                "(id):F,"
  /* discord/guild.json:163:18
     '{"name":"name", "type":{"base":"char", "dec":"*"}}' */
                "(name):?s,"
  /* discord/guild.json:164:18
     '{"name":"icon", "type":{"base":"char", "dec":"*", "nullable":true}}' */
                "(icon):?s,"
  /* discord/guild.json:165:18
     '{"name":"splash", "type":{"base":"char", "dec":"*", "nullable":true}}' */
                "(splash):?s,"
  /* discord/guild.json:166:18
     '{"name":"discovery_splash", "type":{"base":"char", "dec":"*", "nullable":true}}' */
                "(discovery_splash):?s,"
  /* discord/guild.json:167:18
     '{"name":"emojis", "type":{"base":"struct discord_emoji", "dec":"ntl"}}' */
                "(emojis):F,"
  /* discord/guild.json:168:18
     '{"name":"features", "type":{"base":"ja_str", "dec":"ntl"}}' */
                "(features):F,"
  /* discord/guild.json:169:18
     '{"name":"approximate_member_count", "type":{"base":"int"}}' */
                "(approximate_member_count):d,"
  /* discord/guild.json:170:18
     '{"name":"approximate_presence_count", "type":{"base":"int"}}' */
                "(approximate_presence_count):d,"
  /* discord/guild.json:171:18
     '{"name":"description", "type":{"base":"char", "dec":"*"}}' */
                "(description):?s,",
  /* discord/guild.json:162:18
     '{"name":"id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}}' */
                cee_strtou64, &p->id,
  /* discord/guild.json:163:18
     '{"name":"name", "type":{"base":"char", "dec":"*"}}' */
                &p->name,
  /* discord/guild.json:164:18
     '{"name":"icon", "type":{"base":"char", "dec":"*", "nullable":true}}' */
                &p->icon,
  /* discord/guild.json:165:18
     '{"name":"splash", "type":{"base":"char", "dec":"*", "nullable":true}}' */
                &p->splash,
  /* discord/guild.json:166:18
     '{"name":"discovery_splash", "type":{"base":"char", "dec":"*", "nullable":true}}' */
                &p->discovery_splash,
  /* discord/guild.json:167:18
     '{"name":"emojis", "type":{"base":"struct discord_emoji", "dec":"ntl"}}' */
                discord_emoji_list_from_json, &p->emojis,
  /* discord/guild.json:168:18
     '{"name":"features", "type":{"base":"ja_str", "dec":"ntl"}}' */
                ja_str_list_from_json, &p->features,
  /* discord/guild.json:169:18
     '{"name":"approximate_member_count", "type":{"base":"int"}}' */
                &p->approximate_member_count,
  /* discord/guild.json:170:18
     '{"name":"approximate_presence_count", "type":{"base":"int"}}' */
                &p->approximate_presence_count,
  /* discord/guild.json:171:18
     '{"name":"description", "type":{"base":"char", "dec":"*"}}' */
                &p->description);
}

size_t discord_guild_preview_to_json(char *json, size_t len, struct discord_guild_preview *p)
{
  size_t r;
  void *arg_switches[10]={NULL};
  /* discord/guild.json:162:18
     '{"name":"id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}}' */
  arg_switches[0] = &p->id;

  /* discord/guild.json:163:18
     '{"name":"name", "type":{"base":"char", "dec":"*"}}' */
  arg_switches[1] = p->name;

  /* discord/guild.json:164:18
     '{"name":"icon", "type":{"base":"char", "dec":"*", "nullable":true}}' */
  arg_switches[2] = p->icon;

  /* discord/guild.json:165:18
     '{"name":"splash", "type":{"base":"char", "dec":"*", "nullable":true}}' */
  arg_switches[3] = p->splash;

  /* discord/guild.json:166:18
     '{"name":"discovery_splash", "type":{"base":"char", "dec":"*", "nullable":true}}' */
  arg_switches[4] = p->discovery_splash;

  /* discord/guild.json:167:18
     '{"name":"emojis", "type":{"base":"struct discord_emoji", "dec":"ntl"}}' */
  arg_switches[5] = p->emojis;

  /* discord/guild.json:168:18
     '{"name":"features", "type":{"base":"ja_str", "dec":"ntl"}}' */
  arg_switches[6] = p->features;

  /* discord/guild.json:169:18
     '{"name":"approximate_member_count", "type":{"base":"int"}}' */
  arg_switches[7] = &p->approximate_member_count;

  /* discord/guild.json:170:18
     '{"name":"approximate_presence_count", "type":{"base":"int"}}' */
  arg_switches[8] = &p->approximate_presence_count;

  /* discord/guild.json:171:18
     '{"name":"description", "type":{"base":"char", "dec":"*"}}' */
  arg_switches[9] = p->description;

  r=json_inject(json, len, 
  /* discord/guild.json:162:18
     '{"name":"id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}}' */
                "(id):|F|,"
  /* discord/guild.json:163:18
     '{"name":"name", "type":{"base":"char", "dec":"*"}}' */
                "(name):s,"
  /* discord/guild.json:164:18
     '{"name":"icon", "type":{"base":"char", "dec":"*", "nullable":true}}' */
                "(icon):s,"
  /* discord/guild.json:165:18
     '{"name":"splash", "type":{"base":"char", "dec":"*", "nullable":true}}' */
                "(splash):s,"
  /* discord/guild.json:166:18
     '{"name":"discovery_splash", "type":{"base":"char", "dec":"*", "nullable":true}}' */
                "(discovery_splash):s,"
  /* discord/guild.json:167:18
     '{"name":"emojis", "type":{"base":"struct discord_emoji", "dec":"ntl"}}' */
                "(emojis):F,"
  /* discord/guild.json:168:18
     '{"name":"features", "type":{"base":"ja_str", "dec":"ntl"}}' */
                "(features):F,"
  /* discord/guild.json:169:18
     '{"name":"approximate_member_count", "type":{"base":"int"}}' */
                "(approximate_member_count):d,"
  /* discord/guild.json:170:18
     '{"name":"approximate_presence_count", "type":{"base":"int"}}' */
                "(approximate_presence_count):d,"
  /* discord/guild.json:171:18
     '{"name":"description", "type":{"base":"char", "dec":"*"}}' */
                "(description):s,"
                "@arg_switches:b",
  /* discord/guild.json:162:18
     '{"name":"id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}}' */
                cee_u64tostr, &p->id,
  /* discord/guild.json:163:18
     '{"name":"name", "type":{"base":"char", "dec":"*"}}' */
                p->name,
  /* discord/guild.json:164:18
     '{"name":"icon", "type":{"base":"char", "dec":"*", "nullable":true}}' */
                p->icon,
  /* discord/guild.json:165:18
     '{"name":"splash", "type":{"base":"char", "dec":"*", "nullable":true}}' */
                p->splash,
  /* discord/guild.json:166:18
     '{"name":"discovery_splash", "type":{"base":"char", "dec":"*", "nullable":true}}' */
                p->discovery_splash,
  /* discord/guild.json:167:18
     '{"name":"emojis", "type":{"base":"struct discord_emoji", "dec":"ntl"}}' */
                discord_emoji_list_to_json, p->emojis,
  /* discord/guild.json:168:18
     '{"name":"features", "type":{"base":"ja_str", "dec":"ntl"}}' */
                ja_str_list_to_json, p->features,
  /* discord/guild.json:169:18
     '{"name":"approximate_member_count", "type":{"base":"int"}}' */
                &p->approximate_member_count,
  /* discord/guild.json:170:18
     '{"name":"approximate_presence_count", "type":{"base":"int"}}' */
                &p->approximate_presence_count,
  /* discord/guild.json:171:18
     '{"name":"description", "type":{"base":"char", "dec":"*"}}' */
                p->description,
                arg_switches, sizeof(arg_switches), true);
  return r;
}


void discord_guild_preview_cleanup_v(void *p) {
  discord_guild_preview_cleanup((struct discord_guild_preview *)p);
}

void discord_guild_preview_init_v(void *p) {
  discord_guild_preview_init((struct discord_guild_preview *)p);
}

void discord_guild_preview_from_json_v(char *json, size_t len, void *p) {
 discord_guild_preview_from_json(json, len, (struct discord_guild_preview*)p);
}

size_t discord_guild_preview_to_json_v(char *json, size_t len, void *p) {
  return discord_guild_preview_to_json(json, len, (struct discord_guild_preview*)p);
}

void discord_guild_preview_list_free_v(void **p) {
  discord_guild_preview_list_free((struct discord_guild_preview**)p);
}

void discord_guild_preview_list_from_json_v(char *str, size_t len, void *p) {
  discord_guild_preview_list_from_json(str, len, (struct discord_guild_preview ***)p);
}

size_t discord_guild_preview_list_to_json_v(char *str, size_t len, void *p){
  return discord_guild_preview_list_to_json(str, len, (struct discord_guild_preview **)p);
}


void discord_guild_preview_cleanup(struct discord_guild_preview *d) {
  /* discord/guild.json:162:18
     '{"name":"id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}}' */
  (void)d->id;
  /* discord/guild.json:163:18
     '{"name":"name", "type":{"base":"char", "dec":"*"}}' */
  if (d->name)
    free(d->name);
  /* discord/guild.json:164:18
     '{"name":"icon", "type":{"base":"char", "dec":"*", "nullable":true}}' */
  if (d->icon)
    free(d->icon);
  /* discord/guild.json:165:18
     '{"name":"splash", "type":{"base":"char", "dec":"*", "nullable":true}}' */
  if (d->splash)
    free(d->splash);
  /* discord/guild.json:166:18
     '{"name":"discovery_splash", "type":{"base":"char", "dec":"*", "nullable":true}}' */
  if (d->discovery_splash)
    free(d->discovery_splash);
  /* discord/guild.json:167:18
     '{"name":"emojis", "type":{"base":"struct discord_emoji", "dec":"ntl"}}' */
  if (d->emojis)
    discord_emoji_list_free(d->emojis);
  /* discord/guild.json:168:18
     '{"name":"features", "type":{"base":"ja_str", "dec":"ntl"}}' */
  if (d->features)
    ja_str_list_free(d->features);
  /* discord/guild.json:169:18
     '{"name":"approximate_member_count", "type":{"base":"int"}}' */
  (void)d->approximate_member_count;
  /* discord/guild.json:170:18
     '{"name":"approximate_presence_count", "type":{"base":"int"}}' */
  (void)d->approximate_presence_count;
  /* discord/guild.json:171:18
     '{"name":"description", "type":{"base":"char", "dec":"*"}}' */
  if (d->description)
    free(d->description);
}

void discord_guild_preview_init(struct discord_guild_preview *p) {
  memset(p, 0, sizeof(struct discord_guild_preview));
  /* discord/guild.json:162:18
     '{"name":"id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}}' */

  /* discord/guild.json:163:18
     '{"name":"name", "type":{"base":"char", "dec":"*"}}' */

  /* discord/guild.json:164:18
     '{"name":"icon", "type":{"base":"char", "dec":"*", "nullable":true}}' */

  /* discord/guild.json:165:18
     '{"name":"splash", "type":{"base":"char", "dec":"*", "nullable":true}}' */

  /* discord/guild.json:166:18
     '{"name":"discovery_splash", "type":{"base":"char", "dec":"*", "nullable":true}}' */

  /* discord/guild.json:167:18
     '{"name":"emojis", "type":{"base":"struct discord_emoji", "dec":"ntl"}}' */

  /* discord/guild.json:168:18
     '{"name":"features", "type":{"base":"ja_str", "dec":"ntl"}}' */

  /* discord/guild.json:169:18
     '{"name":"approximate_member_count", "type":{"base":"int"}}' */

  /* discord/guild.json:170:18
     '{"name":"approximate_presence_count", "type":{"base":"int"}}' */

  /* discord/guild.json:171:18
     '{"name":"description", "type":{"base":"char", "dec":"*"}}' */

}
void discord_guild_preview_list_free(struct discord_guild_preview **p) {
  ntl_free((void**)p, (void(*)(void*))discord_guild_preview_cleanup);
}

void discord_guild_preview_list_from_json(char *str, size_t len, struct discord_guild_preview ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct discord_guild_preview);
  d.init_elem = NULL;
  d.elem_from_buf = (void(*)(char*,size_t,void*))discord_guild_preview_from_json_p;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_guild_preview_list_to_json(char *str, size_t len, struct discord_guild_preview **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, (size_t(*)(char*,size_t,void*))discord_guild_preview_to_json);
}


void discord_guild_widget_from_json_p(char *json, size_t len, struct discord_guild_widget **pp)
{
  if (!*pp) *pp = malloc(sizeof **pp);
  discord_guild_widget_from_json(json, len, *pp);
}
void discord_guild_widget_from_json(char *json, size_t len, struct discord_guild_widget *p)
{
  discord_guild_widget_init(p);
  json_extract(json, len, 
  /* discord/guild.json:180:18
     '{"name":"enabled", "type":{"base":"bool"}}' */
                "(enabled):b,"
  /* discord/guild.json:181:18
     '{"name":"channel_id", "type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}}' */
                "(channel_id):F,",
  /* discord/guild.json:180:18
     '{"name":"enabled", "type":{"base":"bool"}}' */
                &p->enabled,
  /* discord/guild.json:181:18
     '{"name":"channel_id", "type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}}' */
                cee_strtou64, &p->channel_id);
}

size_t discord_guild_widget_to_json(char *json, size_t len, struct discord_guild_widget *p)
{
  size_t r;
  void *arg_switches[2]={NULL};
  /* discord/guild.json:180:18
     '{"name":"enabled", "type":{"base":"bool"}}' */
  arg_switches[0] = &p->enabled;

  /* discord/guild.json:181:18
     '{"name":"channel_id", "type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}}' */
  arg_switches[1] = &p->channel_id;

  r=json_inject(json, len, 
  /* discord/guild.json:180:18
     '{"name":"enabled", "type":{"base":"bool"}}' */
                "(enabled):b,"
  /* discord/guild.json:181:18
     '{"name":"channel_id", "type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}}' */
                "(channel_id):|F|,"
                "@arg_switches:b",
  /* discord/guild.json:180:18
     '{"name":"enabled", "type":{"base":"bool"}}' */
                &p->enabled,
  /* discord/guild.json:181:18
     '{"name":"channel_id", "type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}}' */
                cee_u64tostr, &p->channel_id,
                arg_switches, sizeof(arg_switches), true);
  return r;
}


void discord_guild_widget_cleanup_v(void *p) {
  discord_guild_widget_cleanup((struct discord_guild_widget *)p);
}

void discord_guild_widget_init_v(void *p) {
  discord_guild_widget_init((struct discord_guild_widget *)p);
}

void discord_guild_widget_from_json_v(char *json, size_t len, void *p) {
 discord_guild_widget_from_json(json, len, (struct discord_guild_widget*)p);
}

size_t discord_guild_widget_to_json_v(char *json, size_t len, void *p) {
  return discord_guild_widget_to_json(json, len, (struct discord_guild_widget*)p);
}

void discord_guild_widget_list_free_v(void **p) {
  discord_guild_widget_list_free((struct discord_guild_widget**)p);
}

void discord_guild_widget_list_from_json_v(char *str, size_t len, void *p) {
  discord_guild_widget_list_from_json(str, len, (struct discord_guild_widget ***)p);
}

size_t discord_guild_widget_list_to_json_v(char *str, size_t len, void *p){
  return discord_guild_widget_list_to_json(str, len, (struct discord_guild_widget **)p);
}


void discord_guild_widget_cleanup(struct discord_guild_widget *d) {
  /* discord/guild.json:180:18
     '{"name":"enabled", "type":{"base":"bool"}}' */
  (void)d->enabled;
  /* discord/guild.json:181:18
     '{"name":"channel_id", "type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}}' */
  (void)d->channel_id;
}

void discord_guild_widget_init(struct discord_guild_widget *p) {
  memset(p, 0, sizeof(struct discord_guild_widget));
  /* discord/guild.json:180:18
     '{"name":"enabled", "type":{"base":"bool"}}' */

  /* discord/guild.json:181:18
     '{"name":"channel_id", "type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}}' */

}
void discord_guild_widget_list_free(struct discord_guild_widget **p) {
  ntl_free((void**)p, (void(*)(void*))discord_guild_widget_cleanup);
}

void discord_guild_widget_list_from_json(char *str, size_t len, struct discord_guild_widget ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct discord_guild_widget);
  d.init_elem = NULL;
  d.elem_from_buf = (void(*)(char*,size_t,void*))discord_guild_widget_from_json_p;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_guild_widget_list_to_json(char *str, size_t len, struct discord_guild_widget **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, (size_t(*)(char*,size_t,void*))discord_guild_widget_to_json);
}


void discord_guild_member_from_json_p(char *json, size_t len, struct discord_guild_member **pp)
{
  if (!*pp) *pp = malloc(sizeof **pp);
  discord_guild_member_from_json(json, len, *pp);
}
void discord_guild_member_from_json(char *json, size_t len, struct discord_guild_member *p)
{
  discord_guild_member_init(p);
  json_extract(json, len, 
  /* discord/guild.json:191:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*" }, "option":true}' */
                "(user):F,"
  /* discord/guild.json:192:20
     '{ "name": "nick", "type":{ "base":"char", "dec":"*"}, "option":true}' */
                "(nick):?s,"
  /* discord/guild.json:193:20
     '{ "name": "roles", "type":{ "base":"ja_u64", "dec":"ntl"}, "comment":"array of role object ids"}' */
                "(roles):F,"
  /* discord/guild.json:194:20
     '{ "name": "joined_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601" }}' */
                "(joined_at):F,"
  /* discord/guild.json:195:20
     '{ "name": "premium_since", "type":{ "base":"char", "dec":"*", "converter":"iso8601" }}' */
                "(premium_since):F,"
  /* discord/guild.json:196:20
     '{ "name": "deaf", "type":{ "base":"bool" }}' */
                "(deaf):b,"
  /* discord/guild.json:197:20
     '{ "name": "mute", "type":{ "base":"bool" }}' */
                "(mute):b,"
  /* discord/guild.json:198:20
     '{ "name": "pending", "type":{ "base":"bool" }, "option":true}' */
                "(pending):b,"
  /* discord/guild.json:199:20
     '{ "name": "permissions", "type":{ "base":"char", "dec":"*"}, "option":true}' */
                "(permissions):?s,",
  /* discord/guild.json:191:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*" }, "option":true}' */
                discord_user_from_json_p, &p->user,
  /* discord/guild.json:192:20
     '{ "name": "nick", "type":{ "base":"char", "dec":"*"}, "option":true}' */
                &p->nick,
  /* discord/guild.json:193:20
     '{ "name": "roles", "type":{ "base":"ja_u64", "dec":"ntl"}, "comment":"array of role object ids"}' */
                ja_u64_list_from_json, &p->roles,
  /* discord/guild.json:194:20
     '{ "name": "joined_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601" }}' */
                cee_iso8601_to_unix_ms, &p->joined_at,
  /* discord/guild.json:195:20
     '{ "name": "premium_since", "type":{ "base":"char", "dec":"*", "converter":"iso8601" }}' */
                cee_iso8601_to_unix_ms, &p->premium_since,
  /* discord/guild.json:196:20
     '{ "name": "deaf", "type":{ "base":"bool" }}' */
                &p->deaf,
  /* discord/guild.json:197:20
     '{ "name": "mute", "type":{ "base":"bool" }}' */
                &p->mute,
  /* discord/guild.json:198:20
     '{ "name": "pending", "type":{ "base":"bool" }, "option":true}' */
                &p->pending,
  /* discord/guild.json:199:20
     '{ "name": "permissions", "type":{ "base":"char", "dec":"*"}, "option":true}' */
                &p->permissions);
}

size_t discord_guild_member_to_json(char *json, size_t len, struct discord_guild_member *p)
{
  size_t r;
  void *arg_switches[9]={NULL};
  /* discord/guild.json:191:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*" }, "option":true}' */
  arg_switches[0] = p->user;

  /* discord/guild.json:192:20
     '{ "name": "nick", "type":{ "base":"char", "dec":"*"}, "option":true}' */
  arg_switches[1] = p->nick;

  /* discord/guild.json:193:20
     '{ "name": "roles", "type":{ "base":"ja_u64", "dec":"ntl"}, "comment":"array of role object ids"}' */
  arg_switches[2] = p->roles;

  /* discord/guild.json:194:20
     '{ "name": "joined_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601" }}' */
  arg_switches[3] = &p->joined_at;

  /* discord/guild.json:195:20
     '{ "name": "premium_since", "type":{ "base":"char", "dec":"*", "converter":"iso8601" }}' */
  arg_switches[4] = &p->premium_since;

  /* discord/guild.json:196:20
     '{ "name": "deaf", "type":{ "base":"bool" }}' */
  arg_switches[5] = &p->deaf;

  /* discord/guild.json:197:20
     '{ "name": "mute", "type":{ "base":"bool" }}' */
  arg_switches[6] = &p->mute;

  /* discord/guild.json:198:20
     '{ "name": "pending", "type":{ "base":"bool" }, "option":true}' */
  arg_switches[7] = &p->pending;

  /* discord/guild.json:199:20
     '{ "name": "permissions", "type":{ "base":"char", "dec":"*"}, "option":true}' */
  arg_switches[8] = p->permissions;

  r=json_inject(json, len, 
  /* discord/guild.json:191:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*" }, "option":true}' */
                "(user):F,"
  /* discord/guild.json:192:20
     '{ "name": "nick", "type":{ "base":"char", "dec":"*"}, "option":true}' */
                "(nick):s,"
  /* discord/guild.json:193:20
     '{ "name": "roles", "type":{ "base":"ja_u64", "dec":"ntl"}, "comment":"array of role object ids"}' */
                "(roles):F,"
  /* discord/guild.json:194:20
     '{ "name": "joined_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601" }}' */
                "(joined_at):|F|,"
  /* discord/guild.json:195:20
     '{ "name": "premium_since", "type":{ "base":"char", "dec":"*", "converter":"iso8601" }}' */
                "(premium_since):|F|,"
  /* discord/guild.json:196:20
     '{ "name": "deaf", "type":{ "base":"bool" }}' */
                "(deaf):b,"
  /* discord/guild.json:197:20
     '{ "name": "mute", "type":{ "base":"bool" }}' */
                "(mute):b,"
  /* discord/guild.json:198:20
     '{ "name": "pending", "type":{ "base":"bool" }, "option":true}' */
                "(pending):b,"
  /* discord/guild.json:199:20
     '{ "name": "permissions", "type":{ "base":"char", "dec":"*"}, "option":true}' */
                "(permissions):s,"
                "@arg_switches:b",
  /* discord/guild.json:191:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*" }, "option":true}' */
                discord_user_to_json, p->user,
  /* discord/guild.json:192:20
     '{ "name": "nick", "type":{ "base":"char", "dec":"*"}, "option":true}' */
                p->nick,
  /* discord/guild.json:193:20
     '{ "name": "roles", "type":{ "base":"ja_u64", "dec":"ntl"}, "comment":"array of role object ids"}' */
                ja_u64_list_to_json, p->roles,
  /* discord/guild.json:194:20
     '{ "name": "joined_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601" }}' */
                cee_unix_ms_to_iso8601, &p->joined_at,
  /* discord/guild.json:195:20
     '{ "name": "premium_since", "type":{ "base":"char", "dec":"*", "converter":"iso8601" }}' */
                cee_unix_ms_to_iso8601, &p->premium_since,
  /* discord/guild.json:196:20
     '{ "name": "deaf", "type":{ "base":"bool" }}' */
                &p->deaf,
  /* discord/guild.json:197:20
     '{ "name": "mute", "type":{ "base":"bool" }}' */
                &p->mute,
  /* discord/guild.json:198:20
     '{ "name": "pending", "type":{ "base":"bool" }, "option":true}' */
                &p->pending,
  /* discord/guild.json:199:20
     '{ "name": "permissions", "type":{ "base":"char", "dec":"*"}, "option":true}' */
                p->permissions,
                arg_switches, sizeof(arg_switches), true);
  return r;
}


void discord_guild_member_cleanup_v(void *p) {
  discord_guild_member_cleanup((struct discord_guild_member *)p);
}

void discord_guild_member_init_v(void *p) {
  discord_guild_member_init((struct discord_guild_member *)p);
}

void discord_guild_member_from_json_v(char *json, size_t len, void *p) {
 discord_guild_member_from_json(json, len, (struct discord_guild_member*)p);
}

size_t discord_guild_member_to_json_v(char *json, size_t len, void *p) {
  return discord_guild_member_to_json(json, len, (struct discord_guild_member*)p);
}

void discord_guild_member_list_free_v(void **p) {
  discord_guild_member_list_free((struct discord_guild_member**)p);
}

void discord_guild_member_list_from_json_v(char *str, size_t len, void *p) {
  discord_guild_member_list_from_json(str, len, (struct discord_guild_member ***)p);
}

size_t discord_guild_member_list_to_json_v(char *str, size_t len, void *p){
  return discord_guild_member_list_to_json(str, len, (struct discord_guild_member **)p);
}


void discord_guild_member_cleanup(struct discord_guild_member *d) {
  /* discord/guild.json:191:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*" }, "option":true}' */
  if (d->user) {
    discord_user_cleanup(d->user);
    free(d->user);
  }
  /* discord/guild.json:192:20
     '{ "name": "nick", "type":{ "base":"char", "dec":"*"}, "option":true}' */
  if (d->nick)
    free(d->nick);
  /* discord/guild.json:193:20
     '{ "name": "roles", "type":{ "base":"ja_u64", "dec":"ntl"}, "comment":"array of role object ids"}' */
  if (d->roles)
    ja_u64_list_free(d->roles);
  /* discord/guild.json:194:20
     '{ "name": "joined_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601" }}' */
  (void)d->joined_at;
  /* discord/guild.json:195:20
     '{ "name": "premium_since", "type":{ "base":"char", "dec":"*", "converter":"iso8601" }}' */
  (void)d->premium_since;
  /* discord/guild.json:196:20
     '{ "name": "deaf", "type":{ "base":"bool" }}' */
  (void)d->deaf;
  /* discord/guild.json:197:20
     '{ "name": "mute", "type":{ "base":"bool" }}' */
  (void)d->mute;
  /* discord/guild.json:198:20
     '{ "name": "pending", "type":{ "base":"bool" }, "option":true}' */
  (void)d->pending;
  /* discord/guild.json:199:20
     '{ "name": "permissions", "type":{ "base":"char", "dec":"*"}, "option":true}' */
  if (d->permissions)
    free(d->permissions);
}

void discord_guild_member_init(struct discord_guild_member *p) {
  memset(p, 0, sizeof(struct discord_guild_member));
  /* discord/guild.json:191:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*" }, "option":true}' */

  /* discord/guild.json:192:20
     '{ "name": "nick", "type":{ "base":"char", "dec":"*"}, "option":true}' */

  /* discord/guild.json:193:20
     '{ "name": "roles", "type":{ "base":"ja_u64", "dec":"ntl"}, "comment":"array of role object ids"}' */

  /* discord/guild.json:194:20
     '{ "name": "joined_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601" }}' */

  /* discord/guild.json:195:20
     '{ "name": "premium_since", "type":{ "base":"char", "dec":"*", "converter":"iso8601" }}' */

  /* discord/guild.json:196:20
     '{ "name": "deaf", "type":{ "base":"bool" }}' */

  /* discord/guild.json:197:20
     '{ "name": "mute", "type":{ "base":"bool" }}' */

  /* discord/guild.json:198:20
     '{ "name": "pending", "type":{ "base":"bool" }, "option":true}' */

  /* discord/guild.json:199:20
     '{ "name": "permissions", "type":{ "base":"char", "dec":"*"}, "option":true}' */

}
void discord_guild_member_list_free(struct discord_guild_member **p) {
  ntl_free((void**)p, (void(*)(void*))discord_guild_member_cleanup);
}

void discord_guild_member_list_from_json(char *str, size_t len, struct discord_guild_member ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct discord_guild_member);
  d.init_elem = NULL;
  d.elem_from_buf = (void(*)(char*,size_t,void*))discord_guild_member_from_json_p;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_guild_member_list_to_json(char *str, size_t len, struct discord_guild_member **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, (size_t(*)(char*,size_t,void*))discord_guild_member_to_json);
}


void discord_integration_from_json_p(char *json, size_t len, struct discord_integration **pp)
{
  if (!*pp) *pp = malloc(sizeof **pp);
  discord_integration_from_json(json, len, *pp);
}
void discord_integration_from_json(char *json, size_t len, struct discord_integration *p)
{
  discord_integration_init(p);
  json_extract(json, len, 
  /* discord/guild.json:208:20
     '{ "name": "id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                "(id):F,"
  /* discord/guild.json:209:20
     '{ "name": "name", "type":{ "base":"char", "dec":"*"}}' */
                "(name):?s,"
  /* discord/guild.json:210:20
     '{ "name": "type", "type":{ "base":"char", "dec":"*"}}' */
                "(type):?s,"
  /* discord/guild.json:211:20
     '{ "name": "enabled", "type":{ "base":"bool"}}' */
                "(enabled):b,"
  /* discord/guild.json:212:20
     '{ "name": "syncing", "type":{ "base":"bool"}}' */
                "(syncing):b,"
  /* discord/guild.json:213:20
     '{ "name": "role_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake"}}' */
                "(role_id):F,"
  /* discord/guild.json:214:20
     '{ "name": "enable_emotions", "type":{ "base":"bool"}}' */
                "(enable_emotions):b,"
  /* discord/guild.json:215:20
     '{ "name": "expire_behavior", "type":{ "base":"int", "int_alias":"enum discord_integration_expire_behaviors"}}' */
                "(expire_behavior):d,"
  /* discord/guild.json:216:20
     '{ "name": "expire_grace_period", "type":{ "base":"int"}}' */
                "(expire_grace_period):d,"
  /* discord/guild.json:217:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*"}, "opt":true}' */
                "(user):F,"
  /* discord/guild.json:218:20
     '{ "name": "account", "type":{ "base":"struct discord_integration_account", "dec":"*"}}' */
                "(account):F,"
  /* discord/guild.json:219:20
     '{ "name": "synced_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601"}}' */
                "(synced_at):F,"
  /* discord/guild.json:220:20
     '{ "name": "subscriber_count", "type":{ "base":"int"}}' */
                "(subscriber_count):d,"
  /* discord/guild.json:221:20
     '{ "name": "revoked", "type":{ "base":"bool"}}' */
                "(revoked):b,"
  /* discord/guild.json:222:20
     '{ "name": "application", "type":{ "base":"struct discord_integration_application", "dec":"*" }}' */
                "(application):F,",
  /* discord/guild.json:208:20
     '{ "name": "id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                cee_strtou64, &p->id,
  /* discord/guild.json:209:20
     '{ "name": "name", "type":{ "base":"char", "dec":"*"}}' */
                &p->name,
  /* discord/guild.json:210:20
     '{ "name": "type", "type":{ "base":"char", "dec":"*"}}' */
                &p->type,
  /* discord/guild.json:211:20
     '{ "name": "enabled", "type":{ "base":"bool"}}' */
                &p->enabled,
  /* discord/guild.json:212:20
     '{ "name": "syncing", "type":{ "base":"bool"}}' */
                &p->syncing,
  /* discord/guild.json:213:20
     '{ "name": "role_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake"}}' */
                cee_strtou64, &p->role_id,
  /* discord/guild.json:214:20
     '{ "name": "enable_emotions", "type":{ "base":"bool"}}' */
                &p->enable_emotions,
  /* discord/guild.json:215:20
     '{ "name": "expire_behavior", "type":{ "base":"int", "int_alias":"enum discord_integration_expire_behaviors"}}' */
                &p->expire_behavior,
  /* discord/guild.json:216:20
     '{ "name": "expire_grace_period", "type":{ "base":"int"}}' */
                &p->expire_grace_period,
  /* discord/guild.json:217:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*"}, "opt":true}' */
                discord_user_from_json_p, &p->user,
  /* discord/guild.json:218:20
     '{ "name": "account", "type":{ "base":"struct discord_integration_account", "dec":"*"}}' */
                discord_integration_account_from_json_p, &p->account,
  /* discord/guild.json:219:20
     '{ "name": "synced_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601"}}' */
                cee_iso8601_to_unix_ms, &p->synced_at,
  /* discord/guild.json:220:20
     '{ "name": "subscriber_count", "type":{ "base":"int"}}' */
                &p->subscriber_count,
  /* discord/guild.json:221:20
     '{ "name": "revoked", "type":{ "base":"bool"}}' */
                &p->revoked,
  /* discord/guild.json:222:20
     '{ "name": "application", "type":{ "base":"struct discord_integration_application", "dec":"*" }}' */
                discord_integration_application_from_json_p, &p->application);
}

size_t discord_integration_to_json(char *json, size_t len, struct discord_integration *p)
{
  size_t r;
  void *arg_switches[15]={NULL};
  /* discord/guild.json:208:20
     '{ "name": "id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  arg_switches[0] = &p->id;

  /* discord/guild.json:209:20
     '{ "name": "name", "type":{ "base":"char", "dec":"*"}}' */
  arg_switches[1] = p->name;

  /* discord/guild.json:210:20
     '{ "name": "type", "type":{ "base":"char", "dec":"*"}}' */
  arg_switches[2] = p->type;

  /* discord/guild.json:211:20
     '{ "name": "enabled", "type":{ "base":"bool"}}' */
  arg_switches[3] = &p->enabled;

  /* discord/guild.json:212:20
     '{ "name": "syncing", "type":{ "base":"bool"}}' */
  arg_switches[4] = &p->syncing;

  /* discord/guild.json:213:20
     '{ "name": "role_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake"}}' */
  arg_switches[5] = &p->role_id;

  /* discord/guild.json:214:20
     '{ "name": "enable_emotions", "type":{ "base":"bool"}}' */
  arg_switches[6] = &p->enable_emotions;

  /* discord/guild.json:215:20
     '{ "name": "expire_behavior", "type":{ "base":"int", "int_alias":"enum discord_integration_expire_behaviors"}}' */
  arg_switches[7] = &p->expire_behavior;

  /* discord/guild.json:216:20
     '{ "name": "expire_grace_period", "type":{ "base":"int"}}' */
  arg_switches[8] = &p->expire_grace_period;

  /* discord/guild.json:217:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*"}, "opt":true}' */
  arg_switches[9] = p->user;

  /* discord/guild.json:218:20
     '{ "name": "account", "type":{ "base":"struct discord_integration_account", "dec":"*"}}' */
  arg_switches[10] = p->account;

  /* discord/guild.json:219:20
     '{ "name": "synced_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601"}}' */
  arg_switches[11] = &p->synced_at;

  /* discord/guild.json:220:20
     '{ "name": "subscriber_count", "type":{ "base":"int"}}' */
  arg_switches[12] = &p->subscriber_count;

  /* discord/guild.json:221:20
     '{ "name": "revoked", "type":{ "base":"bool"}}' */
  arg_switches[13] = &p->revoked;

  /* discord/guild.json:222:20
     '{ "name": "application", "type":{ "base":"struct discord_integration_application", "dec":"*" }}' */
  arg_switches[14] = p->application;

  r=json_inject(json, len, 
  /* discord/guild.json:208:20
     '{ "name": "id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                "(id):|F|,"
  /* discord/guild.json:209:20
     '{ "name": "name", "type":{ "base":"char", "dec":"*"}}' */
                "(name):s,"
  /* discord/guild.json:210:20
     '{ "name": "type", "type":{ "base":"char", "dec":"*"}}' */
                "(type):s,"
  /* discord/guild.json:211:20
     '{ "name": "enabled", "type":{ "base":"bool"}}' */
                "(enabled):b,"
  /* discord/guild.json:212:20
     '{ "name": "syncing", "type":{ "base":"bool"}}' */
                "(syncing):b,"
  /* discord/guild.json:213:20
     '{ "name": "role_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake"}}' */
                "(role_id):|F|,"
  /* discord/guild.json:214:20
     '{ "name": "enable_emotions", "type":{ "base":"bool"}}' */
                "(enable_emotions):b,"
  /* discord/guild.json:215:20
     '{ "name": "expire_behavior", "type":{ "base":"int", "int_alias":"enum discord_integration_expire_behaviors"}}' */
                "(expire_behavior):d,"
  /* discord/guild.json:216:20
     '{ "name": "expire_grace_period", "type":{ "base":"int"}}' */
                "(expire_grace_period):d,"
  /* discord/guild.json:217:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*"}, "opt":true}' */
                "(user):F,"
  /* discord/guild.json:218:20
     '{ "name": "account", "type":{ "base":"struct discord_integration_account", "dec":"*"}}' */
                "(account):F,"
  /* discord/guild.json:219:20
     '{ "name": "synced_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601"}}' */
                "(synced_at):|F|,"
  /* discord/guild.json:220:20
     '{ "name": "subscriber_count", "type":{ "base":"int"}}' */
                "(subscriber_count):d,"
  /* discord/guild.json:221:20
     '{ "name": "revoked", "type":{ "base":"bool"}}' */
                "(revoked):b,"
  /* discord/guild.json:222:20
     '{ "name": "application", "type":{ "base":"struct discord_integration_application", "dec":"*" }}' */
                "(application):F,"
                "@arg_switches:b",
  /* discord/guild.json:208:20
     '{ "name": "id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                cee_u64tostr, &p->id,
  /* discord/guild.json:209:20
     '{ "name": "name", "type":{ "base":"char", "dec":"*"}}' */
                p->name,
  /* discord/guild.json:210:20
     '{ "name": "type", "type":{ "base":"char", "dec":"*"}}' */
                p->type,
  /* discord/guild.json:211:20
     '{ "name": "enabled", "type":{ "base":"bool"}}' */
                &p->enabled,
  /* discord/guild.json:212:20
     '{ "name": "syncing", "type":{ "base":"bool"}}' */
                &p->syncing,
  /* discord/guild.json:213:20
     '{ "name": "role_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake"}}' */
                cee_u64tostr, &p->role_id,
  /* discord/guild.json:214:20
     '{ "name": "enable_emotions", "type":{ "base":"bool"}}' */
                &p->enable_emotions,
  /* discord/guild.json:215:20
     '{ "name": "expire_behavior", "type":{ "base":"int", "int_alias":"enum discord_integration_expire_behaviors"}}' */
                &p->expire_behavior,
  /* discord/guild.json:216:20
     '{ "name": "expire_grace_period", "type":{ "base":"int"}}' */
                &p->expire_grace_period,
  /* discord/guild.json:217:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*"}, "opt":true}' */
                discord_user_to_json, p->user,
  /* discord/guild.json:218:20
     '{ "name": "account", "type":{ "base":"struct discord_integration_account", "dec":"*"}}' */
                discord_integration_account_to_json, p->account,
  /* discord/guild.json:219:20
     '{ "name": "synced_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601"}}' */
                cee_unix_ms_to_iso8601, &p->synced_at,
  /* discord/guild.json:220:20
     '{ "name": "subscriber_count", "type":{ "base":"int"}}' */
                &p->subscriber_count,
  /* discord/guild.json:221:20
     '{ "name": "revoked", "type":{ "base":"bool"}}' */
                &p->revoked,
  /* discord/guild.json:222:20
     '{ "name": "application", "type":{ "base":"struct discord_integration_application", "dec":"*" }}' */
                discord_integration_application_to_json, p->application,
                arg_switches, sizeof(arg_switches), true);
  return r;
}


void discord_integration_cleanup_v(void *p) {
  discord_integration_cleanup((struct discord_integration *)p);
}

void discord_integration_init_v(void *p) {
  discord_integration_init((struct discord_integration *)p);
}

void discord_integration_from_json_v(char *json, size_t len, void *p) {
 discord_integration_from_json(json, len, (struct discord_integration*)p);
}

size_t discord_integration_to_json_v(char *json, size_t len, void *p) {
  return discord_integration_to_json(json, len, (struct discord_integration*)p);
}

void discord_integration_list_free_v(void **p) {
  discord_integration_list_free((struct discord_integration**)p);
}

void discord_integration_list_from_json_v(char *str, size_t len, void *p) {
  discord_integration_list_from_json(str, len, (struct discord_integration ***)p);
}

size_t discord_integration_list_to_json_v(char *str, size_t len, void *p){
  return discord_integration_list_to_json(str, len, (struct discord_integration **)p);
}


void discord_integration_cleanup(struct discord_integration *d) {
  /* discord/guild.json:208:20
     '{ "name": "id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  (void)d->id;
  /* discord/guild.json:209:20
     '{ "name": "name", "type":{ "base":"char", "dec":"*"}}' */
  if (d->name)
    free(d->name);
  /* discord/guild.json:210:20
     '{ "name": "type", "type":{ "base":"char", "dec":"*"}}' */
  if (d->type)
    free(d->type);
  /* discord/guild.json:211:20
     '{ "name": "enabled", "type":{ "base":"bool"}}' */
  (void)d->enabled;
  /* discord/guild.json:212:20
     '{ "name": "syncing", "type":{ "base":"bool"}}' */
  (void)d->syncing;
  /* discord/guild.json:213:20
     '{ "name": "role_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake"}}' */
  (void)d->role_id;
  /* discord/guild.json:214:20
     '{ "name": "enable_emotions", "type":{ "base":"bool"}}' */
  (void)d->enable_emotions;
  /* discord/guild.json:215:20
     '{ "name": "expire_behavior", "type":{ "base":"int", "int_alias":"enum discord_integration_expire_behaviors"}}' */
  (void)d->expire_behavior;
  /* discord/guild.json:216:20
     '{ "name": "expire_grace_period", "type":{ "base":"int"}}' */
  (void)d->expire_grace_period;
  /* discord/guild.json:217:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*"}, "opt":true}' */
  if (d->user) {
    discord_user_cleanup(d->user);
    free(d->user);
  }
  /* discord/guild.json:218:20
     '{ "name": "account", "type":{ "base":"struct discord_integration_account", "dec":"*"}}' */
  if (d->account) {
    discord_integration_account_cleanup(d->account);
    free(d->account);
  }
  /* discord/guild.json:219:20
     '{ "name": "synced_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601"}}' */
  (void)d->synced_at;
  /* discord/guild.json:220:20
     '{ "name": "subscriber_count", "type":{ "base":"int"}}' */
  (void)d->subscriber_count;
  /* discord/guild.json:221:20
     '{ "name": "revoked", "type":{ "base":"bool"}}' */
  (void)d->revoked;
  /* discord/guild.json:222:20
     '{ "name": "application", "type":{ "base":"struct discord_integration_application", "dec":"*" }}' */
  if (d->application) {
    discord_integration_application_cleanup(d->application);
    free(d->application);
  }
}

void discord_integration_init(struct discord_integration *p) {
  memset(p, 0, sizeof(struct discord_integration));
  /* discord/guild.json:208:20
     '{ "name": "id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */

  /* discord/guild.json:209:20
     '{ "name": "name", "type":{ "base":"char", "dec":"*"}}' */

  /* discord/guild.json:210:20
     '{ "name": "type", "type":{ "base":"char", "dec":"*"}}' */

  /* discord/guild.json:211:20
     '{ "name": "enabled", "type":{ "base":"bool"}}' */

  /* discord/guild.json:212:20
     '{ "name": "syncing", "type":{ "base":"bool"}}' */

  /* discord/guild.json:213:20
     '{ "name": "role_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake"}}' */

  /* discord/guild.json:214:20
     '{ "name": "enable_emotions", "type":{ "base":"bool"}}' */

  /* discord/guild.json:215:20
     '{ "name": "expire_behavior", "type":{ "base":"int", "int_alias":"enum discord_integration_expire_behaviors"}}' */

  /* discord/guild.json:216:20
     '{ "name": "expire_grace_period", "type":{ "base":"int"}}' */

  /* discord/guild.json:217:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*"}, "opt":true}' */

  /* discord/guild.json:218:20
     '{ "name": "account", "type":{ "base":"struct discord_integration_account", "dec":"*"}}' */

  /* discord/guild.json:219:20
     '{ "name": "synced_at", "type":{ "base":"char", "dec":"*", "converter":"iso8601"}}' */

  /* discord/guild.json:220:20
     '{ "name": "subscriber_count", "type":{ "base":"int"}}' */

  /* discord/guild.json:221:20
     '{ "name": "revoked", "type":{ "base":"bool"}}' */

  /* discord/guild.json:222:20
     '{ "name": "application", "type":{ "base":"struct discord_integration_application", "dec":"*" }}' */

}
void discord_integration_list_free(struct discord_integration **p) {
  ntl_free((void**)p, (void(*)(void*))discord_integration_cleanup);
}

void discord_integration_list_from_json(char *str, size_t len, struct discord_integration ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct discord_integration);
  d.init_elem = NULL;
  d.elem_from_buf = (void(*)(char*,size_t,void*))discord_integration_from_json_p;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_integration_list_to_json(char *str, size_t len, struct discord_integration **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, (size_t(*)(char*,size_t,void*))discord_integration_to_json);
}



void discord_integration_expire_behaviors_list_free_v(void **p) {
  discord_integration_expire_behaviors_list_free((enum discord_integration_expire_behaviors**)p);
}

void discord_integration_expire_behaviors_list_from_json_v(char *str, size_t len, void *p) {
  discord_integration_expire_behaviors_list_from_json(str, len, (enum discord_integration_expire_behaviors ***)p);
}

size_t discord_integration_expire_behaviors_list_to_json_v(char *str, size_t len, void *p){
  return discord_integration_expire_behaviors_list_to_json(str, len, (enum discord_integration_expire_behaviors **)p);
}

enum discord_integration_expire_behaviors discord_integration_expire_behaviors_eval(char *s){
  if(strcasecmp("REMOVE_ROLE", s) == 0) return DISCORD_INTEGRATION_REMOVE_ROLE;
  if(strcasecmp("KICK", s) == 0) return DISCORD_INTEGRATION_KICK;
  ERR("'%s' doesn't match any known enumerator.", s);
  return -1;
}

char* discord_integration_expire_behaviors_print(enum discord_integration_expire_behaviors v){

  switch (v) {
  case DISCORD_INTEGRATION_REMOVE_ROLE: return "REMOVE_ROLE";
  case DISCORD_INTEGRATION_KICK: return "KICK";
  }

  return NULL;
}

void discord_integration_expire_behaviors_list_free(enum discord_integration_expire_behaviors **p) {
  ntl_free((void**)p, NULL);
}

void discord_integration_expire_behaviors_list_from_json(char *str, size_t len, enum discord_integration_expire_behaviors ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(enum discord_integration_expire_behaviors);
  d.init_elem = NULL;
  d.elem_from_buf = ja_u64_from_json_v;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_integration_expire_behaviors_list_to_json(char *str, size_t len, enum discord_integration_expire_behaviors **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, ja_u64_to_json_v);
}


void discord_integration_account_from_json_p(char *json, size_t len, struct discord_integration_account **pp)
{
  if (!*pp) *pp = malloc(sizeof **pp);
  discord_integration_account_from_json(json, len, *pp);
}
void discord_integration_account_from_json(char *json, size_t len, struct discord_integration_account *p)
{
  discord_integration_account_init(p);
  json_extract(json, len, 
  /* discord/guild.json:241:19
     '{ "name":"id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                "(id):F,"
  /* discord/guild.json:242:19
     '{ "name":"name", "type":{ "base":"char", "dec":"*" }}' */
                "(name):?s,",
  /* discord/guild.json:241:19
     '{ "name":"id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                cee_strtou64, &p->id,
  /* discord/guild.json:242:19
     '{ "name":"name", "type":{ "base":"char", "dec":"*" }}' */
                &p->name);
}

size_t discord_integration_account_to_json(char *json, size_t len, struct discord_integration_account *p)
{
  size_t r;
  void *arg_switches[2]={NULL};
  /* discord/guild.json:241:19
     '{ "name":"id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  arg_switches[0] = &p->id;

  /* discord/guild.json:242:19
     '{ "name":"name", "type":{ "base":"char", "dec":"*" }}' */
  arg_switches[1] = p->name;

  r=json_inject(json, len, 
  /* discord/guild.json:241:19
     '{ "name":"id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                "(id):|F|,"
  /* discord/guild.json:242:19
     '{ "name":"name", "type":{ "base":"char", "dec":"*" }}' */
                "(name):s,"
                "@arg_switches:b",
  /* discord/guild.json:241:19
     '{ "name":"id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                cee_u64tostr, &p->id,
  /* discord/guild.json:242:19
     '{ "name":"name", "type":{ "base":"char", "dec":"*" }}' */
                p->name,
                arg_switches, sizeof(arg_switches), true);
  return r;
}


void discord_integration_account_cleanup_v(void *p) {
  discord_integration_account_cleanup((struct discord_integration_account *)p);
}

void discord_integration_account_init_v(void *p) {
  discord_integration_account_init((struct discord_integration_account *)p);
}

void discord_integration_account_from_json_v(char *json, size_t len, void *p) {
 discord_integration_account_from_json(json, len, (struct discord_integration_account*)p);
}

size_t discord_integration_account_to_json_v(char *json, size_t len, void *p) {
  return discord_integration_account_to_json(json, len, (struct discord_integration_account*)p);
}

void discord_integration_account_list_free_v(void **p) {
  discord_integration_account_list_free((struct discord_integration_account**)p);
}

void discord_integration_account_list_from_json_v(char *str, size_t len, void *p) {
  discord_integration_account_list_from_json(str, len, (struct discord_integration_account ***)p);
}

size_t discord_integration_account_list_to_json_v(char *str, size_t len, void *p){
  return discord_integration_account_list_to_json(str, len, (struct discord_integration_account **)p);
}


void discord_integration_account_cleanup(struct discord_integration_account *d) {
  /* discord/guild.json:241:19
     '{ "name":"id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  (void)d->id;
  /* discord/guild.json:242:19
     '{ "name":"name", "type":{ "base":"char", "dec":"*" }}' */
  if (d->name)
    free(d->name);
}

void discord_integration_account_init(struct discord_integration_account *p) {
  memset(p, 0, sizeof(struct discord_integration_account));
  /* discord/guild.json:241:19
     '{ "name":"id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */

  /* discord/guild.json:242:19
     '{ "name":"name", "type":{ "base":"char", "dec":"*" }}' */

}
void discord_integration_account_list_free(struct discord_integration_account **p) {
  ntl_free((void**)p, (void(*)(void*))discord_integration_account_cleanup);
}

void discord_integration_account_list_from_json(char *str, size_t len, struct discord_integration_account ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct discord_integration_account);
  d.init_elem = NULL;
  d.elem_from_buf = (void(*)(char*,size_t,void*))discord_integration_account_from_json_p;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_integration_account_list_to_json(char *str, size_t len, struct discord_integration_account **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, (size_t(*)(char*,size_t,void*))discord_integration_account_to_json);
}


void discord_integration_application_from_json_p(char *json, size_t len, struct discord_integration_application **pp)
{
  if (!*pp) *pp = malloc(sizeof **pp);
  discord_integration_application_from_json(json, len, *pp);
}
void discord_integration_application_from_json(char *json, size_t len, struct discord_integration_application *p)
{
  discord_integration_application_init(p);
  json_extract(json, len, 
  /* discord/guild.json:251:19
     '{ "name":"id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                "(id):F,"
  /* discord/guild.json:252:19
     '{ "name":"name", "type":{ "base":"char", "dec":"*" }}' */
                "(name):?s,"
  /* discord/guild.json:253:19
     '{ "name":"icon", "type":{ "base":"char", "dec":"*" }}' */
                "(icon):?s,"
  /* discord/guild.json:254:19
     '{ "name":"description", "type":{ "base":"char", "dec":"*" }}' */
                "(description):?s,"
  /* discord/guild.json:255:19
     '{ "name":"summary", "type":{ "base":"char", "dec":"*" }}' */
                "(summary):?s,"
  /* discord/guild.json:256:19
     '{ "name":"bot", "type":{ "base":"struct discord_user", "dec":"*" }, "option":true}' */
                "(bot):F,",
  /* discord/guild.json:251:19
     '{ "name":"id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                cee_strtou64, &p->id,
  /* discord/guild.json:252:19
     '{ "name":"name", "type":{ "base":"char", "dec":"*" }}' */
                &p->name,
  /* discord/guild.json:253:19
     '{ "name":"icon", "type":{ "base":"char", "dec":"*" }}' */
                &p->icon,
  /* discord/guild.json:254:19
     '{ "name":"description", "type":{ "base":"char", "dec":"*" }}' */
                &p->description,
  /* discord/guild.json:255:19
     '{ "name":"summary", "type":{ "base":"char", "dec":"*" }}' */
                &p->summary,
  /* discord/guild.json:256:19
     '{ "name":"bot", "type":{ "base":"struct discord_user", "dec":"*" }, "option":true}' */
                discord_user_from_json_p, &p->bot);
}

size_t discord_integration_application_to_json(char *json, size_t len, struct discord_integration_application *p)
{
  size_t r;
  void *arg_switches[6]={NULL};
  /* discord/guild.json:251:19
     '{ "name":"id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  arg_switches[0] = &p->id;

  /* discord/guild.json:252:19
     '{ "name":"name", "type":{ "base":"char", "dec":"*" }}' */
  arg_switches[1] = p->name;

  /* discord/guild.json:253:19
     '{ "name":"icon", "type":{ "base":"char", "dec":"*" }}' */
  arg_switches[2] = p->icon;

  /* discord/guild.json:254:19
     '{ "name":"description", "type":{ "base":"char", "dec":"*" }}' */
  arg_switches[3] = p->description;

  /* discord/guild.json:255:19
     '{ "name":"summary", "type":{ "base":"char", "dec":"*" }}' */
  arg_switches[4] = p->summary;

  /* discord/guild.json:256:19
     '{ "name":"bot", "type":{ "base":"struct discord_user", "dec":"*" }, "option":true}' */
  arg_switches[5] = p->bot;

  r=json_inject(json, len, 
  /* discord/guild.json:251:19
     '{ "name":"id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                "(id):|F|,"
  /* discord/guild.json:252:19
     '{ "name":"name", "type":{ "base":"char", "dec":"*" }}' */
                "(name):s,"
  /* discord/guild.json:253:19
     '{ "name":"icon", "type":{ "base":"char", "dec":"*" }}' */
                "(icon):s,"
  /* discord/guild.json:254:19
     '{ "name":"description", "type":{ "base":"char", "dec":"*" }}' */
                "(description):s,"
  /* discord/guild.json:255:19
     '{ "name":"summary", "type":{ "base":"char", "dec":"*" }}' */
                "(summary):s,"
  /* discord/guild.json:256:19
     '{ "name":"bot", "type":{ "base":"struct discord_user", "dec":"*" }, "option":true}' */
                "(bot):F,"
                "@arg_switches:b",
  /* discord/guild.json:251:19
     '{ "name":"id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                cee_u64tostr, &p->id,
  /* discord/guild.json:252:19
     '{ "name":"name", "type":{ "base":"char", "dec":"*" }}' */
                p->name,
  /* discord/guild.json:253:19
     '{ "name":"icon", "type":{ "base":"char", "dec":"*" }}' */
                p->icon,
  /* discord/guild.json:254:19
     '{ "name":"description", "type":{ "base":"char", "dec":"*" }}' */
                p->description,
  /* discord/guild.json:255:19
     '{ "name":"summary", "type":{ "base":"char", "dec":"*" }}' */
                p->summary,
  /* discord/guild.json:256:19
     '{ "name":"bot", "type":{ "base":"struct discord_user", "dec":"*" }, "option":true}' */
                discord_user_to_json, p->bot,
                arg_switches, sizeof(arg_switches), true);
  return r;
}


void discord_integration_application_cleanup_v(void *p) {
  discord_integration_application_cleanup((struct discord_integration_application *)p);
}

void discord_integration_application_init_v(void *p) {
  discord_integration_application_init((struct discord_integration_application *)p);
}

void discord_integration_application_from_json_v(char *json, size_t len, void *p) {
 discord_integration_application_from_json(json, len, (struct discord_integration_application*)p);
}

size_t discord_integration_application_to_json_v(char *json, size_t len, void *p) {
  return discord_integration_application_to_json(json, len, (struct discord_integration_application*)p);
}

void discord_integration_application_list_free_v(void **p) {
  discord_integration_application_list_free((struct discord_integration_application**)p);
}

void discord_integration_application_list_from_json_v(char *str, size_t len, void *p) {
  discord_integration_application_list_from_json(str, len, (struct discord_integration_application ***)p);
}

size_t discord_integration_application_list_to_json_v(char *str, size_t len, void *p){
  return discord_integration_application_list_to_json(str, len, (struct discord_integration_application **)p);
}


void discord_integration_application_cleanup(struct discord_integration_application *d) {
  /* discord/guild.json:251:19
     '{ "name":"id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  (void)d->id;
  /* discord/guild.json:252:19
     '{ "name":"name", "type":{ "base":"char", "dec":"*" }}' */
  if (d->name)
    free(d->name);
  /* discord/guild.json:253:19
     '{ "name":"icon", "type":{ "base":"char", "dec":"*" }}' */
  if (d->icon)
    free(d->icon);
  /* discord/guild.json:254:19
     '{ "name":"description", "type":{ "base":"char", "dec":"*" }}' */
  if (d->description)
    free(d->description);
  /* discord/guild.json:255:19
     '{ "name":"summary", "type":{ "base":"char", "dec":"*" }}' */
  if (d->summary)
    free(d->summary);
  /* discord/guild.json:256:19
     '{ "name":"bot", "type":{ "base":"struct discord_user", "dec":"*" }, "option":true}' */
  if (d->bot) {
    discord_user_cleanup(d->bot);
    free(d->bot);
  }
}

void discord_integration_application_init(struct discord_integration_application *p) {
  memset(p, 0, sizeof(struct discord_integration_application));
  /* discord/guild.json:251:19
     '{ "name":"id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */

  /* discord/guild.json:252:19
     '{ "name":"name", "type":{ "base":"char", "dec":"*" }}' */

  /* discord/guild.json:253:19
     '{ "name":"icon", "type":{ "base":"char", "dec":"*" }}' */

  /* discord/guild.json:254:19
     '{ "name":"description", "type":{ "base":"char", "dec":"*" }}' */

  /* discord/guild.json:255:19
     '{ "name":"summary", "type":{ "base":"char", "dec":"*" }}' */

  /* discord/guild.json:256:19
     '{ "name":"bot", "type":{ "base":"struct discord_user", "dec":"*" }, "option":true}' */

}
void discord_integration_application_list_free(struct discord_integration_application **p) {
  ntl_free((void**)p, (void(*)(void*))discord_integration_application_cleanup);
}

void discord_integration_application_list_from_json(char *str, size_t len, struct discord_integration_application ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct discord_integration_application);
  d.init_elem = NULL;
  d.elem_from_buf = (void(*)(char*,size_t,void*))discord_integration_application_from_json_p;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_integration_application_list_to_json(char *str, size_t len, struct discord_integration_application **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, (size_t(*)(char*,size_t,void*))discord_integration_application_to_json);
}


void discord_ban_from_json_p(char *json, size_t len, struct discord_ban **pp)
{
  if (!*pp) *pp = malloc(sizeof **pp);
  discord_ban_from_json(json, len, *pp);
}
void discord_ban_from_json(char *json, size_t len, struct discord_ban *p)
{
  discord_ban_init(p);
  json_extract(json, len, 
  /* discord/guild.json:265:20
     '{ "name": "reason", "type":{ "base":"char", "dec":"*" }}' */
                "(reason):?s,"
  /* discord/guild.json:266:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*"}, "comment":"partial user object"}' */
                "(user):F,",
  /* discord/guild.json:265:20
     '{ "name": "reason", "type":{ "base":"char", "dec":"*" }}' */
                &p->reason,
  /* discord/guild.json:266:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*"}, "comment":"partial user object"}' */
                discord_user_from_json_p, &p->user);
}

size_t discord_ban_to_json(char *json, size_t len, struct discord_ban *p)
{
  size_t r;
  void *arg_switches[2]={NULL};
  /* discord/guild.json:265:20
     '{ "name": "reason", "type":{ "base":"char", "dec":"*" }}' */
  arg_switches[0] = p->reason;

  /* discord/guild.json:266:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*"}, "comment":"partial user object"}' */
  arg_switches[1] = p->user;

  r=json_inject(json, len, 
  /* discord/guild.json:265:20
     '{ "name": "reason", "type":{ "base":"char", "dec":"*" }}' */
                "(reason):s,"
  /* discord/guild.json:266:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*"}, "comment":"partial user object"}' */
                "(user):F,"
                "@arg_switches:b",
  /* discord/guild.json:265:20
     '{ "name": "reason", "type":{ "base":"char", "dec":"*" }}' */
                p->reason,
  /* discord/guild.json:266:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*"}, "comment":"partial user object"}' */
                discord_user_to_json, p->user,
                arg_switches, sizeof(arg_switches), true);
  return r;
}


void discord_ban_cleanup_v(void *p) {
  discord_ban_cleanup((struct discord_ban *)p);
}

void discord_ban_init_v(void *p) {
  discord_ban_init((struct discord_ban *)p);
}

void discord_ban_from_json_v(char *json, size_t len, void *p) {
 discord_ban_from_json(json, len, (struct discord_ban*)p);
}

size_t discord_ban_to_json_v(char *json, size_t len, void *p) {
  return discord_ban_to_json(json, len, (struct discord_ban*)p);
}

void discord_ban_list_free_v(void **p) {
  discord_ban_list_free((struct discord_ban**)p);
}

void discord_ban_list_from_json_v(char *str, size_t len, void *p) {
  discord_ban_list_from_json(str, len, (struct discord_ban ***)p);
}

size_t discord_ban_list_to_json_v(char *str, size_t len, void *p){
  return discord_ban_list_to_json(str, len, (struct discord_ban **)p);
}


void discord_ban_cleanup(struct discord_ban *d) {
  /* discord/guild.json:265:20
     '{ "name": "reason", "type":{ "base":"char", "dec":"*" }}' */
  if (d->reason)
    free(d->reason);
  /* discord/guild.json:266:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*"}, "comment":"partial user object"}' */
  if (d->user) {
    discord_user_cleanup(d->user);
    free(d->user);
  }
}

void discord_ban_init(struct discord_ban *p) {
  memset(p, 0, sizeof(struct discord_ban));
  /* discord/guild.json:265:20
     '{ "name": "reason", "type":{ "base":"char", "dec":"*" }}' */

  /* discord/guild.json:266:20
     '{ "name": "user", "type":{ "base":"struct discord_user", "dec":"*"}, "comment":"partial user object"}' */

}
void discord_ban_list_free(struct discord_ban **p) {
  ntl_free((void**)p, (void(*)(void*))discord_ban_cleanup);
}

void discord_ban_list_from_json(char *str, size_t len, struct discord_ban ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct discord_ban);
  d.init_elem = NULL;
  d.elem_from_buf = (void(*)(char*,size_t,void*))discord_ban_from_json_p;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_ban_list_to_json(char *str, size_t len, struct discord_ban **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, (size_t(*)(char*,size_t,void*))discord_ban_to_json);
}


void discord_welcome_screen_from_json_p(char *json, size_t len, struct discord_welcome_screen **pp)
{
  if (!*pp) *pp = malloc(sizeof **pp);
  discord_welcome_screen_from_json(json, len, *pp);
}
void discord_welcome_screen_from_json(char *json, size_t len, struct discord_welcome_screen *p)
{
  discord_welcome_screen_init(p);
  json_extract(json, len, 
  /* discord/guild.json:275:20
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null }' */
                "(description):?s,"
  /* discord/guild.json:276:20
     '{ "name": "welcome_channels", "type":{ "base":"struct discord_welcome_screen_channel", "dec":"ntl" }, "inject_if_not":null }' */
                "(welcome_channels):F,",
  /* discord/guild.json:275:20
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null }' */
                &p->description,
  /* discord/guild.json:276:20
     '{ "name": "welcome_channels", "type":{ "base":"struct discord_welcome_screen_channel", "dec":"ntl" }, "inject_if_not":null }' */
                discord_welcome_screen_channel_list_from_json, &p->welcome_channels);
}

size_t discord_welcome_screen_to_json(char *json, size_t len, struct discord_welcome_screen *p)
{
  size_t r;
  void *arg_switches[2]={NULL};
  /* discord/guild.json:275:20
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null }' */
  if (p->description != NULL)
    arg_switches[0] = p->description;

  /* discord/guild.json:276:20
     '{ "name": "welcome_channels", "type":{ "base":"struct discord_welcome_screen_channel", "dec":"ntl" }, "inject_if_not":null }' */
  if (p->welcome_channels != NULL)
    arg_switches[1] = p->welcome_channels;

  r=json_inject(json, len, 
  /* discord/guild.json:275:20
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null }' */
                "(description):s,"
  /* discord/guild.json:276:20
     '{ "name": "welcome_channels", "type":{ "base":"struct discord_welcome_screen_channel", "dec":"ntl" }, "inject_if_not":null }' */
                "(welcome_channels):F,"
                "@arg_switches:b",
  /* discord/guild.json:275:20
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null }' */
                p->description,
  /* discord/guild.json:276:20
     '{ "name": "welcome_channels", "type":{ "base":"struct discord_welcome_screen_channel", "dec":"ntl" }, "inject_if_not":null }' */
                discord_welcome_screen_channel_list_to_json, p->welcome_channels,
                arg_switches, sizeof(arg_switches), true);
  return r;
}


void discord_welcome_screen_cleanup_v(void *p) {
  discord_welcome_screen_cleanup((struct discord_welcome_screen *)p);
}

void discord_welcome_screen_init_v(void *p) {
  discord_welcome_screen_init((struct discord_welcome_screen *)p);
}

void discord_welcome_screen_from_json_v(char *json, size_t len, void *p) {
 discord_welcome_screen_from_json(json, len, (struct discord_welcome_screen*)p);
}

size_t discord_welcome_screen_to_json_v(char *json, size_t len, void *p) {
  return discord_welcome_screen_to_json(json, len, (struct discord_welcome_screen*)p);
}

void discord_welcome_screen_list_free_v(void **p) {
  discord_welcome_screen_list_free((struct discord_welcome_screen**)p);
}

void discord_welcome_screen_list_from_json_v(char *str, size_t len, void *p) {
  discord_welcome_screen_list_from_json(str, len, (struct discord_welcome_screen ***)p);
}

size_t discord_welcome_screen_list_to_json_v(char *str, size_t len, void *p){
  return discord_welcome_screen_list_to_json(str, len, (struct discord_welcome_screen **)p);
}


void discord_welcome_screen_cleanup(struct discord_welcome_screen *d) {
  /* discord/guild.json:275:20
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null }' */
  if (d->description)
    free(d->description);
  /* discord/guild.json:276:20
     '{ "name": "welcome_channels", "type":{ "base":"struct discord_welcome_screen_channel", "dec":"ntl" }, "inject_if_not":null }' */
  if (d->welcome_channels)
    discord_welcome_screen_channel_list_free(d->welcome_channels);
}

void discord_welcome_screen_init(struct discord_welcome_screen *p) {
  memset(p, 0, sizeof(struct discord_welcome_screen));
  /* discord/guild.json:275:20
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null }' */

  /* discord/guild.json:276:20
     '{ "name": "welcome_channels", "type":{ "base":"struct discord_welcome_screen_channel", "dec":"ntl" }, "inject_if_not":null }' */

}
void discord_welcome_screen_list_free(struct discord_welcome_screen **p) {
  ntl_free((void**)p, (void(*)(void*))discord_welcome_screen_cleanup);
}

void discord_welcome_screen_list_from_json(char *str, size_t len, struct discord_welcome_screen ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct discord_welcome_screen);
  d.init_elem = NULL;
  d.elem_from_buf = (void(*)(char*,size_t,void*))discord_welcome_screen_from_json_p;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_welcome_screen_list_to_json(char *str, size_t len, struct discord_welcome_screen **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, (size_t(*)(char*,size_t,void*))discord_welcome_screen_to_json);
}


void discord_welcome_screen_channel_from_json_p(char *json, size_t len, struct discord_welcome_screen_channel **pp)
{
  if (!*pp) *pp = malloc(sizeof **pp);
  discord_welcome_screen_channel_from_json(json, len, *pp);
}
void discord_welcome_screen_channel_from_json(char *json, size_t len, struct discord_welcome_screen_channel *p)
{
  discord_welcome_screen_channel_init(p);
  json_extract(json, len, 
  /* discord/guild.json:286:20
     '{ "name": "channel_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                "(channel_id):F,"
  /* discord/guild.json:287:20
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }}' */
                "(description):?s,"
  /* discord/guild.json:288:20
     '{ "name": "emoji_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                "(emoji_id):F,"
  /* discord/guild.json:289:20
     '{ "name": "emoji_name", "type":{ "base":"char", "dec":"*" }}' */
                "(emoji_name):?s,",
  /* discord/guild.json:286:20
     '{ "name": "channel_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                cee_strtou64, &p->channel_id,
  /* discord/guild.json:287:20
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }}' */
                &p->description,
  /* discord/guild.json:288:20
     '{ "name": "emoji_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                cee_strtou64, &p->emoji_id,
  /* discord/guild.json:289:20
     '{ "name": "emoji_name", "type":{ "base":"char", "dec":"*" }}' */
                &p->emoji_name);
}

size_t discord_welcome_screen_channel_to_json(char *json, size_t len, struct discord_welcome_screen_channel *p)
{
  size_t r;
  void *arg_switches[4]={NULL};
  /* discord/guild.json:286:20
     '{ "name": "channel_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  arg_switches[0] = &p->channel_id;

  /* discord/guild.json:287:20
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }}' */
  arg_switches[1] = p->description;

  /* discord/guild.json:288:20
     '{ "name": "emoji_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  arg_switches[2] = &p->emoji_id;

  /* discord/guild.json:289:20
     '{ "name": "emoji_name", "type":{ "base":"char", "dec":"*" }}' */
  arg_switches[3] = p->emoji_name;

  r=json_inject(json, len, 
  /* discord/guild.json:286:20
     '{ "name": "channel_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                "(channel_id):|F|,"
  /* discord/guild.json:287:20
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }}' */
                "(description):s,"
  /* discord/guild.json:288:20
     '{ "name": "emoji_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                "(emoji_id):|F|,"
  /* discord/guild.json:289:20
     '{ "name": "emoji_name", "type":{ "base":"char", "dec":"*" }}' */
                "(emoji_name):s,"
                "@arg_switches:b",
  /* discord/guild.json:286:20
     '{ "name": "channel_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                cee_u64tostr, &p->channel_id,
  /* discord/guild.json:287:20
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }}' */
                p->description,
  /* discord/guild.json:288:20
     '{ "name": "emoji_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
                cee_u64tostr, &p->emoji_id,
  /* discord/guild.json:289:20
     '{ "name": "emoji_name", "type":{ "base":"char", "dec":"*" }}' */
                p->emoji_name,
                arg_switches, sizeof(arg_switches), true);
  return r;
}


void discord_welcome_screen_channel_cleanup_v(void *p) {
  discord_welcome_screen_channel_cleanup((struct discord_welcome_screen_channel *)p);
}

void discord_welcome_screen_channel_init_v(void *p) {
  discord_welcome_screen_channel_init((struct discord_welcome_screen_channel *)p);
}

void discord_welcome_screen_channel_from_json_v(char *json, size_t len, void *p) {
 discord_welcome_screen_channel_from_json(json, len, (struct discord_welcome_screen_channel*)p);
}

size_t discord_welcome_screen_channel_to_json_v(char *json, size_t len, void *p) {
  return discord_welcome_screen_channel_to_json(json, len, (struct discord_welcome_screen_channel*)p);
}

void discord_welcome_screen_channel_list_free_v(void **p) {
  discord_welcome_screen_channel_list_free((struct discord_welcome_screen_channel**)p);
}

void discord_welcome_screen_channel_list_from_json_v(char *str, size_t len, void *p) {
  discord_welcome_screen_channel_list_from_json(str, len, (struct discord_welcome_screen_channel ***)p);
}

size_t discord_welcome_screen_channel_list_to_json_v(char *str, size_t len, void *p){
  return discord_welcome_screen_channel_list_to_json(str, len, (struct discord_welcome_screen_channel **)p);
}


void discord_welcome_screen_channel_cleanup(struct discord_welcome_screen_channel *d) {
  /* discord/guild.json:286:20
     '{ "name": "channel_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  (void)d->channel_id;
  /* discord/guild.json:287:20
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }}' */
  if (d->description)
    free(d->description);
  /* discord/guild.json:288:20
     '{ "name": "emoji_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  (void)d->emoji_id;
  /* discord/guild.json:289:20
     '{ "name": "emoji_name", "type":{ "base":"char", "dec":"*" }}' */
  if (d->emoji_name)
    free(d->emoji_name);
}

void discord_welcome_screen_channel_init(struct discord_welcome_screen_channel *p) {
  memset(p, 0, sizeof(struct discord_welcome_screen_channel));
  /* discord/guild.json:286:20
     '{ "name": "channel_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */

  /* discord/guild.json:287:20
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }}' */

  /* discord/guild.json:288:20
     '{ "name": "emoji_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */

  /* discord/guild.json:289:20
     '{ "name": "emoji_name", "type":{ "base":"char", "dec":"*" }}' */

}
void discord_welcome_screen_channel_list_free(struct discord_welcome_screen_channel **p) {
  ntl_free((void**)p, (void(*)(void*))discord_welcome_screen_channel_cleanup);
}

void discord_welcome_screen_channel_list_from_json(char *str, size_t len, struct discord_welcome_screen_channel ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct discord_welcome_screen_channel);
  d.init_elem = NULL;
  d.elem_from_buf = (void(*)(char*,size_t,void*))discord_welcome_screen_channel_from_json_p;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json2(str, len, &d);
}

size_t discord_welcome_screen_channel_list_to_json(char *str, size_t len, struct discord_welcome_screen_channel **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, (size_t(*)(char*,size_t,void*))discord_welcome_screen_channel_to_json);
}

