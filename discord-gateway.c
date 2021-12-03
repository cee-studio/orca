#define _GNU_SOURCE /* asprintf() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h> /* offsetof() */
#include <ctype.h> /* isspace() */

#include "discord.h"
#include "discord-internal.h"

/* get client from gw pointer */
#define CLIENT(p_gw)                                                          \
  ((struct discord *)((int8_t *)(p_gw)-offsetof(struct discord, gw)))

/* shorten event callback for maintainability purposes */
#define ON(event, ...)                                                        \
  (*gw->cmds.cbs.on_##event)(CLIENT(gw), &gw->bot, ##__VA_ARGS__)

static void
sized_buffer_from_json(char *json, size_t len, void *data)
{
  struct sized_buffer *p = data;

  p->size = asprintf(&p->start, "%.*s", (int)len, json);
}

ORCAcode
discord_get_gateway(struct discord *client, struct sized_buffer *p_json)
{
  struct ua_resp_handle resp_handle = { &sized_buffer_from_json, p_json };

  if (!p_json) {
    logconf_error(&client->conf, "Missing 'p_json'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &resp_handle, NULL, HTTP_GET,
                             "/gateway");
}

ORCAcode
discord_get_gateway_bot(struct discord *client, struct sized_buffer *p_json)
{
  struct ua_resp_handle resp_handle = { &sized_buffer_from_json, p_json };

  if (!p_json) {
    logconf_error(&client->conf, "Missing 'p_json'");
    return ORCA_MISSING_PARAMETER;
  }

  return discord_adapter_run(&client->adapter, &resp_handle, NULL, HTTP_GET,
                             "/gateway/bot");
}

static const char *
opcode_print(enum discord_gateway_opcodes opcode)
{
  const char *str;

  str = discord_gateway_opcodes_print(opcode);
  if (NULL == str) {
    log_warn("Invalid Gateway opcode (code: %d)", opcode);
    str = "Invalid Gateway opcode";
  }
  return str;
}

static const char *
close_opcode_print(enum discord_gateway_close_opcodes opcode)
{
  const char *str;

  str = discord_gateway_close_opcodes_print(opcode);
  if (str) return str;

  str = ws_close_opcode_print((enum ws_close_reason)opcode);
  if (str) return str;

  log_warn("Unknown WebSockets close opcode (code: %d)", opcode);
  return "Unknown WebSockets close opcode";
}

static void
send_resume(struct discord_gateway *gw)
{
  char payload[1024];
  size_t ret;
  struct ws_info info = { 0 };

  gw->status->is_resumable = false; /* reset */

  ret = json_inject(payload, sizeof(payload),
                    "(op):6" /* RESUME OPCODE */
                    "(d):{"
                    "(token):s"
                    "(session_id):s"
                    "(seq):d"
                    "}",
                    gw->id.token, gw->session_id, &gw->payload.seq);
  ASSERT_S(ret < sizeof(payload), "Out of bounds write attempt");

  ws_send_text(gw->ws, &info, payload, ret);

  logconf_info(
    &gw->conf,
    ANSICOLOR("SEND", ANSI_FG_BRIGHT_GREEN) " RESUME (%d bytes) [@@@_%zu_@@@]",
    ret, info.loginfo.counter + 1);
}

static void
send_identify(struct discord_gateway *gw)
{
  char payload[1024];
  size_t ret;
  struct ws_info info = { 0 };

  /* Ratelimit check */
  if ((ws_timestamp(gw->ws) - gw->session.identify_tstamp) < 5) {
    ++gw->session.concurrent;
    VASSERT_S(gw->session.concurrent < gw->session.start_limit.max_concurrency,
              "Reach identify request threshold (%d every 5 seconds)",
              gw->session.start_limit.max_concurrency);
  }
  else {
    gw->session.concurrent = 0;
  }

  ret = json_inject(payload, sizeof(payload),
                    "(op):2" /* IDENTIFY OPCODE */
                    "(d):F",
                    &discord_identify_to_json, &gw->id);
  ASSERT_S(ret < sizeof(payload), "Out of bounds write attempt");

  ws_send_text(gw->ws, &info, payload, ret);

  logconf_info(
    &gw->conf,
    ANSICOLOR("SEND",
              ANSI_FG_BRIGHT_GREEN) " IDENTIFY (%d bytes) [@@@_%zu_@@@]",
    ret, info.loginfo.counter + 1);

  /*get timestamp for this identify */
  gw->session.identify_tstamp = ws_timestamp(gw->ws);
}

/* send heartbeat pulse to websockets server in order
 *  to maintain connection alive */
static void
send_heartbeat(struct discord_gateway *gw)
{
  char payload[64];
  int ret;
  struct ws_info info = { 0 };

  ret =
    json_inject(payload, sizeof(payload), "(op):1,(d):d", &gw->payload.seq);
  ASSERT_S(ret < sizeof(payload), "Out of bounds write attempt");

  ws_send_text(gw->ws, &info, payload, ret);

  logconf_info(
    &gw->conf,
    ANSICOLOR("SEND",
              ANSI_FG_BRIGHT_GREEN) " HEARTBEAT (%d bytes) [@@@_%zu_@@@]",
    ret, info.loginfo.counter + 1);

  gw->hbeat.tstamp = ws_timestamp(gw->ws); /*update heartbeat timestamp */
}

static void
on_hello(struct discord_gateway *gw)
{
  gw->hbeat.interval_ms = 0;
  gw->hbeat.tstamp = ws_timestamp(gw->ws);

  json_extract(gw->payload.data.start, gw->payload.data.size,
               "(heartbeat_interval):ld", &gw->hbeat.interval_ms);

  if (gw->status->is_resumable)
    send_resume(gw);
  else
    send_identify(gw);
}

static enum discord_gateway_events
get_dispatch_event(char name[])
{
#define RETURN_IF_MATCH(event, str)                                           \
  if (STREQ(#event, str)) return DISCORD_GATEWAY_EVENTS_##event

  RETURN_IF_MATCH(READY, name);
  RETURN_IF_MATCH(RESUMED, name);
  RETURN_IF_MATCH(APPLICATION_COMMAND_CREATE, name);
  RETURN_IF_MATCH(APPLICATION_COMMAND_UPDATE, name);
  RETURN_IF_MATCH(APPLICATION_COMMAND_DELETE, name);
  RETURN_IF_MATCH(CHANNEL_CREATE, name);
  RETURN_IF_MATCH(CHANNEL_UPDATE, name);
  RETURN_IF_MATCH(CHANNEL_DELETE, name);
  RETURN_IF_MATCH(CHANNEL_PINS_UPDATE, name);
  RETURN_IF_MATCH(THREAD_CREATE, name);
  RETURN_IF_MATCH(THREAD_UPDATE, name);
  RETURN_IF_MATCH(THREAD_DELETE, name);
  RETURN_IF_MATCH(THREAD_LIST_SYNC, name);
  RETURN_IF_MATCH(THREAD_MEMBER_UPDATE, name);
  RETURN_IF_MATCH(THREAD_MEMBERS_UPDATE, name);
  RETURN_IF_MATCH(GUILD_CREATE, name);
  RETURN_IF_MATCH(GUILD_UPDATE, name);
  RETURN_IF_MATCH(GUILD_DELETE, name);
  RETURN_IF_MATCH(GUILD_BAN_ADD, name);
  RETURN_IF_MATCH(GUILD_BAN_REMOVE, name);
  RETURN_IF_MATCH(GUILD_EMOJIS_UPDATE, name);
  RETURN_IF_MATCH(GUILD_STICKERS_UPDATE, name);
  RETURN_IF_MATCH(GUILD_INTEGRATIONS_UPDATE, name);
  RETURN_IF_MATCH(GUILD_MEMBER_ADD, name);
  RETURN_IF_MATCH(GUILD_MEMBER_UPDATE, name);
  RETURN_IF_MATCH(GUILD_MEMBER_REMOVE, name);
  RETURN_IF_MATCH(GUILD_MEMBERS_CHUNK, name);
  RETURN_IF_MATCH(GUILD_ROLE_CREATE, name);
  RETURN_IF_MATCH(GUILD_ROLE_UPDATE, name);
  RETURN_IF_MATCH(GUILD_ROLE_DELETE, name);
  RETURN_IF_MATCH(INTEGRATION_CREATE, name);
  RETURN_IF_MATCH(INTEGRATION_UPDATE, name);
  RETURN_IF_MATCH(INTEGRATION_DELETE, name);
  RETURN_IF_MATCH(INTERACTION_CREATE, name);
  RETURN_IF_MATCH(INVITE_CREATE, name);
  RETURN_IF_MATCH(INVITE_DELETE, name);
  RETURN_IF_MATCH(MESSAGE_CREATE, name);
  RETURN_IF_MATCH(MESSAGE_UPDATE, name);
  RETURN_IF_MATCH(MESSAGE_DELETE, name);
  RETURN_IF_MATCH(MESSAGE_DELETE_BULK, name);
  RETURN_IF_MATCH(MESSAGE_REACTION_ADD, name);
  RETURN_IF_MATCH(MESSAGE_REACTION_REMOVE, name);
  RETURN_IF_MATCH(MESSAGE_REACTION_REMOVE_ALL, name);
  RETURN_IF_MATCH(MESSAGE_REACTION_REMOVE_EMOJI, name);
  RETURN_IF_MATCH(PRESENCE_UPDATE, name);
  RETURN_IF_MATCH(STAGE_INSTANCE_CREATE, name);
  RETURN_IF_MATCH(STAGE_INSTANCE_DELETE, name);
  RETURN_IF_MATCH(STAGE_INSTANCE_UPDATE, name);
  RETURN_IF_MATCH(TYPING_START, name);
  RETURN_IF_MATCH(USER_UPDATE, name);
  RETURN_IF_MATCH(VOICE_STATE_UPDATE, name);
  RETURN_IF_MATCH(VOICE_SERVER_UPDATE, name);
  RETURN_IF_MATCH(WEBHOOKS_UPDATE, name);
  return DISCORD_GATEWAY_EVENTS_NONE;

#undef RETURN_IF_MATCH
}

static void
on_guild_role_create(struct discord_gateway *gw, struct sized_buffer *data)
{
  struct discord_role role;
  u64_snowflake_t guild_id = 0;

  json_extract(data->start, data->size,
               "(guild_id):s_as_u64"
               "(role):F",
               &guild_id, &discord_role_from_json, &role);

  ON(guild_role_create, guild_id, &role);

  discord_role_cleanup(&role);
}

static void
on_guild_role_update(struct discord_gateway *gw, struct sized_buffer *data)
{
  struct discord_role role;
  u64_snowflake_t guild_id = 0;

  json_extract(data->start, data->size,
               "(guild_id):s_as_u64"
               "(role):F",
               &guild_id, &discord_role_from_json, &role);

  ON(guild_role_update, guild_id, &role);

  discord_role_cleanup(&role);
}

static void
on_guild_role_delete(struct discord_gateway *gw, struct sized_buffer *data)
{
  u64_snowflake_t guild_id = 0, role_id = 0;

  json_extract(data->start, data->size,
               "(guild_id):s_as_u64"
               "(role_id):s_as_u64",
               &guild_id, &role_id);

  ON(guild_role_delete, guild_id, role_id);
}

static void
on_guild_member_add(struct discord_gateway *gw, struct sized_buffer *data)
{
  struct discord_guild_member member;
  u64_snowflake_t guild_id = 0;

  discord_guild_member_from_json(data->start, data->size, &member);

  json_extract(data->start, data->size, "(guild_id):s_as_u64", &guild_id);

  ON(guild_member_add, guild_id, &member);

  discord_guild_member_cleanup(&member);
}

static void
on_guild_member_update(struct discord_gateway *gw, struct sized_buffer *data)
{
  struct discord_guild_member member;
  u64_snowflake_t guild_id = 0;

  discord_guild_member_from_json(data->start, data->size, &member);

  json_extract(data->start, data->size, "(guild_id):s_as_u64", &guild_id);

  ON(guild_member_update, guild_id, &member);

  discord_guild_member_cleanup(&member);
}

static void
on_guild_member_remove(struct discord_gateway *gw, struct sized_buffer *data)
{
  u64_snowflake_t guild_id = 0;
  struct discord_user user;

  json_extract(data->start, data->size,
               "(guild_id):s_as_u64"
               "(user):F",
               &guild_id, &discord_user_from_json, &user);

  ON(guild_member_remove, guild_id, &user);

  discord_user_cleanup(&user);
}

static void
on_guild_ban_add(struct discord_gateway *gw, struct sized_buffer *data)
{
  u64_snowflake_t guild_id = 0;
  struct discord_user user;

  json_extract(data->start, data->size,
               "(guild_id):s_as_u64"
               "(user):F",
               &guild_id, &discord_user_from_json, &user);

  ON(guild_ban_add, guild_id, &user);

  discord_user_cleanup(&user);
}

static void
on_guild_ban_remove(struct discord_gateway *gw, struct sized_buffer *data)
{
  u64_snowflake_t guild_id = 0;
  struct discord_user user;

  json_extract(data->start, data->size,
               "(guild_id):s_as_u64"
               "(user):F",
               &guild_id, &discord_user_from_json, &user);

  ON(guild_ban_remove, guild_id, &user);

  discord_user_cleanup(&user);
}

static void
on_application_command_create(struct discord_gateway *gw,
                              struct sized_buffer *data)
{
  struct discord_application_command cmd;

  discord_application_command_from_json(data->start, data->size, &cmd);

  ON(application_command_create, &cmd);

  discord_application_command_cleanup(&cmd);
}

static void
on_application_command_update(struct discord_gateway *gw,
                              struct sized_buffer *data)
{
  struct discord_application_command cmd;
  discord_application_command_from_json(data->start, data->size, &cmd);

  ON(application_command_update, &cmd);

  discord_application_command_cleanup(&cmd);
}

static void
on_application_command_delete(struct discord_gateway *gw,
                              struct sized_buffer *data)
{
  struct discord_application_command cmd;

  discord_application_command_from_json(data->start, data->size, &cmd);

  ON(application_command_delete, &cmd);

  discord_application_command_cleanup(&cmd);
}

static void
on_channel_create(struct discord_gateway *gw, struct sized_buffer *data)
{
  struct discord_channel channel;

  discord_channel_from_json(data->start, data->size, &channel);

  ON(channel_create, &channel);

  discord_channel_cleanup(&channel);
}

static void
on_channel_update(struct discord_gateway *gw, struct sized_buffer *data)
{
  struct discord_channel channel;

  discord_channel_from_json(data->start, data->size, &channel);

  ON(channel_update, &channel);

  discord_channel_cleanup(&channel);
}

static void
on_channel_delete(struct discord_gateway *gw, struct sized_buffer *data)
{
  struct discord_channel channel;

  discord_channel_from_json(data->start, data->size, &channel);

  ON(channel_delete, &channel);

  discord_channel_cleanup(&channel);
}

static void
on_channel_pins_update(struct discord_gateway *gw, struct sized_buffer *data)
{
  u64_snowflake_t guild_id = 0, channel_id = 0;
  u64_unix_ms_t last_pin_timestamp = 0;

  json_extract(data->start, data->size,
               "(guild_id):s_as_u64"
               "(channel_id):s_as_u64"
               "(last_pin_timestamp):F",
               &guild_id, &channel_id, &cee_iso8601_to_unix_ms,
               &last_pin_timestamp);

  ON(channel_pins_update, guild_id, channel_id, last_pin_timestamp);
}

static void
on_thread_create(struct discord_gateway *gw, struct sized_buffer *data)
{
  struct discord_channel thread;

  discord_channel_from_json(data->start, data->size, &thread);

  ON(thread_create, &thread);

  discord_channel_cleanup(&thread);
}

static void
on_thread_update(struct discord_gateway *gw, struct sized_buffer *data)
{
  struct discord_channel thread;

  discord_channel_from_json(data->start, data->size, &thread);

  ON(thread_update, &thread);

  discord_channel_cleanup(&thread);
}

static void
on_thread_delete(struct discord_gateway *gw, struct sized_buffer *data)
{
  struct discord_channel thread;

  discord_channel_from_json(data->start, data->size, &thread);

  ON(thread_delete, &thread);

  discord_channel_cleanup(&thread);
}

static void
on_interaction_create(struct discord_gateway *gw, struct sized_buffer *data)
{
  struct discord_interaction interaction;

  discord_interaction_from_json(data->start, data->size, &interaction);

  ON(interaction_create, &interaction);

  discord_interaction_cleanup(&interaction);
}

static void
on_message_create(struct discord_gateway *gw, struct sized_buffer *data)
{
  struct discord_message msg;

  discord_message_from_json(data->start, data->size, &msg);

  if (gw->cmds.pool
      && STRNEQ(gw->cmds.prefix.start, msg.content, gw->cmds.prefix.size))
  {
    struct discord_gateway_cmd_cbs *cmd = NULL;
    size_t i;

    for (i = 0; i < gw->cmds.amt; ++i) {
      /* check if command from channel matches set command */
      if (STRNEQ(gw->cmds.pool[i].start, msg.content + gw->cmds.prefix.size,
                 gw->cmds.pool[i].size))
      {
        cmd = &gw->cmds.pool[i];
      }
    }
    if (!cmd && gw->cmds.prefix.size) {
      cmd = &gw->cmds.on_default;
    }

    if (cmd && cmd->cb) {
      char *tmp = msg.content; /* hold original ptr */
      msg.content += (ptrdiff_t)(gw->cmds.prefix.size + cmd->size);
      while (isspace(*msg.content)) { /* skip blank chars */
        ++msg.content;
      }

      (*cmd->cb)(CLIENT(gw), &gw->bot, &msg);

      msg.content = tmp; /* retrieve original ptr */
    }

    discord_message_cleanup(&msg);
    return; /* EARLY RETURN */
  }

  if (gw->cmds.cbs.sb_on_message_create) /* @todo temporary */
    (*gw->cmds.cbs.sb_on_message_create)(CLIENT(gw), &gw->bot, &gw->sb_bot,
                                         &msg, data);
  else if (gw->cmds.cbs.on_message_create)
    ON(message_create, &msg);

  discord_message_cleanup(&msg);
}

static void
on_message_update(struct discord_gateway *gw, struct sized_buffer *data)
{
  struct discord_message msg;

  discord_message_from_json(data->start, data->size, &msg);

  if (gw->cmds.cbs.sb_on_message_update)
    (*gw->cmds.cbs.sb_on_message_update)(CLIENT(gw), &gw->bot, &gw->sb_bot,
                                         &msg, data);
  else if (gw->cmds.cbs.on_message_update)
    ON(message_update, &msg);

  discord_message_cleanup(&msg);
}

static void
on_message_delete(struct discord_gateway *gw, struct sized_buffer *data)
{
  u64_snowflake_t message_id = 0, channel_id = 0, guild_id = 0;

  json_extract(data->start, data->size,
               "(id):s_as_u64"
               "(channel_id):s_as_u64"
               "(guild_id):s_as_u64",
               &message_id, &channel_id, &guild_id);

  ON(message_delete, message_id, channel_id, guild_id);
}

static void
on_message_delete_bulk(struct discord_gateway *gw, struct sized_buffer *data)
{
  const NTL_T(ja_u64) ids = NULL;
  u64_snowflake_t channel_id = 0, guild_id = 0;

  json_extract(data->start, data->size,
               "(ids):F"
               "(channel_id):s_as_u64"
               "(guild_id):s_as_u64",
               &ja_u64_list_from_json, &ids, &channel_id, &guild_id);

  ON(message_delete_bulk, ids, channel_id, guild_id);

  free(ids);
}

static void
on_message_reaction_add(struct discord_gateway *gw, struct sized_buffer *data)
{
  u64_snowflake_t user_id = 0, message_id = 0, channel_id = 0, guild_id = 0;
  struct discord_guild_member member;
  struct discord_emoji emoji;

  json_extract(data->start, data->size,
               "(user_id):s_as_u64"
               "(message_id):s_as_u64"
               "(member):F"
               "(emoji):F"
               "(channel_id):s_as_u64"
               "(guild_id):s_as_u64",
               &user_id, &message_id, &discord_guild_member_from_json, &member,
               &discord_emoji_from_json, &emoji, &channel_id, &guild_id);

  ON(message_reaction_add, user_id, channel_id, message_id, guild_id, &member,
     &emoji);

  discord_guild_member_cleanup(&member);
  discord_emoji_cleanup(&emoji);
}

static void
on_message_reaction_remove(struct discord_gateway *gw,
                           struct sized_buffer *data)
{
  u64_snowflake_t user_id = 0, message_id = 0, channel_id = 0, guild_id = 0;
  struct discord_emoji emoji;

  json_extract(data->start, data->size,
               "(user_id):s_as_u64"
               "(message_id):s_as_u64"
               "(emoji):F"
               "(channel_id):s_as_u64"
               "(guild_id):s_as_u64",
               &user_id, &message_id, &discord_emoji_from_json, &emoji,
               &channel_id, &guild_id);

  ON(message_reaction_remove, user_id, channel_id, message_id, guild_id,
     &emoji);

  discord_emoji_cleanup(&emoji);
}

static void
on_message_reaction_remove_all(struct discord_gateway *gw,
                               struct sized_buffer *data)
{
  u64_snowflake_t channel_id = 0, message_id = 0, guild_id = 0;

  json_extract(data->start, data->size,
               "(channel_id):s_as_u64"
               "(message_id):s_as_u64"
               "(channel_id):s_as_u64",
               &channel_id, &message_id, &guild_id);

  ON(message_reaction_remove_all, channel_id, message_id, guild_id);
}

static void
on_message_reaction_remove_emoji(struct discord_gateway *gw,
                                 struct sized_buffer *data)
{
  u64_snowflake_t channel_id = 0, guild_id = 0, message_id = 0;
  struct discord_emoji emoji;

  json_extract(data->start, data->size,
               "(channel_id):s_as_u64"
               "(guild_id):s_as_u64"
               "(message_id):s_as_u64"
               "(emoji):F",
               &channel_id, &guild_id, &message_id, &discord_emoji_from_json,
               &emoji);

  ON(message_reaction_remove_emoji, channel_id, guild_id, message_id, &emoji);

  discord_emoji_cleanup(&emoji);
}

static void
on_voice_state_update(struct discord_gateway *gw, struct sized_buffer *data)
{
  struct discord_voice_state vs;
  discord_voice_state_from_json(data->start, data->size, &vs);

  if (vs.user_id == gw->bot.id) {
    /* we only care about the voice_state_update of bot */
    _discord_on_voice_state_update(CLIENT(gw), &vs);
  }

  if (gw->cmds.cbs.on_voice_state_update) ON(voice_state_update, &vs);

  discord_voice_state_cleanup(&vs);
}

static void
on_voice_server_update(struct discord_gateway *gw, struct sized_buffer *data)
{
  u64_snowflake_t guild_id = 0;
  char token[512], endpoint[1024];

  json_extract(data->start, data->size,
               "(token):s"
               "(guild_id):s_as_u64"
               "(endpoint):s",
               &token, &guild_id, &endpoint);

  /* this happens for everyone */
  _discord_on_voice_server_update(CLIENT(gw), guild_id, token, endpoint);

  if (gw->cmds.cbs.on_voice_server_update)
    ON(voice_server_update, token, guild_id, endpoint);
}

static void
on_ready(struct discord_gateway *gw, struct sized_buffer *data)
{
  ON(ready);
}

static void
dispatch_run(void *p_cxt)
{
  struct discord_event *cxt = p_cxt;

  logconf_info(&cxt->gw->conf,
               "Thread " ANSICOLOR("starts", ANSI_FG_RED) " to serve %s",
               cxt->name);

  cxt->on_event(cxt->gw, &cxt->data);

  logconf_info(&cxt->gw->conf,
               "Thread " ANSICOLOR("exits", ANSI_FG_RED) " from serving %s",
               cxt->name);

  /* TODO: move to _discord_event_cleanup() */
  free(cxt->name);
  free(cxt->data.start);
  discord_cleanup(CLIENT(cxt->gw));
  free(cxt);
}

static void
on_dispatch(struct discord_gateway *gw)
{
  /* event-callback selector */
  void (*on_event)(struct discord_gateway *, struct sized_buffer *) = NULL;
  /* get dispatch event opcode */
  enum discord_gateway_events event;
  /* how the event-callback should be executed (main thread, worker thread,
   *        ignored) */
  enum discord_event_scheduler mode;

  /* Ratelimit check */
  if ((ws_timestamp(gw->ws) - gw->session.event_tstamp) < 60) {
    ++gw->session.event_count;
    ASSERT_S(gw->session.event_count < 120,
             "Reach event dispatch threshold (120 every 60 seconds)");
  }
  else {
    gw->session.event_tstamp = ws_timestamp(gw->ws);
    gw->session.event_count = 0;
  }

  switch (event = get_dispatch_event(gw->payload.name)) {
  case DISCORD_GATEWAY_EVENTS_READY:
    logconf_info(&gw->conf, "Succesfully started a Discord session!");
    json_extract(gw->payload.data.start, gw->payload.data.size,
                 "(session_id):s", gw->session_id);
    ASSERT_S(!IS_EMPTY_STRING(gw->session_id),
             "Missing session_id from READY event");

    gw->status->is_ready = true;
    gw->reconnect->attempt = 0;
    if (gw->cmds.cbs.on_ready) on_event = &on_ready;
    send_heartbeat(gw);
    break;
  case DISCORD_GATEWAY_EVENTS_RESUMED:
    logconf_info(&gw->conf, "Succesfully resumed a Discord session!");
    gw->status->is_ready = true;
    gw->reconnect->attempt = 0;
    /* @todo add callback */
    send_heartbeat(gw);
    break;
  case DISCORD_GATEWAY_EVENTS_APPLICATION_COMMAND_CREATE:
    if (gw->cmds.cbs.on_application_command_create)
      on_event = &on_application_command_create;
    break;
  case DISCORD_GATEWAY_EVENTS_APPLICATION_COMMAND_UPDATE:
    if (gw->cmds.cbs.on_application_command_update)
      on_event = &on_application_command_update;
    break;
  case DISCORD_GATEWAY_EVENTS_APPLICATION_COMMAND_DELETE:
    if (gw->cmds.cbs.on_application_command_delete)
      on_event = &on_application_command_delete;
    break;
  case DISCORD_GATEWAY_EVENTS_CHANNEL_CREATE:
    if (gw->cmds.cbs.on_channel_create) on_event = &on_channel_create;
    break;
  case DISCORD_GATEWAY_EVENTS_CHANNEL_UPDATE:
    if (gw->cmds.cbs.on_channel_update) on_event = &on_channel_update;
    break;
  case DISCORD_GATEWAY_EVENTS_CHANNEL_DELETE:
    if (gw->cmds.cbs.on_channel_delete) on_event = &on_channel_delete;
    break;
  case DISCORD_GATEWAY_EVENTS_CHANNEL_PINS_UPDATE:
    if (gw->cmds.cbs.on_channel_pins_update)
      on_event = &on_channel_pins_update;
    break;
  case DISCORD_GATEWAY_EVENTS_THREAD_CREATE:
    if (gw->cmds.cbs.on_thread_create) on_event = &on_thread_create;
    break;
  case DISCORD_GATEWAY_EVENTS_THREAD_UPDATE:
    if (gw->cmds.cbs.on_thread_update) on_event = &on_thread_update;
    break;
  case DISCORD_GATEWAY_EVENTS_THREAD_DELETE:
    if (gw->cmds.cbs.on_thread_delete) on_event = &on_thread_delete;
    break;
  case DISCORD_GATEWAY_EVENTS_THREAD_LIST_SYNC:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_THREAD_MEMBER_UPDATE:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_THREAD_MEMBERS_UPDATE:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_GUILD_CREATE:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_GUILD_UPDATE:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_GUILD_DELETE:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_GUILD_BAN_ADD:
    if (gw->cmds.cbs.on_guild_ban_add) on_event = &on_guild_ban_add;
    break;
  case DISCORD_GATEWAY_EVENTS_GUILD_BAN_REMOVE:
    if (gw->cmds.cbs.on_guild_ban_remove) on_event = &on_guild_ban_remove;
    break;
  case DISCORD_GATEWAY_EVENTS_GUILD_EMOJIS_UPDATE:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_GUILD_STICKERS_UPDATE:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_GUILD_INTEGRATIONS_UPDATE:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_GUILD_MEMBER_ADD:
    if (gw->cmds.cbs.on_guild_member_add) on_event = &on_guild_member_add;
    break;
  case DISCORD_GATEWAY_EVENTS_GUILD_MEMBER_UPDATE:
    if (gw->cmds.cbs.on_guild_member_update)
      on_event = &on_guild_member_update;
    break;
  case DISCORD_GATEWAY_EVENTS_GUILD_MEMBER_REMOVE:
    if (gw->cmds.cbs.on_guild_member_remove)
      on_event = &on_guild_member_remove;
    break;
  case DISCORD_GATEWAY_EVENTS_GUILD_ROLE_CREATE:
    if (gw->cmds.cbs.on_guild_role_create) on_event = &on_guild_role_create;
    break;
  case DISCORD_GATEWAY_EVENTS_GUILD_ROLE_UPDATE:
    if (gw->cmds.cbs.on_guild_role_update) on_event = &on_guild_role_update;
    break;
  case DISCORD_GATEWAY_EVENTS_GUILD_ROLE_DELETE:
    if (gw->cmds.cbs.on_guild_role_delete) on_event = &on_guild_role_delete;
    break;
  case DISCORD_GATEWAY_EVENTS_INTEGRATION_CREATE:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_INTEGRATION_UPDATE:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_INTEGRATION_DELETE:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_INTERACTION_CREATE:
    if (gw->cmds.cbs.on_interaction_create) on_event = &on_interaction_create;
    break;
  case DISCORD_GATEWAY_EVENTS_INVITE_CREATE:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_INVITE_DELETE:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_MESSAGE_CREATE:
    if (gw->cmds.pool || gw->cmds.cbs.sb_on_message_create
        || gw->cmds.cbs.on_message_create)
      on_event = &on_message_create;
    break;
  case DISCORD_GATEWAY_EVENTS_MESSAGE_UPDATE:
    if (gw->cmds.cbs.sb_on_message_update || gw->cmds.cbs.on_message_update)
      on_event = &on_message_update;
    break;
  case DISCORD_GATEWAY_EVENTS_MESSAGE_DELETE:
    if (gw->cmds.cbs.on_message_delete) on_event = &on_message_delete;
    break;
  case DISCORD_GATEWAY_EVENTS_MESSAGE_DELETE_BULK:
    if (gw->cmds.cbs.on_message_delete_bulk)
      on_event = &on_message_delete_bulk;
    break;
  case DISCORD_GATEWAY_EVENTS_MESSAGE_REACTION_ADD:
    if (gw->cmds.cbs.on_message_reaction_add)
      on_event = &on_message_reaction_add;
    break;
  case DISCORD_GATEWAY_EVENTS_MESSAGE_REACTION_REMOVE:
    if (gw->cmds.cbs.on_message_reaction_remove)
      on_event = &on_message_reaction_remove;
    break;
  case DISCORD_GATEWAY_EVENTS_MESSAGE_REACTION_REMOVE_ALL:
    if (gw->cmds.cbs.on_message_reaction_remove_all)
      on_event = &on_message_reaction_remove_all;
    break;
  case DISCORD_GATEWAY_EVENTS_MESSAGE_REACTION_REMOVE_EMOJI:
    if (gw->cmds.cbs.on_message_reaction_remove_emoji)
      on_event = &on_message_reaction_remove_emoji;
    break;
  case DISCORD_GATEWAY_EVENTS_PRESENCE_UPDATE:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_STAGE_INSTANCE_CREATE:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_STAGE_INSTANCE_DELETE:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_STAGE_INSTANCE_UPDATE:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_TYPING_START:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_USER_UPDATE:
    /** @todo implement */
    break;
  case DISCORD_GATEWAY_EVENTS_VOICE_STATE_UPDATE:
    if (gw->cmds.cbs.on_voice_state_update) on_event = &on_voice_state_update;
    break;
  case DISCORD_GATEWAY_EVENTS_VOICE_SERVER_UPDATE:
    if (gw->cmds.cbs.on_voice_server_update)
      on_event = &on_voice_server_update;
    break;
  case DISCORD_GATEWAY_EVENTS_WEBHOOKS_UPDATE:
    /** @todo implement */
    break;
  default:
    logconf_warn(&gw->conf,
                 "Expected unimplemented GATEWAY_DISPATCH event (code: %d)",
                 event);
    break;
  }

  if (!on_event) return; /* user not subscribed to event */

  mode = gw->cmds.scheduler(CLIENT(gw), &gw->bot, &gw->payload.data, event);
  switch (mode) {
  case DISCORD_EVENT_IGNORE:
    return;
  case DISCORD_EVENT_MAIN_THREAD:
    (*on_event)(gw, &gw->payload.data);
    return;
  case DISCORD_EVENT_WORKER_THREAD: {
    /* event scheduled to run from a worker thread */
    struct discord_event *cxt = malloc(sizeof *cxt);
    /* work_run return code */
    int ret;

    cxt->name = strdup(gw->payload.name);
    cxt->gw = &(discord_clone(CLIENT(gw))->gw);
    cxt->data.size =
      asprintf(&cxt->data.start, "%.*s", (int)gw->payload.data.size,
               gw->payload.data.start);
    cxt->event = event;
    cxt->on_event = on_event;

    ret = work_run(&dispatch_run, cxt);
    VASSERT_S(0 == ret, "Couldn't create task (code %d)", ret);
    return;
  }
  default:
    ERR("Unknown event handling mode (code: %d)", mode);
  }
}

static void
on_invalid_session(struct discord_gateway *gw)
{
  const char *reason;
  enum ws_close_reason opcode;

  gw->status->shutdown = true;
  gw->status->is_resumable =
    strncmp(gw->payload.data.start, "false", gw->payload.data.size);
  gw->reconnect->enable = true;

  if (gw->status->is_resumable) {
    reason = "Invalid session, will attempt to resume";
    opcode = WS_CLOSE_REASON_NO_REASON;
  }
  else {
    reason = "Invalid session, can't resume";
    opcode = WS_CLOSE_REASON_NORMAL;
  }

  ws_close(gw->ws, opcode, reason, SIZE_MAX);
}

static void
on_reconnect(struct discord_gateway *gw)
{
  const char reason[] = "Discord expects client to reconnect";

  gw->status->shutdown = true;
  gw->status->is_resumable = true;
  gw->reconnect->enable = true;

  ws_close(gw->ws, WS_CLOSE_REASON_NO_REASON, reason, sizeof(reason));
}

static void
on_heartbeat_ack(struct discord_gateway *gw)
{
  /* get request / response interval in milliseconds */
  /* TODO: pthread_rwlock_wrlock() */
  gw->hbeat.ping_ms = ws_timestamp(gw->ws) - gw->hbeat.tstamp;
  logconf_trace(&gw->conf, "PING: %d ms", gw->hbeat.ping_ms);
}

static void
on_connect_cb(void *p_gw,
              struct websockets *ws,
              struct ws_info *info,
              const char *ws_protocols)
{
  struct discord_gateway *gw = p_gw;
  logconf_info(&gw->conf, "Connected, WS-Protocols: '%s'", ws_protocols);
}

static void
on_close_cb(void *p_gw,
            struct websockets *ws,
            struct ws_info *info,
            enum ws_close_reason wscode,
            const char *reason,
            size_t len)
{
  struct discord_gateway *gw = p_gw;
  enum discord_gateway_close_opcodes opcode =
    (enum discord_gateway_close_opcodes)wscode;

  logconf_warn(
    &gw->conf,
    ANSICOLOR("CLOSE %s", ANSI_FG_RED) " (code: %4d, %zu bytes): '%.*s'",
    close_opcode_print(opcode), opcode, len, (int)len, reason);

  if (gw->status->shutdown) {
    /* user-triggered shutdown */
    gw->status->shutdown = false;
    return;
  }

  switch (opcode) {
  case DISCORD_GATEWAY_CLOSE_REASON_UNKNOWN_ERROR:
  case DISCORD_GATEWAY_CLOSE_REASON_INVALID_SEQUENCE:
  case DISCORD_GATEWAY_CLOSE_REASON_UNKNOWN_OPCODE:
  case DISCORD_GATEWAY_CLOSE_REASON_DECODE_ERROR:
  case DISCORD_GATEWAY_CLOSE_REASON_NOT_AUTHENTICATED:
  case DISCORD_GATEWAY_CLOSE_REASON_AUTHENTICATION_FAILED:
  case DISCORD_GATEWAY_CLOSE_REASON_ALREADY_AUTHENTICATED:
  case DISCORD_GATEWAY_CLOSE_REASON_RATE_LIMITED:
  case DISCORD_GATEWAY_CLOSE_REASON_SHARDING_REQUIRED:
  case DISCORD_GATEWAY_CLOSE_REASON_INVALID_API_VERSION:
  case DISCORD_GATEWAY_CLOSE_REASON_INVALID_INTENTS:
  case DISCORD_GATEWAY_CLOSE_REASON_INVALID_SHARD:
  case DISCORD_GATEWAY_CLOSE_REASON_DISALLOWED_INTENTS:
    gw->status->is_resumable = false;
    gw->reconnect->enable = false;
    break;
  default: /*websocket/clouflare opcodes */
    if (WS_CLOSE_REASON_NORMAL == (enum ws_close_reason)opcode) {
      gw->status->is_resumable = true;
      gw->reconnect->enable = false;
    }
    else {
      logconf_warn(
        &gw->conf,
        "Gateway will attempt to reconnect and start a new session");
      gw->status->is_resumable = false;
      gw->reconnect->enable = true;
    }
    break;
  case DISCORD_GATEWAY_CLOSE_REASON_SESSION_TIMED_OUT:
    logconf_warn(
      &gw->conf,
      "Gateway will attempt to reconnect and resume current session");
    gw->status->is_resumable = false;
    gw->reconnect->enable = true;
    break;
  }
}

static void
on_text_cb(void *p_gw,
           struct websockets *ws,
           struct ws_info *info,
           const char *text,
           size_t len)
{
  struct discord_gateway *gw = p_gw;
  /* check sequence value first, then assign */
  int seq = 0;

  json_extract((char *)text, len, "(t):s (s):d (op):d (d):T", gw->payload.name,
               &seq, &gw->payload.opcode, &gw->payload.data);

  if (seq) gw->payload.seq = seq;

  logconf_trace(
    &gw->conf,
    ANSICOLOR("RCV",
              ANSI_FG_BRIGHT_YELLOW) " %s%s%s (%zu bytes) [@@@_%zu_@@@]",
    opcode_print(gw->payload.opcode), (*gw->payload.name) ? " -> " : "",
    gw->payload.name, len, info->loginfo.counter);

  switch (gw->payload.opcode) {
  case DISCORD_GATEWAY_DISPATCH:
    on_dispatch(gw);
    break;
  case DISCORD_GATEWAY_INVALID_SESSION:
    on_invalid_session(gw);
    break;
  case DISCORD_GATEWAY_RECONNECT:
    on_reconnect(gw);
    break;
  case DISCORD_GATEWAY_HELLO:
    on_hello(gw);
    break;
  case DISCORD_GATEWAY_HEARTBEAT_ACK:
    on_heartbeat_ack(gw);
    break;
  default:
    logconf_error(&gw->conf, "Not yet implemented Gateway Event (code: %d)",
                  gw->payload.opcode);
    break;
  }
}

static enum discord_event_scheduler
default_scheduler_cb(struct discord *a,
                     struct discord_user *b,
                     struct sized_buffer *c,
                     enum discord_gateway_events d)
{
  return DISCORD_EVENT_MAIN_THREAD;
}

void
discord_gateway_init(struct discord_gateway *gw,
                     struct logconf *conf,
                     struct sized_buffer *token)
{
  /* Web-Sockets callbacks */
  struct ws_callbacks cbs = { 0 };
  /* Web-Sockets custom attributes */
  struct ws_attr attr = { 0 };
  /* Bot default presence status */
  struct discord_presence_status presence = { 0 };
  struct sized_buffer buf;

  cbs.data = gw;
  cbs.on_connect = &on_connect_cb;
  cbs.on_text = &on_text_cb;
  cbs.on_close = &on_close_cb;

  attr.conf = conf;
  attr.mhandle = CLIENT(gw)->mhandle;

  /* Web-Sockets handler */
  gw->ws = ws_init(&cbs, &attr);
  logconf_branch(&gw->conf, conf, "DISCORD_GATEWAY");

  /* client connection status */
  gw->status = calloc(1, sizeof *gw->status);

  /* reconnect flags */
  gw->reconnect = calloc(1, sizeof *gw->reconnect);
  gw->reconnect->enable = true;
  gw->reconnect->threshold = 5; /**< hard limit for now */
  gw->reconnect->attempt = 0;

  /* connection identify token */
  asprintf(&gw->id.token, "%.*s", (int)token->size, token->start);
  /* connection identify properties */
  gw->id.properties = calloc(1, sizeof *gw->id.properties);
  gw->id.properties->os = "POSIX";
  gw->id.properties->browser = "orca";
  gw->id.properties->device = "orca";

  /* the bot initial presence */
  gw->id.presence = calloc(1, sizeof *gw->id.presence);
  strcpy(presence.status, "online");
  presence.since = cee_timestamp_ms();
  discord_set_presence(CLIENT(gw), &presence);

  /* default callbacks */
  gw->cmds.scheduler = default_scheduler_cb;

  /* fetch and store the bot info */
  if (token->size) {
    discord_get_current_user(CLIENT(gw), &gw->bot);
    /* TODO: remove this function v */
    sb_discord_get_current_user(CLIENT(gw), &gw->sb_bot);
  }

  /* check for default prefix in config file */
  buf = logconf_get_field(conf, "discord.default_prefix");
  if (buf.size) {
    bool enable_prefix = false;
    json_extract(buf.start, buf.size, "(enable):b", &enable_prefix);

    if (enable_prefix) {
      char *prefix = NULL;
      json_extract(buf.start, buf.size, "(prefix):?s", &prefix);

      gw->cmds.prefix.start = prefix;
      gw->cmds.prefix.size = prefix ? strlen(prefix) : 0;
    }
  }
}

void
discord_gateway_cleanup(struct discord_gateway *gw)
{
  /* cleanup WebSockets handle */
  ws_cleanup(gw->ws);
  /* cleanup bot identification */
  if (gw->id.token) free(gw->id.token);
  free(gw->id.properties);
  free(gw->id.presence);
  /* free client connection status */
  free(gw->status);
  /* free client reconnect flags */
  free(gw->reconnect);
  /* cleanup user bot */
  discord_user_cleanup(&gw->bot);
  if (gw->sb_bot.start) free(gw->sb_bot.start);
  /* cleanup user commands */
  if (gw->cmds.pool) free(gw->cmds.pool);
  if (gw->cmds.prefix.start) free(gw->cmds.prefix.start);
}

/* the event loop to serve the events sent by Discord
 * TODO: move to discord-loop.c */
static ORCAcode
_discord_gateway_loop(struct discord_gateway *gw)
{
  /* get gateway bot info */
  struct sized_buffer json = { 0 };
  /* build URL that will be used to connect to Discord */
  char *base_url, url[1024];
  /* snprintf() OOB check */
  size_t ret;

  if (discord_get_gateway_bot(CLIENT(gw), &json)) {
    logconf_fatal(&gw->conf, "Couldn't retrieve Gateway Bot information");
    return ORCA_DISCORD_BAD_AUTH;
  }

  json_extract(json.start, json.size,
               "(url):?s,(shards):d,(session_start_limit):F", &base_url,
               &gw->session.shards, &discord_session_start_limit_from_json,
               &gw->session.start_limit);

  ret = snprintf(url, sizeof(url), "%s%s" DISCORD_GATEWAY_URL_SUFFIX, base_url,
                 ('/' == base_url[strlen(base_url) - 1]) ? "" : "/");
  ASSERT_S(ret < sizeof(url), "Out of bounds write attempt");

  free(json.start);
  free(base_url);

  if (!gw->session.start_limit.remaining) {
    logconf_fatal(&gw->conf,
                  "Reach sessions threshold (%d),"
                  "Please wait %d seconds and try again",
                  gw->session.start_limit.total,
                  gw->session.start_limit.reset_after / 1000);
    return ORCA_DISCORD_RATELIMIT;
  }

  ws_set_url(gw->ws, url, NULL);

  ws_start(gw->ws, NULL);
  while (1) {
    discord_request_check_timeouts_async(&CLIENT(gw)->adapter.rlimit);
    discord_request_check_pending_async(&CLIENT(gw)->adapter.rlimit);

    if (!ws_perform(gw->ws, 5)) {
      /* severed connection */
      break;
    }

    discord_request_check_results_async(&CLIENT(gw)->adapter.rlimit);

    if (!gw->status->is_ready) {
      /* wait until on_ready() */
      continue;
    }

    /* check if timespan since first pulse is greater than
     * minimum heartbeat interval required*/
    if (gw->hbeat.interval_ms < (ws_timestamp(gw->ws) - gw->hbeat.tstamp)) {
      send_heartbeat(gw);
    }

    if (gw->cmds.cbs.on_idle) ON(idle);
  }
  ws_end(gw->ws);

  gw->status->is_ready = false;

  return ORCA_OK;
}

ORCAcode
discord_gateway_run(struct discord_gateway *gw)
{
  while (gw->reconnect->attempt < gw->reconnect->threshold) {
    ORCAcode code = _discord_gateway_loop(gw);
    if (code != ORCA_OK || !gw->reconnect->enable) {
      logconf_warn(&gw->conf, "Discord Gateway Shutdown");
      return code;
    }
    ++gw->reconnect->attempt;
    logconf_info(&gw->conf, "Reconnect attempt #%d", gw->reconnect->attempt);
  }

  /* reset for next run */
  memset(&gw->status, 0, sizeof(gw->status));
  gw->reconnect->enable = false;
  gw->reconnect->attempt = 0;
  logconf_fatal(&gw->conf, "Failed reconnecting to Discord after %d tries",
                gw->reconnect->threshold);

  return ORCA_DISCORD_CONNECTION;
}

void
discord_gateway_shutdown(struct discord_gateway *gw)
{
  const char reason[] = "Client triggered shutdown";

  /* TODO: pthread_rwlock_wrlock() */
  gw->reconnect->enable = false;
  gw->status->shutdown = true;
  gw->status->is_resumable = false;

  ws_close(gw->ws, WS_CLOSE_REASON_NORMAL, reason, sizeof(reason));
}

void
discord_gateway_reconnect(struct discord_gateway *gw, bool resume)
{
  const char reason[] = "Client triggered reconnect";
  enum ws_close_reason opcode;

  /* TODO: pthread_rwlock_wrlock() */
  gw->reconnect->enable = true;
  gw->status->shutdown = true;
  gw->status->is_resumable = resume;
  opcode = gw->status->is_resumable ? WS_CLOSE_REASON_NO_REASON
                                    : WS_CLOSE_REASON_NORMAL;

  ws_close(gw->ws, opcode, reason, sizeof(reason));
}
