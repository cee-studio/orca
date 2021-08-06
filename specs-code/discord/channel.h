/* This file is generated from specs/discord/channel.json, Please don't edit it. */
/**
 * @file specs-code/discord/channel.h
 * @see https://discord.com/developers/docs/resources/channel
 */



enum discord_channel_types {
  DISCORD_CHANNEL_GUILD_TEXT = 0,
  DISCORD_CHANNEL_DM = 1,
  DISCORD_CHANNEL_GUILD_VOICE = 2,
  DISCORD_CHANNEL_GROUP_DM = 3,
  DISCORD_CHANNEL_GUILD_CATEGORY = 4,
  DISCORD_CHANNEL_GUILD_NEWS = 5,
  DISCORD_CHANNEL_GUILD_STORE = 6,
  DISCORD_CHANNEL_GUILD_NEWS_THREAD = 10,
  DISCORD_CHANNEL_GUILD_PUBLIC_THREAD = 11,
  DISCORD_CHANNEL_GUILD_PRIVATE_THREAD = 12,
  DISCORD_CHANNEL_GUILD_STAGE_VOICE = 13,
};
extern char* discord_channel_types_to_string(enum discord_channel_types);
extern enum discord_channel_types discord_channel_types_from_string(char*);
extern bool discord_channel_types_has(enum discord_channel_types, char*);

// Channel Structure
// defined at specs/discord/channel.json:29:22
/**
 * @see https://discord.com/developers/docs/resources/channel#channel-object-channel-structure
 *
 * - Initializer:
 *   - <tt> discord_channel_init(struct discord_channel *) </tt>
 * - Cleanup:
 *   - <tt> discord_channel_cleanup(struct discord_channel *) </tt>
 *   - <tt> discord_channel_list_free(struct discord_channel **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_channel_from_json(char *rbuf, size_t len, struct discord_channel **) </tt>
 *   - <tt> discord_channel_list_from_json(char *rbuf, size_t len, struct discord_channel ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_channel_to_json(char *wbuf, size_t len, struct discord_channel *) </tt>
 *   - <tt> discord_channel_list_to_json(char *wbuf, size_t len, struct discord_channel **) </tt>
 */
struct discord_channel {
  /* specs/discord/channel.json:32:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"id"}' */
  u64_snowflake_t id;

  /* specs/discord/channel.json:33:83
     '{"type":{"base":"int", "int_alias":"enum discord_channel_types"}, "name":"type"}' */
  enum discord_channel_types type;

  /* specs/discord/channel.json:34:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"guild_id",
         "option":true, "inject_if_not":0 }' */
  u64_snowflake_t guild_id;

  /* specs/discord/channel.json:36:41
     '{"type":{"base":"int"}, "name":"position",
         "option":true, "inject_if_not":0 }' */
  int position;

  /* specs/discord/channel.json:38:83
     '{"type":{"base":"struct discord_channel_overwrite", "dec":"ntl"}, "name":"permission_overwrites",
         "option":true, "inject_if_not":null }' */
  struct discord_channel_overwrite **permission_overwrites;

  /* specs/discord/channel.json:40:74
     '{"type":{"base":"char", "dec":"[DISCORD_MAX_NAME_LEN]"}, "name":"name", 
         "option":true, "inject_if_not":null}' */
  char name[DISCORD_MAX_NAME_LEN];

  /* specs/discord/channel.json:42:75
     '{"type":{"base":"char", "dec":"[DISCORD_MAX_TOPIC_LEN]"}, "name":"topic",
         "option":true, "inject_if_not":null }' */
  char topic[DISCORD_MAX_TOPIC_LEN];

  /* specs/discord/channel.json:44:42
     '{"type":{"base":"bool"}, "name":"nsfw", "option":true, "inject_if_not":false}' */
  bool nsfw;

  /* specs/discord/channel.json:45:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"last_message_id",
         "option":true, "inject_if_not":0}' */
  u64_snowflake_t last_message_id;

  /* specs/discord/channel.json:47:41
     '{"type":{"base":"int"}, "name":"bitrate", "option":true, "inject_if_not":0}' */
  int bitrate;

  /* specs/discord/channel.json:48:41
     '{"type":{"base":"int"}, "name":"user_limit", "option":true, "inject_if_not":0}' */
  int user_limit;

  /* specs/discord/channel.json:49:41
     '{"type":{"base":"int"}, "name":"rate_limit_per_user", 
         "option":true, "inject_if_not":0}' */
  int rate_limit_per_user;

  /* specs/discord/channel.json:51:70
     '{"type":{"base":"struct discord_user", "dec":"ntl"}, "name":"recipients",
         "option":true, "inject_if_not":null}' */
  struct discord_user **recipients;

  /* specs/discord/channel.json:53:68
     '{"type":{"base":"char", "dec":"[MAX_SHA256_LEN]"}, "name":"icon",
         "option":true, "inject_if_not":null}' */
  char icon[MAX_SHA256_LEN];

  /* specs/discord/channel.json:55:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"owner_id",
         "option":true, "inject_if_not":0}' */
  u64_snowflake_t owner_id;

  /* specs/discord/channel.json:57:78
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"application_id",
         "option":true, "inject_if_not":0}' */
  u64_snowflake_t application_id;

  /* specs/discord/channel.json:59:95
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake", "nullable":true}, "name":"parent_id",
         "option":true, "inject_if_not":0}' */
  u64_snowflake_t parent_id;

  /* specs/discord/channel.json:61:93
     '{"type":{"base":"char", "dec":"*", "converter":"iso8601", "nullable":true}, "name":"last_pin_timestamp",
         "option":true, "inject_if_not":0}' */
  u64_unix_ms_t last_pin_timestamp;

  /* specs/discord/channel.json:63:73
     '{"type":{"base":"struct discord_message", "dec":"ntl"}, "name":"messages"}' */
  struct discord_message **messages;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[19];
    void *record_defined[19];
    void *record_null[19];
  } __M; // metadata
/// @endcond
};
extern void discord_channel_cleanup_v(void *p);
extern void discord_channel_cleanup(struct discord_channel *p);
extern void discord_channel_init_v(void *p);
extern void discord_channel_init(struct discord_channel *p);
extern void discord_channel_from_json_v(char *json, size_t len, void *pp);
extern void discord_channel_from_json(char *json, size_t len, struct discord_channel **pp);
extern size_t discord_channel_to_json_v(char *json, size_t len, void *p);
extern size_t discord_channel_to_json(char *json, size_t len, struct discord_channel *p);
extern size_t discord_channel_to_query_v(char *json, size_t len, void *p);
extern size_t discord_channel_to_query(char *json, size_t len, struct discord_channel *p);
extern void discord_channel_list_free_v(void **p);
extern void discord_channel_list_free(struct discord_channel **p);
extern void discord_channel_list_from_json_v(char *str, size_t len, void *p);
extern void discord_channel_list_from_json(char *str, size_t len, struct discord_channel ***p);
extern size_t discord_channel_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_channel_list_to_json(char *str, size_t len, struct discord_channel **p);


enum discord_message_sticker_format_types {
  DISCORD_MESSAGE_STICKER_PNG = 1,
  DISCORD_MESSAGE_STICKER_APNG = 2,
  DISCORD_MESSAGE_STICKER_LOTTIE = 3,
};
extern char* discord_message_sticker_format_types_to_string(enum discord_message_sticker_format_types);
extern enum discord_message_sticker_format_types discord_message_sticker_format_types_from_string(char*);
extern bool discord_message_sticker_format_types_has(enum discord_message_sticker_format_types, char*);

// Message Sticker Structure
// defined at specs/discord/channel.json:82:22
/**
 * @see https://discord.com/developers/docs/resources/channel#message-object-message-sticker-structure
 *
 * - Initializer:
 *   - <tt> discord_message_sticker_init(struct discord_message_sticker *) </tt>
 * - Cleanup:
 *   - <tt> discord_message_sticker_cleanup(struct discord_message_sticker *) </tt>
 *   - <tt> discord_message_sticker_list_free(struct discord_message_sticker **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_message_sticker_from_json(char *rbuf, size_t len, struct discord_message_sticker **) </tt>
 *   - <tt> discord_message_sticker_list_from_json(char *rbuf, size_t len, struct discord_message_sticker ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_message_sticker_to_json(char *wbuf, size_t len, struct discord_message_sticker *) </tt>
 *   - <tt> discord_message_sticker_list_to_json(char *wbuf, size_t len, struct discord_message_sticker **) </tt>
 */
struct discord_message_sticker {
  /* specs/discord/channel.json:84:18
     '{"name":"id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}}' */
  u64_snowflake_t id;

  /* specs/discord/channel.json:85:18
     '{"name":"pack_id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}}' */
  u64_snowflake_t pack_id;

  /* specs/discord/channel.json:86:18
     '{"name":"name", "type":{"base":"char", "dec":"*"}}' */
  char *name;

  /* specs/discord/channel.json:87:18
     '{"name":"description", "type":{"base":"char", "dec":"*"}}' */
  char *description;

  /* specs/discord/channel.json:88:18
     '{"name":"tags", "type":{"base":"char", "dec":"*"}, "option":true, "inject_of_not":null}' */
  char *tags;

  /* specs/discord/channel.json:89:18
     '{"name":"asset","type":{"base":"char", "dec":"[MAX_SHA256_LEN]"}}' */
  char asset[MAX_SHA256_LEN];

  /* specs/discord/channel.json:90:18
     '{"name":"preview_asset", "type":{"base":"char", "dec":"[MAX_SHA256_LEN]"}, 
         "option":true, "inject_if_not":null}' */
  char preview_asset[MAX_SHA256_LEN];

  /* specs/discord/channel.json:92:18
     '{"name":"type", "type":{"base":"int", "int_alias":"enum discord_message_sticker_format_types"}}' */
  enum discord_message_sticker_format_types type;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[8];
    void *record_defined[8];
    void *record_null[8];
  } __M; // metadata
/// @endcond
};
extern void discord_message_sticker_cleanup_v(void *p);
extern void discord_message_sticker_cleanup(struct discord_message_sticker *p);
extern void discord_message_sticker_init_v(void *p);
extern void discord_message_sticker_init(struct discord_message_sticker *p);
extern void discord_message_sticker_from_json_v(char *json, size_t len, void *pp);
extern void discord_message_sticker_from_json(char *json, size_t len, struct discord_message_sticker **pp);
extern size_t discord_message_sticker_to_json_v(char *json, size_t len, void *p);
extern size_t discord_message_sticker_to_json(char *json, size_t len, struct discord_message_sticker *p);
extern size_t discord_message_sticker_to_query_v(char *json, size_t len, void *p);
extern size_t discord_message_sticker_to_query(char *json, size_t len, struct discord_message_sticker *p);
extern void discord_message_sticker_list_free_v(void **p);
extern void discord_message_sticker_list_free(struct discord_message_sticker **p);
extern void discord_message_sticker_list_from_json_v(char *str, size_t len, void *p);
extern void discord_message_sticker_list_from_json(char *str, size_t len, struct discord_message_sticker ***p);
extern size_t discord_message_sticker_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_message_sticker_list_to_json(char *str, size_t len, struct discord_message_sticker **p);


enum discord_message_flags {
  DISCORD_MESSAGE_CROSSPOSTED = 1, // 1<<0
  DISCORD_MESSAGE_IS_CROSSPOST = 2, // 1<<1
  DISCORD_MESSAGE_SUPRESS_EMBEDS = 4, // 1<<2
  DISCORD_MESSAGE_SOURCE_MESSAGE_DELETED = 8, // 1<<3
  DISCORD_MESSAGE_URGENT = 16, // 1<<4
};
extern char* discord_message_flags_to_string(enum discord_message_flags);
extern enum discord_message_flags discord_message_flags_from_string(char*);
extern bool discord_message_flags_has(enum discord_message_flags, char*);

// Message Reference Structure
// defined at specs/discord/channel.json:112:22
/**
 * @see https://discord.com/developers/docs/resources/channel#message-object-message-reference-structure
 *
 * - Initializer:
 *   - <tt> discord_message_reference_init(struct discord_message_reference *) </tt>
 * - Cleanup:
 *   - <tt> discord_message_reference_cleanup(struct discord_message_reference *) </tt>
 *   - <tt> discord_message_reference_list_free(struct discord_message_reference **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_message_reference_from_json(char *rbuf, size_t len, struct discord_message_reference **) </tt>
 *   - <tt> discord_message_reference_list_from_json(char *rbuf, size_t len, struct discord_message_reference ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_message_reference_to_json(char *wbuf, size_t len, struct discord_message_reference *) </tt>
 *   - <tt> discord_message_reference_list_to_json(char *wbuf, size_t len, struct discord_message_reference **) </tt>
 */
struct discord_message_reference {
  /* specs/discord/channel.json:114:18
     '{"name":"message_id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}, "option":true, "inject_if_not":0}' */
  u64_snowflake_t message_id;

  /* specs/discord/channel.json:115:18
     '{"name":"channel_id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}, "option":true, "inject_if_not":0}' */
  u64_snowflake_t channel_id;

  /* specs/discord/channel.json:116:18
     '{"name":"guild_id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}, "option":true, "inject_if_not":0}' */
  u64_snowflake_t guild_id;

  /* specs/discord/channel.json:117:18
     '{"name":"fail_if_not_exists", "type":{"base":"bool"}, "option":true, "inject_if_not":false}' */
  bool fail_if_not_exists;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[4];
    void *record_defined[4];
    void *record_null[4];
  } __M; // metadata
/// @endcond
};
extern void discord_message_reference_cleanup_v(void *p);
extern void discord_message_reference_cleanup(struct discord_message_reference *p);
extern void discord_message_reference_init_v(void *p);
extern void discord_message_reference_init(struct discord_message_reference *p);
extern void discord_message_reference_from_json_v(char *json, size_t len, void *pp);
extern void discord_message_reference_from_json(char *json, size_t len, struct discord_message_reference **pp);
extern size_t discord_message_reference_to_json_v(char *json, size_t len, void *p);
extern size_t discord_message_reference_to_json(char *json, size_t len, struct discord_message_reference *p);
extern size_t discord_message_reference_to_query_v(char *json, size_t len, void *p);
extern size_t discord_message_reference_to_query(char *json, size_t len, struct discord_message_reference *p);
extern void discord_message_reference_list_free_v(void **p);
extern void discord_message_reference_list_free(struct discord_message_reference **p);
extern void discord_message_reference_list_from_json_v(char *str, size_t len, void *p);
extern void discord_message_reference_list_from_json(char *str, size_t len, struct discord_message_reference ***p);
extern size_t discord_message_reference_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_message_reference_list_to_json(char *str, size_t len, struct discord_message_reference **p);

// Message Application Structure
// defined at specs/discord/channel.json:124:22
/**
 * @see https://discord.com/developers/docs/resources/channel#message-object-message-application-structure
 *
 * - Initializer:
 *   - <tt> discord_message_application_init(struct discord_message_application *) </tt>
 * - Cleanup:
 *   - <tt> discord_message_application_cleanup(struct discord_message_application *) </tt>
 *   - <tt> discord_message_application_list_free(struct discord_message_application **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_message_application_from_json(char *rbuf, size_t len, struct discord_message_application **) </tt>
 *   - <tt> discord_message_application_list_from_json(char *rbuf, size_t len, struct discord_message_application ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_message_application_to_json(char *wbuf, size_t len, struct discord_message_application *) </tt>
 *   - <tt> discord_message_application_list_to_json(char *wbuf, size_t len, struct discord_message_application **) </tt>
 */
struct discord_message_application {
  /* specs/discord/channel.json:126:18
     '{"name":"id", "type":{"base":"char", "dec":"*", "converter":"snowflake"}}' */
  u64_snowflake_t id;

  /* specs/discord/channel.json:127:18
     '{"name":"cover_image", "type":{"base":"char", "dec":"*"}, "option":true, "inject_if_not":null}' */
  char *cover_image;

  /* specs/discord/channel.json:128:18
     '{"name":"description", "type":{"base":"char", "dec":"*"}}' */
  char *description;

  /* specs/discord/channel.json:129:18
     '{"name":"icon", "type":{"base":"char", "dec":"*"}, "inject_if_not":null}' */
  char *icon;

  /* specs/discord/channel.json:130:18
     '{"name":"name", "type":{"base":"char", "dec":"*"}}' */
  char *name;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[5];
    void *record_defined[5];
    void *record_null[5];
  } __M; // metadata
/// @endcond
};
extern void discord_message_application_cleanup_v(void *p);
extern void discord_message_application_cleanup(struct discord_message_application *p);
extern void discord_message_application_init_v(void *p);
extern void discord_message_application_init(struct discord_message_application *p);
extern void discord_message_application_from_json_v(char *json, size_t len, void *pp);
extern void discord_message_application_from_json(char *json, size_t len, struct discord_message_application **pp);
extern size_t discord_message_application_to_json_v(char *json, size_t len, void *p);
extern size_t discord_message_application_to_json(char *json, size_t len, struct discord_message_application *p);
extern size_t discord_message_application_to_query_v(char *json, size_t len, void *p);
extern size_t discord_message_application_to_query(char *json, size_t len, struct discord_message_application *p);
extern void discord_message_application_list_free_v(void **p);
extern void discord_message_application_list_free(struct discord_message_application **p);
extern void discord_message_application_list_from_json_v(char *str, size_t len, void *p);
extern void discord_message_application_list_from_json(char *str, size_t len, struct discord_message_application ***p);
extern size_t discord_message_application_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_message_application_list_to_json(char *str, size_t len, struct discord_message_application **p);


enum discord_message_activity_types {
  DISCORD_MESSAGE_ACTIVITY_JOIN = 1,
  DISCORD_MESSAGE_ACTIVITY_SPECTATE = 2,
  DISCORD_MESSAGE_ACTIVITY_LISTEN = 3,
  DISCORD_MESSAGE_ACTIVITY_JOIN_REQUEST = 5,
};
extern char* discord_message_activity_types_to_string(enum discord_message_activity_types);
extern enum discord_message_activity_types discord_message_activity_types_from_string(char*);
extern bool discord_message_activity_types_has(enum discord_message_activity_types, char*);

// Message Activity Structure
// defined at specs/discord/channel.json:149:22
/**
 * @see https://discord.com/developers/docs/resources/channel#message-object-message-activity-structure
 *
 * - Initializer:
 *   - <tt> discord_message_activity_init(struct discord_message_activity *) </tt>
 * - Cleanup:
 *   - <tt> discord_message_activity_cleanup(struct discord_message_activity *) </tt>
 *   - <tt> discord_message_activity_list_free(struct discord_message_activity **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_message_activity_from_json(char *rbuf, size_t len, struct discord_message_activity **) </tt>
 *   - <tt> discord_message_activity_list_from_json(char *rbuf, size_t len, struct discord_message_activity ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_message_activity_to_json(char *wbuf, size_t len, struct discord_message_activity *) </tt>
 *   - <tt> discord_message_activity_list_to_json(char *wbuf, size_t len, struct discord_message_activity **) </tt>
 */
struct discord_message_activity {
  /* specs/discord/channel.json:151:18
     '{"name":"type", "type":{"base":"int", "int_alias":"enum discord_message_activity_types"}}' */
  enum discord_message_activity_types type;

  /* specs/discord/channel.json:152:18
     '{"name":"party_id", "type":{"base":"char", "dec":"*"},
         "option":true, "inject_if_not":null}' */
  char *party_id;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[2];
    void *record_defined[2];
    void *record_null[2];
  } __M; // metadata
/// @endcond
};
extern void discord_message_activity_cleanup_v(void *p);
extern void discord_message_activity_cleanup(struct discord_message_activity *p);
extern void discord_message_activity_init_v(void *p);
extern void discord_message_activity_init(struct discord_message_activity *p);
extern void discord_message_activity_from_json_v(char *json, size_t len, void *pp);
extern void discord_message_activity_from_json(char *json, size_t len, struct discord_message_activity **pp);
extern size_t discord_message_activity_to_json_v(char *json, size_t len, void *p);
extern size_t discord_message_activity_to_json(char *json, size_t len, struct discord_message_activity *p);
extern size_t discord_message_activity_to_query_v(char *json, size_t len, void *p);
extern size_t discord_message_activity_to_query(char *json, size_t len, struct discord_message_activity *p);
extern void discord_message_activity_list_free_v(void **p);
extern void discord_message_activity_list_free(struct discord_message_activity **p);
extern void discord_message_activity_list_from_json_v(char *str, size_t len, void *p);
extern void discord_message_activity_list_from_json(char *str, size_t len, struct discord_message_activity ***p);
extern size_t discord_message_activity_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_message_activity_list_to_json(char *str, size_t len, struct discord_message_activity **p);


enum discord_message_types {
  DISCORD_MESSAGE_DEFAULT = 0,
  DISCORD_MESSAGE_RECIPIENT_ADD = 1,
  DISCORD_MESSAGE_RECIPIENT_REMOVE = 3,
  DISCORD_MESSAGE_CALL = 5,
  DISCORD_MESSAGE_CHANNEL_NAME_CHANGE = 5,
  DISCORD_MESSAGE_CHANNEL_ICON_CHANGE = 5,
  DISCORD_MESSAGE_CHANNEL_PINNED_MESSAGE = 5,
  DISCORD_MESSAGE_GUILD_MEMBER_JOIN = 5,
  DISCORD_MESSAGE_USER_PREMIUM_GUILD_SUBSCRIPTION = 5,
  DISCORD_MESSAGE_USER_PREMIUM_GUILD_SUBSCRIPTION_TIER_1 = 9,
  DISCORD_MESSAGE_USER_PREMIUM_GUILD_SUBSCRIPTION_TIER_2 = 10,
  DISCORD_MESSAGE_USER_PREMIUM_GUILD_SUBSCRIPTION_TIER_3 = 11,
  DISCORD_MESSAGE_CHANNEL_FOLLOW_ADD = 12,
  DISCORD_MESSAGE_GUILD_DISCOVERY_DISQUALIFIED = 14,
  DISCORD_MESSAGE_GUILD_DISCOVERY_REQUALIFIED = 15,
  DISCORD_MESSAGE_REPLY = 19,
  DISCORD_MESSAGE_APPLICATION_COMMAND = 20,
};
extern char* discord_message_types_to_string(enum discord_message_types);
extern enum discord_message_types discord_message_types_from_string(char*);
extern bool discord_message_types_has(enum discord_message_types, char*);

// Message Structure
// defined at specs/discord/channel.json:184:22
/**
 * @see https://discord.com/developers/docs/resources/channel#message-object
 *
 * - Initializer:
 *   - <tt> discord_message_init(struct discord_message *) </tt>
 * - Cleanup:
 *   - <tt> discord_message_cleanup(struct discord_message *) </tt>
 *   - <tt> discord_message_list_free(struct discord_message **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_message_from_json(char *rbuf, size_t len, struct discord_message **) </tt>
 *   - <tt> discord_message_list_from_json(char *rbuf, size_t len, struct discord_message ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_message_to_json(char *wbuf, size_t len, struct discord_message *) </tt>
 *   - <tt> discord_message_list_to_json(char *wbuf, size_t len, struct discord_message **) </tt>
 */
struct discord_message {
  /* specs/discord/channel.json:186:79
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"id"}' */
  u64_snowflake_t id;

  /* specs/discord/channel.json:187:79
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"channel_id"}' */
  u64_snowflake_t channel_id;

  /* specs/discord/channel.json:188:79
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"guild_id", "option":true, "inject_if_not":0}' */
  u64_snowflake_t guild_id;

  /* specs/discord/channel.json:189:69
     '{"type":{"base":"struct discord_user", "dec":"*"}, "name":"author"}' */
  struct discord_user *author;

  /* specs/discord/channel.json:190:77
     '{"type":{"base":"struct discord_guild_member", "dec":"*"}, "name":"member", "option":true, "comment":"partial guild member object"}' */
  struct discord_guild_member *member; ///< partial guild member object

  /* specs/discord/channel.json:191:54
     '{"type":{"base":"char", "dec":"*"}, "name":"content"}' */
  char *content;

  /* specs/discord/channel.json:192:76
     '{"type":{"base":"char", "dec":"*", "converter":"iso8601"},"name":"timestamp"}' */
  u64_unix_ms_t timestamp;

  /* specs/discord/channel.json:193:77
     '{"type":{"base":"char", "dec":"*", "converter":"iso8601"}, "name":"edited_timestamp", "inject_if_not":0}' */
  u64_unix_ms_t edited_timestamp;

  /* specs/discord/channel.json:194:43
     '{"type":{"base":"bool"}, "name":"tts"}' */
  bool tts;

  /* specs/discord/channel.json:195:43
     '{"type":{"base":"bool"}, "name":"mention_everyone"}' */
  bool mention_everyone;

  /* specs/discord/channel.json:196:71
     '{"type":{"base":"struct discord_user", "dec":"ntl"}, "name":"mentions", "comment":"array of user objects, with an additional partial member field"}' */
  struct discord_user **mentions; ///< array of user objects, with an additional partial member field

  /* specs/discord/channel.json:197:58
     '{"type":{"base":"ja_u64", "dec":"ntl"}, "name":"mention_roles", "comment":"array of role object ids"}' */
  ja_u64 **mention_roles; ///< array of role object ids

  /* specs/discord/channel.json:198:82
     '{"type":{"base":"struct discord_channel_mention", "dec":"ntl"}, "name":"mention_channels", "option":true }' */
  struct discord_channel_mention **mention_channels;

  /* specs/discord/channel.json:199:85
     '{"type":{"base":"struct discord_channel_attachment", "dec":"ntl"}, "name":"attachments"}' */
  struct discord_channel_attachment **attachments;

  /* specs/discord/channel.json:200:72
     '{"type":{"base":"struct discord_embed", "dec":"ntl"}, "name":"embeds"}' */
  struct discord_embed **embeds;

  /* specs/discord/channel.json:201:82
     '{"type":{"base":"struct discord_channel_reaction","dec":"ntl"}, "name":"reactions", "option":true }' */
  struct discord_channel_reaction **reactions;

  /* specs/discord/channel.json:202:54
     '{"type":{"base":"char", "dec":"*"}, "name":"nonce", "comment":"integer or string", "option":true }' */
  char *nonce; ///< integer or string

  /* specs/discord/channel.json:203:43
     '{"type":{"base":"bool"}, "name":"pinned"}' */
  bool pinned;

  /* specs/discord/channel.json:204:79
     '{"type":{"base":"char", "dec":"*", "converter":"snowflake"}, "name":"webhook_id", "option":true }' */
  u64_snowflake_t webhook_id;

  /* specs/discord/channel.json:205:84
     '{"type":{"base":"int", "int_alias":"enum discord_message_types"}, "name":"type"}' */
  enum discord_message_types type;

  /* specs/discord/channel.json:206:81
     '{"type":{"base":"struct discord_message_activity", "dec":"*"}, "name":"activity", "option":true, "inject_if_not":null }' */
  struct discord_message_activity *activity;

  /* specs/discord/channel.json:207:86
     '{"type":{"base":"struct discord_message_application", "dec":"ntl"}, "name":"application", "option":true, "inject_if_not":null }' */
  struct discord_message_application **application;

  /* specs/discord/channel.json:208:82
     '{"type":{"base":"struct discord_message_reference", "dec":"*"}, "name":"message_reference", "option":true, "inject_if_not":null }' */
  struct discord_message_reference *message_reference;

  /* specs/discord/channel.json:209:84
     '{"type":{"base":"int", "int_alias":"enum discord_message_flags"}, "name":"flags", "option":true, "inject_if_not":0 }' */
  enum discord_message_flags flags;

  /* specs/discord/channel.json:210:72
     '{"type":{"base":"struct discord_message", "dec":"*"}, "name":"referenced_message", "lazy_init":true, "option":true, "inject_if_not":null, "comment":"this will cause recursive allocation if allocating as the parent"}' */
  struct discord_message *referenced_message; ///< this will cause recursive allocation if allocating as the parent

  /* specs/discord/channel.json:211:84
     '{"type":{"base":"struct discord_message_interaction", "dec":"*"}, "name":"interaction", "option":true, "inject_if_not":null, "comment":"the message associated with the message_reference"}' */
  struct discord_message_interaction *interaction; ///< the message associated with the message_reference

  /* specs/discord/channel.json:212:72
     '{"type":{"base":"struct discord_channel", "dec":"*"}, "name":"thread", "option":true, "inject_if_not":null, "comment":"the channel that was started from this message, includes thread member obejct"}' */
  struct discord_channel *thread; ///< the channel that was started from this message, includes thread member obejct

  /* specs/discord/channel.json:213:76
     '{"type":{"base":"struct discord_component", "dec":"ntl"}, "name":"components", "option":true, "inject_if_not":null, "comment":"sent if the message contains components like buttons, actions rows, or other interactive components"}' */
  struct discord_component **components; ///< sent if the message contains components like buttons, actions rows, or other interactive components

  /* specs/discord/channel.json:214:82
     '{"type":{"base":"struct discord_message_sticker", "dec":"ntl"}, "name":"sticker_items", "option":true, "inject_if_not":null, "comment":"sent if the message contains stickets"}' */
  struct discord_message_sticker **sticker_items; ///< sent if the message contains stickets

  /* specs/discord/channel.json:215:82
     '{"type":{"base":"struct discord_message_sticker", "dec":"ntl"}, "name":"stickers", "option":true, "inject_if_not":null, "comment":"[DEPRECATED] array of sticker objects"}' */
  struct discord_message_sticker **stickers; ///< [DEPRECATED] array of sticker objects

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[30];
    void *record_defined[30];
    void *record_null[30];
  } __M; // metadata
/// @endcond
};
extern void discord_message_cleanup_v(void *p);
extern void discord_message_cleanup(struct discord_message *p);
extern void discord_message_init_v(void *p);
extern void discord_message_init(struct discord_message *p);
extern void discord_message_from_json_v(char *json, size_t len, void *pp);
extern void discord_message_from_json(char *json, size_t len, struct discord_message **pp);
extern size_t discord_message_to_json_v(char *json, size_t len, void *p);
extern size_t discord_message_to_json(char *json, size_t len, struct discord_message *p);
extern size_t discord_message_to_query_v(char *json, size_t len, void *p);
extern size_t discord_message_to_query(char *json, size_t len, struct discord_message *p);
extern void discord_message_list_free_v(void **p);
extern void discord_message_list_free(struct discord_message **p);
extern void discord_message_list_from_json_v(char *str, size_t len, void *p);
extern void discord_message_list_from_json(char *str, size_t len, struct discord_message ***p);
extern size_t discord_message_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_message_list_to_json(char *str, size_t len, struct discord_message **p);

// Followed Channel Structure
// defined at specs/discord/channel.json:222:22
/**
 * @see https://discord.com/developers/docs/resources/channel#followed-channel-object-followed-channel-structure
 *
 * - Initializer:
 *   - <tt> discord_channel_followed_channel_init(struct discord_channel_followed_channel *) </tt>
 * - Cleanup:
 *   - <tt> discord_channel_followed_channel_cleanup(struct discord_channel_followed_channel *) </tt>
 *   - <tt> discord_channel_followed_channel_list_free(struct discord_channel_followed_channel **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_channel_followed_channel_from_json(char *rbuf, size_t len, struct discord_channel_followed_channel **) </tt>
 *   - <tt> discord_channel_followed_channel_list_from_json(char *rbuf, size_t len, struct discord_channel_followed_channel ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_channel_followed_channel_to_json(char *wbuf, size_t len, struct discord_channel_followed_channel *) </tt>
 *   - <tt> discord_channel_followed_channel_list_to_json(char *wbuf, size_t len, struct discord_channel_followed_channel **) </tt>
 */
struct discord_channel_followed_channel {
  /* specs/discord/channel.json:225:20
     '{ "name": "channel_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  u64_snowflake_t channel_id;

  /* specs/discord/channel.json:226:20
     '{ "name": "webhook_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  u64_snowflake_t webhook_id;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[2];
    void *record_defined[2];
    void *record_null[2];
  } __M; // metadata
/// @endcond
};
extern void discord_channel_followed_channel_cleanup_v(void *p);
extern void discord_channel_followed_channel_cleanup(struct discord_channel_followed_channel *p);
extern void discord_channel_followed_channel_init_v(void *p);
extern void discord_channel_followed_channel_init(struct discord_channel_followed_channel *p);
extern void discord_channel_followed_channel_from_json_v(char *json, size_t len, void *pp);
extern void discord_channel_followed_channel_from_json(char *json, size_t len, struct discord_channel_followed_channel **pp);
extern size_t discord_channel_followed_channel_to_json_v(char *json, size_t len, void *p);
extern size_t discord_channel_followed_channel_to_json(char *json, size_t len, struct discord_channel_followed_channel *p);
extern size_t discord_channel_followed_channel_to_query_v(char *json, size_t len, void *p);
extern size_t discord_channel_followed_channel_to_query(char *json, size_t len, struct discord_channel_followed_channel *p);
extern void discord_channel_followed_channel_list_free_v(void **p);
extern void discord_channel_followed_channel_list_free(struct discord_channel_followed_channel **p);
extern void discord_channel_followed_channel_list_from_json_v(char *str, size_t len, void *p);
extern void discord_channel_followed_channel_list_from_json(char *str, size_t len, struct discord_channel_followed_channel ***p);
extern size_t discord_channel_followed_channel_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_channel_followed_channel_list_to_json(char *str, size_t len, struct discord_channel_followed_channel **p);

// Reaction Structure
// defined at specs/discord/channel.json:233:22
/**
 * @see https://discord.com/developers/docs/resources/channel#reaction-object-reaction-structure
 *
 * - Initializer:
 *   - <tt> discord_channel_reaction_init(struct discord_channel_reaction *) </tt>
 * - Cleanup:
 *   - <tt> discord_channel_reaction_cleanup(struct discord_channel_reaction *) </tt>
 *   - <tt> discord_channel_reaction_list_free(struct discord_channel_reaction **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_channel_reaction_from_json(char *rbuf, size_t len, struct discord_channel_reaction **) </tt>
 *   - <tt> discord_channel_reaction_list_from_json(char *rbuf, size_t len, struct discord_channel_reaction ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_channel_reaction_to_json(char *wbuf, size_t len, struct discord_channel_reaction *) </tt>
 *   - <tt> discord_channel_reaction_list_to_json(char *wbuf, size_t len, struct discord_channel_reaction **) </tt>
 */
struct discord_channel_reaction {
  /* specs/discord/channel.json:236:20
     '{ "name": "count", "type":{ "base":"int" }}' */
  int count;

  /* specs/discord/channel.json:237:20
     '{ "name": "me", "type":{ "base":"bool" }}' */
  bool me;

  /* specs/discord/channel.json:238:20
     '{ "name": "emoji", "type":{ "base":"struct discord_emoji", "dec":"*" }, "comment":"partial emoji object"}' */
  struct discord_emoji *emoji; ///< partial emoji object

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[3];
    void *record_defined[3];
    void *record_null[3];
  } __M; // metadata
/// @endcond
};
extern void discord_channel_reaction_cleanup_v(void *p);
extern void discord_channel_reaction_cleanup(struct discord_channel_reaction *p);
extern void discord_channel_reaction_init_v(void *p);
extern void discord_channel_reaction_init(struct discord_channel_reaction *p);
extern void discord_channel_reaction_from_json_v(char *json, size_t len, void *pp);
extern void discord_channel_reaction_from_json(char *json, size_t len, struct discord_channel_reaction **pp);
extern size_t discord_channel_reaction_to_json_v(char *json, size_t len, void *p);
extern size_t discord_channel_reaction_to_json(char *json, size_t len, struct discord_channel_reaction *p);
extern size_t discord_channel_reaction_to_query_v(char *json, size_t len, void *p);
extern size_t discord_channel_reaction_to_query(char *json, size_t len, struct discord_channel_reaction *p);
extern void discord_channel_reaction_list_free_v(void **p);
extern void discord_channel_reaction_list_free(struct discord_channel_reaction **p);
extern void discord_channel_reaction_list_from_json_v(char *str, size_t len, void *p);
extern void discord_channel_reaction_list_from_json(char *str, size_t len, struct discord_channel_reaction ***p);
extern size_t discord_channel_reaction_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_channel_reaction_list_to_json(char *str, size_t len, struct discord_channel_reaction **p);

// Overwrite Structure
// defined at specs/discord/channel.json:244:22
/**
 * - Initializer:
 *   - <tt> discord_channel_overwrite_init(struct discord_channel_overwrite *) </tt>
 * - Cleanup:
 *   - <tt> discord_channel_overwrite_cleanup(struct discord_channel_overwrite *) </tt>
 *   - <tt> discord_channel_overwrite_list_free(struct discord_channel_overwrite **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_channel_overwrite_from_json(char *rbuf, size_t len, struct discord_channel_overwrite **) </tt>
 *   - <tt> discord_channel_overwrite_list_from_json(char *rbuf, size_t len, struct discord_channel_overwrite ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_channel_overwrite_to_json(char *wbuf, size_t len, struct discord_channel_overwrite *) </tt>
 *   - <tt> discord_channel_overwrite_list_to_json(char *wbuf, size_t len, struct discord_channel_overwrite **) </tt>
 */
struct discord_channel_overwrite {
  /* specs/discord/channel.json:247:20
     '{ "name": "id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  u64_snowflake_t id;

  /* specs/discord/channel.json:248:20
     '{ "name": "type", "type":{ "base":"int" }}' */
  int type;

  /* specs/discord/channel.json:249:20
     '{ "name": "allow", "type":{ "base":"s_as_hex_uint", "int_alias":"enum discord_permissions_bitwise_flags"}, 
          "comment":"permission bit set"}' */
  enum discord_permissions_bitwise_flags allow; ///< permission bit set

  /* specs/discord/channel.json:251:20
     '{ "name": "deny", "type":{ "base":"s_as_hex_uint", "int_alias":"enum discord_permissions_bitwise_flags"}, 
          "comment":"permission bit set"}' */
  enum discord_permissions_bitwise_flags deny; ///< permission bit set

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[4];
    void *record_defined[4];
    void *record_null[4];
  } __M; // metadata
/// @endcond
};
extern void discord_channel_overwrite_cleanup_v(void *p);
extern void discord_channel_overwrite_cleanup(struct discord_channel_overwrite *p);
extern void discord_channel_overwrite_init_v(void *p);
extern void discord_channel_overwrite_init(struct discord_channel_overwrite *p);
extern void discord_channel_overwrite_from_json_v(char *json, size_t len, void *pp);
extern void discord_channel_overwrite_from_json(char *json, size_t len, struct discord_channel_overwrite **pp);
extern size_t discord_channel_overwrite_to_json_v(char *json, size_t len, void *p);
extern size_t discord_channel_overwrite_to_json(char *json, size_t len, struct discord_channel_overwrite *p);
extern size_t discord_channel_overwrite_to_query_v(char *json, size_t len, void *p);
extern size_t discord_channel_overwrite_to_query(char *json, size_t len, struct discord_channel_overwrite *p);
extern void discord_channel_overwrite_list_free_v(void **p);
extern void discord_channel_overwrite_list_free(struct discord_channel_overwrite **p);
extern void discord_channel_overwrite_list_from_json_v(char *str, size_t len, void *p);
extern void discord_channel_overwrite_list_from_json(char *str, size_t len, struct discord_channel_overwrite ***p);
extern size_t discord_channel_overwrite_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_channel_overwrite_list_to_json(char *str, size_t len, struct discord_channel_overwrite **p);

// Thread Metadata Object
// defined at specs/discord/channel.json:259:22
/**
 * @see https://discord.com/developers/docs/resources/channel#thread-metadata-object
 *
 * - Initializer:
 *   - <tt> discord_thread_metadata_init(struct discord_thread_metadata *) </tt>
 * - Cleanup:
 *   - <tt> discord_thread_metadata_cleanup(struct discord_thread_metadata *) </tt>
 *   - <tt> discord_thread_metadata_list_free(struct discord_thread_metadata **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_thread_metadata_from_json(char *rbuf, size_t len, struct discord_thread_metadata **) </tt>
 *   - <tt> discord_thread_metadata_list_from_json(char *rbuf, size_t len, struct discord_thread_metadata ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_thread_metadata_to_json(char *wbuf, size_t len, struct discord_thread_metadata *) </tt>
 *   - <tt> discord_thread_metadata_list_to_json(char *wbuf, size_t len, struct discord_thread_metadata **) </tt>
 */
struct discord_thread_metadata {
  /* specs/discord/channel.json:262:20
     '{ "name": "archived", "type":{ "base":"bool" }}' */
  bool archived;

  /* specs/discord/channel.json:263:20
     '{ "name": "archiver_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  u64_snowflake_t archiver_id;

  /* specs/discord/channel.json:264:20
     '{ "name": "auto_archive_duration", "type":{ "base":"int" }}' */
  int auto_archive_duration;

  /* specs/discord/channel.json:265:20
     '{ "name": "archive_timestamp", "type":{ "base":"char", "dec":"*", "converter":"iso8601" }}' */
  u64_unix_ms_t archive_timestamp;

  /* specs/discord/channel.json:266:20
     '{ "name": "locked", "type":{ "base":"bool" }}' */
  bool locked;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[5];
    void *record_defined[5];
    void *record_null[5];
  } __M; // metadata
/// @endcond
};
extern void discord_thread_metadata_cleanup_v(void *p);
extern void discord_thread_metadata_cleanup(struct discord_thread_metadata *p);
extern void discord_thread_metadata_init_v(void *p);
extern void discord_thread_metadata_init(struct discord_thread_metadata *p);
extern void discord_thread_metadata_from_json_v(char *json, size_t len, void *pp);
extern void discord_thread_metadata_from_json(char *json, size_t len, struct discord_thread_metadata **pp);
extern size_t discord_thread_metadata_to_json_v(char *json, size_t len, void *p);
extern size_t discord_thread_metadata_to_json(char *json, size_t len, struct discord_thread_metadata *p);
extern size_t discord_thread_metadata_to_query_v(char *json, size_t len, void *p);
extern size_t discord_thread_metadata_to_query(char *json, size_t len, struct discord_thread_metadata *p);
extern void discord_thread_metadata_list_free_v(void **p);
extern void discord_thread_metadata_list_free(struct discord_thread_metadata **p);
extern void discord_thread_metadata_list_from_json_v(char *str, size_t len, void *p);
extern void discord_thread_metadata_list_from_json(char *str, size_t len, struct discord_thread_metadata ***p);
extern size_t discord_thread_metadata_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_thread_metadata_list_to_json(char *str, size_t len, struct discord_thread_metadata **p);

// Thread Member Object
// defined at specs/discord/channel.json:273:22
/**
 * @see https://discord.com/developers/docs/resources/channel#thread-member-object
 *
 * - Initializer:
 *   - <tt> discord_thread_member_init(struct discord_thread_member *) </tt>
 * - Cleanup:
 *   - <tt> discord_thread_member_cleanup(struct discord_thread_member *) </tt>
 *   - <tt> discord_thread_member_list_free(struct discord_thread_member **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_thread_member_from_json(char *rbuf, size_t len, struct discord_thread_member **) </tt>
 *   - <tt> discord_thread_member_list_from_json(char *rbuf, size_t len, struct discord_thread_member ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_thread_member_to_json(char *wbuf, size_t len, struct discord_thread_member *) </tt>
 *   - <tt> discord_thread_member_list_to_json(char *wbuf, size_t len, struct discord_thread_member **) </tt>
 */
struct discord_thread_member {
  /* specs/discord/channel.json:276:20
     '{ "name": "id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  u64_snowflake_t id;

  /* specs/discord/channel.json:277:20
     '{ "name": "user_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  u64_snowflake_t user_id;

  /* specs/discord/channel.json:278:20
     '{ "name": "join_timestamp", "type":{ "base":"char", "dec":"*", "converter":"iso8601" }}' */
  u64_unix_ms_t join_timestamp;

  /* specs/discord/channel.json:279:20
     '{ "name": "flags", "type":{ "base":"int" }}' */
  int flags;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[4];
    void *record_defined[4];
    void *record_null[4];
  } __M; // metadata
/// @endcond
};
extern void discord_thread_member_cleanup_v(void *p);
extern void discord_thread_member_cleanup(struct discord_thread_member *p);
extern void discord_thread_member_init_v(void *p);
extern void discord_thread_member_init(struct discord_thread_member *p);
extern void discord_thread_member_from_json_v(char *json, size_t len, void *pp);
extern void discord_thread_member_from_json(char *json, size_t len, struct discord_thread_member **pp);
extern size_t discord_thread_member_to_json_v(char *json, size_t len, void *p);
extern size_t discord_thread_member_to_json(char *json, size_t len, struct discord_thread_member *p);
extern size_t discord_thread_member_to_query_v(char *json, size_t len, void *p);
extern size_t discord_thread_member_to_query(char *json, size_t len, struct discord_thread_member *p);
extern void discord_thread_member_list_free_v(void **p);
extern void discord_thread_member_list_free(struct discord_thread_member **p);
extern void discord_thread_member_list_from_json_v(char *str, size_t len, void *p);
extern void discord_thread_member_list_from_json(char *str, size_t len, struct discord_thread_member ***p);
extern size_t discord_thread_member_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_thread_member_list_to_json(char *str, size_t len, struct discord_thread_member **p);

// Attachment Strcture
// defined at specs/discord/channel.json:286:22
/**
 * @see https://discord.com/developers/docs/resources/channel#attachment-object
 *
 * - Initializer:
 *   - <tt> discord_channel_attachment_init(struct discord_channel_attachment *) </tt>
 * - Cleanup:
 *   - <tt> discord_channel_attachment_cleanup(struct discord_channel_attachment *) </tt>
 *   - <tt> discord_channel_attachment_list_free(struct discord_channel_attachment **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_channel_attachment_from_json(char *rbuf, size_t len, struct discord_channel_attachment **) </tt>
 *   - <tt> discord_channel_attachment_list_from_json(char *rbuf, size_t len, struct discord_channel_attachment ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_channel_attachment_to_json(char *wbuf, size_t len, struct discord_channel_attachment *) </tt>
 *   - <tt> discord_channel_attachment_list_to_json(char *wbuf, size_t len, struct discord_channel_attachment **) </tt>
 */
struct discord_channel_attachment {
  /* specs/discord/channel.json:289:20
     '{ "name": "id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  u64_snowflake_t id;

  /* specs/discord/channel.json:290:20
     '{ "name": "filename", "type":{ "base":"char", "dec":"[256]" }}' */
  char filename[256];

  /* specs/discord/channel.json:291:20
     '{ "name": "size", "type":{ "base":"int" }}' */
  int size;

  /* specs/discord/channel.json:292:20
     '{ "name": "url", "type":{ "base":"char", "dec":"*" }}' */
  char *url;

  /* specs/discord/channel.json:293:20
     '{ "name": "proxy_url", "type":{ "base":"char", "dec":"*" }}' */
  char *proxy_url;

  /* specs/discord/channel.json:294:20
     '{ "name": "height", "type":{ "base":"int", "nullable":true }}' */
  int height;

  /* specs/discord/channel.json:295:20
     '{ "name": "width", "type":{ "base":"int", "nullable":true }}' */
  int width;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[7];
    void *record_defined[7];
    void *record_null[7];
  } __M; // metadata
/// @endcond
};
extern void discord_channel_attachment_cleanup_v(void *p);
extern void discord_channel_attachment_cleanup(struct discord_channel_attachment *p);
extern void discord_channel_attachment_init_v(void *p);
extern void discord_channel_attachment_init(struct discord_channel_attachment *p);
extern void discord_channel_attachment_from_json_v(char *json, size_t len, void *pp);
extern void discord_channel_attachment_from_json(char *json, size_t len, struct discord_channel_attachment **pp);
extern size_t discord_channel_attachment_to_json_v(char *json, size_t len, void *p);
extern size_t discord_channel_attachment_to_json(char *json, size_t len, struct discord_channel_attachment *p);
extern size_t discord_channel_attachment_to_query_v(char *json, size_t len, void *p);
extern size_t discord_channel_attachment_to_query(char *json, size_t len, struct discord_channel_attachment *p);
extern void discord_channel_attachment_list_free_v(void **p);
extern void discord_channel_attachment_list_free(struct discord_channel_attachment **p);
extern void discord_channel_attachment_list_from_json_v(char *str, size_t len, void *p);
extern void discord_channel_attachment_list_from_json(char *str, size_t len, struct discord_channel_attachment ***p);
extern size_t discord_channel_attachment_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_channel_attachment_list_to_json(char *str, size_t len, struct discord_channel_attachment **p);

// Channel Mention Structure
// defined at specs/discord/channel.json:302:22
/**
 * @see https://discord.com/developers/docs/resources/channel#channel-mention-object-channel-mention-structure
 *
 * - Initializer:
 *   - <tt> discord_channel_mention_init(struct discord_channel_mention *) </tt>
 * - Cleanup:
 *   - <tt> discord_channel_mention_cleanup(struct discord_channel_mention *) </tt>
 *   - <tt> discord_channel_mention_list_free(struct discord_channel_mention **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_channel_mention_from_json(char *rbuf, size_t len, struct discord_channel_mention **) </tt>
 *   - <tt> discord_channel_mention_list_from_json(char *rbuf, size_t len, struct discord_channel_mention ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_channel_mention_to_json(char *wbuf, size_t len, struct discord_channel_mention *) </tt>
 *   - <tt> discord_channel_mention_list_to_json(char *wbuf, size_t len, struct discord_channel_mention **) </tt>
 */
struct discord_channel_mention {
  /* specs/discord/channel.json:305:20
     '{ "name": "id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  u64_snowflake_t id;

  /* specs/discord/channel.json:306:20
     '{ "name": "guild_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }}' */
  u64_snowflake_t guild_id;

  /* specs/discord/channel.json:307:20
     '{ "name": "type", "type":{ "base":"int", "int_alias":"enum discord_channel_types" }}' */
  enum discord_channel_types type;

  /* specs/discord/channel.json:308:20
     '{ "name": "name", "type":{ "base":"char", "dec":"*" }}' */
  char *name;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[4];
    void *record_defined[4];
    void *record_null[4];
  } __M; // metadata
/// @endcond
};
extern void discord_channel_mention_cleanup_v(void *p);
extern void discord_channel_mention_cleanup(struct discord_channel_mention *p);
extern void discord_channel_mention_init_v(void *p);
extern void discord_channel_mention_init(struct discord_channel_mention *p);
extern void discord_channel_mention_from_json_v(char *json, size_t len, void *pp);
extern void discord_channel_mention_from_json(char *json, size_t len, struct discord_channel_mention **pp);
extern size_t discord_channel_mention_to_json_v(char *json, size_t len, void *p);
extern size_t discord_channel_mention_to_json(char *json, size_t len, struct discord_channel_mention *p);
extern size_t discord_channel_mention_to_query_v(char *json, size_t len, void *p);
extern size_t discord_channel_mention_to_query(char *json, size_t len, struct discord_channel_mention *p);
extern void discord_channel_mention_list_free_v(void **p);
extern void discord_channel_mention_list_free(struct discord_channel_mention **p);
extern void discord_channel_mention_list_from_json_v(char *str, size_t len, void *p);
extern void discord_channel_mention_list_from_json(char *str, size_t len, struct discord_channel_mention ***p);
extern size_t discord_channel_mention_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_channel_mention_list_to_json(char *str, size_t len, struct discord_channel_mention **p);

// Allowed Mentions Structure
// defined at specs/discord/channel.json:315:22
/**
 * @see https://discord.com/developers/docs/resources/channel#allowed-mentions-object-allowed-mentions-structure
 *
 * - Initializer:
 *   - <tt> discord_channel_allowed_mentions_init(struct discord_channel_allowed_mentions *) </tt>
 * - Cleanup:
 *   - <tt> discord_channel_allowed_mentions_cleanup(struct discord_channel_allowed_mentions *) </tt>
 *   - <tt> discord_channel_allowed_mentions_list_free(struct discord_channel_allowed_mentions **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_channel_allowed_mentions_from_json(char *rbuf, size_t len, struct discord_channel_allowed_mentions **) </tt>
 *   - <tt> discord_channel_allowed_mentions_list_from_json(char *rbuf, size_t len, struct discord_channel_allowed_mentions ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_channel_allowed_mentions_to_json(char *wbuf, size_t len, struct discord_channel_allowed_mentions *) </tt>
 *   - <tt> discord_channel_allowed_mentions_list_to_json(char *wbuf, size_t len, struct discord_channel_allowed_mentions **) </tt>
 */
struct discord_channel_allowed_mentions {
  /* specs/discord/channel.json:318:20
     '{ "name": "parse", "type":{ "base":"ja_str", "dec":"ntl" }}' */
  ja_str **parse;

  /* specs/discord/channel.json:319:20
     '{ "name": "roles", "type":{ "base":"ja_u64", "dec":"ntl" }, "comment":"list of snowflakes"}' */
  ja_u64 **roles; ///< list of snowflakes

  /* specs/discord/channel.json:320:20
     '{ "name": "users", "type":{ "base":"ja_u64", "dec":"ntl" }, "comment":"list of snowflakes"}' */
  ja_u64 **users; ///< list of snowflakes

  /* specs/discord/channel.json:321:20
     '{ "name": "replied_user", "type":{ "base":"bool" }}' */
  bool replied_user;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[4];
    void *record_defined[4];
    void *record_null[4];
  } __M; // metadata
/// @endcond
};
extern void discord_channel_allowed_mentions_cleanup_v(void *p);
extern void discord_channel_allowed_mentions_cleanup(struct discord_channel_allowed_mentions *p);
extern void discord_channel_allowed_mentions_init_v(void *p);
extern void discord_channel_allowed_mentions_init(struct discord_channel_allowed_mentions *p);
extern void discord_channel_allowed_mentions_from_json_v(char *json, size_t len, void *pp);
extern void discord_channel_allowed_mentions_from_json(char *json, size_t len, struct discord_channel_allowed_mentions **pp);
extern size_t discord_channel_allowed_mentions_to_json_v(char *json, size_t len, void *p);
extern size_t discord_channel_allowed_mentions_to_json(char *json, size_t len, struct discord_channel_allowed_mentions *p);
extern size_t discord_channel_allowed_mentions_to_query_v(char *json, size_t len, void *p);
extern size_t discord_channel_allowed_mentions_to_query(char *json, size_t len, struct discord_channel_allowed_mentions *p);
extern void discord_channel_allowed_mentions_list_free_v(void **p);
extern void discord_channel_allowed_mentions_list_free(struct discord_channel_allowed_mentions **p);
extern void discord_channel_allowed_mentions_list_from_json_v(char *str, size_t len, void *p);
extern void discord_channel_allowed_mentions_list_from_json(char *str, size_t len, struct discord_channel_allowed_mentions ***p);
extern size_t discord_channel_allowed_mentions_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_channel_allowed_mentions_list_to_json(char *str, size_t len, struct discord_channel_allowed_mentions **p);

// Embed Structure
// defined at specs/discord/channel.json:327:22
/**
 * @see https://discord.com/developers/docs/resources/channel#embed-object-embed-structure
 *
 * - Initializer:
 *   - <tt> discord_embed_init(struct discord_embed *) </tt>
 * - Cleanup:
 *   - <tt> discord_embed_cleanup(struct discord_embed *) </tt>
 *   - <tt> discord_embed_list_free(struct discord_embed **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_embed_from_json(char *rbuf, size_t len, struct discord_embed **) </tt>
 *   - <tt> discord_embed_list_from_json(char *rbuf, size_t len, struct discord_embed ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_embed_to_json(char *wbuf, size_t len, struct discord_embed *) </tt>
 *   - <tt> discord_embed_list_to_json(char *wbuf, size_t len, struct discord_embed **) </tt>
 */
struct discord_embed {
  /* specs/discord/channel.json:330:20
     '{ "name": "title", "type":{ "base":"char", "dec":"[DISCORD_EMBED_TITLE_LEN]" }, "option":true, "inject_if_not":null}' */
  char title[DISCORD_EMBED_TITLE_LEN];

  /* specs/discord/channel.json:331:20
     '{ "name": "type", "type":{ "base":"char", "dec":"[32]" }, "option":true, "inject_if_not":null}' */
  char type[32];

  /* specs/discord/channel.json:332:20
     '{ "name": "description", "type":{ "base":"char", "dec":"[DISCORD_EMBED_DESCRIPTION_LEN]"}, "option":true, "inject_if_not":null}' */
  char description[DISCORD_EMBED_DESCRIPTION_LEN];

  /* specs/discord/channel.json:333:20
     '{ "name": "url", "type":{ "base":"char", "dec":"*"}, "option":true, "inject_if_not":null}' */
  char *url;

  /* specs/discord/channel.json:334:20
     '{ "name": "timestamp", "type":{ "base":"char", "dec":"*", "converter":"iso8601" }, "option":true, "inject_if_not":0}' */
  u64_unix_ms_t timestamp;

  /* specs/discord/channel.json:335:20
     '{ "name": "color", "type":{ "base":"int" }, "option":true, "inject_if_not":0}' */
  int color;

  /* specs/discord/channel.json:336:20
     '{ "name": "footer", "type":{ "base":"struct discord_embed_footer", "dec":"*"}, "option":true, "inject_if_not":null}' */
  struct discord_embed_footer *footer;

  /* specs/discord/channel.json:337:20
     '{ "name": "image", "type":{ "base":"struct discord_embed_image", "dec":"*"}, "inject_if_not":null}' */
  struct discord_embed_image *image;

  /* specs/discord/channel.json:338:20
     '{ "name": "thumbnail", "type":{ "base":"struct discord_embed_thumbnail", "dec":"*"}, "inject_if_not":null}' */
  struct discord_embed_thumbnail *thumbnail;

  /* specs/discord/channel.json:339:20
     '{ "name": "video", "type":{ "base":"struct discord_embed_video", "dec":"*"}, "inject_if_not":null}' */
  struct discord_embed_video *video;

  /* specs/discord/channel.json:340:20
     '{ "name": "provider", "type":{ "base":"struct discord_embed_provider", "dec":"*"}, "inject_if_not":null}' */
  struct discord_embed_provider *provider;

  /* specs/discord/channel.json:341:20
     '{ "name": "author", "type":{ "base":"struct discord_embed_author", "dec":"*"}, "inject_if_not":null}' */
  struct discord_embed_author *author;

  /* specs/discord/channel.json:342:20
     '{ "name": "fields", "type":{ "base":"struct discord_embed_field", "dec":"ntl"}, "option":true, "inject_if_not":null}' */
  struct discord_embed_field **fields;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[13];
    void *record_defined[13];
    void *record_null[13];
  } __M; // metadata
/// @endcond
};
extern void discord_embed_cleanup_v(void *p);
extern void discord_embed_cleanup(struct discord_embed *p);
extern void discord_embed_init_v(void *p);
extern void discord_embed_init(struct discord_embed *p);
extern void discord_embed_from_json_v(char *json, size_t len, void *pp);
extern void discord_embed_from_json(char *json, size_t len, struct discord_embed **pp);
extern size_t discord_embed_to_json_v(char *json, size_t len, void *p);
extern size_t discord_embed_to_json(char *json, size_t len, struct discord_embed *p);
extern size_t discord_embed_to_query_v(char *json, size_t len, void *p);
extern size_t discord_embed_to_query(char *json, size_t len, struct discord_embed *p);
extern void discord_embed_list_free_v(void **p);
extern void discord_embed_list_free(struct discord_embed **p);
extern void discord_embed_list_from_json_v(char *str, size_t len, void *p);
extern void discord_embed_list_from_json(char *str, size_t len, struct discord_embed ***p);
extern size_t discord_embed_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_embed_list_to_json(char *str, size_t len, struct discord_embed **p);

// Embed Thumbnail Structure
// defined at specs/discord/channel.json:349:22
/**
 * @see https://discord.com/developers/docs/resources/channel#embed-object-embed-thumbnail-structure
 *
 * - Initializer:
 *   - <tt> discord_embed_thumbnail_init(struct discord_embed_thumbnail *) </tt>
 * - Cleanup:
 *   - <tt> discord_embed_thumbnail_cleanup(struct discord_embed_thumbnail *) </tt>
 *   - <tt> discord_embed_thumbnail_list_free(struct discord_embed_thumbnail **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_embed_thumbnail_from_json(char *rbuf, size_t len, struct discord_embed_thumbnail **) </tt>
 *   - <tt> discord_embed_thumbnail_list_from_json(char *rbuf, size_t len, struct discord_embed_thumbnail ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_embed_thumbnail_to_json(char *wbuf, size_t len, struct discord_embed_thumbnail *) </tt>
 *   - <tt> discord_embed_thumbnail_list_to_json(char *wbuf, size_t len, struct discord_embed_thumbnail **) </tt>
 */
struct discord_embed_thumbnail {
  /* specs/discord/channel.json:351:20
     '{ "name": "url", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null}' */
  char *url;

  /* specs/discord/channel.json:352:20
     '{ "name": "proxy_url", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null}' */
  char *proxy_url;

  /* specs/discord/channel.json:353:20
     '{ "name": "height", "type":{ "base":"int" }, "inject_if_not":0}' */
  int height;

  /* specs/discord/channel.json:354:20
     '{ "name": "width", "type":{ "base":"int" }, "inject_if_not":0}' */
  int width;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[4];
    void *record_defined[4];
    void *record_null[4];
  } __M; // metadata
/// @endcond
};
extern void discord_embed_thumbnail_cleanup_v(void *p);
extern void discord_embed_thumbnail_cleanup(struct discord_embed_thumbnail *p);
extern void discord_embed_thumbnail_init_v(void *p);
extern void discord_embed_thumbnail_init(struct discord_embed_thumbnail *p);
extern void discord_embed_thumbnail_from_json_v(char *json, size_t len, void *pp);
extern void discord_embed_thumbnail_from_json(char *json, size_t len, struct discord_embed_thumbnail **pp);
extern size_t discord_embed_thumbnail_to_json_v(char *json, size_t len, void *p);
extern size_t discord_embed_thumbnail_to_json(char *json, size_t len, struct discord_embed_thumbnail *p);
extern size_t discord_embed_thumbnail_to_query_v(char *json, size_t len, void *p);
extern size_t discord_embed_thumbnail_to_query(char *json, size_t len, struct discord_embed_thumbnail *p);
extern void discord_embed_thumbnail_list_free_v(void **p);
extern void discord_embed_thumbnail_list_free(struct discord_embed_thumbnail **p);
extern void discord_embed_thumbnail_list_from_json_v(char *str, size_t len, void *p);
extern void discord_embed_thumbnail_list_from_json(char *str, size_t len, struct discord_embed_thumbnail ***p);
extern size_t discord_embed_thumbnail_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_embed_thumbnail_list_to_json(char *str, size_t len, struct discord_embed_thumbnail **p);

// Embed Video Structure
// defined at specs/discord/channel.json:361:22
/**
 * @see https://discord.com/developers/docs/resources/channel#embed-object-embed-video-structure
 *
 * - Initializer:
 *   - <tt> discord_embed_video_init(struct discord_embed_video *) </tt>
 * - Cleanup:
 *   - <tt> discord_embed_video_cleanup(struct discord_embed_video *) </tt>
 *   - <tt> discord_embed_video_list_free(struct discord_embed_video **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_embed_video_from_json(char *rbuf, size_t len, struct discord_embed_video **) </tt>
 *   - <tt> discord_embed_video_list_from_json(char *rbuf, size_t len, struct discord_embed_video ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_embed_video_to_json(char *wbuf, size_t len, struct discord_embed_video *) </tt>
 *   - <tt> discord_embed_video_list_to_json(char *wbuf, size_t len, struct discord_embed_video **) </tt>
 */
struct discord_embed_video {
  /* specs/discord/channel.json:363:20
     '{ "name": "url", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null}' */
  char *url;

  /* specs/discord/channel.json:364:20
     '{ "name": "proxy_url", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null}' */
  char *proxy_url;

  /* specs/discord/channel.json:365:20
     '{ "name": "height", "type":{ "base":"int" }, "inject_if_not":0}' */
  int height;

  /* specs/discord/channel.json:366:20
     '{ "name": "width", "type":{ "base":"int" }, "inject_if_not":0}' */
  int width;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[4];
    void *record_defined[4];
    void *record_null[4];
  } __M; // metadata
/// @endcond
};
extern void discord_embed_video_cleanup_v(void *p);
extern void discord_embed_video_cleanup(struct discord_embed_video *p);
extern void discord_embed_video_init_v(void *p);
extern void discord_embed_video_init(struct discord_embed_video *p);
extern void discord_embed_video_from_json_v(char *json, size_t len, void *pp);
extern void discord_embed_video_from_json(char *json, size_t len, struct discord_embed_video **pp);
extern size_t discord_embed_video_to_json_v(char *json, size_t len, void *p);
extern size_t discord_embed_video_to_json(char *json, size_t len, struct discord_embed_video *p);
extern size_t discord_embed_video_to_query_v(char *json, size_t len, void *p);
extern size_t discord_embed_video_to_query(char *json, size_t len, struct discord_embed_video *p);
extern void discord_embed_video_list_free_v(void **p);
extern void discord_embed_video_list_free(struct discord_embed_video **p);
extern void discord_embed_video_list_from_json_v(char *str, size_t len, void *p);
extern void discord_embed_video_list_from_json(char *str, size_t len, struct discord_embed_video ***p);
extern size_t discord_embed_video_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_embed_video_list_to_json(char *str, size_t len, struct discord_embed_video **p);

// Embed Image Structure
// defined at specs/discord/channel.json:373:22
/**
 * @see https://discord.com/developers/docs/resources/channel#embed-object-embed-image-structure
 *
 * - Initializer:
 *   - <tt> discord_embed_image_init(struct discord_embed_image *) </tt>
 * - Cleanup:
 *   - <tt> discord_embed_image_cleanup(struct discord_embed_image *) </tt>
 *   - <tt> discord_embed_image_list_free(struct discord_embed_image **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_embed_image_from_json(char *rbuf, size_t len, struct discord_embed_image **) </tt>
 *   - <tt> discord_embed_image_list_from_json(char *rbuf, size_t len, struct discord_embed_image ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_embed_image_to_json(char *wbuf, size_t len, struct discord_embed_image *) </tt>
 *   - <tt> discord_embed_image_list_to_json(char *wbuf, size_t len, struct discord_embed_image **) </tt>
 */
struct discord_embed_image {
  /* specs/discord/channel.json:375:20
     '{ "name": "url", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null}' */
  char *url;

  /* specs/discord/channel.json:376:20
     '{ "name": "proxy_url", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null}' */
  char *proxy_url;

  /* specs/discord/channel.json:377:20
     '{ "name": "height", "type":{ "base":"int" }, "inject_if_not":0}' */
  int height;

  /* specs/discord/channel.json:378:20
     '{ "name": "width", "type":{ "base":"int" }, "inject_if_not":0}' */
  int width;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[4];
    void *record_defined[4];
    void *record_null[4];
  } __M; // metadata
/// @endcond
};
extern void discord_embed_image_cleanup_v(void *p);
extern void discord_embed_image_cleanup(struct discord_embed_image *p);
extern void discord_embed_image_init_v(void *p);
extern void discord_embed_image_init(struct discord_embed_image *p);
extern void discord_embed_image_from_json_v(char *json, size_t len, void *pp);
extern void discord_embed_image_from_json(char *json, size_t len, struct discord_embed_image **pp);
extern size_t discord_embed_image_to_json_v(char *json, size_t len, void *p);
extern size_t discord_embed_image_to_json(char *json, size_t len, struct discord_embed_image *p);
extern size_t discord_embed_image_to_query_v(char *json, size_t len, void *p);
extern size_t discord_embed_image_to_query(char *json, size_t len, struct discord_embed_image *p);
extern void discord_embed_image_list_free_v(void **p);
extern void discord_embed_image_list_free(struct discord_embed_image **p);
extern void discord_embed_image_list_from_json_v(char *str, size_t len, void *p);
extern void discord_embed_image_list_from_json(char *str, size_t len, struct discord_embed_image ***p);
extern size_t discord_embed_image_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_embed_image_list_to_json(char *str, size_t len, struct discord_embed_image **p);

// Embed Provider Structure
// defined at specs/discord/channel.json:385:22
/**
 * @see https://discord.com/developers/docs/resources/channel#embed-object-embed-provider-structure
 *
 * - Initializer:
 *   - <tt> discord_embed_provider_init(struct discord_embed_provider *) </tt>
 * - Cleanup:
 *   - <tt> discord_embed_provider_cleanup(struct discord_embed_provider *) </tt>
 *   - <tt> discord_embed_provider_list_free(struct discord_embed_provider **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_embed_provider_from_json(char *rbuf, size_t len, struct discord_embed_provider **) </tt>
 *   - <tt> discord_embed_provider_list_from_json(char *rbuf, size_t len, struct discord_embed_provider ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_embed_provider_to_json(char *wbuf, size_t len, struct discord_embed_provider *) </tt>
 *   - <tt> discord_embed_provider_list_to_json(char *wbuf, size_t len, struct discord_embed_provider **) </tt>
 */
struct discord_embed_provider {
  /* specs/discord/channel.json:387:20
     '{ "name": "name", "type":{"base":"char", "dec":"*"}, "inject_if_not":null}' */
  char *name;

  /* specs/discord/channel.json:388:20
     '{ "name": "url", "type":{"base":"char", "dec":"*"}, "inject_if_not":null}' */
  char *url;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[2];
    void *record_defined[2];
    void *record_null[2];
  } __M; // metadata
/// @endcond
};
extern void discord_embed_provider_cleanup_v(void *p);
extern void discord_embed_provider_cleanup(struct discord_embed_provider *p);
extern void discord_embed_provider_init_v(void *p);
extern void discord_embed_provider_init(struct discord_embed_provider *p);
extern void discord_embed_provider_from_json_v(char *json, size_t len, void *pp);
extern void discord_embed_provider_from_json(char *json, size_t len, struct discord_embed_provider **pp);
extern size_t discord_embed_provider_to_json_v(char *json, size_t len, void *p);
extern size_t discord_embed_provider_to_json(char *json, size_t len, struct discord_embed_provider *p);
extern size_t discord_embed_provider_to_query_v(char *json, size_t len, void *p);
extern size_t discord_embed_provider_to_query(char *json, size_t len, struct discord_embed_provider *p);
extern void discord_embed_provider_list_free_v(void **p);
extern void discord_embed_provider_list_free(struct discord_embed_provider **p);
extern void discord_embed_provider_list_from_json_v(char *str, size_t len, void *p);
extern void discord_embed_provider_list_from_json(char *str, size_t len, struct discord_embed_provider ***p);
extern size_t discord_embed_provider_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_embed_provider_list_to_json(char *str, size_t len, struct discord_embed_provider **p);

// Embed Author Structure
// defined at specs/discord/channel.json:395:22
/**
 * @see https://discord.com/developers/docs/resources/channel#embed-object-embed-author-structure
 *
 * - Initializer:
 *   - <tt> discord_embed_author_init(struct discord_embed_author *) </tt>
 * - Cleanup:
 *   - <tt> discord_embed_author_cleanup(struct discord_embed_author *) </tt>
 *   - <tt> discord_embed_author_list_free(struct discord_embed_author **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_embed_author_from_json(char *rbuf, size_t len, struct discord_embed_author **) </tt>
 *   - <tt> discord_embed_author_list_from_json(char *rbuf, size_t len, struct discord_embed_author ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_embed_author_to_json(char *wbuf, size_t len, struct discord_embed_author *) </tt>
 *   - <tt> discord_embed_author_list_to_json(char *wbuf, size_t len, struct discord_embed_author **) </tt>
 */
struct discord_embed_author {
  /* specs/discord/channel.json:397:20
     '{ "name": "name", "type":{ "base":"char", "dec":"[DISCORD_EMBED_AUTHOR_NAME_LEN]" }, "inject_if_not":null}' */
  char name[DISCORD_EMBED_AUTHOR_NAME_LEN];

  /* specs/discord/channel.json:398:20
     '{ "name": "url", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null}' */
  char *url;

  /* specs/discord/channel.json:399:20
     '{ "name": "icon_url", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null}' */
  char *icon_url;

  /* specs/discord/channel.json:400:20
     '{ "name": "proxy_icon_url", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null}' */
  char *proxy_icon_url;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[4];
    void *record_defined[4];
    void *record_null[4];
  } __M; // metadata
/// @endcond
};
extern void discord_embed_author_cleanup_v(void *p);
extern void discord_embed_author_cleanup(struct discord_embed_author *p);
extern void discord_embed_author_init_v(void *p);
extern void discord_embed_author_init(struct discord_embed_author *p);
extern void discord_embed_author_from_json_v(char *json, size_t len, void *pp);
extern void discord_embed_author_from_json(char *json, size_t len, struct discord_embed_author **pp);
extern size_t discord_embed_author_to_json_v(char *json, size_t len, void *p);
extern size_t discord_embed_author_to_json(char *json, size_t len, struct discord_embed_author *p);
extern size_t discord_embed_author_to_query_v(char *json, size_t len, void *p);
extern size_t discord_embed_author_to_query(char *json, size_t len, struct discord_embed_author *p);
extern void discord_embed_author_list_free_v(void **p);
extern void discord_embed_author_list_free(struct discord_embed_author **p);
extern void discord_embed_author_list_from_json_v(char *str, size_t len, void *p);
extern void discord_embed_author_list_from_json(char *str, size_t len, struct discord_embed_author ***p);
extern size_t discord_embed_author_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_embed_author_list_to_json(char *str, size_t len, struct discord_embed_author **p);

// Embed Footer Structure
// defined at specs/discord/channel.json:407:22
/**
 * @see https://discord.com/developers/docs/resources/channel#embed-object-embed-footer-structure
 *
 * - Initializer:
 *   - <tt> discord_embed_footer_init(struct discord_embed_footer *) </tt>
 * - Cleanup:
 *   - <tt> discord_embed_footer_cleanup(struct discord_embed_footer *) </tt>
 *   - <tt> discord_embed_footer_list_free(struct discord_embed_footer **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_embed_footer_from_json(char *rbuf, size_t len, struct discord_embed_footer **) </tt>
 *   - <tt> discord_embed_footer_list_from_json(char *rbuf, size_t len, struct discord_embed_footer ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_embed_footer_to_json(char *wbuf, size_t len, struct discord_embed_footer *) </tt>
 *   - <tt> discord_embed_footer_list_to_json(char *wbuf, size_t len, struct discord_embed_footer **) </tt>
 */
struct discord_embed_footer {
  /* specs/discord/channel.json:409:20
     '{ "name": "text", "type": {"base":"char", "dec":"[DISCORD_EMBED_FOOTER_TEXT_LEN]"}, "inject_if_not":null}' */
  char text[DISCORD_EMBED_FOOTER_TEXT_LEN];

  /* specs/discord/channel.json:410:20
     '{ "name": "icon_url", "type": {"base":"char", "dec":"*" }, "option":true, "inject_if_not":null}' */
  char *icon_url;

  /* specs/discord/channel.json:411:20
     '{ "name": "proxy_icon_url", "type": {"base":"char", "dec":"*"}, "option":true, "inject_if_not":null}' */
  char *proxy_icon_url;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[3];
    void *record_defined[3];
    void *record_null[3];
  } __M; // metadata
/// @endcond
};
extern void discord_embed_footer_cleanup_v(void *p);
extern void discord_embed_footer_cleanup(struct discord_embed_footer *p);
extern void discord_embed_footer_init_v(void *p);
extern void discord_embed_footer_init(struct discord_embed_footer *p);
extern void discord_embed_footer_from_json_v(char *json, size_t len, void *pp);
extern void discord_embed_footer_from_json(char *json, size_t len, struct discord_embed_footer **pp);
extern size_t discord_embed_footer_to_json_v(char *json, size_t len, void *p);
extern size_t discord_embed_footer_to_json(char *json, size_t len, struct discord_embed_footer *p);
extern size_t discord_embed_footer_to_query_v(char *json, size_t len, void *p);
extern size_t discord_embed_footer_to_query(char *json, size_t len, struct discord_embed_footer *p);
extern void discord_embed_footer_list_free_v(void **p);
extern void discord_embed_footer_list_free(struct discord_embed_footer **p);
extern void discord_embed_footer_list_from_json_v(char *str, size_t len, void *p);
extern void discord_embed_footer_list_from_json(char *str, size_t len, struct discord_embed_footer ***p);
extern size_t discord_embed_footer_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_embed_footer_list_to_json(char *str, size_t len, struct discord_embed_footer **p);

// Embed Field Structure
// defined at specs/discord/channel.json:418:22
/**
 * @see https://discord.com/developers/docs/resources/channel#embed-object-embed-field-structure
 *
 * - Initializer:
 *   - <tt> discord_embed_field_init(struct discord_embed_field *) </tt>
 * - Cleanup:
 *   - <tt> discord_embed_field_cleanup(struct discord_embed_field *) </tt>
 *   - <tt> discord_embed_field_list_free(struct discord_embed_field **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_embed_field_from_json(char *rbuf, size_t len, struct discord_embed_field **) </tt>
 *   - <tt> discord_embed_field_list_from_json(char *rbuf, size_t len, struct discord_embed_field ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_embed_field_to_json(char *wbuf, size_t len, struct discord_embed_field *) </tt>
 *   - <tt> discord_embed_field_list_to_json(char *wbuf, size_t len, struct discord_embed_field **) </tt>
 */
struct discord_embed_field {
  /* specs/discord/channel.json:420:20
     '{ "name": "name", "type": { "base":"char", "dec":"[DISCORD_EMBED_FIELD_NAME_LEN]" }, "inject_if_not":null}' */
  char name[DISCORD_EMBED_FIELD_NAME_LEN];

  /* specs/discord/channel.json:421:20
     '{ "name": "value", "type": { "base":"char", "dec":"[DISCORD_EMBED_FIELD_VALUE_LEN]" }, "inject_if_not":null}' */
  char value[DISCORD_EMBED_FIELD_VALUE_LEN];

  /* specs/discord/channel.json:422:20
     '{ "name": "Inline", "json_key":"inline", "type": { "base":"bool" }, "option":true}' */
  bool Inline;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[3];
    void *record_defined[3];
    void *record_null[3];
  } __M; // metadata
/// @endcond
};
extern void discord_embed_field_cleanup_v(void *p);
extern void discord_embed_field_cleanup(struct discord_embed_field *p);
extern void discord_embed_field_init_v(void *p);
extern void discord_embed_field_init(struct discord_embed_field *p);
extern void discord_embed_field_from_json_v(char *json, size_t len, void *pp);
extern void discord_embed_field_from_json(char *json, size_t len, struct discord_embed_field **pp);
extern size_t discord_embed_field_to_json_v(char *json, size_t len, void *p);
extern size_t discord_embed_field_to_json(char *json, size_t len, struct discord_embed_field *p);
extern size_t discord_embed_field_to_query_v(char *json, size_t len, void *p);
extern size_t discord_embed_field_to_query(char *json, size_t len, struct discord_embed_field *p);
extern void discord_embed_field_list_free_v(void **p);
extern void discord_embed_field_list_free(struct discord_embed_field **p);
extern void discord_embed_field_list_from_json_v(char *str, size_t len, void *p);
extern void discord_embed_field_list_from_json(char *str, size_t len, struct discord_embed_field ***p);
extern size_t discord_embed_field_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_embed_field_list_to_json(char *str, size_t len, struct discord_embed_field **p);
