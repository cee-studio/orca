/* This file is generated from specs/discord/channel.endpoints-params.json, Please don't edit it. */
/**
 * @file specs-code/discord/channel.endpoints-params.h
 * @see https://discord.com/developers/docs/resources/channel
 */


// Modify Channel
// defined at specs/discord/channel.endpoints-params.json:10:22
/**
 * @see https://discord.com/developers/docs/resources/channel#modify-channel
 *
 * - Initializer:
 *   - <tt> void discord_modify_channel_params_init(struct discord_modify_channel_params *) </tt>
 * - Cleanup:
 *   - <tt> void discord_modify_channel_params_cleanup(struct discord_modify_channel_params *) </tt>
 *   - <tt> void discord_modify_channel_params_list_free(struct discord_modify_channel_params **) </tt>
 * - JSON Decoder:
 *   - <tt> void discord_modify_channel_params_from_json(char *rbuf, size_t len, struct discord_modify_channel_params **) </tt>
 *   - <tt> void discord_modify_channel_params_list_from_json(char *rbuf, size_t len, struct discord_modify_channel_params ***) </tt>
 * - JSON Encoder:
 *   - <tt> void discord_modify_channel_params_to_json(char *wbuf, size_t len, struct discord_modify_channel_params *) </tt>
 *   - <tt> void discord_modify_channel_params_list_to_json(char *wbuf, size_t len, struct discord_modify_channel_params **) </tt>
 */
struct discord_modify_channel_params {
  /* specs/discord/channel.endpoints-params.json:13:20
     '{ "name": "name", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null }' */
  char *name;

  /* specs/discord/channel.endpoints-params.json:14:20
     '{ "name": "icon", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null }' */
  char *icon;

  /* specs/discord/channel.endpoints-params.json:15:20
     '{ "name": "type", "type":{ "base":"int" }}' */
  int type;

  /* specs/discord/channel.endpoints-params.json:16:20
     '{ "name": "position", "type":{ "base":"int" }, "inject_if_not":0 }' */
  int position;

  /* specs/discord/channel.endpoints-params.json:17:20
     '{ "name": "topic", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null }' */
  char *topic;

  /* specs/discord/channel.endpoints-params.json:18:20
     '{ "name": "nsfw", "type":{ "base":"bool" }, "inject_if_not":false }' */
  bool nsfw;

  /* specs/discord/channel.endpoints-params.json:19:20
     '{ "name": "rate_limit_per_user", "type":{ "base":"int" }, "inject_if_not":0 }' */
  int rate_limit_per_user;

  /* specs/discord/channel.endpoints-params.json:20:20
     '{ "name": "bitrate", "type":{ "base":"int" }, "inject_if_not":0 }' */
  int bitrate;

  /* specs/discord/channel.endpoints-params.json:21:20
     '{ "name": "user_limit", "type":{ "base":"int" }, "inject_if_not":0 }' */
  int user_limit;

  /* specs/discord/channel.endpoints-params.json:22:20
     '{ "name": "permission_overwrites", "type":{ "base":"struct discord_channel_overwrite", "dec":"ntl" }, "inject_if_not":null }' */
  struct discord_channel_overwrite **permission_overwrites;

  /* specs/discord/channel.endpoints-params.json:23:20
     '{ "name": "parent_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }, "inject_if_not":0 }' */
  u64_snowflake_t parent_id;

  /* specs/discord/channel.endpoints-params.json:24:20
     '{ "name": "rtc_region", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null }' */
  char *rtc_region;

  /* specs/discord/channel.endpoints-params.json:25:20
     '{ "name": "video_quality_mode", "type":{ "base":"int" }, "inject_if_not":0 }' */
  int video_quality_mode;

  /* specs/discord/channel.endpoints-params.json:26:20
     '{ "name": "archived", "type":{ "base":"bool" }, "inject_if_not":false }' */
  bool archived;

  /* specs/discord/channel.endpoints-params.json:27:20
     '{ "name": "auto_archive_duration", "type":{ "base":"int" }, "inject_if_not":0 }' */
  int auto_archive_duration;

  /* specs/discord/channel.endpoints-params.json:28:20
     '{ "name": "locked", "type":{ "base":"bool" }, "inject_if_not":false }' */
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
    void *arg_switches[16];
    void *record_defined[16];
    void *record_null[16];
  } __M; // metadata
/// @endcond
};
extern void discord_modify_channel_params_cleanup_v(void *p);
extern void discord_modify_channel_params_cleanup(struct discord_modify_channel_params *p);
extern void discord_modify_channel_params_init_v(void *p);
extern void discord_modify_channel_params_init(struct discord_modify_channel_params *p);
extern void discord_modify_channel_params_from_json_v(char *json, size_t len, void *pp);
extern void discord_modify_channel_params_from_json(char *json, size_t len, struct discord_modify_channel_params **pp);
extern size_t discord_modify_channel_params_to_json_v(char *json, size_t len, void *p);
extern size_t discord_modify_channel_params_to_json(char *json, size_t len, struct discord_modify_channel_params *p);
extern size_t discord_modify_channel_params_to_query_v(char *json, size_t len, void *p);
extern size_t discord_modify_channel_params_to_query(char *json, size_t len, struct discord_modify_channel_params *p);
extern void discord_modify_channel_params_list_free_v(void **p);
extern void discord_modify_channel_params_list_free(struct discord_modify_channel_params **p);
extern void discord_modify_channel_params_list_from_json_v(char *str, size_t len, void *p);
extern void discord_modify_channel_params_list_from_json(char *str, size_t len, struct discord_modify_channel_params ***p);
extern size_t discord_modify_channel_params_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_modify_channel_params_list_to_json(char *str, size_t len, struct discord_modify_channel_params **p);

// Get Reactions
// defined at specs/discord/channel.endpoints-params.json:35:22
/**
 * @see https://discord.com/developers/docs/resources/channel#get-reactions
 *
 * - Initializer:
 *   - <tt> void discord_get_reactions_params_init(struct discord_get_reactions_params *) </tt>
 * - Cleanup:
 *   - <tt> void discord_get_reactions_params_cleanup(struct discord_get_reactions_params *) </tt>
 *   - <tt> void discord_get_reactions_params_list_free(struct discord_get_reactions_params **) </tt>
 * - JSON Decoder:
 *   - <tt> void discord_get_reactions_params_from_json(char *rbuf, size_t len, struct discord_get_reactions_params **) </tt>
 *   - <tt> void discord_get_reactions_params_list_from_json(char *rbuf, size_t len, struct discord_get_reactions_params ***) </tt>
 * - JSON Encoder:
 *   - <tt> void discord_get_reactions_params_to_json(char *wbuf, size_t len, struct discord_get_reactions_params *) </tt>
 *   - <tt> void discord_get_reactions_params_list_to_json(char *wbuf, size_t len, struct discord_get_reactions_params **) </tt>
 */
struct discord_get_reactions_params {
  /* specs/discord/channel.endpoints-params.json:38:20
     '{ "name": "after", "type":{ "base":"char", "dec":"*", "converter":"snowflake" }, "loc":"query"}' */
  u64_snowflake_t after;

  /* specs/discord/channel.endpoints-params.json:39:20
     '{ "name": "limit", "type":{ "base":"int" }, "loc":"query"}' */
  int limit;

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
extern void discord_get_reactions_params_cleanup_v(void *p);
extern void discord_get_reactions_params_cleanup(struct discord_get_reactions_params *p);
extern void discord_get_reactions_params_init_v(void *p);
extern void discord_get_reactions_params_init(struct discord_get_reactions_params *p);
extern void discord_get_reactions_params_from_json_v(char *json, size_t len, void *pp);
extern void discord_get_reactions_params_from_json(char *json, size_t len, struct discord_get_reactions_params **pp);
extern size_t discord_get_reactions_params_to_json_v(char *json, size_t len, void *p);
extern size_t discord_get_reactions_params_to_json(char *json, size_t len, struct discord_get_reactions_params *p);
extern size_t discord_get_reactions_params_to_query_v(char *json, size_t len, void *p);
extern size_t discord_get_reactions_params_to_query(char *json, size_t len, struct discord_get_reactions_params *p);
extern void discord_get_reactions_params_list_free_v(void **p);
extern void discord_get_reactions_params_list_free(struct discord_get_reactions_params **p);
extern void discord_get_reactions_params_list_from_json_v(char *str, size_t len, void *p);
extern void discord_get_reactions_params_list_from_json(char *str, size_t len, struct discord_get_reactions_params ***p);
extern size_t discord_get_reactions_params_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_get_reactions_params_list_to_json(char *str, size_t len, struct discord_get_reactions_params **p);

// Edit Channel Permissions
// defined at specs/discord/channel.endpoints-params.json:46:22
/**
 * @see https://discord.com/developers/docs/resources/channel#edit-channel-permissions
 *
 * - Initializer:
 *   - <tt> void discord_edit_channel_permissions_params_init(struct discord_edit_channel_permissions_params *) </tt>
 * - Cleanup:
 *   - <tt> void discord_edit_channel_permissions_params_cleanup(struct discord_edit_channel_permissions_params *) </tt>
 *   - <tt> void discord_edit_channel_permissions_params_list_free(struct discord_edit_channel_permissions_params **) </tt>
 * - JSON Decoder:
 *   - <tt> void discord_edit_channel_permissions_params_from_json(char *rbuf, size_t len, struct discord_edit_channel_permissions_params **) </tt>
 *   - <tt> void discord_edit_channel_permissions_params_list_from_json(char *rbuf, size_t len, struct discord_edit_channel_permissions_params ***) </tt>
 * - JSON Encoder:
 *   - <tt> void discord_edit_channel_permissions_params_to_json(char *wbuf, size_t len, struct discord_edit_channel_permissions_params *) </tt>
 *   - <tt> void discord_edit_channel_permissions_params_list_to_json(char *wbuf, size_t len, struct discord_edit_channel_permissions_params **) </tt>
 */
struct discord_edit_channel_permissions_params {
  /* specs/discord/channel.endpoints-params.json:49:20
     '{ "name": "allow", "type":{ "base":"s_as_hex_uint", "int_alias":"enum discord_permissions_bitwise_flags"}, "comment":"permission bit set" }' */
  enum discord_permissions_bitwise_flags allow; ///< permission bit set

  /* specs/discord/channel.endpoints-params.json:50:20
     '{ "name": "deny", "type":{ "base":"s_as_hex_uint", "int_alias":"enum discord_permissions_bitwise_flags"}, "comment":"permission bit set" }' */
  enum discord_permissions_bitwise_flags deny; ///< permission bit set

  /* specs/discord/channel.endpoints-params.json:51:20
     '{ "name": "type", "type":{ "base":"int" }}' */
  int type;

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
extern void discord_edit_channel_permissions_params_cleanup_v(void *p);
extern void discord_edit_channel_permissions_params_cleanup(struct discord_edit_channel_permissions_params *p);
extern void discord_edit_channel_permissions_params_init_v(void *p);
extern void discord_edit_channel_permissions_params_init(struct discord_edit_channel_permissions_params *p);
extern void discord_edit_channel_permissions_params_from_json_v(char *json, size_t len, void *pp);
extern void discord_edit_channel_permissions_params_from_json(char *json, size_t len, struct discord_edit_channel_permissions_params **pp);
extern size_t discord_edit_channel_permissions_params_to_json_v(char *json, size_t len, void *p);
extern size_t discord_edit_channel_permissions_params_to_json(char *json, size_t len, struct discord_edit_channel_permissions_params *p);
extern size_t discord_edit_channel_permissions_params_to_query_v(char *json, size_t len, void *p);
extern size_t discord_edit_channel_permissions_params_to_query(char *json, size_t len, struct discord_edit_channel_permissions_params *p);
extern void discord_edit_channel_permissions_params_list_free_v(void **p);
extern void discord_edit_channel_permissions_params_list_free(struct discord_edit_channel_permissions_params **p);
extern void discord_edit_channel_permissions_params_list_from_json_v(char *str, size_t len, void *p);
extern void discord_edit_channel_permissions_params_list_from_json(char *str, size_t len, struct discord_edit_channel_permissions_params ***p);
extern size_t discord_edit_channel_permissions_params_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_edit_channel_permissions_params_list_to_json(char *str, size_t len, struct discord_edit_channel_permissions_params **p);

// Follow News Channel
// defined at specs/discord/channel.endpoints-params.json:58:22
/**
 * @see https://discord.com/developers/docs/resources/channel#follow-news-channel
 *
 * - Initializer:
 *   - <tt> void discord_follow_news_channel_params_init(struct discord_follow_news_channel_params *) </tt>
 * - Cleanup:
 *   - <tt> void discord_follow_news_channel_params_cleanup(struct discord_follow_news_channel_params *) </tt>
 *   - <tt> void discord_follow_news_channel_params_list_free(struct discord_follow_news_channel_params **) </tt>
 * - JSON Decoder:
 *   - <tt> void discord_follow_news_channel_params_from_json(char *rbuf, size_t len, struct discord_follow_news_channel_params **) </tt>
 *   - <tt> void discord_follow_news_channel_params_list_from_json(char *rbuf, size_t len, struct discord_follow_news_channel_params ***) </tt>
 * - JSON Encoder:
 *   - <tt> void discord_follow_news_channel_params_to_json(char *wbuf, size_t len, struct discord_follow_news_channel_params *) </tt>
 *   - <tt> void discord_follow_news_channel_params_list_to_json(char *wbuf, size_t len, struct discord_follow_news_channel_params **) </tt>
 */
struct discord_follow_news_channel_params {
  /* specs/discord/channel.endpoints-params.json:61:20
     '{ "name": "webhook_channel_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake"} }' */
  u64_snowflake_t webhook_channel_id;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[1];
    void *record_defined[1];
    void *record_null[1];
  } __M; // metadata
/// @endcond
};
extern void discord_follow_news_channel_params_cleanup_v(void *p);
extern void discord_follow_news_channel_params_cleanup(struct discord_follow_news_channel_params *p);
extern void discord_follow_news_channel_params_init_v(void *p);
extern void discord_follow_news_channel_params_init(struct discord_follow_news_channel_params *p);
extern void discord_follow_news_channel_params_from_json_v(char *json, size_t len, void *pp);
extern void discord_follow_news_channel_params_from_json(char *json, size_t len, struct discord_follow_news_channel_params **pp);
extern size_t discord_follow_news_channel_params_to_json_v(char *json, size_t len, void *p);
extern size_t discord_follow_news_channel_params_to_json(char *json, size_t len, struct discord_follow_news_channel_params *p);
extern size_t discord_follow_news_channel_params_to_query_v(char *json, size_t len, void *p);
extern size_t discord_follow_news_channel_params_to_query(char *json, size_t len, struct discord_follow_news_channel_params *p);
extern void discord_follow_news_channel_params_list_free_v(void **p);
extern void discord_follow_news_channel_params_list_free(struct discord_follow_news_channel_params **p);
extern void discord_follow_news_channel_params_list_from_json_v(char *str, size_t len, void *p);
extern void discord_follow_news_channel_params_list_from_json(char *str, size_t len, struct discord_follow_news_channel_params ***p);
extern size_t discord_follow_news_channel_params_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_follow_news_channel_params_list_to_json(char *str, size_t len, struct discord_follow_news_channel_params **p);

// Create Channel Invite
// defined at specs/discord/channel.endpoints-params.json:68:22
/**
 * @see https://discord.com/developers/docs/resources/channel#create-channel-invite
 *
 * - Initializer:
 *   - <tt> void discord_create_channel_invite_params_init(struct discord_create_channel_invite_params *) </tt>
 * - Cleanup:
 *   - <tt> void discord_create_channel_invite_params_cleanup(struct discord_create_channel_invite_params *) </tt>
 *   - <tt> void discord_create_channel_invite_params_list_free(struct discord_create_channel_invite_params **) </tt>
 * - JSON Decoder:
 *   - <tt> void discord_create_channel_invite_params_from_json(char *rbuf, size_t len, struct discord_create_channel_invite_params **) </tt>
 *   - <tt> void discord_create_channel_invite_params_list_from_json(char *rbuf, size_t len, struct discord_create_channel_invite_params ***) </tt>
 * - JSON Encoder:
 *   - <tt> void discord_create_channel_invite_params_to_json(char *wbuf, size_t len, struct discord_create_channel_invite_params *) </tt>
 *   - <tt> void discord_create_channel_invite_params_list_to_json(char *wbuf, size_t len, struct discord_create_channel_invite_params **) </tt>
 */
struct discord_create_channel_invite_params {
  /* specs/discord/channel.endpoints-params.json:71:20
     '{ "name": "max_age", "type":{ "base":"int" }}' */
  int max_age;

  /* specs/discord/channel.endpoints-params.json:72:20
     '{ "name": "max_uses", "type":{ "base":"int" }}' */
  int max_uses;

  /* specs/discord/channel.endpoints-params.json:73:20
     '{ "name": "temporary", "type":{ "base":"bool" }}' */
  bool temporary;

  /* specs/discord/channel.endpoints-params.json:74:20
     '{ "name": "unique", "type":{ "base":"bool" }}' */
  bool unique;

  /* specs/discord/channel.endpoints-params.json:75:20
     '{ "name": "target_type", "type":{ "base":"int" }, "option":true, "inject_if_not":0 }' */
  int target_type;

  /* specs/discord/channel.endpoints-params.json:76:20
     '{ "name": "target_user_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake"}, "option":true, "inject_if_not":0 }' */
  u64_snowflake_t target_user_id;

  /* specs/discord/channel.endpoints-params.json:77:20
     '{ "name": "target_application_id", "type":{ "base":"char", "dec":"*", "converter":"snowflake"}, "option":true, "inject_if_not":0 }' */
  u64_snowflake_t target_application_id;

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
extern void discord_create_channel_invite_params_cleanup_v(void *p);
extern void discord_create_channel_invite_params_cleanup(struct discord_create_channel_invite_params *p);
extern void discord_create_channel_invite_params_init_v(void *p);
extern void discord_create_channel_invite_params_init(struct discord_create_channel_invite_params *p);
extern void discord_create_channel_invite_params_from_json_v(char *json, size_t len, void *pp);
extern void discord_create_channel_invite_params_from_json(char *json, size_t len, struct discord_create_channel_invite_params **pp);
extern size_t discord_create_channel_invite_params_to_json_v(char *json, size_t len, void *p);
extern size_t discord_create_channel_invite_params_to_json(char *json, size_t len, struct discord_create_channel_invite_params *p);
extern size_t discord_create_channel_invite_params_to_query_v(char *json, size_t len, void *p);
extern size_t discord_create_channel_invite_params_to_query(char *json, size_t len, struct discord_create_channel_invite_params *p);
extern void discord_create_channel_invite_params_list_free_v(void **p);
extern void discord_create_channel_invite_params_list_free(struct discord_create_channel_invite_params **p);
extern void discord_create_channel_invite_params_list_from_json_v(char *str, size_t len, void *p);
extern void discord_create_channel_invite_params_list_from_json(char *str, size_t len, struct discord_create_channel_invite_params ***p);
extern size_t discord_create_channel_invite_params_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_create_channel_invite_params_list_to_json(char *str, size_t len, struct discord_create_channel_invite_params **p);

// Group DM Add Recipient
// defined at specs/discord/channel.endpoints-params.json:84:22
/**
 * @see https://discord.com/developers/docs/resources/channel#group-dm-add-recipient
 *
 * - Initializer:
 *   - <tt> void discord_group_dm_add_recipient_params_init(struct discord_group_dm_add_recipient_params *) </tt>
 * - Cleanup:
 *   - <tt> void discord_group_dm_add_recipient_params_cleanup(struct discord_group_dm_add_recipient_params *) </tt>
 *   - <tt> void discord_group_dm_add_recipient_params_list_free(struct discord_group_dm_add_recipient_params **) </tt>
 * - JSON Decoder:
 *   - <tt> void discord_group_dm_add_recipient_params_from_json(char *rbuf, size_t len, struct discord_group_dm_add_recipient_params **) </tt>
 *   - <tt> void discord_group_dm_add_recipient_params_list_from_json(char *rbuf, size_t len, struct discord_group_dm_add_recipient_params ***) </tt>
 * - JSON Encoder:
 *   - <tt> void discord_group_dm_add_recipient_params_to_json(char *wbuf, size_t len, struct discord_group_dm_add_recipient_params *) </tt>
 *   - <tt> void discord_group_dm_add_recipient_params_list_to_json(char *wbuf, size_t len, struct discord_group_dm_add_recipient_params **) </tt>
 */
struct discord_group_dm_add_recipient_params {
  /* specs/discord/channel.endpoints-params.json:87:20
     '{ "name": "access_token", "type":{ "base":"char", "dec":"*" }}' */
  char *access_token;

  /* specs/discord/channel.endpoints-params.json:88:20
     '{ "name": "nick", "type":{ "base":"char", "dec":"*" }}' */
  char *nick;

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
extern void discord_group_dm_add_recipient_params_cleanup_v(void *p);
extern void discord_group_dm_add_recipient_params_cleanup(struct discord_group_dm_add_recipient_params *p);
extern void discord_group_dm_add_recipient_params_init_v(void *p);
extern void discord_group_dm_add_recipient_params_init(struct discord_group_dm_add_recipient_params *p);
extern void discord_group_dm_add_recipient_params_from_json_v(char *json, size_t len, void *pp);
extern void discord_group_dm_add_recipient_params_from_json(char *json, size_t len, struct discord_group_dm_add_recipient_params **pp);
extern size_t discord_group_dm_add_recipient_params_to_json_v(char *json, size_t len, void *p);
extern size_t discord_group_dm_add_recipient_params_to_json(char *json, size_t len, struct discord_group_dm_add_recipient_params *p);
extern size_t discord_group_dm_add_recipient_params_to_query_v(char *json, size_t len, void *p);
extern size_t discord_group_dm_add_recipient_params_to_query(char *json, size_t len, struct discord_group_dm_add_recipient_params *p);
extern void discord_group_dm_add_recipient_params_list_free_v(void **p);
extern void discord_group_dm_add_recipient_params_list_free(struct discord_group_dm_add_recipient_params **p);
extern void discord_group_dm_add_recipient_params_list_from_json_v(char *str, size_t len, void *p);
extern void discord_group_dm_add_recipient_params_list_from_json(char *str, size_t len, struct discord_group_dm_add_recipient_params ***p);
extern size_t discord_group_dm_add_recipient_params_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_group_dm_add_recipient_params_list_to_json(char *str, size_t len, struct discord_group_dm_add_recipient_params **p);

// Start Thread with Message
// defined at specs/discord/channel.endpoints-params.json:95:22
/**
 * @see https://discord.com/developers/docs/resources/channel#start-thread-with-message-json-params
 *
 * - Initializer:
 *   - <tt> void discord_start_thread_with_message_params_init(struct discord_start_thread_with_message_params *) </tt>
 * - Cleanup:
 *   - <tt> void discord_start_thread_with_message_params_cleanup(struct discord_start_thread_with_message_params *) </tt>
 *   - <tt> void discord_start_thread_with_message_params_list_free(struct discord_start_thread_with_message_params **) </tt>
 * - JSON Decoder:
 *   - <tt> void discord_start_thread_with_message_params_from_json(char *rbuf, size_t len, struct discord_start_thread_with_message_params **) </tt>
 *   - <tt> void discord_start_thread_with_message_params_list_from_json(char *rbuf, size_t len, struct discord_start_thread_with_message_params ***) </tt>
 * - JSON Encoder:
 *   - <tt> void discord_start_thread_with_message_params_to_json(char *wbuf, size_t len, struct discord_start_thread_with_message_params *) </tt>
 *   - <tt> void discord_start_thread_with_message_params_list_to_json(char *wbuf, size_t len, struct discord_start_thread_with_message_params **) </tt>
 */
struct discord_start_thread_with_message_params {
  /* specs/discord/channel.endpoints-params.json:98:20
     '{ "name": "name", "type":{ "base":"char", "dec":"*" }, "inject_if_not":null }' */
  char *name;

  /* specs/discord/channel.endpoints-params.json:99:20
     '{ "name": "auto_archive_duration", "type":{ "base":"int" }, "inject_if_not":0 }' */
  int auto_archive_duration;

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
extern void discord_start_thread_with_message_params_cleanup_v(void *p);
extern void discord_start_thread_with_message_params_cleanup(struct discord_start_thread_with_message_params *p);
extern void discord_start_thread_with_message_params_init_v(void *p);
extern void discord_start_thread_with_message_params_init(struct discord_start_thread_with_message_params *p);
extern void discord_start_thread_with_message_params_from_json_v(char *json, size_t len, void *pp);
extern void discord_start_thread_with_message_params_from_json(char *json, size_t len, struct discord_start_thread_with_message_params **pp);
extern size_t discord_start_thread_with_message_params_to_json_v(char *json, size_t len, void *p);
extern size_t discord_start_thread_with_message_params_to_json(char *json, size_t len, struct discord_start_thread_with_message_params *p);
extern size_t discord_start_thread_with_message_params_to_query_v(char *json, size_t len, void *p);
extern size_t discord_start_thread_with_message_params_to_query(char *json, size_t len, struct discord_start_thread_with_message_params *p);
extern void discord_start_thread_with_message_params_list_free_v(void **p);
extern void discord_start_thread_with_message_params_list_free(struct discord_start_thread_with_message_params **p);
extern void discord_start_thread_with_message_params_list_from_json_v(char *str, size_t len, void *p);
extern void discord_start_thread_with_message_params_list_from_json(char *str, size_t len, struct discord_start_thread_with_message_params ***p);
extern size_t discord_start_thread_with_message_params_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_start_thread_with_message_params_list_to_json(char *str, size_t len, struct discord_start_thread_with_message_params **p);

// Start Thread without Message
// defined at specs/discord/channel.endpoints-params.json:106:22
/**
 * @see https://discord.com/developers/docs/resources/channel#start-thread-without-message-json-params
 *
 * - Initializer:
 *   - <tt> void discord_start_thread_without_message_params_init(struct discord_start_thread_without_message_params *) </tt>
 * - Cleanup:
 *   - <tt> void discord_start_thread_without_message_params_cleanup(struct discord_start_thread_without_message_params *) </tt>
 *   - <tt> void discord_start_thread_without_message_params_list_free(struct discord_start_thread_without_message_params **) </tt>
 * - JSON Decoder:
 *   - <tt> void discord_start_thread_without_message_params_from_json(char *rbuf, size_t len, struct discord_start_thread_without_message_params **) </tt>
 *   - <tt> void discord_start_thread_without_message_params_list_from_json(char *rbuf, size_t len, struct discord_start_thread_without_message_params ***) </tt>
 * - JSON Encoder:
 *   - <tt> void discord_start_thread_without_message_params_to_json(char *wbuf, size_t len, struct discord_start_thread_without_message_params *) </tt>
 *   - <tt> void discord_start_thread_without_message_params_list_to_json(char *wbuf, size_t len, struct discord_start_thread_without_message_params **) </tt>
 */
struct discord_start_thread_without_message_params {
  /* specs/discord/channel.endpoints-params.json:109:20
     '{ "name": "name", "type":{ "base":"char", "dec":"*" } }' */
  char *name;

  /* specs/discord/channel.endpoints-params.json:110:20
     '{ "name": "auto_archive_duration", "type":{ "base":"int" }, "inject_if_not":0 }' */
  int auto_archive_duration;

  /* specs/discord/channel.endpoints-params.json:111:20
     '{ "name": "type", "type":{ "base":"int", "int_alias":"enum discord_channel_types" } }' */
  enum discord_channel_types type;

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
extern void discord_start_thread_without_message_params_cleanup_v(void *p);
extern void discord_start_thread_without_message_params_cleanup(struct discord_start_thread_without_message_params *p);
extern void discord_start_thread_without_message_params_init_v(void *p);
extern void discord_start_thread_without_message_params_init(struct discord_start_thread_without_message_params *p);
extern void discord_start_thread_without_message_params_from_json_v(char *json, size_t len, void *pp);
extern void discord_start_thread_without_message_params_from_json(char *json, size_t len, struct discord_start_thread_without_message_params **pp);
extern size_t discord_start_thread_without_message_params_to_json_v(char *json, size_t len, void *p);
extern size_t discord_start_thread_without_message_params_to_json(char *json, size_t len, struct discord_start_thread_without_message_params *p);
extern size_t discord_start_thread_without_message_params_to_query_v(char *json, size_t len, void *p);
extern size_t discord_start_thread_without_message_params_to_query(char *json, size_t len, struct discord_start_thread_without_message_params *p);
extern void discord_start_thread_without_message_params_list_free_v(void **p);
extern void discord_start_thread_without_message_params_list_free(struct discord_start_thread_without_message_params **p);
extern void discord_start_thread_without_message_params_list_from_json_v(char *str, size_t len, void *p);
extern void discord_start_thread_without_message_params_list_from_json(char *str, size_t len, struct discord_start_thread_without_message_params ***p);
extern size_t discord_start_thread_without_message_params_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_start_thread_without_message_params_list_to_json(char *str, size_t len, struct discord_start_thread_without_message_params **p);

// List Active Threads
// defined at specs/discord/channel.endpoints-params.json:118:22
/**
 * @see https://discord.com/developers/docs/resources/channel#list-active-threads-response-body
 *
 * - Initializer:
 *   - <tt> void discord_thread_response_body_init(struct discord_thread_response_body *) </tt>
 * - Cleanup:
 *   - <tt> void discord_thread_response_body_cleanup(struct discord_thread_response_body *) </tt>
 *   - <tt> void discord_thread_response_body_list_free(struct discord_thread_response_body **) </tt>
 * - JSON Decoder:
 *   - <tt> void discord_thread_response_body_from_json(char *rbuf, size_t len, struct discord_thread_response_body **) </tt>
 *   - <tt> void discord_thread_response_body_list_from_json(char *rbuf, size_t len, struct discord_thread_response_body ***) </tt>
 * - JSON Encoder:
 *   - <tt> void discord_thread_response_body_to_json(char *wbuf, size_t len, struct discord_thread_response_body *) </tt>
 *   - <tt> void discord_thread_response_body_list_to_json(char *wbuf, size_t len, struct discord_thread_response_body **) </tt>
 */
struct discord_thread_response_body {
  /* specs/discord/channel.endpoints-params.json:121:20
     '{ "name": "threads", "type":{ "base":"struct discord_channel", "dec":"ntl" } }' */
  struct discord_channel **threads;

  /* specs/discord/channel.endpoints-params.json:122:20
     '{ "name": "members", "type":{ "base":"struct discord_thread_member", "dec":"ntl" } }' */
  struct discord_thread_member **members;

  /* specs/discord/channel.endpoints-params.json:123:20
     '{ "name": "has_more", "type":{ "base":"bool" } }' */
  bool has_more;

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
extern void discord_thread_response_body_cleanup_v(void *p);
extern void discord_thread_response_body_cleanup(struct discord_thread_response_body *p);
extern void discord_thread_response_body_init_v(void *p);
extern void discord_thread_response_body_init(struct discord_thread_response_body *p);
extern void discord_thread_response_body_from_json_v(char *json, size_t len, void *pp);
extern void discord_thread_response_body_from_json(char *json, size_t len, struct discord_thread_response_body **pp);
extern size_t discord_thread_response_body_to_json_v(char *json, size_t len, void *p);
extern size_t discord_thread_response_body_to_json(char *json, size_t len, struct discord_thread_response_body *p);
extern size_t discord_thread_response_body_to_query_v(char *json, size_t len, void *p);
extern size_t discord_thread_response_body_to_query(char *json, size_t len, struct discord_thread_response_body *p);
extern void discord_thread_response_body_list_free_v(void **p);
extern void discord_thread_response_body_list_free(struct discord_thread_response_body **p);
extern void discord_thread_response_body_list_from_json_v(char *str, size_t len, void *p);
extern void discord_thread_response_body_list_from_json(char *str, size_t len, struct discord_thread_response_body ***p);
extern size_t discord_thread_response_body_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_thread_response_body_list_to_json(char *str, size_t len, struct discord_thread_response_body **p);
