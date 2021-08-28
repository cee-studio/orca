/* This file is generated from specs/discord/application_commands.endpoints-params.json, Please don't edit it. */
/**
 * @file specs-code/discord/application_commands.endpoints-params.h
 * @see https://discord.com/developers/docs/interactions/application-commands
 */


// Create Global Application Command
// defined at specs/discord/application_commands.endpoints-params.json:10:22
/**
 * @see https://discord.com/developers/docs/interactions/application-commands#create-global-application-command
 *
 * @verbatim embed:rst:leading-asterisk
 * .. container:: toggle

 *   .. container:: header

 *     **Methods**

 *   * Initializer:

 *     * :code:`void discord_create_global_application_command_params_init(struct discord_create_global_application_command_params *)`
 *   * Cleanup:

 *     * :code:`void discord_create_global_application_command_params_cleanup(struct discord_create_global_application_command_params *)`
 *     * :code:`void discord_create_global_application_command_params_list_free(struct discord_create_global_application_command_params **)`
 *   * JSON Decoder:

 *     * :code:`void discord_create_global_application_command_params_from_json(char *rbuf, size_t len, struct discord_create_global_application_command_params **)`
 *     * :code:`void discord_create_global_application_command_params_list_from_json(char *rbuf, size_t len, struct discord_create_global_application_command_params ***)`
 *   * JSON Encoder:

 *     * :code:`void discord_create_global_application_command_params_to_json(char *wbuf, size_t len, struct discord_create_global_application_command_params *)`
 *     * :code:`void discord_create_global_application_command_params_list_to_json(char *wbuf, size_t len, struct discord_create_global_application_command_params **)`
 * @endverbatim
 */
struct discord_create_global_application_command_params {
  /* specs/discord/application_commands.endpoints-params.json:13:20
     '{ "name": "name", "type":{ "base":"char", "dec":"*" }, "comment":"1-32 lowercase character name"}' */
  char *name; ///< 1-32 lowercase character name

  /* specs/discord/application_commands.endpoints-params.json:14:20
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }, "comment":"1-100 character description"}' */
  char *description; ///< 1-100 character description

  /* specs/discord/application_commands.endpoints-params.json:15:20
     '{ "name": "options", "type":{"base":"int", "int_alias":"enum discord_application_command_option_types", "dec":"ntl", "comment":"the parameters for the command"}}' */
  enum discord_application_command_option_types **options;

  /* specs/discord/application_commands.endpoints-params.json:16:20
     '{ "name": "default_permission", "type":{"base":"bool"}, "comment":"whether the command is enabled by default when the app is added to a guild"}' */
  bool default_permission; ///< whether the command is enabled by default when the app is added to a guild

  /* specs/discord/application_commands.endpoints-params.json:17:20
     '{ "name": "type", "type":{"base":"int", "int_alias":"enum discord_application_command_types"}}' */
  enum discord_application_command_types type;

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
extern void discord_create_global_application_command_params_cleanup_v(void *p);
extern void discord_create_global_application_command_params_cleanup(struct discord_create_global_application_command_params *p);
extern void discord_create_global_application_command_params_init_v(void *p);
extern void discord_create_global_application_command_params_init(struct discord_create_global_application_command_params *p);
extern void discord_create_global_application_command_params_from_json_v(char *json, size_t len, void *pp);
extern void discord_create_global_application_command_params_from_json(char *json, size_t len, struct discord_create_global_application_command_params **pp);
extern size_t discord_create_global_application_command_params_to_json_v(char *json, size_t len, void *p);
extern size_t discord_create_global_application_command_params_to_json(char *json, size_t len, struct discord_create_global_application_command_params *p);
extern size_t discord_create_global_application_command_params_to_query_v(char *json, size_t len, void *p);
extern size_t discord_create_global_application_command_params_to_query(char *json, size_t len, struct discord_create_global_application_command_params *p);
extern void discord_create_global_application_command_params_list_free_v(void **p);
extern void discord_create_global_application_command_params_list_free(struct discord_create_global_application_command_params **p);
extern void discord_create_global_application_command_params_list_from_json_v(char *str, size_t len, void *p);
extern void discord_create_global_application_command_params_list_from_json(char *str, size_t len, struct discord_create_global_application_command_params ***p);
extern size_t discord_create_global_application_command_params_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_create_global_application_command_params_list_to_json(char *str, size_t len, struct discord_create_global_application_command_params **p);

// Edit Global Application Command
// defined at specs/discord/application_commands.endpoints-params.json:24:23
/**
 * @see https://discord.com/developers/docs/interactions/application-commands#edit-global-application-command
 *
 * @verbatim embed:rst:leading-asterisk
 * .. container:: toggle

 *   .. container:: header

 *     **Methods**

 *   * Initializer:

 *     * :code:`void discord_edit_global_application_command_params_init(struct discord_edit_global_application_command_params *)`
 *   * Cleanup:

 *     * :code:`void discord_edit_global_application_command_params_cleanup(struct discord_edit_global_application_command_params *)`
 *     * :code:`void discord_edit_global_application_command_params_list_free(struct discord_edit_global_application_command_params **)`
 *   * JSON Decoder:

 *     * :code:`void discord_edit_global_application_command_params_from_json(char *rbuf, size_t len, struct discord_edit_global_application_command_params **)`
 *     * :code:`void discord_edit_global_application_command_params_list_from_json(char *rbuf, size_t len, struct discord_edit_global_application_command_params ***)`
 *   * JSON Encoder:

 *     * :code:`void discord_edit_global_application_command_params_to_json(char *wbuf, size_t len, struct discord_edit_global_application_command_params *)`
 *     * :code:`void discord_edit_global_application_command_params_list_to_json(char *wbuf, size_t len, struct discord_edit_global_application_command_params **)`
 * @endverbatim
 */
struct discord_edit_global_application_command_params {
  /* specs/discord/application_commands.endpoints-params.json:27:20
     '{ "name": "name", "type":{ "base":"char", "dec":"*" }, "comment":"1-32 lowercase character name"}' */
  char *name; ///< 1-32 lowercase character name

  /* specs/discord/application_commands.endpoints-params.json:28:20
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }, "comment":"1-100 character description"}' */
  char *description; ///< 1-100 character description

  /* specs/discord/application_commands.endpoints-params.json:29:20
     '{ "name": "options", "type":{"base":"int", "int_alias":"enum discord_application_command_option_types", "dec":"ntl", "comment":"the parameters for the command"}}' */
  enum discord_application_command_option_types **options;

  /* specs/discord/application_commands.endpoints-params.json:30:20
     '{ "name": "default_permission", "type":{"base":"bool"}, "comment":"whether the command is enabled by default when the app is added to a guild"}' */
  bool default_permission; ///< whether the command is enabled by default when the app is added to a guild

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
extern void discord_edit_global_application_command_params_cleanup_v(void *p);
extern void discord_edit_global_application_command_params_cleanup(struct discord_edit_global_application_command_params *p);
extern void discord_edit_global_application_command_params_init_v(void *p);
extern void discord_edit_global_application_command_params_init(struct discord_edit_global_application_command_params *p);
extern void discord_edit_global_application_command_params_from_json_v(char *json, size_t len, void *pp);
extern void discord_edit_global_application_command_params_from_json(char *json, size_t len, struct discord_edit_global_application_command_params **pp);
extern size_t discord_edit_global_application_command_params_to_json_v(char *json, size_t len, void *p);
extern size_t discord_edit_global_application_command_params_to_json(char *json, size_t len, struct discord_edit_global_application_command_params *p);
extern size_t discord_edit_global_application_command_params_to_query_v(char *json, size_t len, void *p);
extern size_t discord_edit_global_application_command_params_to_query(char *json, size_t len, struct discord_edit_global_application_command_params *p);
extern void discord_edit_global_application_command_params_list_free_v(void **p);
extern void discord_edit_global_application_command_params_list_free(struct discord_edit_global_application_command_params **p);
extern void discord_edit_global_application_command_params_list_from_json_v(char *str, size_t len, void *p);
extern void discord_edit_global_application_command_params_list_from_json(char *str, size_t len, struct discord_edit_global_application_command_params ***p);
extern size_t discord_edit_global_application_command_params_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_edit_global_application_command_params_list_to_json(char *str, size_t len, struct discord_edit_global_application_command_params **p);

// Create Guild Application Command
// defined at specs/discord/application_commands.endpoints-params.json:37:23
/**
 * @see https://discord.com/developers/docs/interactions/application-commands#create-guild-application-command
 *
 * @verbatim embed:rst:leading-asterisk
 * .. container:: toggle

 *   .. container:: header

 *     **Methods**

 *   * Initializer:

 *     * :code:`void discord_create_guild_application_command_params_init(struct discord_create_guild_application_command_params *)`
 *   * Cleanup:

 *     * :code:`void discord_create_guild_application_command_params_cleanup(struct discord_create_guild_application_command_params *)`
 *     * :code:`void discord_create_guild_application_command_params_list_free(struct discord_create_guild_application_command_params **)`
 *   * JSON Decoder:

 *     * :code:`void discord_create_guild_application_command_params_from_json(char *rbuf, size_t len, struct discord_create_guild_application_command_params **)`
 *     * :code:`void discord_create_guild_application_command_params_list_from_json(char *rbuf, size_t len, struct discord_create_guild_application_command_params ***)`
 *   * JSON Encoder:

 *     * :code:`void discord_create_guild_application_command_params_to_json(char *wbuf, size_t len, struct discord_create_guild_application_command_params *)`
 *     * :code:`void discord_create_guild_application_command_params_list_to_json(char *wbuf, size_t len, struct discord_create_guild_application_command_params **)`
 * @endverbatim
 */
struct discord_create_guild_application_command_params {
  /* specs/discord/application_commands.endpoints-params.json:40:20
     '{ "name": "name", "type":{ "base":"char", "dec":"*" }, "comment":"1-32 lowercase character name"}' */
  char *name; ///< 1-32 lowercase character name

  /* specs/discord/application_commands.endpoints-params.json:41:20
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }, "comment":"1-100 character description"}' */
  char *description; ///< 1-100 character description

  /* specs/discord/application_commands.endpoints-params.json:42:20
     '{ "name": "options", "type":{"base":"int", "int_alias":"enum discord_application_command_option_types", "dec":"ntl", "comment":"the parameters for the command"}}' */
  enum discord_application_command_option_types **options;

  /* specs/discord/application_commands.endpoints-params.json:43:20
     '{ "name": "default_permission", "type":{"base":"bool"}, "comment":"whether the command is enabled by default when the app is added to a guild"}' */
  bool default_permission; ///< whether the command is enabled by default when the app is added to a guild

  /* specs/discord/application_commands.endpoints-params.json:44:20
     '{ "name": "type", "type":{"base":"int", "int_alias":"enum discord_application_command_types"}}' */
  enum discord_application_command_types type;

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
extern void discord_create_guild_application_command_params_cleanup_v(void *p);
extern void discord_create_guild_application_command_params_cleanup(struct discord_create_guild_application_command_params *p);
extern void discord_create_guild_application_command_params_init_v(void *p);
extern void discord_create_guild_application_command_params_init(struct discord_create_guild_application_command_params *p);
extern void discord_create_guild_application_command_params_from_json_v(char *json, size_t len, void *pp);
extern void discord_create_guild_application_command_params_from_json(char *json, size_t len, struct discord_create_guild_application_command_params **pp);
extern size_t discord_create_guild_application_command_params_to_json_v(char *json, size_t len, void *p);
extern size_t discord_create_guild_application_command_params_to_json(char *json, size_t len, struct discord_create_guild_application_command_params *p);
extern size_t discord_create_guild_application_command_params_to_query_v(char *json, size_t len, void *p);
extern size_t discord_create_guild_application_command_params_to_query(char *json, size_t len, struct discord_create_guild_application_command_params *p);
extern void discord_create_guild_application_command_params_list_free_v(void **p);
extern void discord_create_guild_application_command_params_list_free(struct discord_create_guild_application_command_params **p);
extern void discord_create_guild_application_command_params_list_from_json_v(char *str, size_t len, void *p);
extern void discord_create_guild_application_command_params_list_from_json(char *str, size_t len, struct discord_create_guild_application_command_params ***p);
extern size_t discord_create_guild_application_command_params_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_create_guild_application_command_params_list_to_json(char *str, size_t len, struct discord_create_guild_application_command_params **p);

// Edit Guild Application Command
// defined at specs/discord/application_commands.endpoints-params.json:51:23
/**
 * @see https://discord.com/developers/docs/interactions/application-commands#edit-guild-application-command
 *
 * @verbatim embed:rst:leading-asterisk
 * .. container:: toggle

 *   .. container:: header

 *     **Methods**

 *   * Initializer:

 *     * :code:`void discord_edit_guild_application_command_params_init(struct discord_edit_guild_application_command_params *)`
 *   * Cleanup:

 *     * :code:`void discord_edit_guild_application_command_params_cleanup(struct discord_edit_guild_application_command_params *)`
 *     * :code:`void discord_edit_guild_application_command_params_list_free(struct discord_edit_guild_application_command_params **)`
 *   * JSON Decoder:

 *     * :code:`void discord_edit_guild_application_command_params_from_json(char *rbuf, size_t len, struct discord_edit_guild_application_command_params **)`
 *     * :code:`void discord_edit_guild_application_command_params_list_from_json(char *rbuf, size_t len, struct discord_edit_guild_application_command_params ***)`
 *   * JSON Encoder:

 *     * :code:`void discord_edit_guild_application_command_params_to_json(char *wbuf, size_t len, struct discord_edit_guild_application_command_params *)`
 *     * :code:`void discord_edit_guild_application_command_params_list_to_json(char *wbuf, size_t len, struct discord_edit_guild_application_command_params **)`
 * @endverbatim
 */
struct discord_edit_guild_application_command_params {
  /* specs/discord/application_commands.endpoints-params.json:54:20
     '{ "name": "name", "type":{ "base":"char", "dec":"*" }, "comment":"1-32 lowercase character name"}' */
  char *name; ///< 1-32 lowercase character name

  /* specs/discord/application_commands.endpoints-params.json:55:20
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }, "comment":"1-100 character description"}' */
  char *description; ///< 1-100 character description

  /* specs/discord/application_commands.endpoints-params.json:56:20
     '{ "name": "options", "type":{"base":"int", "int_alias":"enum discord_application_command_option_types", "dec":"ntl", "comment":"the parameters for the command"}}' */
  enum discord_application_command_option_types **options;

  /* specs/discord/application_commands.endpoints-params.json:57:20
     '{ "name": "default_permission", "type":{"base":"bool"}, "comment":"whether the command is enabled by default when the app is added to a guild"}' */
  bool default_permission; ///< whether the command is enabled by default when the app is added to a guild

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
extern void discord_edit_guild_application_command_params_cleanup_v(void *p);
extern void discord_edit_guild_application_command_params_cleanup(struct discord_edit_guild_application_command_params *p);
extern void discord_edit_guild_application_command_params_init_v(void *p);
extern void discord_edit_guild_application_command_params_init(struct discord_edit_guild_application_command_params *p);
extern void discord_edit_guild_application_command_params_from_json_v(char *json, size_t len, void *pp);
extern void discord_edit_guild_application_command_params_from_json(char *json, size_t len, struct discord_edit_guild_application_command_params **pp);
extern size_t discord_edit_guild_application_command_params_to_json_v(char *json, size_t len, void *p);
extern size_t discord_edit_guild_application_command_params_to_json(char *json, size_t len, struct discord_edit_guild_application_command_params *p);
extern size_t discord_edit_guild_application_command_params_to_query_v(char *json, size_t len, void *p);
extern size_t discord_edit_guild_application_command_params_to_query(char *json, size_t len, struct discord_edit_guild_application_command_params *p);
extern void discord_edit_guild_application_command_params_list_free_v(void **p);
extern void discord_edit_guild_application_command_params_list_free(struct discord_edit_guild_application_command_params **p);
extern void discord_edit_guild_application_command_params_list_from_json_v(char *str, size_t len, void *p);
extern void discord_edit_guild_application_command_params_list_from_json(char *str, size_t len, struct discord_edit_guild_application_command_params ***p);
extern size_t discord_edit_guild_application_command_params_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_edit_guild_application_command_params_list_to_json(char *str, size_t len, struct discord_edit_guild_application_command_params **p);

// Edit Application Command Permissions
// defined at specs/discord/application_commands.endpoints-params.json:64:23
/**
 * @see https://discord.com/developers/docs/interactions/application-commands#edit-application-command-permissions
 *
 * @verbatim embed:rst:leading-asterisk
 * .. container:: toggle

 *   .. container:: header

 *     **Methods**

 *   * Initializer:

 *     * :code:`void discord_edit_application_command_permissions_params_init(struct discord_edit_application_command_permissions_params *)`
 *   * Cleanup:

 *     * :code:`void discord_edit_application_command_permissions_params_cleanup(struct discord_edit_application_command_permissions_params *)`
 *     * :code:`void discord_edit_application_command_permissions_params_list_free(struct discord_edit_application_command_permissions_params **)`
 *   * JSON Decoder:

 *     * :code:`void discord_edit_application_command_permissions_params_from_json(char *rbuf, size_t len, struct discord_edit_application_command_permissions_params **)`
 *     * :code:`void discord_edit_application_command_permissions_params_list_from_json(char *rbuf, size_t len, struct discord_edit_application_command_permissions_params ***)`
 *   * JSON Encoder:

 *     * :code:`void discord_edit_application_command_permissions_params_to_json(char *wbuf, size_t len, struct discord_edit_application_command_permissions_params *)`
 *     * :code:`void discord_edit_application_command_permissions_params_list_to_json(char *wbuf, size_t len, struct discord_edit_application_command_permissions_params **)`
 * @endverbatim
 */
struct discord_edit_application_command_permissions_params {
  /* specs/discord/application_commands.endpoints-params.json:67:20
     '{ "name": "permissions", "type":{"base": "struct discord_application_command_permissions", "dec":"ntl"}, "comment":"the permissions for the command in the guild"}' */
  struct discord_application_command_permissions **permissions; ///< the permissions for the command in the guild

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
extern void discord_edit_application_command_permissions_params_cleanup_v(void *p);
extern void discord_edit_application_command_permissions_params_cleanup(struct discord_edit_application_command_permissions_params *p);
extern void discord_edit_application_command_permissions_params_init_v(void *p);
extern void discord_edit_application_command_permissions_params_init(struct discord_edit_application_command_permissions_params *p);
extern void discord_edit_application_command_permissions_params_from_json_v(char *json, size_t len, void *pp);
extern void discord_edit_application_command_permissions_params_from_json(char *json, size_t len, struct discord_edit_application_command_permissions_params **pp);
extern size_t discord_edit_application_command_permissions_params_to_json_v(char *json, size_t len, void *p);
extern size_t discord_edit_application_command_permissions_params_to_json(char *json, size_t len, struct discord_edit_application_command_permissions_params *p);
extern size_t discord_edit_application_command_permissions_params_to_query_v(char *json, size_t len, void *p);
extern size_t discord_edit_application_command_permissions_params_to_query(char *json, size_t len, struct discord_edit_application_command_permissions_params *p);
extern void discord_edit_application_command_permissions_params_list_free_v(void **p);
extern void discord_edit_application_command_permissions_params_list_free(struct discord_edit_application_command_permissions_params **p);
extern void discord_edit_application_command_permissions_params_list_from_json_v(char *str, size_t len, void *p);
extern void discord_edit_application_command_permissions_params_list_from_json(char *str, size_t len, struct discord_edit_application_command_permissions_params ***p);
extern size_t discord_edit_application_command_permissions_params_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_edit_application_command_permissions_params_list_to_json(char *str, size_t len, struct discord_edit_application_command_permissions_params **p);