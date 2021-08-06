/* This file is generated from specs/discord/invite.endpoints-params.json, Please don't edit it. */
/**
 * @file specs-code/discord/invite.endpoints-params.h
 * @see https://discord.com/developers/docs/resources/invite
 */


// Get Invite
// defined at specs/discord/invite.endpoints-params.json:10:22
/**
 * @see https://discord.com/developers/docs/resources/invite#get-invite-query-string-params
 *
 * - Initializer:
 *   - <tt> discord_get_invite_params_init(struct discord_get_invite_params *) </tt>
 * - Cleanup:
 *   - <tt> discord_get_invite_params_cleanup(struct discord_get_invite_params *) </tt>
 *   - <tt> discord_get_invite_params_list_free(struct discord_get_invite_params **) </tt>
 * - JSON Decoder:
 *   - <tt> discord_get_invite_params_from_json(char *rbuf, size_t len, struct discord_get_invite_params **) </tt>
 *   - <tt> discord_get_invite_params_list_from_json(char *rbuf, size_t len, struct discord_get_invite_params ***) </tt>
 * - JSON Encoder:
 *   - <tt> discord_get_invite_params_to_json(char *wbuf, size_t len, struct discord_get_invite_params *) </tt>
 *   - <tt> discord_get_invite_params_list_to_json(char *wbuf, size_t len, struct discord_get_invite_params **) </tt>
 */
struct discord_get_invite_params {
  /* specs/discord/invite.endpoints-params.json:13:20
     '{ "name": "with_counts", "type":{ "base":"bool" }, "comment":"whether the invite should contain approximate member counts"}' */
  bool with_counts; ///< whether the invite should contain approximate member counts

  /* specs/discord/invite.endpoints-params.json:14:20
     '{ "name": "with_expiration", "type":{ "base":"bool" }, "comment":"whether the invite should contain the expiration date"}' */
  bool with_expiration; ///< whether the invite should contain the expiration date

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
extern void discord_get_invite_params_cleanup_v(void *p);
extern void discord_get_invite_params_cleanup(struct discord_get_invite_params *p);
extern void discord_get_invite_params_init_v(void *p);
extern void discord_get_invite_params_init(struct discord_get_invite_params *p);
extern void discord_get_invite_params_from_json_v(char *json, size_t len, void *pp);
extern void discord_get_invite_params_from_json(char *json, size_t len, struct discord_get_invite_params **pp);
extern size_t discord_get_invite_params_to_json_v(char *json, size_t len, void *p);
extern size_t discord_get_invite_params_to_json(char *json, size_t len, struct discord_get_invite_params *p);
extern size_t discord_get_invite_params_to_query_v(char *json, size_t len, void *p);
extern size_t discord_get_invite_params_to_query(char *json, size_t len, struct discord_get_invite_params *p);
extern void discord_get_invite_params_list_free_v(void **p);
extern void discord_get_invite_params_list_free(struct discord_get_invite_params **p);
extern void discord_get_invite_params_list_from_json_v(char *str, size_t len, void *p);
extern void discord_get_invite_params_list_from_json(char *str, size_t len, struct discord_get_invite_params ***p);
extern size_t discord_get_invite_params_list_to_json_v(char *str, size_t len, void *p);
extern size_t discord_get_invite_params_list_to_json(char *str, size_t len, struct discord_get_invite_params **p);
