/* This file is generated from specs/github/gist.endpoints-params.json, Please don't edit it. */
/**
 * @file specs-code/github/one-specs.h
 * @see https://docs.github.com/en/rest/reference/gists
 */


// defined at specs/github/gist.endpoints-params.json:10:32
/**
 * @brief Gist Create
 *
 * @see https://docs.github.com/en/rest/reference/gists#create-a-gist--parameters
 */
struct github_gist_create_params;
/* This file is generated from specs/github/gist.json, Please don't edit it. */

// defined at specs/github/gist.json:9:33
/**
 * @brief Gist Structure
 *
 */
struct github_gist;
/* This file is generated from specs/github/user.json, Please don't edit it. */

// defined at specs/github/user.json:9:33
/**
 * @brief User Structure
 *
 */
struct github_user;
/* This file is generated from specs/github/gist.endpoints-params.json, Please don't edit it. */
/* This file is generated from specs/github/gist.json, Please don't edit it. */
/* This file is generated from specs/github/user.json, Please don't edit it. */
/* This file is generated from specs/github/gist.endpoints-params.json, Please don't edit it. */

// Gist Create
// defined at specs/github/gist.endpoints-params.json:10:32
/**
 * @see https://docs.github.com/en/rest/reference/gists#create-a-gist--parameters
 *
 * - Initializer:
 *   - <tt> void github_gist_create_params_init(struct github_gist_create_params *) </tt>
 * - Cleanup:
 *   - <tt> void github_gist_create_params_cleanup(struct github_gist_create_params *) </tt>
 *   - <tt> void github_gist_create_params_list_free(struct github_gist_create_params **) </tt>
 * - JSON Decoder:
 *   - <tt> void github_gist_create_params_from_json(char *rbuf, size_t len, struct github_gist_create_params **) </tt>
 *   - <tt> void github_gist_create_params_list_from_json(char *rbuf, size_t len, struct github_gist_create_params ***) </tt>
 * - JSON Encoder:
 *   - <tt> void github_gist_create_params_to_json(char *wbuf, size_t len, struct github_gist_create_params *) </tt>
 *   - <tt> void github_gist_create_params_list_to_json(char *wbuf, size_t len, struct github_gist_create_params **) </tt>
 */
struct github_gist_create_params {
  /* specs/github/gist.endpoints-params.json:13:28
     '{ "name": "description", "type":{ "base":"char", "dec":"*" }}' */
  char *description;

  /* specs/github/gist.endpoints-params.json:14:28
     '{ "name": "title", "type":{ "base":"char", "dec":"*" }}' */
  char *title;

  /* specs/github/gist.endpoints-params.json:15:28
     '{ "name": "contents", "type":{ "base":"char", "dec":"*" }}' */
  char *contents;

  /* specs/github/gist.endpoints-params.json:16:28
     '{ "name": "public", "type":{ "base":"char", "dec":"*" }}' */
  char *public;

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
/* This file is generated from specs/github/gist.json, Please don't edit it. */

// Gist Structure
// defined at specs/github/gist.json:9:33
/**
 * - Initializer:
 *   - <tt> void github_gist_init(struct github_gist *) </tt>
 * - Cleanup:
 *   - <tt> void github_gist_cleanup(struct github_gist *) </tt>
 *   - <tt> void github_gist_list_free(struct github_gist **) </tt>
 * - JSON Decoder:
 *   - <tt> void github_gist_from_json(char *rbuf, size_t len, struct github_gist **) </tt>
 *   - <tt> void github_gist_list_from_json(char *rbuf, size_t len, struct github_gist ***) </tt>
 * - JSON Encoder:
 *   - <tt> void github_gist_to_json(char *wbuf, size_t len, struct github_gist *) </tt>
 *   - <tt> void github_gist_list_to_json(char *wbuf, size_t len, struct github_gist **) </tt>
 */
struct github_gist {
  /* specs/github/gist.json:12:28
     '{ "name": "url", "type":{ "base":"char", "dec":"*"}}' */
  char *url;

  /* specs/github/gist.json:13:28
     '{ "name": "id", "type":{ "base":"char", "dec":"*"}}' */
  char *id;

  /* specs/github/gist.json:14:28
     '{ "name": "node_id", "type":{ "base":"char", "dec":"*"}}' */
  char *node_id;

  /* specs/github/gist.json:15:28
     '{ "name": "html_url", "type":{ "base":"char", "dec":"*"}}' */
  char *html_url;

  /* specs/github/gist.json:16:28
     '{ "name": "created_at", "type":{ "base":"char", "dec":"*"}}' */
  char *created_at;

  /* specs/github/gist.json:17:28
     '{ "name": "updated_at", "type":{ "base":"char", "dec":"*"}}' */
  char *updated_at;

  /* specs/github/gist.json:18:28
     '{ "name": "description", "type":{ "base":"char", "dec":"*"}}' */
  char *description;

  /* specs/github/gist.json:19:28
     '{ "name": "comments", "type":{ "base":"int"}}' */
  int comments;

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
/* This file is generated from specs/github/user.json, Please don't edit it. */

// User Structure
// defined at specs/github/user.json:9:33
/**
 * - Initializer:
 *   - <tt> void github_user_init(struct github_user *) </tt>
 * - Cleanup:
 *   - <tt> void github_user_cleanup(struct github_user *) </tt>
 *   - <tt> void github_user_list_free(struct github_user **) </tt>
 * - JSON Decoder:
 *   - <tt> void github_user_from_json(char *rbuf, size_t len, struct github_user **) </tt>
 *   - <tt> void github_user_list_from_json(char *rbuf, size_t len, struct github_user ***) </tt>
 * - JSON Encoder:
 *   - <tt> void github_user_to_json(char *wbuf, size_t len, struct github_user *) </tt>
 *   - <tt> void github_user_list_to_json(char *wbuf, size_t len, struct github_user **) </tt>
 */
struct github_user {
  /* specs/github/user.json:12:28
     '{ "name": "login", "type":{ "base":"char", "dec":"*"}}' */
  char *login;

  /* specs/github/user.json:13:28
     '{ "name": "id", "type":{ "base":"int"}}' */
  int id;

  /* specs/github/user.json:14:28
     '{ "name": "node_id", "type":{ "base":"char", "dec":"*"}}' */
  char *node_id;

  /* specs/github/user.json:15:28
     '{ "name": "avatar_url", "type":{ "base":"char", "dec":"*"}}' */
  char *avatar_url;

  /* specs/github/user.json:16:28
     '{ "name": "gravatar_id", "type":{ "base":"char", "dec":"*"}}' */
  char *gravatar_id;

  /* specs/github/user.json:17:28
     '{ "name": "html_url", "type":{ "base":"char", "dec":"*"}}' */
  char *html_url;

  /* specs/github/user.json:18:28
     '{ "name": "type", "type":{ "base":"char", "dec":"*"}}' */
  char *type;

  /* specs/github/user.json:19:28
     '{ "name": "site_admin", "type":{ "base":"bool"}}' */
  bool site_admin;

  /* specs/github/user.json:20:28
     '{ "name": "name", "type":{ "base":"char", "dec":"*"}}' */
  char *name;

  /* specs/github/user.json:21:28
     '{ "name": "company", "type":{ "base":"char", "dec":"*"}}' */
  char *company;

  /* specs/github/user.json:22:28
     '{ "name": "blog", "type":{ "base":"char", "dec":"*"}}' */
  char *blog;

  /* specs/github/user.json:23:28
     '{ "name": "location", "type":{ "base":"char", "dec":"*"}}' */
  char *location;

  /* specs/github/user.json:24:28
     '{ "name": "email", "type":{ "base":"char", "dec":"*"}}' */
  char *email;

  /* specs/github/user.json:25:28
     '{ "name": "hireable", "type":{ "base":"char", "dec":"*"}}' */
  char *hireable;

  /* specs/github/user.json:26:28
     '{ "name": "bio", "type":{ "base":"char", "dec":"*"}}' */
  char *bio;

  /* specs/github/user.json:27:28
     '{ "name": "public_repos", "type":{ "base":"int"}}' */
  int public_repos;

  /* specs/github/user.json:28:28
     '{ "name": "public_gists", "type":{ "base":"int"}}' */
  int public_gists;

  /* specs/github/user.json:29:28
     '{ "name": "followers", "type":{ "base":"int"}}' */
  int followers;

  /* specs/github/user.json:30:28
     '{ "name": "following", "type":{ "base":"int"}}' */
  int following;

  /* specs/github/user.json:31:28
     '{ "name": "created_at", "type":{ "base":"char", "dec":"*"}}' */
  char *created_at;

  /* specs/github/user.json:32:28
     '{ "name": "updated_at", "type":{ "base":"char", "dec":"*"}}' */
  char *updated_at;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[21];
    void *record_defined[21];
    void *record_null[21];
  } __M; // metadata
/// @endcond
};
/* This file is generated from specs/github/gist.endpoints-params.json, Please don't edit it. */

extern void github_gist_create_params_cleanup_v(void *p);
extern void github_gist_create_params_cleanup(struct github_gist_create_params *p);
extern void github_gist_create_params_init_v(void *p);
extern void github_gist_create_params_init(struct github_gist_create_params *p);
extern void github_gist_create_params_from_json_v(char *json, size_t len, void *pp);
extern void github_gist_create_params_from_json(char *json, size_t len, struct github_gist_create_params **pp);
extern size_t github_gist_create_params_to_json_v(char *json, size_t len, void *p);
extern size_t github_gist_create_params_to_json(char *json, size_t len, struct github_gist_create_params *p);
extern size_t github_gist_create_params_to_query_v(char *json, size_t len, void *p);
extern size_t github_gist_create_params_to_query(char *json, size_t len, struct github_gist_create_params *p);
extern void github_gist_create_params_list_free_v(void **p);
extern void github_gist_create_params_list_free(struct github_gist_create_params **p);
extern void github_gist_create_params_list_from_json_v(char *str, size_t len, void *p);
extern void github_gist_create_params_list_from_json(char *str, size_t len, struct github_gist_create_params ***p);
extern size_t github_gist_create_params_list_to_json_v(char *str, size_t len, void *p);
extern size_t github_gist_create_params_list_to_json(char *str, size_t len, struct github_gist_create_params **p);
/* This file is generated from specs/github/gist.json, Please don't edit it. */

extern void github_gist_cleanup_v(void *p);
extern void github_gist_cleanup(struct github_gist *p);
extern void github_gist_init_v(void *p);
extern void github_gist_init(struct github_gist *p);
extern void github_gist_from_json_v(char *json, size_t len, void *pp);
extern void github_gist_from_json(char *json, size_t len, struct github_gist **pp);
extern size_t github_gist_to_json_v(char *json, size_t len, void *p);
extern size_t github_gist_to_json(char *json, size_t len, struct github_gist *p);
extern size_t github_gist_to_query_v(char *json, size_t len, void *p);
extern size_t github_gist_to_query(char *json, size_t len, struct github_gist *p);
extern void github_gist_list_free_v(void **p);
extern void github_gist_list_free(struct github_gist **p);
extern void github_gist_list_from_json_v(char *str, size_t len, void *p);
extern void github_gist_list_from_json(char *str, size_t len, struct github_gist ***p);
extern size_t github_gist_list_to_json_v(char *str, size_t len, void *p);
extern size_t github_gist_list_to_json(char *str, size_t len, struct github_gist **p);
/* This file is generated from specs/github/user.json, Please don't edit it. */

extern void github_user_cleanup_v(void *p);
extern void github_user_cleanup(struct github_user *p);
extern void github_user_init_v(void *p);
extern void github_user_init(struct github_user *p);
extern void github_user_from_json_v(char *json, size_t len, void *pp);
extern void github_user_from_json(char *json, size_t len, struct github_user **pp);
extern size_t github_user_to_json_v(char *json, size_t len, void *p);
extern size_t github_user_to_json(char *json, size_t len, struct github_user *p);
extern size_t github_user_to_query_v(char *json, size_t len, void *p);
extern size_t github_user_to_query(char *json, size_t len, struct github_user *p);
extern void github_user_list_free_v(void **p);
extern void github_user_list_free(struct github_user **p);
extern void github_user_list_from_json_v(char *str, size_t len, void *p);
extern void github_user_list_from_json(char *str, size_t len, struct github_user ***p);
extern size_t github_user_list_to_json_v(char *str, size_t len, void *p);
extern size_t github_user_list_to_json(char *str, size_t len, struct github_user **p);
