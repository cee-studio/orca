/* This file is generated from specs/github/github-user.json, Please don't edit it. */
/**
 * @file specs-code/github/all_structs.h
 * @see https://docs.github.com/en/rest/reference/users#get-a-user
 */


// User Structure
// defined at specs/github/github-user.json:9:33
/**
 * - Initializer:
 *   - <tt> github_user_init(struct github_user *) </tt>
 * - Cleanup:
 *   - <tt> github_user_cleanup(struct github_user *) </tt>
 *   - <tt> github_user_list_free(struct github_user **) </tt>
 * - JSON Decoder:
 *   - <tt> github_user_from_json(char *rbuf, size_t len, struct github_user **) </tt>
 *   - <tt> github_user_list_from_json(char *rbuf, size_t len, struct github_user ***) </tt>
 * - JSON Encoder:
 *   - <tt> github_user_to_json(char *wbuf, size_t len, struct github_user *) </tt>
 *   - <tt> github_user_list_to_json(char *wbuf, size_t len, struct github_user **) </tt>
 */
struct github_user {
  /* specs/github/github-user.json:12:28
     '{ "name": "login", "type":{ "base":"char", "dec":"*"}}' */
  char *login;

  /* specs/github/github-user.json:13:28
     '{ "name": "id", "type":{ "base":"int64_t"}}' */
  int64_t id;

  /* specs/github/github-user.json:14:28
     '{ "name": "node_id", "type":{ "base":"char", "dec":"*"}}' */
  char *node_id;

  /* specs/github/github-user.json:15:28
     '{ "name": "avatar_url", "type":{ "base":"char", "dec":"*"}}' */
  char *avatar_url;

  /* specs/github/github-user.json:16:28
     '{ "name": "gravatar_id", "type":{ "base":"char", "dec":"*"}}' */
  char *gravatar_id;

  /* specs/github/github-user.json:17:28
     '{ "name": "html_url", "type":{ "base":"char", "dec":"*"}}' */
  char *html_url;

  /* specs/github/github-user.json:18:28
     '{ "name": "type", "type":{ "base":"char", "dec":"*"}}' */
  char *type;

  /* specs/github/github-user.json:19:28
     '{ "name": "site_admin", "type":{ "base":"bool"}}' */
  bool site_admin;

  /* specs/github/github-user.json:20:28
     '{ "name": "name", "type":{ "base":"char", "dec":"*"}}' */
  char *name;

  /* specs/github/github-user.json:21:28
     '{ "name": "company", "type":{ "base":"char", "dec":"*"}}' */
  char *company;

  /* specs/github/github-user.json:22:28
     '{ "name": "blog", "type":{ "base":"char", "dec":"*"}}' */
  char *blog;

  /* specs/github/github-user.json:23:28
     '{ "name": "location", "type":{ "base":"char", "dec":"*"}}' */
  char *location;

  /* specs/github/github-user.json:24:28
     '{ "name": "email", "type":{ "base":"char", "dec":"*"}}' */
  char *email;

  /* specs/github/github-user.json:25:28
     '{ "name": "hireable", "type":{ "base":"char", "dec":"*"}}' */
  char *hireable;

  /* specs/github/github-user.json:26:28
     '{ "name": "bio", "type":{ "base":"char", "dec":"*"}}' */
  char *bio;

  /* specs/github/github-user.json:27:28
     '{ "name": "public_repos", "type":{ "base":"int"}}' */
  int public_repos;

  /* specs/github/github-user.json:28:28
     '{ "name": "public_gists", "type":{ "base":"int"}}' */
  int public_gists;

  /* specs/github/github-user.json:29:28
     '{ "name": "followers", "type":{ "base":"int"}}' */
  int followers;

  /* specs/github/github-user.json:30:28
     '{ "name": "following", "type":{ "base":"int"}}' */
  int following;

  /* specs/github/github-user.json:31:28
     '{ "name": "created_at", "type":{ "base":"char", "dec":"*"}}' */
  char *created_at;

  /* specs/github/github-user.json:32:28
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
