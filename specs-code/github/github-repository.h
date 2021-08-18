/* This file is generated from specs/github/github-repository.json, Please don't edit it. */
/**
 * @file specs-code/github/github-repository.h
 * @see https://docs.github.com/en/rest/reference/repos#get-a-repository
 */


// Repository Structure
// defined at specs/github/github-repository.json:9:33
/**
 * - Initializer:
 *   - <tt> github_repository_init(struct github_repository *) </tt>
 * - Cleanup:
 *   - <tt> github_repository_cleanup(struct github_repository *) </tt>
 *   - <tt> github_repository_list_free(struct github_repository **) </tt>
 * - JSON Decoder:
 *   - <tt> github_repository_from_json(char *rbuf, size_t len, struct github_repository **) </tt>
 *   - <tt> github_repository_list_from_json(char *rbuf, size_t len, struct github_repository ***) </tt>
 * - JSON Encoder:
 *   - <tt> github_repository_to_json(char *wbuf, size_t len, struct github_repository *) </tt>
 *   - <tt> github_repository_list_to_json(char *wbuf, size_t len, struct github_repository **) </tt>
 */
struct github_repository {
  /* specs/github/github-repository.json:12:28
     '{ "name": "id", "type":{ "base":"int"}}' */
  int id;

  /* specs/github/github-repository.json:13:28
     '{ "name": "node_id", "type":{ "base":"char", "dec":"*"}}' */
  char *node_id;

  /* specs/github/github-repository.json:14:28
     '{ "name": "name", "type":{ "base":"char", "dec":"*"}}' */
  char *name;

  /* specs/github/github-repository.json:15:28
     '{ "name": "full_name", "type":{ "base":"char", "dec":"*"}}' */
  char *full_name;

  /* specs/github/github-repository.json:16:28
     '{ "name": "private", "type":{ "base":"bool"}}' */
  bool private;

  /* specs/github/github-repository.json:17:77
     '{ "type": {"base":"struct github_user", "dec":"*"}, "name":"owner"}' */
  struct github_user *owner;

  // The following is metadata used to 
  // 1. control which field should be extracted/injected
  // 2. record which field is presented(defined) in JSON
  // 3. record which field is null in JSON
/// @cond DOXYGEN_SHOULD_SKIP_THIS
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[6];
    void *record_defined[6];
    void *record_null[6];
  } __M; // metadata
/// @endcond
};
extern void github_repository_cleanup_v(void *p);
extern void github_repository_cleanup(struct github_repository *p);
extern void github_repository_init_v(void *p);
extern void github_repository_init(struct github_repository *p);
extern void github_repository_from_json_v(char *json, size_t len, void *pp);
extern void github_repository_from_json(char *json, size_t len, struct github_repository **pp);
extern size_t github_repository_to_json_v(char *json, size_t len, void *p);
extern size_t github_repository_to_json(char *json, size_t len, struct github_repository *p);
extern size_t github_repository_to_query_v(char *json, size_t len, void *p);
extern size_t github_repository_to_query(char *json, size_t len, struct github_repository *p);
extern void github_repository_list_free_v(void **p);
extern void github_repository_list_free(struct github_repository **p);
extern void github_repository_list_from_json_v(char *str, size_t len, void *p);
extern void github_repository_list_from_json(char *str, size_t len, struct github_repository ***p);
extern size_t github_repository_list_to_json_v(char *str, size_t len, void *p);
extern size_t github_repository_list_to_json(char *str, size_t len, struct github_repository **p);
