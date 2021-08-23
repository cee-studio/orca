/* This file is generated from specs/github/gist.endpoints-params.json, Please don't edit it. */
/**
 * @file specs-code/github/gist.endpoints-params.h
 * @see https://docs.github.com/en/rest/reference/gists
 */


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
