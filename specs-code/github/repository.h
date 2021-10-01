/* This file is generated from specs/github/repository.json, Please don't edit it. */
/**
 * @file specs-code/github/repository.h
 * @see https://docs.github.com/en/rest/reference/repos#get-all-repository-topics
 */


/* Topic Structure */
/* defined at specs/github/repository.json:9:33 */
/**
 * @verbatim embed:rst:leading-asterisk
 * .. container:: toggle

 *   .. container:: header

 *     **Methods**

 *   * Initializer:

 *     * :code:`void github_topic_init(struct github_topic *)`
 *   * Cleanup:

 *     * :code:`void github_topic_cleanup(struct github_topic *)`
 *     * :code:`void github_topic_list_free(struct github_topic **)`
 *   * JSON Decoder:

 *     * :code:`void github_topic_from_json(char *rbuf, size_t len, struct github_topic **)`
 *     * :code:`void github_topic_list_from_json(char *rbuf, size_t len, struct github_topic ***)`
 *   * JSON Encoder:

 *     * :code:`void github_topic_to_json(char *wbuf, size_t len, struct github_topic *)`
 *     * :code:`void github_topic_list_to_json(char *wbuf, size_t len, struct github_topic **)`
 * @endverbatim
 */
struct github_topic {
  /* specs/github/repository.json:12:28
     '{ "name": "names", "type":{ "base":"ja_str", "dec":"ntl"}}' */
  ja_str **names;

  /* The following is metadata used to 
     1. control which field should be extracted/injected
     2. record which field is presented(defined) in JSON
     3. record which field is null in JSON */
/** @cond DOXYGEN_SHOULD_SKIP_THIS */
  struct {
    bool enable_arg_switches;
    bool enable_record_defined;
    bool enable_record_null;
    void *arg_switches[1];
    void *record_defined[1];
    void *record_null[1];
  } __M; /**< metadata */
/** @endcond */
};
extern void github_topic_cleanup_v(void *p);
extern void github_topic_cleanup(struct github_topic *p);
extern void github_topic_init_v(void *p);
extern void github_topic_init(struct github_topic *p);
extern void github_topic_from_json_v(char *json, size_t len, void *pp);
extern void github_topic_from_json(char *json, size_t len, struct github_topic **pp);
extern size_t github_topic_to_json_v(char *json, size_t len, void *p);
extern size_t github_topic_to_json(char *json, size_t len, struct github_topic *p);
extern void github_topic_list_free_v(void **p);
extern void github_topic_list_free(struct github_topic **p);
extern void github_topic_list_from_json_v(char *str, size_t len, void *p);
extern void github_topic_list_from_json(char *str, size_t len, struct github_topic ***p);
extern size_t github_topic_list_to_json_v(char *str, size_t len, void *p);
extern size_t github_topic_list_to_json(char *str, size_t len, struct github_topic **p);
