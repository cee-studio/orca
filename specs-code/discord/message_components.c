/* This file is generated from specs/discord/message_components.json, Please don't edit it. */
/**
 * @file specs-code/discord/message_components.c
 * @author cee-studio
 * @date 17 Jul 2021
 * @brief Specs generated file
 * @see https://discord.com/developers/docs/interactions/message-components#message-components
 */

#include "specs.h"

void discord_component_from_json(char *json, size_t len, struct discord_component *p)
{
  static size_t ret=0; // used for debugging
  size_t r=0;
  r=json_extract(json, len, 
  /* specs/discord/message_components.json:12:18
     '{"name":"type", "type":{"base":"int", "int_alias":"enum discord_component_types"}, "comment":"component type"}' */
                "(type):d,"
  /* specs/discord/message_components.json:13:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "comment":"a developer-defined identifier for the component, max 100 characters"}' */
                "(custom_id):s,"
  /* specs/discord/message_components.json:14:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"whether the component is disabled, default false"}' */
                "(disabled):b,"
  /* specs/discord/message_components.json:15:18
     '{"name":"style", "type":{"base":"int", "int_alias":"enum discord_button_styles"}, "option":true, "inject_if_not":0, "comment":"one of button styles"}' */
                "(style):d,"
  /* specs/discord/message_components.json:16:18
     '{"name":"label", "type":{"base":"char", "dec":"[80+1]"}, "option":true, "comment":"text that appears on the button, max 80 characters", "inject_if_not":""}' */
                "(label):s,"
  /* specs/discord/message_components.json:17:18
     '{"name":"emoji", "type":{"base":"struct discord_emoji", "dec":"*"}, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
                "(emoji):F,"
  /* specs/discord/message_components.json:18:18
     '{"name":"url", "type":{"base":"char", "dec":"*"}, "option":true, "comment":"a url for link-style buttons", "inject_if_not":null}' */
                "(url):?s,"
  /* specs/discord/message_components.json:19:18
     '{"name":"options", "type":{"base":"struct discord_select_menu", "dec":"ntl"}, "option":true, "comment":"the choices in the select, max 25", "inject_if_not":null}' */
                "(options):F,"
  /* specs/discord/message_components.json:20:18
     '{"name":"placeholder", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"custom placeholder text if nothing is selected, max 100 characters", "inject_if_not":""}' */
                "(placeholder):s,"
  /* specs/discord/message_components.json:21:18
     '{"name":"min_values", "type":{"base":"int"}, "option":true, "comment":"the minimum number of items that must be chosen; default 1, min 0, max 25"}' */
                "(min_values):d,"
  /* specs/discord/message_components.json:22:18
     '{"name":"max_values", "type":{"base":"int"}, "option":true, "comment":"the maximum number of items that must be chosen; default 1, min 0, max 25"}' */
                "(max_values):d,"
  /* specs/discord/message_components.json:23:18
     '{"name":"components", "type":{ "base":"struct discord_component", "dec":"ntl" }, "option":true, "comment":"a list of child components", "inject_if_not":null}' */
                "(components):F,"
                "@arg_switches:b"
                "@record_defined"
                "@record_null",
  /* specs/discord/message_components.json:12:18
     '{"name":"type", "type":{"base":"int", "int_alias":"enum discord_component_types"}, "comment":"component type"}' */
                &p->type,
  /* specs/discord/message_components.json:13:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "comment":"a developer-defined identifier for the component, max 100 characters"}' */
                p->custom_id,
  /* specs/discord/message_components.json:14:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"whether the component is disabled, default false"}' */
                &p->disabled,
  /* specs/discord/message_components.json:15:18
     '{"name":"style", "type":{"base":"int", "int_alias":"enum discord_button_styles"}, "option":true, "inject_if_not":0, "comment":"one of button styles"}' */
                &p->style,
  /* specs/discord/message_components.json:16:18
     '{"name":"label", "type":{"base":"char", "dec":"[80+1]"}, "option":true, "comment":"text that appears on the button, max 80 characters", "inject_if_not":""}' */
                p->label,
  /* specs/discord/message_components.json:17:18
     '{"name":"emoji", "type":{"base":"struct discord_emoji", "dec":"*"}, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
                discord_emoji_from_json, p->emoji,
  /* specs/discord/message_components.json:18:18
     '{"name":"url", "type":{"base":"char", "dec":"*"}, "option":true, "comment":"a url for link-style buttons", "inject_if_not":null}' */
                &p->url,
  /* specs/discord/message_components.json:19:18
     '{"name":"options", "type":{"base":"struct discord_select_menu", "dec":"ntl"}, "option":true, "comment":"the choices in the select, max 25", "inject_if_not":null}' */
                discord_select_menu_list_from_json, &p->options,
  /* specs/discord/message_components.json:20:18
     '{"name":"placeholder", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"custom placeholder text if nothing is selected, max 100 characters", "inject_if_not":""}' */
                p->placeholder,
  /* specs/discord/message_components.json:21:18
     '{"name":"min_values", "type":{"base":"int"}, "option":true, "comment":"the minimum number of items that must be chosen; default 1, min 0, max 25"}' */
                &p->min_values,
  /* specs/discord/message_components.json:22:18
     '{"name":"max_values", "type":{"base":"int"}, "option":true, "comment":"the maximum number of items that must be chosen; default 1, min 0, max 25"}' */
                &p->max_values,
  /* specs/discord/message_components.json:23:18
     '{"name":"components", "type":{ "base":"struct discord_component", "dec":"ntl" }, "option":true, "comment":"a list of child components", "inject_if_not":null}' */
                discord_component_list_from_json, &p->components,
                p->__M.arg_switches, sizeof(p->__M.arg_switches), p->__M.enable_arg_switches,
                p->__M.record_defined, sizeof(p->__M.record_defined),
                p->__M.record_null, sizeof(p->__M.record_null));
  ret = r;
}

static void discord_component_use_default_inject_settings(struct discord_component *p)
{
  p->__M.enable_arg_switches = true;
  /* specs/discord/message_components.json:12:18
     '{"name":"type", "type":{"base":"int", "int_alias":"enum discord_component_types"}, "comment":"component type"}' */
  p->__M.arg_switches[0] = &p->type;

  /* specs/discord/message_components.json:13:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "comment":"a developer-defined identifier for the component, max 100 characters"}' */
  p->__M.arg_switches[1] = p->custom_id;

  /* specs/discord/message_components.json:14:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"whether the component is disabled, default false"}' */
  if (p->disabled != false)
    p->__M.arg_switches[2] = &p->disabled;

  /* specs/discord/message_components.json:15:18
     '{"name":"style", "type":{"base":"int", "int_alias":"enum discord_button_styles"}, "option":true, "inject_if_not":0, "comment":"one of button styles"}' */
  if (p->style != 0)
    p->__M.arg_switches[3] = &p->style;

  /* specs/discord/message_components.json:16:18
     '{"name":"label", "type":{"base":"char", "dec":"[80+1]"}, "option":true, "comment":"text that appears on the button, max 80 characters", "inject_if_not":""}' */
  if (strlen(p->label) != 0)
    p->__M.arg_switches[4] = p->label;

  /* specs/discord/message_components.json:17:18
     '{"name":"emoji", "type":{"base":"struct discord_emoji", "dec":"*"}, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
  if (p->emoji != NULL)
    p->__M.arg_switches[5] = p->emoji;

  /* specs/discord/message_components.json:18:18
     '{"name":"url", "type":{"base":"char", "dec":"*"}, "option":true, "comment":"a url for link-style buttons", "inject_if_not":null}' */
  if (p->url != NULL)
    p->__M.arg_switches[6] = p->url;

  /* specs/discord/message_components.json:19:18
     '{"name":"options", "type":{"base":"struct discord_select_menu", "dec":"ntl"}, "option":true, "comment":"the choices in the select, max 25", "inject_if_not":null}' */
  if (p->options != NULL)
    p->__M.arg_switches[7] = p->options;

  /* specs/discord/message_components.json:20:18
     '{"name":"placeholder", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"custom placeholder text if nothing is selected, max 100 characters", "inject_if_not":""}' */
  if (strlen(p->placeholder) != 0)
    p->__M.arg_switches[8] = p->placeholder;

  /* specs/discord/message_components.json:21:18
     '{"name":"min_values", "type":{"base":"int"}, "option":true, "comment":"the minimum number of items that must be chosen; default 1, min 0, max 25"}' */
  p->__M.arg_switches[9] = &p->min_values;

  /* specs/discord/message_components.json:22:18
     '{"name":"max_values", "type":{"base":"int"}, "option":true, "comment":"the maximum number of items that must be chosen; default 1, min 0, max 25"}' */
  p->__M.arg_switches[10] = &p->max_values;

  /* specs/discord/message_components.json:23:18
     '{"name":"components", "type":{ "base":"struct discord_component", "dec":"ntl" }, "option":true, "comment":"a list of child components", "inject_if_not":null}' */
  if (p->components != NULL)
    p->__M.arg_switches[11] = p->components;

}

size_t discord_component_to_json(char *json, size_t len, struct discord_component *p)
{
  size_t r;
  discord_component_use_default_inject_settings(p);
  r=json_inject(json, len, 
  /* specs/discord/message_components.json:12:18
     '{"name":"type", "type":{"base":"int", "int_alias":"enum discord_component_types"}, "comment":"component type"}' */
                "(type):d,"
  /* specs/discord/message_components.json:13:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "comment":"a developer-defined identifier for the component, max 100 characters"}' */
                "(custom_id):s,"
  /* specs/discord/message_components.json:14:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"whether the component is disabled, default false"}' */
                "(disabled):b,"
  /* specs/discord/message_components.json:15:18
     '{"name":"style", "type":{"base":"int", "int_alias":"enum discord_button_styles"}, "option":true, "inject_if_not":0, "comment":"one of button styles"}' */
                "(style):d,"
  /* specs/discord/message_components.json:16:18
     '{"name":"label", "type":{"base":"char", "dec":"[80+1]"}, "option":true, "comment":"text that appears on the button, max 80 characters", "inject_if_not":""}' */
                "(label):s,"
  /* specs/discord/message_components.json:17:18
     '{"name":"emoji", "type":{"base":"struct discord_emoji", "dec":"*"}, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
                "(emoji):F,"
  /* specs/discord/message_components.json:18:18
     '{"name":"url", "type":{"base":"char", "dec":"*"}, "option":true, "comment":"a url for link-style buttons", "inject_if_not":null}' */
                "(url):s,"
  /* specs/discord/message_components.json:19:18
     '{"name":"options", "type":{"base":"struct discord_select_menu", "dec":"ntl"}, "option":true, "comment":"the choices in the select, max 25", "inject_if_not":null}' */
                "(options):F,"
  /* specs/discord/message_components.json:20:18
     '{"name":"placeholder", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"custom placeholder text if nothing is selected, max 100 characters", "inject_if_not":""}' */
                "(placeholder):s,"
  /* specs/discord/message_components.json:21:18
     '{"name":"min_values", "type":{"base":"int"}, "option":true, "comment":"the minimum number of items that must be chosen; default 1, min 0, max 25"}' */
                "(min_values):d,"
  /* specs/discord/message_components.json:22:18
     '{"name":"max_values", "type":{"base":"int"}, "option":true, "comment":"the maximum number of items that must be chosen; default 1, min 0, max 25"}' */
                "(max_values):d,"
  /* specs/discord/message_components.json:23:18
     '{"name":"components", "type":{ "base":"struct discord_component", "dec":"ntl" }, "option":true, "comment":"a list of child components", "inject_if_not":null}' */
                "(components):F,"
                "@arg_switches:b",
  /* specs/discord/message_components.json:12:18
     '{"name":"type", "type":{"base":"int", "int_alias":"enum discord_component_types"}, "comment":"component type"}' */
                &p->type,
  /* specs/discord/message_components.json:13:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "comment":"a developer-defined identifier for the component, max 100 characters"}' */
                p->custom_id,
  /* specs/discord/message_components.json:14:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"whether the component is disabled, default false"}' */
                &p->disabled,
  /* specs/discord/message_components.json:15:18
     '{"name":"style", "type":{"base":"int", "int_alias":"enum discord_button_styles"}, "option":true, "inject_if_not":0, "comment":"one of button styles"}' */
                &p->style,
  /* specs/discord/message_components.json:16:18
     '{"name":"label", "type":{"base":"char", "dec":"[80+1]"}, "option":true, "comment":"text that appears on the button, max 80 characters", "inject_if_not":""}' */
                p->label,
  /* specs/discord/message_components.json:17:18
     '{"name":"emoji", "type":{"base":"struct discord_emoji", "dec":"*"}, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
                discord_emoji_to_json, p->emoji,
  /* specs/discord/message_components.json:18:18
     '{"name":"url", "type":{"base":"char", "dec":"*"}, "option":true, "comment":"a url for link-style buttons", "inject_if_not":null}' */
                p->url,
  /* specs/discord/message_components.json:19:18
     '{"name":"options", "type":{"base":"struct discord_select_menu", "dec":"ntl"}, "option":true, "comment":"the choices in the select, max 25", "inject_if_not":null}' */
                discord_select_menu_list_to_json, p->options,
  /* specs/discord/message_components.json:20:18
     '{"name":"placeholder", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"custom placeholder text if nothing is selected, max 100 characters", "inject_if_not":""}' */
                p->placeholder,
  /* specs/discord/message_components.json:21:18
     '{"name":"min_values", "type":{"base":"int"}, "option":true, "comment":"the minimum number of items that must be chosen; default 1, min 0, max 25"}' */
                &p->min_values,
  /* specs/discord/message_components.json:22:18
     '{"name":"max_values", "type":{"base":"int"}, "option":true, "comment":"the maximum number of items that must be chosen; default 1, min 0, max 25"}' */
                &p->max_values,
  /* specs/discord/message_components.json:23:18
     '{"name":"components", "type":{ "base":"struct discord_component", "dec":"ntl" }, "option":true, "comment":"a list of child components", "inject_if_not":null}' */
                discord_component_list_to_json, p->components,
                p->__M.arg_switches, sizeof(p->__M.arg_switches), p->__M.enable_arg_switches);
  return r;
}


typedef void (*vfvp)(void *);
typedef void (*vfcpsvp)(char *, size_t, void *);
typedef size_t (*sfcpsvp)(char *, size_t, void *);
void discord_component_cleanup_v(void *p) {
  discord_component_cleanup((struct discord_component *)p);
}

void discord_component_init_v(void *p) {
  discord_component_init((struct discord_component *)p);
}

void discord_component_free_v(void *p) {
 discord_component_free((struct discord_component *)p);
};

void discord_component_from_json_v(char *json, size_t len, void *p) {
 discord_component_from_json(json, len, (struct discord_component*)p);
}

size_t discord_component_to_json_v(char *json, size_t len, void *p) {
  return discord_component_to_json(json, len, (struct discord_component*)p);
}

void discord_component_list_free_v(void **p) {
  discord_component_list_free((struct discord_component**)p);
}

void discord_component_list_from_json_v(char *str, size_t len, void *p) {
  discord_component_list_from_json(str, len, (struct discord_component ***)p);
}

size_t discord_component_list_to_json_v(char *str, size_t len, void *p){
  return discord_component_list_to_json(str, len, (struct discord_component **)p);
}


void discord_component_cleanup(struct discord_component *d) {
  /* specs/discord/message_components.json:12:18
     '{"name":"type", "type":{"base":"int", "int_alias":"enum discord_component_types"}, "comment":"component type"}' */
  // p->type is a scalar
  /* specs/discord/message_components.json:13:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "comment":"a developer-defined identifier for the component, max 100 characters"}' */
  // p->custom_id is a scalar
  /* specs/discord/message_components.json:14:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"whether the component is disabled, default false"}' */
  // p->disabled is a scalar
  /* specs/discord/message_components.json:15:18
     '{"name":"style", "type":{"base":"int", "int_alias":"enum discord_button_styles"}, "option":true, "inject_if_not":0, "comment":"one of button styles"}' */
  // p->style is a scalar
  /* specs/discord/message_components.json:16:18
     '{"name":"label", "type":{"base":"char", "dec":"[80+1]"}, "option":true, "comment":"text that appears on the button, max 80 characters", "inject_if_not":""}' */
  // p->label is a scalar
  /* specs/discord/message_components.json:17:18
     '{"name":"emoji", "type":{"base":"struct discord_emoji", "dec":"*"}, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
  if (d->emoji)
    discord_emoji_free(d->emoji);
  /* specs/discord/message_components.json:18:18
     '{"name":"url", "type":{"base":"char", "dec":"*"}, "option":true, "comment":"a url for link-style buttons", "inject_if_not":null}' */
  if (d->url)
    free(d->url);
  /* specs/discord/message_components.json:19:18
     '{"name":"options", "type":{"base":"struct discord_select_menu", "dec":"ntl"}, "option":true, "comment":"the choices in the select, max 25", "inject_if_not":null}' */
  if (d->options)
    discord_select_menu_list_free(d->options);
  /* specs/discord/message_components.json:20:18
     '{"name":"placeholder", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"custom placeholder text if nothing is selected, max 100 characters", "inject_if_not":""}' */
  // p->placeholder is a scalar
  /* specs/discord/message_components.json:21:18
     '{"name":"min_values", "type":{"base":"int"}, "option":true, "comment":"the minimum number of items that must be chosen; default 1, min 0, max 25"}' */
  // p->min_values is a scalar
  /* specs/discord/message_components.json:22:18
     '{"name":"max_values", "type":{"base":"int"}, "option":true, "comment":"the maximum number of items that must be chosen; default 1, min 0, max 25"}' */
  // p->max_values is a scalar
  /* specs/discord/message_components.json:23:18
     '{"name":"components", "type":{ "base":"struct discord_component", "dec":"ntl" }, "option":true, "comment":"a list of child components", "inject_if_not":null}' */
  if (d->components)
    discord_component_list_free(d->components);
}

void discord_component_init(struct discord_component *p) {
  memset(p, 0, sizeof(struct discord_component));
  /* specs/discord/message_components.json:12:18
     '{"name":"type", "type":{"base":"int", "int_alias":"enum discord_component_types"}, "comment":"component type"}' */

  /* specs/discord/message_components.json:13:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "comment":"a developer-defined identifier for the component, max 100 characters"}' */

  /* specs/discord/message_components.json:14:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"whether the component is disabled, default false"}' */

  /* specs/discord/message_components.json:15:18
     '{"name":"style", "type":{"base":"int", "int_alias":"enum discord_button_styles"}, "option":true, "inject_if_not":0, "comment":"one of button styles"}' */

  /* specs/discord/message_components.json:16:18
     '{"name":"label", "type":{"base":"char", "dec":"[80+1]"}, "option":true, "comment":"text that appears on the button, max 80 characters", "inject_if_not":""}' */

  /* specs/discord/message_components.json:17:18
     '{"name":"emoji", "type":{"base":"struct discord_emoji", "dec":"*"}, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
  p->emoji = discord_emoji_alloc();

  /* specs/discord/message_components.json:18:18
     '{"name":"url", "type":{"base":"char", "dec":"*"}, "option":true, "comment":"a url for link-style buttons", "inject_if_not":null}' */

  /* specs/discord/message_components.json:19:18
     '{"name":"options", "type":{"base":"struct discord_select_menu", "dec":"ntl"}, "option":true, "comment":"the choices in the select, max 25", "inject_if_not":null}' */

  /* specs/discord/message_components.json:20:18
     '{"name":"placeholder", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"custom placeholder text if nothing is selected, max 100 characters", "inject_if_not":""}' */

  /* specs/discord/message_components.json:21:18
     '{"name":"min_values", "type":{"base":"int"}, "option":true, "comment":"the minimum number of items that must be chosen; default 1, min 0, max 25"}' */

  /* specs/discord/message_components.json:22:18
     '{"name":"max_values", "type":{"base":"int"}, "option":true, "comment":"the maximum number of items that must be chosen; default 1, min 0, max 25"}' */

  /* specs/discord/message_components.json:23:18
     '{"name":"components", "type":{ "base":"struct discord_component", "dec":"ntl" }, "option":true, "comment":"a list of child components", "inject_if_not":null}' */

}
struct discord_component* discord_component_alloc() {
  struct discord_component *p= malloc(sizeof(struct discord_component));
  discord_component_init(p);
  return p;
}

void discord_component_free(struct discord_component *p) {
  discord_component_cleanup(p);
  free(p);
}

void discord_component_list_free(struct discord_component **p) {
  ntl_free((void**)p, (vfvp)discord_component_cleanup);
}

void discord_component_list_from_json(char *str, size_t len, struct discord_component ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct discord_component);
  d.init_elem = discord_component_init_v;
  d.elem_from_buf = discord_component_from_json_v;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json(str, len, &d);
}

size_t discord_component_list_to_json(char *str, size_t len, struct discord_component **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, discord_component_to_json_v);
}



enum discord_component_types discord_component_types_from_string(char *s){
  if(strcasecmp("ACTION_ROW", s) == 0) return DISCORD_COMPONENT_ACTION_ROW;
  if(strcasecmp("BUTTON", s) == 0) return DISCORD_COMPONENT_BUTTON;
  if(strcasecmp("SELECT_MENU", s) == 0) return DISCORD_COMPONENT_SELECT_MENU;
  abort();
}
char* discord_component_types_to_string(enum discord_component_types v){
  if (v == DISCORD_COMPONENT_ACTION_ROW) return "ACTION_ROW";
  if (v == DISCORD_COMPONENT_BUTTON) return "BUTTON";
  if (v == DISCORD_COMPONENT_SELECT_MENU) return "SELECT_MENU";

  return (void*)0;
}
bool discord_component_types_has(enum discord_component_types v, char *s) {
  enum discord_component_types v1 = discord_component_types_from_string(s);
  if (v == v1) return true;
  if (v == v1) return true;
  if (v == v1) return true;
  return false;
}

void discord_button_from_json(char *json, size_t len, struct discord_button *p)
{
  static size_t ret=0; // used for debugging
  size_t r=0;
  r=json_extract(json, len, 
  /* specs/discord/message_components.json:44:18
     '{"name":"type", "type": {"base":"int", "int_alias":"enum discord_component_types"}, "comment": "2 for a button"}' */
                "(type):d,"
  /* specs/discord/message_components.json:45:18
     '{"name":"style", "type": {"base":"int", "int_alias":"enum discord_button_styles"}, "comment": "one of button styles"}' */
                "(style):d,"
  /* specs/discord/message_components.json:46:18
     '{"name":"label", "type":{"base":"char", "dec":"[80+1]"}, "option":true, "comment":"text that appears on the button, max 80 characters", "inject_if_not":""}' */
                "(label):s,"
  /* specs/discord/message_components.json:47:18
     '{"name":"emoji", "type":{ "base":"struct discord_emoji", "dec":"*" }, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
                "(emoji):F,"
  /* specs/discord/message_components.json:48:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"a developer-defined identifier for the component, max 100 characters", "inject_if_not":""}' */
                "(custom_id):s,"
  /* specs/discord/message_components.json:49:18
     '{"name":"url", "type":{"base":"char", "dec":"*"}, "option":true, "comment":"a url for link-style buttons", "inject_if_not":null}' */
                "(url):?s,"
  /* specs/discord/message_components.json:50:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"whether the component is disabled, default false"}' */
                "(disabled):b,"
                "@arg_switches:b"
                "@record_defined"
                "@record_null",
  /* specs/discord/message_components.json:44:18
     '{"name":"type", "type": {"base":"int", "int_alias":"enum discord_component_types"}, "comment": "2 for a button"}' */
                &p->type,
  /* specs/discord/message_components.json:45:18
     '{"name":"style", "type": {"base":"int", "int_alias":"enum discord_button_styles"}, "comment": "one of button styles"}' */
                &p->style,
  /* specs/discord/message_components.json:46:18
     '{"name":"label", "type":{"base":"char", "dec":"[80+1]"}, "option":true, "comment":"text that appears on the button, max 80 characters", "inject_if_not":""}' */
                p->label,
  /* specs/discord/message_components.json:47:18
     '{"name":"emoji", "type":{ "base":"struct discord_emoji", "dec":"*" }, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
                discord_emoji_from_json, p->emoji,
  /* specs/discord/message_components.json:48:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"a developer-defined identifier for the component, max 100 characters", "inject_if_not":""}' */
                p->custom_id,
  /* specs/discord/message_components.json:49:18
     '{"name":"url", "type":{"base":"char", "dec":"*"}, "option":true, "comment":"a url for link-style buttons", "inject_if_not":null}' */
                &p->url,
  /* specs/discord/message_components.json:50:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"whether the component is disabled, default false"}' */
                &p->disabled,
                p->__M.arg_switches, sizeof(p->__M.arg_switches), p->__M.enable_arg_switches,
                p->__M.record_defined, sizeof(p->__M.record_defined),
                p->__M.record_null, sizeof(p->__M.record_null));
  ret = r;
}

static void discord_button_use_default_inject_settings(struct discord_button *p)
{
  p->__M.enable_arg_switches = true;
  /* specs/discord/message_components.json:44:18
     '{"name":"type", "type": {"base":"int", "int_alias":"enum discord_component_types"}, "comment": "2 for a button"}' */
  p->__M.arg_switches[0] = &p->type;

  /* specs/discord/message_components.json:45:18
     '{"name":"style", "type": {"base":"int", "int_alias":"enum discord_button_styles"}, "comment": "one of button styles"}' */
  p->__M.arg_switches[1] = &p->style;

  /* specs/discord/message_components.json:46:18
     '{"name":"label", "type":{"base":"char", "dec":"[80+1]"}, "option":true, "comment":"text that appears on the button, max 80 characters", "inject_if_not":""}' */
  if (strlen(p->label) != 0)
    p->__M.arg_switches[2] = p->label;

  /* specs/discord/message_components.json:47:18
     '{"name":"emoji", "type":{ "base":"struct discord_emoji", "dec":"*" }, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
  if (p->emoji != NULL)
    p->__M.arg_switches[3] = p->emoji;

  /* specs/discord/message_components.json:48:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"a developer-defined identifier for the component, max 100 characters", "inject_if_not":""}' */
  if (strlen(p->custom_id) != 0)
    p->__M.arg_switches[4] = p->custom_id;

  /* specs/discord/message_components.json:49:18
     '{"name":"url", "type":{"base":"char", "dec":"*"}, "option":true, "comment":"a url for link-style buttons", "inject_if_not":null}' */
  if (p->url != NULL)
    p->__M.arg_switches[5] = p->url;

  /* specs/discord/message_components.json:50:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"whether the component is disabled, default false"}' */
  if (p->disabled != false)
    p->__M.arg_switches[6] = &p->disabled;

}

size_t discord_button_to_json(char *json, size_t len, struct discord_button *p)
{
  size_t r;
  discord_button_use_default_inject_settings(p);
  r=json_inject(json, len, 
  /* specs/discord/message_components.json:44:18
     '{"name":"type", "type": {"base":"int", "int_alias":"enum discord_component_types"}, "comment": "2 for a button"}' */
                "(type):d,"
  /* specs/discord/message_components.json:45:18
     '{"name":"style", "type": {"base":"int", "int_alias":"enum discord_button_styles"}, "comment": "one of button styles"}' */
                "(style):d,"
  /* specs/discord/message_components.json:46:18
     '{"name":"label", "type":{"base":"char", "dec":"[80+1]"}, "option":true, "comment":"text that appears on the button, max 80 characters", "inject_if_not":""}' */
                "(label):s,"
  /* specs/discord/message_components.json:47:18
     '{"name":"emoji", "type":{ "base":"struct discord_emoji", "dec":"*" }, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
                "(emoji):F,"
  /* specs/discord/message_components.json:48:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"a developer-defined identifier for the component, max 100 characters", "inject_if_not":""}' */
                "(custom_id):s,"
  /* specs/discord/message_components.json:49:18
     '{"name":"url", "type":{"base":"char", "dec":"*"}, "option":true, "comment":"a url for link-style buttons", "inject_if_not":null}' */
                "(url):s,"
  /* specs/discord/message_components.json:50:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"whether the component is disabled, default false"}' */
                "(disabled):b,"
                "@arg_switches:b",
  /* specs/discord/message_components.json:44:18
     '{"name":"type", "type": {"base":"int", "int_alias":"enum discord_component_types"}, "comment": "2 for a button"}' */
                &p->type,
  /* specs/discord/message_components.json:45:18
     '{"name":"style", "type": {"base":"int", "int_alias":"enum discord_button_styles"}, "comment": "one of button styles"}' */
                &p->style,
  /* specs/discord/message_components.json:46:18
     '{"name":"label", "type":{"base":"char", "dec":"[80+1]"}, "option":true, "comment":"text that appears on the button, max 80 characters", "inject_if_not":""}' */
                p->label,
  /* specs/discord/message_components.json:47:18
     '{"name":"emoji", "type":{ "base":"struct discord_emoji", "dec":"*" }, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
                discord_emoji_to_json, p->emoji,
  /* specs/discord/message_components.json:48:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"a developer-defined identifier for the component, max 100 characters", "inject_if_not":""}' */
                p->custom_id,
  /* specs/discord/message_components.json:49:18
     '{"name":"url", "type":{"base":"char", "dec":"*"}, "option":true, "comment":"a url for link-style buttons", "inject_if_not":null}' */
                p->url,
  /* specs/discord/message_components.json:50:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"whether the component is disabled, default false"}' */
                &p->disabled,
                p->__M.arg_switches, sizeof(p->__M.arg_switches), p->__M.enable_arg_switches);
  return r;
}


typedef void (*vfvp)(void *);
typedef void (*vfcpsvp)(char *, size_t, void *);
typedef size_t (*sfcpsvp)(char *, size_t, void *);
void discord_button_cleanup_v(void *p) {
  discord_button_cleanup((struct discord_button *)p);
}

void discord_button_init_v(void *p) {
  discord_button_init((struct discord_button *)p);
}

void discord_button_free_v(void *p) {
 discord_button_free((struct discord_button *)p);
};

void discord_button_from_json_v(char *json, size_t len, void *p) {
 discord_button_from_json(json, len, (struct discord_button*)p);
}

size_t discord_button_to_json_v(char *json, size_t len, void *p) {
  return discord_button_to_json(json, len, (struct discord_button*)p);
}

void discord_button_list_free_v(void **p) {
  discord_button_list_free((struct discord_button**)p);
}

void discord_button_list_from_json_v(char *str, size_t len, void *p) {
  discord_button_list_from_json(str, len, (struct discord_button ***)p);
}

size_t discord_button_list_to_json_v(char *str, size_t len, void *p){
  return discord_button_list_to_json(str, len, (struct discord_button **)p);
}


void discord_button_cleanup(struct discord_button *d) {
  /* specs/discord/message_components.json:44:18
     '{"name":"type", "type": {"base":"int", "int_alias":"enum discord_component_types"}, "comment": "2 for a button"}' */
  // p->type is a scalar
  /* specs/discord/message_components.json:45:18
     '{"name":"style", "type": {"base":"int", "int_alias":"enum discord_button_styles"}, "comment": "one of button styles"}' */
  // p->style is a scalar
  /* specs/discord/message_components.json:46:18
     '{"name":"label", "type":{"base":"char", "dec":"[80+1]"}, "option":true, "comment":"text that appears on the button, max 80 characters", "inject_if_not":""}' */
  // p->label is a scalar
  /* specs/discord/message_components.json:47:18
     '{"name":"emoji", "type":{ "base":"struct discord_emoji", "dec":"*" }, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
  if (d->emoji)
    discord_emoji_free(d->emoji);
  /* specs/discord/message_components.json:48:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"a developer-defined identifier for the component, max 100 characters", "inject_if_not":""}' */
  // p->custom_id is a scalar
  /* specs/discord/message_components.json:49:18
     '{"name":"url", "type":{"base":"char", "dec":"*"}, "option":true, "comment":"a url for link-style buttons", "inject_if_not":null}' */
  if (d->url)
    free(d->url);
  /* specs/discord/message_components.json:50:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"whether the component is disabled, default false"}' */
  // p->disabled is a scalar
}

void discord_button_init(struct discord_button *p) {
  memset(p, 0, sizeof(struct discord_button));
  /* specs/discord/message_components.json:44:18
     '{"name":"type", "type": {"base":"int", "int_alias":"enum discord_component_types"}, "comment": "2 for a button"}' */

  /* specs/discord/message_components.json:45:18
     '{"name":"style", "type": {"base":"int", "int_alias":"enum discord_button_styles"}, "comment": "one of button styles"}' */

  /* specs/discord/message_components.json:46:18
     '{"name":"label", "type":{"base":"char", "dec":"[80+1]"}, "option":true, "comment":"text that appears on the button, max 80 characters", "inject_if_not":""}' */

  /* specs/discord/message_components.json:47:18
     '{"name":"emoji", "type":{ "base":"struct discord_emoji", "dec":"*" }, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
  p->emoji = discord_emoji_alloc();

  /* specs/discord/message_components.json:48:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"a developer-defined identifier for the component, max 100 characters", "inject_if_not":""}' */

  /* specs/discord/message_components.json:49:18
     '{"name":"url", "type":{"base":"char", "dec":"*"}, "option":true, "comment":"a url for link-style buttons", "inject_if_not":null}' */

  /* specs/discord/message_components.json:50:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"whether the component is disabled, default false"}' */

}
struct discord_button* discord_button_alloc() {
  struct discord_button *p= malloc(sizeof(struct discord_button));
  discord_button_init(p);
  return p;
}

void discord_button_free(struct discord_button *p) {
  discord_button_cleanup(p);
  free(p);
}

void discord_button_list_free(struct discord_button **p) {
  ntl_free((void**)p, (vfvp)discord_button_cleanup);
}

void discord_button_list_from_json(char *str, size_t len, struct discord_button ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct discord_button);
  d.init_elem = discord_button_init_v;
  d.elem_from_buf = discord_button_from_json_v;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json(str, len, &d);
}

size_t discord_button_list_to_json(char *str, size_t len, struct discord_button **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, discord_button_to_json_v);
}



enum discord_button_styles discord_button_styles_from_string(char *s){
  if(strcasecmp("PRIMARY", s) == 0) return DISCORD_BUTTON_PRIMARY;
  if(strcasecmp("SECONDARY", s) == 0) return DISCORD_BUTTON_SECONDARY;
  if(strcasecmp("SUCCESS", s) == 0) return DISCORD_BUTTON_SUCCESS;
  if(strcasecmp("DANGER", s) == 0) return DISCORD_BUTTON_DANGER;
  if(strcasecmp("LINK", s) == 0) return DISCORD_BUTTON_LINK;
  abort();
}
char* discord_button_styles_to_string(enum discord_button_styles v){
  if (v == DISCORD_BUTTON_PRIMARY) return "PRIMARY";
  if (v == DISCORD_BUTTON_SECONDARY) return "SECONDARY";
  if (v == DISCORD_BUTTON_SUCCESS) return "SUCCESS";
  if (v == DISCORD_BUTTON_DANGER) return "DANGER";
  if (v == DISCORD_BUTTON_LINK) return "LINK";

  return (void*)0;
}
bool discord_button_styles_has(enum discord_button_styles v, char *s) {
  enum discord_button_styles v1 = discord_button_styles_from_string(s);
  if (v == v1) return true;
  if (v == v1) return true;
  if (v == v1) return true;
  if (v == v1) return true;
  if (v == v1) return true;
  return false;
}

void discord_select_menu_from_json(char *json, size_t len, struct discord_select_menu *p)
{
  static size_t ret=0; // used for debugging
  size_t r=0;
  r=json_extract(json, len, 
  /* specs/discord/message_components.json:73:18
     '{"name":"type", "type": {"base":"int", "int_alias":"enum discord_component_types"}, "comment": "3 for a select menu"}' */
                "(type):d,"
  /* specs/discord/message_components.json:74:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "comment":"a developer-defined identifier for the component, max 100 characters", "inject_if_not":""}' */
                "(custom_id):s,"
  /* specs/discord/message_components.json:75:18
     '{"name":"options", "type":{"base":"struct discord_select_menu", "dec":"ntl"}, "comment":"the choices in the select, max 25"}' */
                "(options):F,"
  /* specs/discord/message_components.json:76:18
     '{"name":"placeholder", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"custom placeholder text if nothing is selected, max 100 characters", "inject_if_not":""}' */
                "(placeholder):s,"
  /* specs/discord/message_components.json:77:18
     '{"name":"min_values", "type":{"base":"int"}, "option":true, "comment":"the minimum number of items that must be chosen; default 1, min 0, max 25"}' */
                "(min_values):d,"
  /* specs/discord/message_components.json:78:18
     '{"name":"max_values", "type":{"base":"int"}, "option":true, "comment":"the maximum number of items that must be chosen; default 1, min 0, max 25"}' */
                "(max_values):d,"
  /* specs/discord/message_components.json:79:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"disable the select, default false"}' */
                "(disabled):b,"
                "@arg_switches:b"
                "@record_defined"
                "@record_null",
  /* specs/discord/message_components.json:73:18
     '{"name":"type", "type": {"base":"int", "int_alias":"enum discord_component_types"}, "comment": "3 for a select menu"}' */
                &p->type,
  /* specs/discord/message_components.json:74:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "comment":"a developer-defined identifier for the component, max 100 characters", "inject_if_not":""}' */
                p->custom_id,
  /* specs/discord/message_components.json:75:18
     '{"name":"options", "type":{"base":"struct discord_select_menu", "dec":"ntl"}, "comment":"the choices in the select, max 25"}' */
                discord_select_menu_list_from_json, &p->options,
  /* specs/discord/message_components.json:76:18
     '{"name":"placeholder", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"custom placeholder text if nothing is selected, max 100 characters", "inject_if_not":""}' */
                p->placeholder,
  /* specs/discord/message_components.json:77:18
     '{"name":"min_values", "type":{"base":"int"}, "option":true, "comment":"the minimum number of items that must be chosen; default 1, min 0, max 25"}' */
                &p->min_values,
  /* specs/discord/message_components.json:78:18
     '{"name":"max_values", "type":{"base":"int"}, "option":true, "comment":"the maximum number of items that must be chosen; default 1, min 0, max 25"}' */
                &p->max_values,
  /* specs/discord/message_components.json:79:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"disable the select, default false"}' */
                &p->disabled,
                p->__M.arg_switches, sizeof(p->__M.arg_switches), p->__M.enable_arg_switches,
                p->__M.record_defined, sizeof(p->__M.record_defined),
                p->__M.record_null, sizeof(p->__M.record_null));
  ret = r;
}

static void discord_select_menu_use_default_inject_settings(struct discord_select_menu *p)
{
  p->__M.enable_arg_switches = true;
  /* specs/discord/message_components.json:73:18
     '{"name":"type", "type": {"base":"int", "int_alias":"enum discord_component_types"}, "comment": "3 for a select menu"}' */
  p->__M.arg_switches[0] = &p->type;

  /* specs/discord/message_components.json:74:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "comment":"a developer-defined identifier for the component, max 100 characters", "inject_if_not":""}' */
  if (strlen(p->custom_id) != 0)
    p->__M.arg_switches[1] = p->custom_id;

  /* specs/discord/message_components.json:75:18
     '{"name":"options", "type":{"base":"struct discord_select_menu", "dec":"ntl"}, "comment":"the choices in the select, max 25"}' */
  p->__M.arg_switches[2] = p->options;

  /* specs/discord/message_components.json:76:18
     '{"name":"placeholder", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"custom placeholder text if nothing is selected, max 100 characters", "inject_if_not":""}' */
  if (strlen(p->placeholder) != 0)
    p->__M.arg_switches[3] = p->placeholder;

  /* specs/discord/message_components.json:77:18
     '{"name":"min_values", "type":{"base":"int"}, "option":true, "comment":"the minimum number of items that must be chosen; default 1, min 0, max 25"}' */
  p->__M.arg_switches[4] = &p->min_values;

  /* specs/discord/message_components.json:78:18
     '{"name":"max_values", "type":{"base":"int"}, "option":true, "comment":"the maximum number of items that must be chosen; default 1, min 0, max 25"}' */
  p->__M.arg_switches[5] = &p->max_values;

  /* specs/discord/message_components.json:79:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"disable the select, default false"}' */
  if (p->disabled != false)
    p->__M.arg_switches[6] = &p->disabled;

}

size_t discord_select_menu_to_json(char *json, size_t len, struct discord_select_menu *p)
{
  size_t r;
  discord_select_menu_use_default_inject_settings(p);
  r=json_inject(json, len, 
  /* specs/discord/message_components.json:73:18
     '{"name":"type", "type": {"base":"int", "int_alias":"enum discord_component_types"}, "comment": "3 for a select menu"}' */
                "(type):d,"
  /* specs/discord/message_components.json:74:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "comment":"a developer-defined identifier for the component, max 100 characters", "inject_if_not":""}' */
                "(custom_id):s,"
  /* specs/discord/message_components.json:75:18
     '{"name":"options", "type":{"base":"struct discord_select_menu", "dec":"ntl"}, "comment":"the choices in the select, max 25"}' */
                "(options):F,"
  /* specs/discord/message_components.json:76:18
     '{"name":"placeholder", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"custom placeholder text if nothing is selected, max 100 characters", "inject_if_not":""}' */
                "(placeholder):s,"
  /* specs/discord/message_components.json:77:18
     '{"name":"min_values", "type":{"base":"int"}, "option":true, "comment":"the minimum number of items that must be chosen; default 1, min 0, max 25"}' */
                "(min_values):d,"
  /* specs/discord/message_components.json:78:18
     '{"name":"max_values", "type":{"base":"int"}, "option":true, "comment":"the maximum number of items that must be chosen; default 1, min 0, max 25"}' */
                "(max_values):d,"
  /* specs/discord/message_components.json:79:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"disable the select, default false"}' */
                "(disabled):b,"
                "@arg_switches:b",
  /* specs/discord/message_components.json:73:18
     '{"name":"type", "type": {"base":"int", "int_alias":"enum discord_component_types"}, "comment": "3 for a select menu"}' */
                &p->type,
  /* specs/discord/message_components.json:74:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "comment":"a developer-defined identifier for the component, max 100 characters", "inject_if_not":""}' */
                p->custom_id,
  /* specs/discord/message_components.json:75:18
     '{"name":"options", "type":{"base":"struct discord_select_menu", "dec":"ntl"}, "comment":"the choices in the select, max 25"}' */
                discord_select_menu_list_to_json, p->options,
  /* specs/discord/message_components.json:76:18
     '{"name":"placeholder", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"custom placeholder text if nothing is selected, max 100 characters", "inject_if_not":""}' */
                p->placeholder,
  /* specs/discord/message_components.json:77:18
     '{"name":"min_values", "type":{"base":"int"}, "option":true, "comment":"the minimum number of items that must be chosen; default 1, min 0, max 25"}' */
                &p->min_values,
  /* specs/discord/message_components.json:78:18
     '{"name":"max_values", "type":{"base":"int"}, "option":true, "comment":"the maximum number of items that must be chosen; default 1, min 0, max 25"}' */
                &p->max_values,
  /* specs/discord/message_components.json:79:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"disable the select, default false"}' */
                &p->disabled,
                p->__M.arg_switches, sizeof(p->__M.arg_switches), p->__M.enable_arg_switches);
  return r;
}


typedef void (*vfvp)(void *);
typedef void (*vfcpsvp)(char *, size_t, void *);
typedef size_t (*sfcpsvp)(char *, size_t, void *);
void discord_select_menu_cleanup_v(void *p) {
  discord_select_menu_cleanup((struct discord_select_menu *)p);
}

void discord_select_menu_init_v(void *p) {
  discord_select_menu_init((struct discord_select_menu *)p);
}

void discord_select_menu_free_v(void *p) {
 discord_select_menu_free((struct discord_select_menu *)p);
};

void discord_select_menu_from_json_v(char *json, size_t len, void *p) {
 discord_select_menu_from_json(json, len, (struct discord_select_menu*)p);
}

size_t discord_select_menu_to_json_v(char *json, size_t len, void *p) {
  return discord_select_menu_to_json(json, len, (struct discord_select_menu*)p);
}

void discord_select_menu_list_free_v(void **p) {
  discord_select_menu_list_free((struct discord_select_menu**)p);
}

void discord_select_menu_list_from_json_v(char *str, size_t len, void *p) {
  discord_select_menu_list_from_json(str, len, (struct discord_select_menu ***)p);
}

size_t discord_select_menu_list_to_json_v(char *str, size_t len, void *p){
  return discord_select_menu_list_to_json(str, len, (struct discord_select_menu **)p);
}


void discord_select_menu_cleanup(struct discord_select_menu *d) {
  /* specs/discord/message_components.json:73:18
     '{"name":"type", "type": {"base":"int", "int_alias":"enum discord_component_types"}, "comment": "3 for a select menu"}' */
  // p->type is a scalar
  /* specs/discord/message_components.json:74:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "comment":"a developer-defined identifier for the component, max 100 characters", "inject_if_not":""}' */
  // p->custom_id is a scalar
  /* specs/discord/message_components.json:75:18
     '{"name":"options", "type":{"base":"struct discord_select_menu", "dec":"ntl"}, "comment":"the choices in the select, max 25"}' */
  if (d->options)
    discord_select_menu_list_free(d->options);
  /* specs/discord/message_components.json:76:18
     '{"name":"placeholder", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"custom placeholder text if nothing is selected, max 100 characters", "inject_if_not":""}' */
  // p->placeholder is a scalar
  /* specs/discord/message_components.json:77:18
     '{"name":"min_values", "type":{"base":"int"}, "option":true, "comment":"the minimum number of items that must be chosen; default 1, min 0, max 25"}' */
  // p->min_values is a scalar
  /* specs/discord/message_components.json:78:18
     '{"name":"max_values", "type":{"base":"int"}, "option":true, "comment":"the maximum number of items that must be chosen; default 1, min 0, max 25"}' */
  // p->max_values is a scalar
  /* specs/discord/message_components.json:79:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"disable the select, default false"}' */
  // p->disabled is a scalar
}

void discord_select_menu_init(struct discord_select_menu *p) {
  memset(p, 0, sizeof(struct discord_select_menu));
  /* specs/discord/message_components.json:73:18
     '{"name":"type", "type": {"base":"int", "int_alias":"enum discord_component_types"}, "comment": "3 for a select menu"}' */

  /* specs/discord/message_components.json:74:18
     '{"name":"custom_id", "type":{"base":"char", "dec":"[100+1]"}, "comment":"a developer-defined identifier for the component, max 100 characters", "inject_if_not":""}' */

  /* specs/discord/message_components.json:75:18
     '{"name":"options", "type":{"base":"struct discord_select_menu", "dec":"ntl"}, "comment":"the choices in the select, max 25"}' */

  /* specs/discord/message_components.json:76:18
     '{"name":"placeholder", "type":{"base":"char", "dec":"[100+1]"}, "option":true, "comment":"custom placeholder text if nothing is selected, max 100 characters", "inject_if_not":""}' */

  /* specs/discord/message_components.json:77:18
     '{"name":"min_values", "type":{"base":"int"}, "option":true, "comment":"the minimum number of items that must be chosen; default 1, min 0, max 25"}' */

  /* specs/discord/message_components.json:78:18
     '{"name":"max_values", "type":{"base":"int"}, "option":true, "comment":"the maximum number of items that must be chosen; default 1, min 0, max 25"}' */

  /* specs/discord/message_components.json:79:18
     '{"name":"disabled", "type":{"base":"bool"}, "option":true, "inject_if_not":false, "comment":"disable the select, default false"}' */

}
struct discord_select_menu* discord_select_menu_alloc() {
  struct discord_select_menu *p= malloc(sizeof(struct discord_select_menu));
  discord_select_menu_init(p);
  return p;
}

void discord_select_menu_free(struct discord_select_menu *p) {
  discord_select_menu_cleanup(p);
  free(p);
}

void discord_select_menu_list_free(struct discord_select_menu **p) {
  ntl_free((void**)p, (vfvp)discord_select_menu_cleanup);
}

void discord_select_menu_list_from_json(char *str, size_t len, struct discord_select_menu ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct discord_select_menu);
  d.init_elem = discord_select_menu_init_v;
  d.elem_from_buf = discord_select_menu_from_json_v;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json(str, len, &d);
}

size_t discord_select_menu_list_to_json(char *str, size_t len, struct discord_select_menu **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, discord_select_menu_to_json_v);
}


void discord_select_option_from_json(char *json, size_t len, struct discord_select_option *p)
{
  static size_t ret=0; // used for debugging
  size_t r=0;
  r=json_extract(json, len, 
  /* specs/discord/message_components.json:88:18
     '{"name":"label", "type":{"base":"char", "dec":"[25+1]"}, "comment":"the user-facing name of the option, max 25 characters"}' */
                "(label):s,"
  /* specs/discord/message_components.json:89:18
     '{"name":"value", "type":{"base":"char", "dec":"[100+1]"}, "comment":"the dev define value of the option, max 100 characters"}' */
                "(value):s,"
  /* specs/discord/message_components.json:90:18
     '{"name":"description", "type":{"base":"char", "dec":"[50+1]"}, "option":true, "comment":"a additional description of the option, max 50 characters", "inject_if_not":""}' */
                "(description):s,"
  /* specs/discord/message_components.json:91:18
     '{"name":"emoji", "type":{"base":"struct discord_emoji", "dec":"*"}, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
                "(emoji):F,"
  /* specs/discord/message_components.json:92:18
     '{"name":"Default", "json_key":"default", "type":{"base":"bool"}, "option":true, "comment":"will render this option as selected by default"}' */
                "(default):b,"
                "@arg_switches:b"
                "@record_defined"
                "@record_null",
  /* specs/discord/message_components.json:88:18
     '{"name":"label", "type":{"base":"char", "dec":"[25+1]"}, "comment":"the user-facing name of the option, max 25 characters"}' */
                p->label,
  /* specs/discord/message_components.json:89:18
     '{"name":"value", "type":{"base":"char", "dec":"[100+1]"}, "comment":"the dev define value of the option, max 100 characters"}' */
                p->value,
  /* specs/discord/message_components.json:90:18
     '{"name":"description", "type":{"base":"char", "dec":"[50+1]"}, "option":true, "comment":"a additional description of the option, max 50 characters", "inject_if_not":""}' */
                p->description,
  /* specs/discord/message_components.json:91:18
     '{"name":"emoji", "type":{"base":"struct discord_emoji", "dec":"*"}, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
                discord_emoji_from_json, p->emoji,
  /* specs/discord/message_components.json:92:18
     '{"name":"Default", "json_key":"default", "type":{"base":"bool"}, "option":true, "comment":"will render this option as selected by default"}' */
                &p->Default,
                p->__M.arg_switches, sizeof(p->__M.arg_switches), p->__M.enable_arg_switches,
                p->__M.record_defined, sizeof(p->__M.record_defined),
                p->__M.record_null, sizeof(p->__M.record_null));
  ret = r;
}

static void discord_select_option_use_default_inject_settings(struct discord_select_option *p)
{
  p->__M.enable_arg_switches = true;
  /* specs/discord/message_components.json:88:18
     '{"name":"label", "type":{"base":"char", "dec":"[25+1]"}, "comment":"the user-facing name of the option, max 25 characters"}' */
  p->__M.arg_switches[0] = p->label;

  /* specs/discord/message_components.json:89:18
     '{"name":"value", "type":{"base":"char", "dec":"[100+1]"}, "comment":"the dev define value of the option, max 100 characters"}' */
  p->__M.arg_switches[1] = p->value;

  /* specs/discord/message_components.json:90:18
     '{"name":"description", "type":{"base":"char", "dec":"[50+1]"}, "option":true, "comment":"a additional description of the option, max 50 characters", "inject_if_not":""}' */
  if (strlen(p->description) != 0)
    p->__M.arg_switches[2] = p->description;

  /* specs/discord/message_components.json:91:18
     '{"name":"emoji", "type":{"base":"struct discord_emoji", "dec":"*"}, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
  if (p->emoji != NULL)
    p->__M.arg_switches[3] = p->emoji;

  /* specs/discord/message_components.json:92:18
     '{"name":"Default", "json_key":"default", "type":{"base":"bool"}, "option":true, "comment":"will render this option as selected by default"}' */
  p->__M.arg_switches[4] = &p->Default;

}

size_t discord_select_option_to_json(char *json, size_t len, struct discord_select_option *p)
{
  size_t r;
  discord_select_option_use_default_inject_settings(p);
  r=json_inject(json, len, 
  /* specs/discord/message_components.json:88:18
     '{"name":"label", "type":{"base":"char", "dec":"[25+1]"}, "comment":"the user-facing name of the option, max 25 characters"}' */
                "(label):s,"
  /* specs/discord/message_components.json:89:18
     '{"name":"value", "type":{"base":"char", "dec":"[100+1]"}, "comment":"the dev define value of the option, max 100 characters"}' */
                "(value):s,"
  /* specs/discord/message_components.json:90:18
     '{"name":"description", "type":{"base":"char", "dec":"[50+1]"}, "option":true, "comment":"a additional description of the option, max 50 characters", "inject_if_not":""}' */
                "(description):s,"
  /* specs/discord/message_components.json:91:18
     '{"name":"emoji", "type":{"base":"struct discord_emoji", "dec":"*"}, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
                "(emoji):F,"
  /* specs/discord/message_components.json:92:18
     '{"name":"Default", "json_key":"default", "type":{"base":"bool"}, "option":true, "comment":"will render this option as selected by default"}' */
                "(default):b,"
                "@arg_switches:b",
  /* specs/discord/message_components.json:88:18
     '{"name":"label", "type":{"base":"char", "dec":"[25+1]"}, "comment":"the user-facing name of the option, max 25 characters"}' */
                p->label,
  /* specs/discord/message_components.json:89:18
     '{"name":"value", "type":{"base":"char", "dec":"[100+1]"}, "comment":"the dev define value of the option, max 100 characters"}' */
                p->value,
  /* specs/discord/message_components.json:90:18
     '{"name":"description", "type":{"base":"char", "dec":"[50+1]"}, "option":true, "comment":"a additional description of the option, max 50 characters", "inject_if_not":""}' */
                p->description,
  /* specs/discord/message_components.json:91:18
     '{"name":"emoji", "type":{"base":"struct discord_emoji", "dec":"*"}, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
                discord_emoji_to_json, p->emoji,
  /* specs/discord/message_components.json:92:18
     '{"name":"Default", "json_key":"default", "type":{"base":"bool"}, "option":true, "comment":"will render this option as selected by default"}' */
                &p->Default,
                p->__M.arg_switches, sizeof(p->__M.arg_switches), p->__M.enable_arg_switches);
  return r;
}


typedef void (*vfvp)(void *);
typedef void (*vfcpsvp)(char *, size_t, void *);
typedef size_t (*sfcpsvp)(char *, size_t, void *);
void discord_select_option_cleanup_v(void *p) {
  discord_select_option_cleanup((struct discord_select_option *)p);
}

void discord_select_option_init_v(void *p) {
  discord_select_option_init((struct discord_select_option *)p);
}

void discord_select_option_free_v(void *p) {
 discord_select_option_free((struct discord_select_option *)p);
};

void discord_select_option_from_json_v(char *json, size_t len, void *p) {
 discord_select_option_from_json(json, len, (struct discord_select_option*)p);
}

size_t discord_select_option_to_json_v(char *json, size_t len, void *p) {
  return discord_select_option_to_json(json, len, (struct discord_select_option*)p);
}

void discord_select_option_list_free_v(void **p) {
  discord_select_option_list_free((struct discord_select_option**)p);
}

void discord_select_option_list_from_json_v(char *str, size_t len, void *p) {
  discord_select_option_list_from_json(str, len, (struct discord_select_option ***)p);
}

size_t discord_select_option_list_to_json_v(char *str, size_t len, void *p){
  return discord_select_option_list_to_json(str, len, (struct discord_select_option **)p);
}


void discord_select_option_cleanup(struct discord_select_option *d) {
  /* specs/discord/message_components.json:88:18
     '{"name":"label", "type":{"base":"char", "dec":"[25+1]"}, "comment":"the user-facing name of the option, max 25 characters"}' */
  // p->label is a scalar
  /* specs/discord/message_components.json:89:18
     '{"name":"value", "type":{"base":"char", "dec":"[100+1]"}, "comment":"the dev define value of the option, max 100 characters"}' */
  // p->value is a scalar
  /* specs/discord/message_components.json:90:18
     '{"name":"description", "type":{"base":"char", "dec":"[50+1]"}, "option":true, "comment":"a additional description of the option, max 50 characters", "inject_if_not":""}' */
  // p->description is a scalar
  /* specs/discord/message_components.json:91:18
     '{"name":"emoji", "type":{"base":"struct discord_emoji", "dec":"*"}, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
  if (d->emoji)
    discord_emoji_free(d->emoji);
  /* specs/discord/message_components.json:92:18
     '{"name":"Default", "json_key":"default", "type":{"base":"bool"}, "option":true, "comment":"will render this option as selected by default"}' */
  // p->Default is a scalar
}

void discord_select_option_init(struct discord_select_option *p) {
  memset(p, 0, sizeof(struct discord_select_option));
  /* specs/discord/message_components.json:88:18
     '{"name":"label", "type":{"base":"char", "dec":"[25+1]"}, "comment":"the user-facing name of the option, max 25 characters"}' */

  /* specs/discord/message_components.json:89:18
     '{"name":"value", "type":{"base":"char", "dec":"[100+1]"}, "comment":"the dev define value of the option, max 100 characters"}' */

  /* specs/discord/message_components.json:90:18
     '{"name":"description", "type":{"base":"char", "dec":"[50+1]"}, "option":true, "comment":"a additional description of the option, max 50 characters", "inject_if_not":""}' */

  /* specs/discord/message_components.json:91:18
     '{"name":"emoji", "type":{"base":"struct discord_emoji", "dec":"*"}, "option":true, "comment":"name, id and animated", "inject_if_not":null}' */
  p->emoji = discord_emoji_alloc();

  /* specs/discord/message_components.json:92:18
     '{"name":"Default", "json_key":"default", "type":{"base":"bool"}, "option":true, "comment":"will render this option as selected by default"}' */

}
struct discord_select_option* discord_select_option_alloc() {
  struct discord_select_option *p= malloc(sizeof(struct discord_select_option));
  discord_select_option_init(p);
  return p;
}

void discord_select_option_free(struct discord_select_option *p) {
  discord_select_option_cleanup(p);
  free(p);
}

void discord_select_option_list_free(struct discord_select_option **p) {
  ntl_free((void**)p, (vfvp)discord_select_option_cleanup);
}

void discord_select_option_list_from_json(char *str, size_t len, struct discord_select_option ***p)
{
  struct ntl_deserializer d;
  memset(&d, 0, sizeof(d));
  d.elem_size = sizeof(struct discord_select_option);
  d.init_elem = discord_select_option_init_v;
  d.elem_from_buf = discord_select_option_from_json_v;
  d.ntl_recipient_p= (void***)p;
  extract_ntl_from_json(str, len, &d);
}

size_t discord_select_option_list_to_json(char *str, size_t len, struct discord_select_option **p)
{
  return ntl_to_buf(str, len, (void **)p, NULL, discord_select_option_to_json_v);
}

