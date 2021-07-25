#include <stdio.h>
#include <stdlib.h>

#include "user-agent.h"

#include "mujs.h"
#include "js_user-agent.h"
#include "js_sqlite3.h"

const char *handle=NULL; /* handle to stowed away js function */
const char *g_config_file;

#define DB_NAME  "\"test-js-bindings.db\""
#define SQL_EXEC_STMT "\"DROP TABLE IF EXISTS cats;"              \
                      "CREATE TABLE cats (name TEXT, age INT);\""
#define SQL_PREPARE_STMT "\"INSERT INTO cats (name, age) VALUES (?, ?)\""

void js_request(js_State *J)
{
  struct logconf config={0};
  logconf_setup(&config, NULL);
  struct user_agent *ua = ua_init(&config);
  ua_set_url(ua, "http://www.example.com/");

  struct ua_info info={0};
  int nparam=0;
  jsua_run(J, ua, &info, &nparam);
  struct sized_buffer resp_body = ua_info_get_resp_body(&info);
  fprintf(stderr, "%.*s\n", (int)resp_body.size, resp_body.start);

  ua_info_cleanup(&info);
  ua_cleanup(ua);
}

int main(void)
{
  js_State *J = js_newstate(NULL, NULL, JS_STRICT);
  jssqlite3_init(J);

  js_dostring(J, "var db = new Database();");
  js_dostring(J, "db.open("DB_NAME");");

  js_dostring(J, "db.exec("SQL_EXEC_STMT");");
  js_dostring(J, "var stmt = db.prepare("SQL_PREPARE_STMT");");
  js_dostring(J, "stmt.run('Joey', 2);");

  js_dostring(J, "db.close();");

  ABORT();

  js_newcfunction(J, &js_request, "request", 2);
  js_copy(J, 1);
  handle = js_ref(J);

  js_getregistry(J, handle);
  js_pushstring(J, "GET");
  js_pushstring(J, "index.html");
  if (js_pcall(J, 2)) {
    fprintf(stderr, "Error\n");
    return EXIT_FAILURE;
  }
  js_pop(J, 1);

  return EXIT_SUCCESS;
}
