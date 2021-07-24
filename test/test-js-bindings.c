#include <stdio.h>
#include <stdlib.h>

#include "user-agent.h"

#include "mujs.h"
#include "js_user-agent.h"
#include "js_sqlite3.h"

const char *handle=NULL; /* handle to stowed away js function */
const char *g_config_file;

#define DB_NAME  "\"test-jso.db\""
#define SQL_STMT "\"DROP TABLE IF EXISTS Cars;"                       \
                 "CREATE TABLE Cars(Id INT, Name TEXT, Price INT);"   \
                 "INSERT INTO Cars VALUES(1, 'Audi', 52642);"         \
                 "INSERT INTO Cars VALUES(2, 'Mercedes', 57127);"     \
                 "INSERT INTO Cars VALUES(3, 'Skoda', 9000);"         \
                 "INSERT INTO Cars VALUES(4, 'Volvo', 29000);"        \
                 "INSERT INTO Cars VALUES(5, 'Bentley', 350000);"     \
                 "INSERT INTO Cars VALUES(6, 'Citroen', 21000);"      \
                 "INSERT INTO Cars VALUES(7, 'Hummer', 41400);"       \
                 "INSERT INTO Cars VALUES(8, 'Volkswagen', 21600);\""

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
  jssqlite_init(J);

  js_dostring(J, "var sqlite = new Sqlite();");
  js_dostring(J, "sqlite.open("DB_NAME");");
  js_dostring(J, "sqlite.exec("SQL_STMT");");
  js_dostring(J, "sqlite.close();");

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
