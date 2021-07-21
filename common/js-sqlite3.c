#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "cee-utils.h"
#include "json-actor.h"

#include "mujs.h"
#include "jsi.h"

#include "js-sqlite3.h"


static void
js_sqlite_close(js_State *J, void *p_db) {
  if (p_db) {
    sqlite3_close(*(sqlite3 **)p_db);
    free(p_db);
  }
}

static void 
new_Sqlite(js_State *J)
{
  sqlite3 **db = malloc(sizeof(sqlite3*));
  js_currentfunction(J);
  js_getproperty(J, -1, "prototype");
  js_newuserdata(J, "Sqlite", db, &js_sqlite_close);
}

static void 
Sqlite_prototype_open(js_State *J)
{
  sqlite3 **db = js_touserdata(J, 0, "Sqlite");
  const char *dbname = js_tostring(J, 1);
  int rc = sqlite3_open(dbname, db);
  js_pushnumber(J, (double)rc);
}

static void 
Sqlite_prototype_close(js_State *J)
{
  sqlite3 **db = js_touserdata(J, 0, "Sqlite");
  sqlite3_close(*db);
  *db = NULL;
  js_pushundefined(J);
}

static void 
Sqlite_prototype_exec(js_State *J)
{
  sqlite3 **db = js_touserdata(J, 0, "Sqlite");
  const char *sql = js_tostring(J, 1);
  int rc = sqlite3_exec(*db, sql, 0, 0, NULL);
  js_pushnumber(J, (double)rc);
}

void 
js_sqlite_init(js_State *J)
{
  js_getglobal(J, "Object"); 
  // Orca.prototype.[[Prototype]] = Object.prototype
  js_getproperty(J, -1, "prototype");
  // Orca.prototype.[[UserData]] = null
  js_newuserdata(J, "Sqlite", NULL, NULL);
  {
    // Sqlite.prototype.open = function() { ... }
    js_newcfunction(J, &Sqlite_prototype_open, "Sqlite.prototype.open", 1);
    js_defproperty(J, -2, "open", JS_DONTENUM);

    // Sqlite.prototype.close = function() { ... }
    js_newcfunction(J, &Sqlite_prototype_close, "Sqlite.prototype.close", 1);
    js_defproperty(J, -2, "close", JS_DONTENUM);
    
    // Sqlite.prototype.close = function() { ... }
    js_newcfunction(J, &Sqlite_prototype_exec, "Sqlite.prototype.exec", 1);
    js_defproperty(J, -2, "exec", JS_DONTENUM);
  }
  js_newcconstructor(J, &new_Sqlite, &new_Sqlite, "Sqlite", 1);
  js_defglobal(J, "Sqlite", JS_DONTENUM); 
}
