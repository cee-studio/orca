#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "cee-utils.h"
#include "json-actor.h"

#include "mujs.h"
#include "jsi.h"

#include "js_sqlite3.h"

struct stmt_cxt {
  sqlite3 *db;
  sqlite3_stmt *stmt;
};

static void
destroy_Database(js_State *J, void *p_db) {
  if (p_db) {
    sqlite3_close(*(sqlite3 **)p_db);
    free(p_db);
  }
}

static void 
new_Database(js_State *J)
{
  sqlite3 **db = malloc(sizeof(sqlite3*));
  js_currentfunction(J);
  js_getproperty(J, -1, "prototype");
  js_newuserdata(J, "Database", db, &destroy_Database);
}

static void 
Database_prototype_open(js_State *J)
{
  if (!js_isstring(J, 1)) { 
    js_error(J, "Expected 'first' argument to be 'a string'"); 
  }

  sqlite3 **db = js_touserdata(J, 0, "Database");
  const char *dbname = js_tostring(J, 1);
  if (SQLITE_OK != sqlite3_open(dbname, db)) {
    js_error(J, "Couldn't open database '%s': %s", dbname, sqlite3_errmsg(*db)); 
  }
  js_pushundefined(J);
}

static void 
Database_prototype_close(js_State *J)
{
  sqlite3 **db = js_touserdata(J, 0, "Database");
  sqlite3_close(*db);
  *db = NULL;
  js_pushundefined(J);
}

static void 
Database_prototype_exec(js_State *J)
{
  if (!js_isstring(J, 1)) { 
    js_error(J, "Expected 'first' argument to be 'a string'"); 
  }

  sqlite3 **db = js_touserdata(J, 0, "Database");
  const char *sql = js_tostring(J, 1);
  if (SQLITE_OK != sqlite3_exec(*db, sql, 0, 0, NULL)) {
    js_error(J, "Couldn't run SQL statements: %s", sqlite3_errmsg(*db)); 
  }
  js_pushundefined(J);
}

static void 
Database_prototype_prepare(js_State *J)
{
  if (!js_isstring(J, 1)) { 
    js_error(J, "Expected 'first' argument to be 'a string'"); 
  }

  sqlite3 **db = js_touserdata(J, 0, "Database");
  const char *sql = js_tostring(J, 1);

  /* var a = new Statement(this) */
  js_getglobal(J, "Statement");
  js_copy(J, 0); // push 'this'
  if (js_pconstruct(J, 1)) { // push Statement to top of stack
    js_error(J, "Failed to call 'new Statement'");
  }

  struct stmt_cxt *stmt_cxt = js_touserdata(J, -1, "Statement");
  if (SQLITE_OK != sqlite3_prepare(*db, sql, -1, &stmt_cxt->stmt, NULL)) {
    js_error(J, "Failed to execute statement: %s", sqlite3_errmsg(*db));
  }
}

static void 
jssqlite3_db_init(js_State *J)
{
  js_getglobal(J, "Object"); 
  // Database.prototype.[[Prototype]] = Object.prototype
  js_getproperty(J, -1, "prototype");
  // Database.prototype.[[UserData]] = null
  js_newuserdata(J, "Database", NULL, NULL);
  {
    // Database.prototype.open = function() { ... }
    js_newcfunction(J, &Database_prototype_open, "Database.prototype.open", 1);
    js_defproperty(J, -2, "open", JS_DONTENUM);

    // Database.prototype.close = function() { ... }
    js_newcfunction(J, &Database_prototype_close, "Database.prototype.close", 1);
    js_defproperty(J, -2, "close", JS_DONTENUM);
    
    // Database.prototype.close = function() { ... }
    js_newcfunction(J, &Database_prototype_exec, "Database.prototype.exec", 1);
    js_defproperty(J, -2, "exec", JS_DONTENUM);
    
    // Database.prototype.prepare = function() { ... }
    js_newcfunction(J, &Database_prototype_prepare, "Database.prototype.prepare", 1);
    js_defproperty(J, -2, "prepare", JS_DONTENUM);
  }
  js_newcconstructor(J, &new_Database, &new_Database, "Database", 1);
  js_defglobal(J, "Database", JS_DONTENUM); 
}

static void
destroy_Statement(js_State *J, void *p_stmt_cxt) {
  if (p_stmt_cxt) free(p_stmt_cxt);
}

static void 
new_Statement(js_State *J)
{
  struct stmt_cxt *stmt_cxt = malloc(sizeof *stmt_cxt);
  sqlite3 **p_db = js_touserdata(J, 1, "Database");
  stmt_cxt->db = *p_db;

  js_currentfunction(J);
  js_getproperty(J, -1, "prototype");
  js_newuserdata(J, "Statement", stmt_cxt, &destroy_Statement);
}

static int
jssqlite3_bind(js_State *J, int idx, sqlite3_stmt *stmt)
{
  switch (js_type(J, idx)) {
  case JS_ISSTRING:
      return sqlite3_bind_text(stmt, idx, js_tostring(J, idx), -1, SQLITE_TRANSIENT);
  case JS_ISUNDEFINED:
  case JS_ISNULL:
      return sqlite3_bind_null(stmt, idx);
  case JS_ISBOOLEAN:
      return sqlite3_bind_int(stmt, idx, js_toint32(J, idx));
  case JS_ISNUMBER:
      return sqlite3_bind_double(stmt, idx, js_tonumber(J, idx));
  default:
      js_error(J, "Can't bind value of type '%s'", js_typeof(J, idx));
      break;
  }
  return -1;
}

static void 
Statement_prototype_run(js_State *J)
{
  struct stmt_cxt *stmt_cxt = js_touserdata(J, 0, "Statement");
  int ret_code;

  int nparam = js_gettop(J);
  for (int i=1; i < nparam; ++i) {
    ret_code = jssqlite3_bind(J, i, stmt_cxt->stmt);
    if (SQLITE_OK != ret_code) {
      sqlite3_finalize(stmt_cxt->stmt);
      js_error(J, "Failed to bind parameter No#%d of type '%s': %s", i, js_typeof(J, i), sqlite3_errstr(ret_code));
    }

    while (1) {
      ret_code = sqlite3_step(stmt_cxt->stmt);
      if (SQLITE_ROW == ret_code)
        continue;
      else if (SQLITE_DONE == ret_code)
        break;
      else {
        sqlite3_finalize(stmt_cxt->stmt);
        js_error(J, "%s", sqlite3_errstr(ret_code));
      }
    }

    sqlite3_reset(stmt_cxt->stmt);
    sqlite3_clear_bindings(stmt_cxt->stmt);
  }

  sqlite3_finalize(stmt_cxt->stmt);
  // @todo return info object
  js_pushundefined(J);
}

static void 
jssqlite3_stmt_init(js_State *J)
{
  js_getglobal(J, "Object"); 
  // Statement.prototype.[[Prototype]] = Object.prototype
  js_getproperty(J, -1, "prototype");
  // Statement.prototype.[[UserData]] = null
  js_newuserdata(J, "Statement", NULL, NULL);
  {
    // Statement.prototype.run = function() { ... }
    // this should receive any amount of args
    js_newcfunction(J, &Statement_prototype_run, "Statement.prototype.run", 0);
    js_defproperty(J, -2, "run", JS_DONTENUM);
  }
  js_newcconstructor(J, &new_Statement, &new_Statement, "Statement", 1);
  js_defglobal(J, "Statement", JS_DONTENUM); 
}

void
jssqlite3_init(js_State *J) 
{
  jssqlite3_db_init(J);
  jssqlite3_stmt_init(J);
  D_RUN(js_trap(J, 0));
}
