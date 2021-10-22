#include <stdio.h>
#include <stdint.h>

#include "websockets.h"
#include "log.h"

#define URL "ws://demos.kaazing.com/echo"

void on_connect_cb(void *data, struct websockets *ws, struct ws_info *info, const char *ws_protocols) 
{
  (void)data; (void)ws; (void)info;
  log_info("Connected, WS-Protocols: '%s'", ws_protocols);
}

void on_text_cb(void *data, struct websockets *ws, struct ws_info *info, const char *text, size_t len) 
{
  (void)data; (void)ws; (void)info;
  log_trace("RECEIVE:\n%.*s", (int)len, text);
}

void on_close_cb(void *data, struct websockets *ws, struct ws_info *info, enum ws_close_reason wscode, const char *reason, size_t len)
{
  (void)data; (void)ws; (void)info;
  log_info("Closed connection (%d) : %.*s", wscode, (int)len, reason);
}

int main(int argc, char *argv[])
{
  const char *config_file;
  if (argc > 1)
    config_file = argv[1];
  else
    config_file = "../config.json";

  FILE *fp = fopen(config_file, "rb");
  struct logconf conf={};
  struct websockets *ws;
  _Bool is_running = false;
  struct ws_callbacks cbs = {
    .on_connect = &on_connect_cb,
    .on_text = &on_text_cb,
    .on_close = &on_close_cb
  };

  logconf_setup(&conf, "TEST", fp);

  ws = ws_init(&cbs, &conf);
  ws_set_url(ws, URL, NULL);

  /* run the event-loop */
  ws_start(ws);
#if 0 /* set custom headers */
  ws_reqheader_add(ws, "Authorization", "foo");
#endif
  while (1) {
    ws_perform(ws, &is_running, 5);
    if (!is_running) break; /* exit event loop */

    /* connection is established */
  }

  ws_cleanup(ws);
  logconf_cleanup(&conf);
  fclose(fp);
}
