#include <string.h>

#include "slack.h"
#include "slack-internal.h"

ORCAcode
slack_chat_post_message(struct slack *client,
                        struct slack_chat_post_message_params *params,
                        struct sized_buffer *ret)
{
#if 0
  ORCA_EXPECT(client, params != NULL, ORCA_BAD_PARAMETER);
  ORCA_EXPECT(client, !IS_EMPTY_STRING(params->channel), ORCA_BAD_PARAMETER);

  char *payload = NULL;
  size_t len = json_ainject(&payload,
                            "(token):s"
                            "(channel):s"
#if 0
                "(as_user):b"
#endif
                            "(icon_url):s"
                            "(icon_emoji):s"
                            "(text):s"
                            "(thread_ts):s"
                            "(username):s",
                            params->token, params->channel,
#if 0
                &params->as_user,
#endif
                            params->icon_url, params->icon_emoji, params->text,
                            params->thread_ts, params->username);

  if (!payload) {
    log_error("Couldn't create payload");
    return ORCA_BAD_PARAMETER;
  }

  ua_reqheader_add(client->webapi.ua, "Content-type", "application/json");

  ORCAcode code;
  code = slack_webapi_run(&client->webapi, ret,
                          &(struct sized_buffer){ payload, len }, HTTP_POST,
                          "/chat.postMessage");

  ua_reqheader_add(client->webapi.ua, "Content-type",
                   "application/x-www-form-urlencoded");

  free(payload);

  return code;
#else
  return -1;
#endif
}
