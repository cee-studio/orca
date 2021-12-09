/**
 * @file discord-internal.h
 * @author cee-studio
 * @brief File containing internal functions and datatypes
 */

#ifndef DISCORD_INTERNAL_H
#define DISCORD_INTERNAL_H

#include <inttypes.h>
#include <pthread.h>

#include "json-actor.h"
#include "json-actor-boxed.h"

#include "logconf.h" /* struct logconf */
#include "user-agent.h"
#include "websockets.h"
#include "work.h"
#include "cee-utils.h"

#include "uthash.h"
#include "queue.h"
#include "heap-inl.h"

#include "discord-voice-connections.h"

/**
 * @brief The ratelimiting handler structure
 *
 * - Initializer:
 *   - discord_ratelimit_init()
 * - Cleanup:
 *   - discord_ratelimit_cleanup()
 */
struct discord_ratelimit {
  /** DISCORD_RATELIMIT logging module */
  struct logconf conf;
  /** buckets discovered */
  struct discord_bucket *buckets;
  /** for undefined routes */
  struct discord_bucket *b_null;
  /* request timeouts */
  struct heap timeouts;
  /* client-wide ratelimiting timeout */
  struct {
    /** global ratelimit */
    u64_unix_ms_t wait_ms;
    /** global rwlock  */
    pthread_rwlock_t rwlock;
    /** global lock */
    pthread_mutex_t lock;
  } * global;
};

/**
 * @brief Initialize ratelimit handler
 *
 * @param rlimit the ratelimit handler
 * @param conf optional pointer to a initialized logconf
 */
void discord_ratelimit_init(struct discord_ratelimit *rlimit,
                            struct logconf *conf);

/**
 * @brief Free ratelimit handler
 *
 * @param rlimit the ratelimit handler
 */
void discord_ratelimit_cleanup(struct discord_ratelimit *rlimit);

/**
 * @brief Get global timeout timestamp
 *
 * @param rlimit the ratelimit handler
 * @return the most recent global timeout timestamp
 */
u64_unix_ms_t discord_ratelimit_get_global_wait(
  struct discord_ratelimit *rlimit);

/** @brief Behavior of request return object */
struct discord_request_attr {
  /** size of `obj` in bytes */
  size_t size;
  /** initialize `obj` fields */
  void (*init)(void *obj);
  /** callback for filling `obj` with JSON values */
  void (*from_json)(char *json, size_t len, void *obj);
  /** perform a cleanup on `obj` */
  void (*cleanup)(void *obj);
  /** user callback to be triggered on request completion */
  void (*done)(struct discord *client, ORCAcode code, const void *obj);
  /** if true the request will be dealt with as soon as possible */
  bool high_p;
};

/**
 * @brief The handle used for performing HTTP Requests
 *
 * This is a wrapper over struct user_agent
 *
 * - Initializer:
 *   - discord_adapter_init()
 * - Cleanup:
 *   - discord_adapter_cleanup()
 */
struct discord_adapter {
  /** if true then next request will be dealt with asynchronously */
  bool toggle_async;
  /** behavior config for next async request */
  struct discord_request_attr attr;

  /** DISCORD_HTTP or DISCORD_WEBHOOK logging module */
  struct logconf conf;
  /** the user agent handle for performing requests */
  struct user_agent *ua;
  /** ratelimit handler structure */
  struct discord_ratelimit rlimit;

  /** idle request handles of type 'struct discord_request' */
  QUEUE *idleq;

  /** previous request error context */
  struct {
    /** informational on the previous request */
    struct ua_info info;
    /** JSON error code on failed request */
    int jsoncode;
    /** the entire JSON response of the error */
    char jsonstr[512];
  } err;

  /** reusable buffer for async return objects */
  struct {
    /** return object buffer */
    uint8_t *buf;
    /** size in memory */
    size_t size;
  } obj;
};

/**
 * @brief Initialize the fields of a Discord Adapter handle
 *
 * @param adapter a pointer to the http handle
 * @param conf optional pointer to a pre-initialized logconf
 * @param token the bot token
 */
void discord_adapter_init(struct discord_adapter *adapter,
                          struct logconf *conf,
                          struct sized_buffer *token);

/**
 * @brief Free a Discord Adapter handle
 *
 * @param adapter a pointer to the adapter handle
 */
void discord_adapter_cleanup(struct discord_adapter *adapter);

/**
 * @brief Perform a request to Discord
 *
 * This functions is a selector over discord_request_perform() or
 *        discord_request_perform_async()
 * @param adapter the handle initialized with discord_adapter_init()
 * @param handle the callbacks to be triggered should the request
 *        fail or succeed
 * @param body the body sent for methods that require (ex: post), leave as
 *        null if unecessary
 * @param method the method in opcode format of the request being sent
 * @param endpoint_fmt the format endpoint that be appended to base_url when
 *        performing a request, same behavior as printf()
 * @return a code for checking on how the operation went, ORCA_OK means
 *        nothing out of ordinary
 * @note if async is set then this function will enqueue the request instead of
 * performing it immediately
 */
ORCAcode discord_adapter_run(struct discord_adapter *adapter,
                             struct ua_resp_handle *handle,
                             struct sized_buffer *body,
                             enum http_method method,
                             char endpoint_fmt[],
                             ...);

/**
 * @brief Toggle next request to run asynchronously
 *
 * @param adapter the handle initialized with discord_adapter_init()
 * @param attr attributes of the asynchronous task
 */
void discord_adapter_toggle_async(struct discord_adapter *adapter,
                                  struct discord_request_attr *attr);

/**
 * @brief Context for requests that are scheduled to run asynchronously
 *
 * - Perform request:
 *   - discord_request_perform()
 *   - discord_request_perform_async()
 * - Cleanup handle:
 *   - discord_request_cleanup()
 * - Delay a request (and its bucket):
 *   - discord_request_set_timeout()
 */
struct discord_request {
  /** async attributes */
  struct discord_request_attr attr;
  /** the request's bucket */
  struct discord_bucket *bucket;
  /** the request's response handle */
  struct ua_resp_handle handle;
  /** the request's request body @note buffer is kept and recycled */
  struct {
    char *start;
    size_t size;
    size_t memsize;
  } body;
  /** the request's http method */
  enum http_method method;
  /** the request's endpoint */
  char endpoint[2048];
  /** the connection handler assigned at discord_ratelimit_prepare_requests()
   */
  struct ua_conn *conn;
  /** the request bucket's queue entry */
  QUEUE entry;
  /** the min-heap node (for timeouts) */
  struct heap_node node;
  /** the timeout timestamp */
  u64_unix_ms_t timeout_ms;
};

/**
 * @brief Free a request handle
 *
 * @param cxt a pointer to the request
 */
void discord_request_cleanup(struct discord_request *cxt);

/**
 * @brief Perform a blocking request to Discord
 *
 * @param adapter the handle initialized with discord_adapter_init()
 * @param handle the callbacks to be triggered should the request
 *        fail or succeed
 * @param body the body sent for methods that require (ex: post), leave as
 *        null if unecessary
 * @param method the method in opcode format of the request being sent
 * @param endpoint the fully-formed request's endpoint
 * @return a code for checking on how the transfer went ORCA_OK means the
 *        transfer was succesful
 */
ORCAcode discord_request_perform(struct discord_adapter *adapter,
                                 struct ua_resp_handle *handle,
                                 struct sized_buffer *body,
                                 enum http_method method,
                                 char endpoint[]);
/**
 * @brief Enqueue a request to be performed asynchronously
 *
 * @param adapter the handle initialized with discord_adapter_init()
 * @param attr attributes for asynchronous task
 * @param handle the callbacks to be triggered should the request
 *        fail or succeed
 * @param body the body sent for methods that require (ex: post), leave as
 *        null if unecessary
 * @param method the method in opcode format of the request being sent
 * @param endpoint the fully-formed request's endpoint
 * @return a code for checking on how the transfer went ORCA_OK means the
 *        request has been successfully enqueued
 */
ORCAcode discord_request_perform_async(struct discord_adapter *adapter,
                                       struct discord_request_attr *attr,
                                       struct ua_resp_handle *handle,
                                       struct sized_buffer *body,
                                       enum http_method method,
                                       char endpoint[]);

/**
 * @brief Check and execute timed-out requests
 *
 * @param rlimit the ratelimit handler
 */
void discord_request_check_timeouts_async(struct discord_ratelimit *rlimit);

/**
 * @brief Check and send pending bucket's requests
 *
 * Send pending requests for non-busy buckets. A busy bucket is classified as
 *        one currently waiting on ratelimiting, or updating its values
 * @param rlimit the ratelimit handler
 */
void discord_request_check_pending_async(struct discord_ratelimit *rlimit);

/**
 * @brief Check requests results
 *
 * Any completed request will be moved to `adapter->idle` queue for
 *        recycling. Bucket values will be updated accordingly, and
 *        the user-defined callback may be triggered.
 * @param rlimit the ratelimit handler
 */
void discord_request_check_results_async(struct discord_ratelimit *rlimit);

/**
 * @brief Stop all on-going, pending and timed-out requests
 *
 * The requests will be moved over to client's 'idleq' queue
 * @param rlimit the ratelimit handler
 */
void discord_request_stop_all(struct discord_ratelimit *rlimit);

/**
 * @brief Pause all on-going timed-out requests
 *
 * The requests will be moved over to bucket's 'waitq' queue
 * @param rlimit the ratelimit handler
 */
void discord_request_pause_all(struct discord_ratelimit *rlimit);

/**
 * @brief The bucket struct for handling ratelimiting
 *
 * - Get bucket:
 *   - discord_bucket_get()
 * - Get cooldown:
 *   - discord_bucket_cooldown()
 * - Add/update buckets
 *   - discord_bucket_build()
 *
 * @see https://discord.com/developers/docs/topics/rate-limits
 */
struct discord_bucket {
  /** the route associated with this bucket */
  char route[128];
  /** the hash associated with this bucket (logging purposes) */
  char hash[64];
  /** maximum connections this bucket can handle before ratelimit */
  long limit;
  /** connections this bucket can do before waiting for cooldown */
  long remaining;
  /** timestamp of when cooldown timer resets */
  u64_unix_ms_t reset_tstamp;
  /** synchronize ratelimiting between threads */
  pthread_mutex_t lock;
  /** pending requests of type 'struct discord_request' */
  QUEUE waitq;
  /** busy requests of type 'struct discord_request' */
  QUEUE busyq;
  /** avoid excessive timeouts */
  bool freeze;
  /** makes this structure hashable */
  UT_hash_handle hh;
};

/**
 * @brief Return bucket timeout timestamp
 *
 * @param rlimit the ratelimit handler
 * @param b the bucket to be checked for time out
 * @return the timeout timestamp
 */
u64_unix_ms_t discord_bucket_get_timeout(struct discord_ratelimit *rlimit,
                                         struct discord_bucket *b);

/**
 * @brief Trigger bucket pending cooldown
 *
 * @param rlimit the ratelimit handler
 * @param the bucket to wait on cooldown
 * @note blocking function
 */
void discord_bucket_cooldown(struct discord_ratelimit *rlimit,
                             struct discord_bucket *bucket);

/**
 * @brief Get a `struct discord_bucket` assigned to `route`
 *
 * @param rlimit the ratelimit handler
 * @param endpoint endpoint that will be checked for a bucket match
 * @return bucket assigned to `route` or `ratelimit->b_null` if no match found
 */
struct discord_bucket *discord_bucket_get(struct discord_ratelimit *rlimit,
                                          const char route[]);

/**
 * @brief Update the bucket with response header data
 *
 * @param rlimit the ratelimit handler
 * @param bucket NULL when bucket is first discovered
 * @param route the route associated with the bucket
 * @param info informational struct containing details on the current transfer
 * @note If the bucket was just discovered it will be created here.
 */
void discord_bucket_build(struct discord_ratelimit *rlimit,
                          struct discord_bucket *bucket,
                          const char route[],
                          struct ua_info *info);

struct discord_gateway_cmd_cbs {
  char *start;
  size_t size;
  discord_message_cb cb;
};

struct discord_gateway_cbs {
  /** triggers on every event loop iteration */
  discord_idle_cb on_idle;

  /** triggers when connection first establishes */
  discord_idle_cb on_ready;

  /** triggers when a command is created */
  discord_application_command_cb on_application_command_create;
  /** triggers when a command is updated */
  discord_application_command_cb on_application_command_update;
  /** triggers when a command is deleted */
  discord_application_command_cb on_application_command_delete;

  /** triggers when a channel is created */
  discord_channel_cb on_channel_create;
  /** triggers when a channel is updated */
  discord_channel_cb on_channel_update;
  /** triggers when a channel is deleted */
  discord_channel_cb on_channel_delete;
  /** triggers when a channel pinned messages updates */
  discord_channel_pins_update_cb on_channel_pins_update;
  /** triggers when a thread is created */
  discord_channel_cb on_thread_create;
  /** triggers when a thread is updated */
  discord_channel_cb on_thread_update;
  /** triggers when a thread is deleted */
  discord_channel_cb on_thread_delete;

  /** triggers when a ban occurs */
  discord_guild_ban_cb on_guild_ban_add;
  /** triggers when a ban is removed */
  discord_guild_ban_cb on_guild_ban_remove;

  /** triggers when a guild member joins a guild */
  discord_guild_member_cb on_guild_member_add;
  /** triggers when a guild member is removed from a guild */
  discord_guild_member_remove_cb on_guild_member_remove;
  /** triggers when a guild member status is updated (ex: receive role) */
  discord_guild_member_cb on_guild_member_update;

  /** triggers when a guild role is created */
  discord_guild_role_cb on_guild_role_create;
  /** triggers when a guild role is updated */
  discord_guild_role_cb on_guild_role_update;
  /** triggers when a guild role is deleted */
  discord_guild_role_delete_cb on_guild_role_delete;

  /** triggers when a interaction is created  */
  discord_interaction_cb on_interaction_create;

  /** triggers when a message is created */
  discord_message_cb on_message_create;
  /** @todo this is temporary */
  discord_sb_message_cb sb_on_message_create;
  /** trigger when a message is updated */
  discord_message_cb on_message_update;
  /** @todo this is temporary */
  discord_sb_message_cb sb_on_message_update;
  /** triggers when a message is deleted */
  discord_message_delete_cb on_message_delete;
  /** triggers when a bulk of messages is deleted */
  discord_message_delete_bulk_cb on_message_delete_bulk;
  /** triggers when a reaction is added to a message */
  discord_message_reaction_add_cb on_message_reaction_add;
  /** triggers when a reaction is removed from a message */
  discord_message_reaction_remove_cb on_message_reaction_remove;
  /** triggers when all reactions are removed from a message */
  discord_message_reaction_remove_all_cb on_message_reaction_remove_all;
  /** triggers when all occurences of a specific reaction is removed from a
   * message */
  discord_message_reaction_remove_emoji_cb on_message_reaction_remove_emoji;

  /** triggers when a voice state is updated */
  discord_voice_state_update_cb on_voice_state_update;
  /** triggers when a voice server is updated */
  discord_voice_server_update_cb on_voice_server_update;
};

/**
 * @brief The handle used for establishing a Discord Gateway connection
 *        via WebSockets
 *
 * - Initializer:
 *   - discord_gateway_init()
 * - Cleanup:
 *   - discord_gateway_cleanup()
 *
 * @note A wrapper over struct websockets
 */
struct discord_gateway {
  /** DISCORD_GATEWAY logging module */
  struct logconf conf;
  /** the websockets handle that connects to Discord */
  struct websockets *ws;

  /** reconnect structure */
  struct {
    /** will attempt reconnecting if true */
    bool enable;
    /** current reconnect attempt (resets to 0 when succesful) */
    int attempt;
    /** max amount of reconnects before giving up */
    int threshold;
  } * reconnect;

  /** status structure */
  struct {
    /** will attempt to resume session if connection shutsdowns */
    bool is_resumable;
    /** can start sending/receiving additional events to discord */
    bool is_ready;
    /** if true shutdown websockets connection as soon as possible */
    bool shutdown;
  } * status;

  /** the info sent for connection authentication */
  struct discord_identify id;
  /** the session id (for resuming lost connections) */
  char session_id[512];

  /** session structure */
  struct {
    int shards;
    struct discord_session_start_limit start_limit;
    /** active concurrent sessions */
    int concurrent;
    /** timestamp of last succesful identify request */
    u64_unix_ms_t identify_tstamp;
    /** timestamp of last succesful event timestamp in ms (resets every 60s) */
    u64_unix_ms_t event_tstamp;
    /** event counter to avoid reaching limit of 120 events per 60 sec */
    int event_count;
  } session;

  /** the client's user structure */
  struct discord_user bot;
  /** the client's user raw JSON @todo this is temporary */
  struct sized_buffer sb_bot;

  /** response-payload structure */
  struct {
    /** field 'op' */
    enum discord_gateway_opcodes opcode;
    /** field 's' */
    int seq;
    /** field 't' */
    char name[64];
    /** field 'd' */
    struct sized_buffer data;
  } payload;

  /** heartbeating (keep-alive) structure */
  struct {
    /** fixed interval between heartbeats */
    u64_unix_ms_t interval_ms;
    /** start pulse timestamp in milliseconds */
    u64_unix_ms_t tstamp;
    /** latency calculated by HEARTBEAT and HEARTBEAT_ACK interval */
    int ping_ms;
  } hbeat;

  /** user-commands structure */
  struct {
    /** the prefix expected before every command @see discord_set_prefix() */
    struct sized_buffer prefix;
    /** user's command/callback pair @see discord_set_on_command() */
    struct discord_gateway_cmd_cbs *pool;
    /** amount of command/callback pairs in pool */
    size_t amt;
    /** user's default callback incase prefix matches but command doesn't */
    struct discord_gateway_cmd_cbs on_default;

    /** user's callbacks */
    struct discord_gateway_cbs cbs;
    /**
     * context on how each event callback is executed
     *          @see discord_set_event_scheduler()
     */
    discord_event_scheduler_cb scheduler;
  } cmds;
};

/**
 * @brief Context in case event is scheduled to be triggered
 *        from Orca's worker threads
 */
struct discord_event {
  /** the event name */
  char *name;
  /** a copy of payload data */
  struct sized_buffer data;
  /** the discord gateway client */
  struct discord_gateway *gw;
  /** the event unique id value */
  enum discord_gateway_events event;
  /** the event callback */
  void (*on_event)(struct discord_gateway *gw, struct sized_buffer *data);
};

/**
 * @brief Initialize the fields of Discord Gateway handle
 *
 * @param gw a pointer to the gateway handle
 * @param conf optional pointer to a initialized logconf
 * @param token the bot token
 */
void discord_gateway_init(struct discord_gateway *gw,
                          struct logconf *conf,
                          struct sized_buffer *token);

/**
 * @brief Free a Discord Gateway handle
 *
 * @param gw a pointer to the gateway handle
 */
void discord_gateway_cleanup(struct discord_gateway *gw);

/**
 * @brief Start a connection to the Discord Gateway
 *
 * @param gw the handle initialized with discord_gateway_init()
 * @return ORCAcode for how the run went, ORCA_OK means nothing out of the
 *        ordinary
 */
ORCAcode discord_gateway_run(struct discord_gateway *gw);

/**
 * @brief Gracefully shutdown a ongoing Discord connection over WebSockets
 *
 * @param gw the handle initialized with discord_gateway_init()
 */
void discord_gateway_shutdown(struct discord_gateway *gw);

/**
 * @brief Gracefully reconnect a ongoing Discord connection over WebSockets
 *
 * @param gw the handle initialized with discord_gateway_init()
 * @param resume true to attempt to resume to previous session,
 *        false restart a fresh session
 */
void discord_gateway_reconnect(struct discord_gateway *gw, bool resume);

/**
 * @brief The Discord opaque structure handler
 *
 * Used to access/perform public functions from discord.h
 *
 * - Initializer:
 *   - discord_init(), discord_config_init()
 * - Cleanup:
 *   - discord_cleanup()
 *
 * @see discord_run()
 * @note defined at discord-internal.h
 */
struct discord {
  /** @privatesection */
  /** DISCORD logging module */
  struct logconf conf;
  /** whether this is the original client or a clone */
  bool is_original;
  /** the bot token */
  struct sized_buffer token;
  /** custom libcurl's IO multiplexer */
  CURLM *mhandle;
  /** the HTTP adapter for performing requests */
  struct discord_adapter adapter;
  /** the WebSockets handle for establishing a connection to Discord */
  struct discord_gateway gw;
  /** the WebSockets handles for establishing voice connections to Discord */
  struct discord_voice vcs[DISCORD_MAX_VOICE_CONNECTIONS];
  /** @todo create a analogous struct for Gateway's callbacks */
  struct discord_voice_cbs voice_cbs;
  /** space for user arbitrary data */
  void *data;
};

/* MISCELLANEOUS */

/**
 * @brief Encodes a raw JSON payload to multipart data
 *
 * Set as a ua_curl_mime_setopt() callback, the Content-Type must be changed to
 *        `multipart/form-data` by ua_reqheader_add(), and the
 *        discord_adapter_run() HTTP method must be `HTTP_MIMEPOST`
 * @param mime the pre-initialized curl_mime handler
 * @param p_cxt a `void*[2]` that expects `struct discord_attachment**` and
 *        `struct sized_buffer` on each respective element
 */
void _discord_params_to_mime(curl_mime *mime, void *p_cxt);

#endif /* DISCORD_INTERNAL_H */
