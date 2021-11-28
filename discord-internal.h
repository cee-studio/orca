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

#include "discord-voice-connections.h"

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
  /** DISCORD_HTTP or DISCORD_WEBHOOK logging module */
  struct logconf conf;
  /** the user agent handle for performing requests */
  struct user_agent *ua;
  /** ratelimit handler structure */
  struct discord_ratelimit *ratelimit;
  /** request queues */
  struct {
    /** requests on hold (waiting for their turn) */
    QUEUE hold;
    /** unused request handles (can be recycled) */
    QUEUE idle;
  } queue;
  /** error storage context */
  struct {
    /** informational on the latest transfer */
    struct ua_info info;
    /** JSON error code on failed request */
    int jsoncode;
    /** the entire JSON response of the error */
    char jsonstr[512];
  } err;
};

/**
 * @brief Initialize the fields of a Discord Adapter handle
 *
 * @param adapter a pointer to the allocated handle
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
 * @brief Start a HTTP Request to Discord
 *
 * @param adapter the handle initialized with discord_adapter_init()
 * @param resp_handle the callbacks to be triggered should the request
 *        fail or succeed
 * @param req_body the body sent for methods that require (ex: post), leave as
 *        null if unecessary
 * @param http_method the method in opcode format of the request being sent
 * @param endpoint the format endpoint that be appended to base_url when
 *        performing a request, same behavior as printf()
 * @return a code for checking on how the transfer went ORCA_OK means the
 *        transfer was succesful
 * @note Helper over ua_run()
 */
ORCAcode discord_adapter_run(struct discord_adapter *adapter,
                             struct ua_resp_handle *resp_handle,
                             struct sized_buffer *req_body,
                             enum http_method http_method,
                             char endpoint_fmt[],
                             ...);

/**
 * @brief Enqueue a request to be executed asynchronously
 *
 * @param adapter the handle initialized with discord_adapter_init()
 * @param resp_handle the callbacks to be triggered should the request
 *        fail or succeed
 * @param req_body the body sent for methods that require (ex: post), leave as
 *        null if unecessary
 * @param http_method the method in opcode format of the request being sent
 * @param endpoint the endpoint to be appended to base_url when
 *        performing a request
 */
void discord_adapter_enqueue(struct discord_adapter *adapter,
                             struct ua_resp_handle *resp_handle,
                             struct sized_buffer *req_body,
                             enum http_method http_method,
                             char endpoint[]);

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
  /** routes discovered */
  struct discord_route *routes;
  /** buckets discovered */
  struct discord_bucket *buckets;
  /** for undefined routes */
  struct discord_bucket *b_null;
  /** for routes without a bucket match */
  struct discord_bucket *b_miss;
  /** global ratelimit */
  u64_unix_ms_t global;
  /** lock used when accessing or modifying 'global' */
  pthread_rwlock_t rwlock;
  /** lock used when adding or searching for buckets */
  pthread_mutex_t lock;
};

/**
 * @brief Initialize ratelimit handler
 *
 * @param conf optional pointer to a initialized logconf
 */
struct discord_ratelimit *discord_ratelimit_init(struct logconf *conf);

/**
 * @brief Free ratelimit handler
 *
 * @param ratelimit the ratelimit handler
 */
void discord_ratelimit_cleanup(struct discord_ratelimit *ratelimit);

/**
 * @brief A bucket may have multiple routes pointing at it
 *
 * Bucket routes can be either one of the two:
 * 1. major parameters: channel id, guild id, webhook id
 * 2. the endpoint itself
 */
struct discord_route {
  /** route associated with bucket */
  char route[256];
  /* bucket associated with route */
  struct discord_bucket *bucket;
  /** makes this structure hashable */
  UT_hash_handle hh;
};

/**
 * @brief Get a `struct discord_route` assigned to `route`
 *
 * Check if bucket associated with `route` has already been discovered
 * @param ratelimit the ratelimit handler
 * @param route that will be checked for a match
 * @return `struct discord_route` associated with route or NULL if no match
 *        found
 */
struct discord_route *discord_route_get(struct discord_ratelimit *ratelimit,
                                        const char route[]);

/** 
 * @brief Context in case request is scheduled to run asynchronously
 */
struct discord_request_cxt {
  /** 
   * the discord adapter client initialized with discord_clone()
   * @note this is a workaround so that each context can carry its own header
   * @todo passing only a 'struct curl_slist' around should be enough
   */
  struct discord_adapter *p_adapter;
  /** the request's route */
  struct discord_route *route;
  /** the request's response handle */
  struct ua_resp_handle resp_handle;
  /** the request's request body @note buffer is kept and recycled */
  struct sized_buffer req_body;
  /** the request's http method */
  enum http_method http_method;
  /** the request's endpoint */
  char endpoint[2048];
  /** the connection handler assigned at discord_adapter_prepare() */
  struct ua_conn *conn;
  /** the request bucket's queue entry */
  QUEUE entry;
};

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
  /** the unique hash associated with this bucket */
  char hash[128];
  /** amount of busy connections that have not yet finished its requests */
  int busy;
  /** connections this bucket can do before waiting for cooldown */
  int remaining;
  /** timestamp of when cooldown timer resets */
  u64_unix_ms_t reset_tstamp;
  /** synchronize ratelimiting between threads */
  pthread_mutex_t lock;
  /** makes this structure hashable */
  UT_hash_handle hh;
};

/**
 * @brief Check bucket for ratelimit cooldown
 *
 * Check if connections from a bucket hit its threshold, and lock every
 * connection associated with the bucket until cooldown time elapses
 * @param ratelimit the ratelimit handler
 * @param bucket check if bucket expects a cooldown before performing a request
 * @return timespan to wait for in milliseconds
 */
long discord_bucket_get_cooldown(struct discord_ratelimit *ratelimit,
                                 struct discord_bucket *bucket);

/**
 * @brief Get a `struct discord_bucket` assigned to `route`
 *
 * @param ratelimit the ratelimit handler
 * @param route that will be checked for a bucket match
 * @return bucket assigned to `route` or `ratelimit->b_null` if no match found
 * @note helper over discord_route_get()
 */
struct discord_bucket *discord_bucket_get(struct discord_ratelimit *ratelimit,
                                          const char route[]);

/**
 * @brief Update the bucket with response header data
 *
 * @param ratelimit the ratelimit handler
 * @param bucket NULL when bucket is first discovered
 * @param route the route associated with the bucket
 * @param code numerical information for the current transfer
 * @param info informational struct containing details on the current transfer
 * @note If the bucket was just discovered it will be created here.
 */
void discord_bucket_build(struct discord_ratelimit *ratelimit,
                          struct discord_bucket *bucket,
                          const char route[],
                          ORCAcode code,
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
  struct {
    char *url;
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

  /**
   * response-payload structure
   * @see
   * https://discord.com/developers/docs/topics/gateway#payloads-gateway-payload-structure
   */
  struct {
    /** field 'op' */
    enum discord_gateway_opcodes opcode;
    /** field 's' */
    int seq;
    /** field 't' */
    char event_name[64];
    /** field 'd' */
    struct sized_buffer event_data;
  } * payload;

  /**
   * heartbeating (keep-alive) structure
   * @note Discord expects a proccess called hearbeating in order to keep the
   * client connection alive
   * @see https://discord.com/developers/docs/topics/gateway#heartbeating
   */
  struct {
    /** fixed interval between heartbeats */
    u64_unix_ms_t interval_ms;
    /** start pulse timestamp in milliseconds */
    u64_unix_ms_t tstamp;
    /** latency calculated by HEARTBEAT and HEARTBEAT_ACK interval */
    int ping_ms;
  } * hbeat;

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
  } * user_cmd;
};

/**
 * @brief Context in case event is scheduled to be triggered
 *        from the orca threadpool
 */
struct discord_event_cxt {
  /** the event name */
  char *event_name;
  /** a copy of payload data */
  struct sized_buffer data;
  /** the discord gateway client */
  struct discord_gateway *p_gw;
  /** the event unique id value */
  enum discord_gateway_events event;
  /** the event callback */
  void (*on_event)(struct discord_gateway *gw, struct sized_buffer *data);
};

/**
 * @brief Initialize the fields of Discord Gateway handle
 *
 * @param gw a pointer to the allocated handle
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
 * ordinary
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
  struct logconf *conf;
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
  /**
   * keep user arbitrary data
   * @see discord_get_data(), discord_set_data()
   */
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
