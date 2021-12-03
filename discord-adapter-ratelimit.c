/* See:
https://discord.com/developers/docs/topics/rate-limits#rate-limits */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "discord.h"
#include "discord-internal.h"

#include "cee-utils.h"
#include "clock.h"

/* get client from adapter pointer */
#define CLIENT(p_rlimit)                                                      \
  ((struct discord *)((int8_t *)(p_rlimit)-offsetof(struct discord,           \
                                                    adapter.rlimit)))

/* get request context from heap node */
#define CXT(p_node)                                                           \
  ((struct discord_request *)((int8_t *)(p_node)-offsetof(                    \
    struct discord_request, node)))

static int
timer_less_than(const struct heap_node *ha, const struct heap_node *hb)
{
  const struct discord_request *a = CXT(ha);
  const struct discord_request *b = CXT(hb);

  return a->timeout_ms <= b->timeout_ms;
}

static struct discord_route *
_discord_route_init(struct discord_ratelimit *rlimit,
                    const char route[],
                    struct discord_bucket *b)
{
  struct discord_route *r;
  int ret;

  r = calloc(1, sizeof(struct discord_route));
  ret = snprintf(r->route, sizeof(r->route), "%s", route);
  ASSERT_S(ret < sizeof(r->route), "Out of bounds write attempt");
  r->bucket = b;

  pthread_mutex_lock(&rlimit->global->lock);
  HASH_ADD_STR(rlimit->routes, route, r);
  pthread_mutex_unlock(&rlimit->global->lock);

  return r;
}

static void
_discord_route_cleanup(struct discord_route *r)
{
  free(r);
}

static struct discord_bucket *
_discord_bucket_init(struct discord_ratelimit *rlimit,
                     const int limit,
                     const char hash[],
                     const size_t len)
{
  struct discord_bucket *b;
  int ret;

  b = calloc(1, sizeof(struct discord_bucket));
  b->remaining = 1;
  b->limit = limit;
  ret = snprintf(b->hash, sizeof(b->hash), "%.*s", (int)len, hash);
  ASSERT_S(ret < sizeof(b->hash), "Out of bounds write attempt");
  if (pthread_mutex_init(&b->lock, NULL))
    ERR("Couldn't initialize pthread mutex");

  QUEUE_INIT(&b->pending);

  pthread_mutex_lock(&rlimit->global->lock);
  HASH_ADD_STR(rlimit->buckets, hash, b);
  pthread_mutex_unlock(&rlimit->global->lock);

  return b;
}

static struct discord_bucket *
_discord_bucket_find(struct discord_ratelimit *rlimit,
                     const struct sized_buffer *hash)
{
  struct discord_bucket *b;

  /* attempt to find bucket with key 'hash' */
  pthread_mutex_lock(&rlimit->global->lock);
  HASH_FIND(hh, rlimit->buckets, hash->start, hash->size, b);
  pthread_mutex_unlock(&rlimit->global->lock);

  return b;
}

static void
_discord_bucket_cleanup(struct discord_bucket *b)
{
  pthread_mutex_destroy(&b->lock);
  free(b);
}

void
discord_ratelimit_init(struct discord_ratelimit *rlimit, struct logconf *conf)
{
  logconf_branch(&rlimit->conf, conf, "DISCORD_RATELIMIT");
  /* global resources */
  rlimit->global = calloc(1, sizeof *rlimit->global);
  if (pthread_rwlock_init(&rlimit->global->rwlock, NULL))
    ERR("Couldn't initialize pthread rwlock");
  if (pthread_mutex_init(&rlimit->global->lock, NULL))
    ERR("Couldn't initialize pthread mutex");
  /* for routes that still haven't discovered a bucket match */
  rlimit->b_null = _discord_bucket_init(rlimit, 1, "null", 4);
  /* for routes that can't be assigned to any existing bucket */
  rlimit->b_miss = _discord_bucket_init(rlimit, INT_MAX, "miss", 4);
  /* initialize min-heap for handling timeouts */
  heap_init(&rlimit->timeouts);
}

/* cleanup routes and buckets */
void
discord_ratelimit_cleanup(struct discord_ratelimit *rlimit)
{
  struct discord_bucket *b, *b_tmp;
  struct discord_route *r, *r_tmp;

  /* cleanup buckets */
  HASH_ITER(hh, rlimit->buckets, b, b_tmp)
  {
    HASH_DEL(rlimit->buckets, b);
    _discord_bucket_cleanup(b);
  }
  /* cleanup routes */
  HASH_ITER(hh, rlimit->routes, r, r_tmp)
  {
    HASH_DEL(rlimit->routes, r);
    _discord_route_cleanup(r);
  }
  /* cleanup global resources */
  pthread_rwlock_destroy(&rlimit->global->rwlock);
  pthread_mutex_destroy(&rlimit->global->lock);
  free(rlimit->global);
}

u64_unix_ms_t
discord_ratelimit_get_global_wait(struct discord_ratelimit *rlimit)
{
  u64_unix_ms_t global;

  pthread_rwlock_rdlock(&rlimit->global->rwlock);
  global = rlimit->global->wait_ms;
  pthread_rwlock_unlock(&rlimit->global->rwlock);

  return global;
}

void
discord_ratelimit_run_timeouts(struct discord_ratelimit *rlimit)
{
  struct discord_request *cxt;
  struct heap_node *node;

  while (1) {
    node = heap_min(&rlimit->timeouts);
    if (!node) break;

    cxt = CXT(node);
    if (cxt->timeout_ms > discord_timestamp(CLIENT(rlimit))) break;

    --cxt->bucket->busy;
    heap_remove(&rlimit->timeouts, node, &timer_less_than);
    QUEUE_INSERT_HEAD(&cxt->bucket->pending, &cxt->entry);
  }
}

static void
_discord_request_start(struct discord_ratelimit *rlimit,
                       struct discord_bucket *b,
                       struct discord_request *cxt)
{
  CURL *ehandle;

  --b->remaining;
  ++b->busy;

  cxt->conn = ua_conn_start(cxt->adapter->ua);
  ehandle = ua_conn_curl_easy_get(cxt->conn);
  ua_conn_setup(cxt->adapter->ua, cxt->conn, &cxt->resp_handle, &cxt->req_body,
                cxt->method, cxt->endpoint);
  /* link 'cxt' to 'ehandle' for easy retrieval */
  curl_easy_setopt(ehandle, CURLOPT_PRIVATE, cxt);
  /* let curl begin transfer */
  curl_multi_add_handle(CLIENT(rlimit)->mhandle, ehandle);
}

static void
_discord_request_run_single(struct discord_ratelimit *rlimit,
                            struct discord_bucket *b)
{
  struct discord_request *cxt;
  QUEUE *q;

  q = QUEUE_HEAD(&b->pending);
  cxt = QUEUE_DATA(q, struct discord_request, entry);
  QUEUE_REMOVE(&cxt->entry);

  b->remaining = 1;

  _discord_request_start(rlimit, b, cxt);
}

static void
_discord_request_send_batch(struct discord_ratelimit *rlimit,
                            struct discord_bucket *b)
{
  struct discord_request *cxt;
  QUEUE *q;

  while (b->remaining > 0 && !QUEUE_EMPTY(&b->pending)) {
    q = QUEUE_HEAD(&b->pending);
    cxt = QUEUE_DATA(q, struct discord_request, entry);
    QUEUE_REMOVE(&cxt->entry);

    if (discord_bucket_timeout(rlimit, b, cxt)) break;

    _discord_request_start(rlimit, b, cxt);
  };
}

void
discord_ratelimit_prepare_requests(struct discord_ratelimit *rlimit)
{
  struct discord_bucket *b;

  for (b = rlimit->buckets; b != NULL; b = b->hh.next) {
    if (b->busy || QUEUE_EMPTY(&b->pending)) continue;

    /* perform standalone request if bucket is stale (update bucket fields)
     */
    if (b->reset_tstamp < discord_timestamp(CLIENT(rlimit))) {
      _discord_request_run_single(rlimit, b);
      continue;
    }

    _discord_request_send_batch(rlimit, b);
  }
}

/* return ratelimit timeout timestamp for this bucket */
static u64_unix_ms_t
_discord_bucket_get_timeout(struct discord_ratelimit *rlimit,
                            struct discord_bucket *b)
{
  u64_unix_ms_t global;
  u64_unix_ms_t reset;

  global = discord_ratelimit_get_global_wait(rlimit);
  reset = (b->remaining < 1) ? b->reset_tstamp : 0ULL;

  return (global > reset) ? global : reset;
}

bool
discord_bucket_timeout(struct discord_ratelimit *rlimit,
                       struct discord_bucket *b,
                       struct discord_request *cxt)
{
  u64_unix_ms_t timeout;
  u64_unix_ms_t now = discord_timestamp(CLIENT(rlimit));

  timeout = _discord_bucket_get_timeout(rlimit, b);
  if (now > timeout) return false;

  logconf_info(&rlimit->conf, "[%.4s] RATELIMITING (timeout %ld ms)", b->hash,
               timeout - now);

  cxt->timeout_ms = timeout;
  ++b->busy;

  heap_insert(&rlimit->timeouts, &cxt->node, &timer_less_than);

  return true;
}

static long
_discord_bucket_get_cooldown(struct discord_ratelimit *rlimit,
                             struct discord_bucket *b)
{
  u64_unix_ms_t now = discord_timestamp(CLIENT(rlimit));
  u64_unix_ms_t reset = _discord_bucket_get_timeout(rlimit, b);

  return (long)(reset - now);
}

void
discord_bucket_cooldown(struct discord_ratelimit *rlimit,
                        struct discord_bucket *b)
{
  long delay_ms = _discord_bucket_get_cooldown(rlimit, b);

  if (delay_ms > 0) {
    logconf_info(&rlimit->conf, "[%.4s] RATELIMITING (wait %ld ms)", b->hash,
                 delay_ms);
    cee_sleep_ms(delay_ms);
  }

  --b->remaining;
}

struct discord_route *
discord_route_get(struct discord_ratelimit *rlimit, const char route[])
{
  struct discord_route *r;

  pthread_mutex_lock(&rlimit->global->lock);
  HASH_FIND_STR(rlimit->routes, route, r);
  pthread_mutex_unlock(&rlimit->global->lock);

  return r;
}

/* attempt to find a bucket associated with this route */
struct discord_bucket *
discord_bucket_get(struct discord_ratelimit *rlimit, const char route[])
{
  struct discord_route *r;
  struct discord_bucket *b;

  logconf_debug(&rlimit->conf,
                "[null] Attempt to find matching bucket for route '%s'",
                route);

  r = discord_route_get(rlimit, route);

  if (!r) {
    logconf_debug(
      &rlimit->conf,
      "[null] Couldn't match bucket to route '%s', will attempt to "
      "create a new one",
      route);
    b = rlimit->b_null;
  }
  else {
    b = r->bucket;
  }

  logconf_debug(&rlimit->conf, "[%.4s] Found a match!", b->hash);
#if 0
  if (IS_STALE(b)) b->remaining = b->limit;
#endif
  return b;
}

/* attempt to parse rate limit's header fields to the bucket
 *  linked with the connection which was performed */
static void
_discord_bucket_populate(struct discord_ratelimit *rlimit,
                         struct discord_bucket *b,
                         struct ua_info *info)
{
  struct sized_buffer reset, remaining, reset_after, date;
  u64_unix_ms_t _server;
  int _remaining;

  /* fetch individual header fields */
  reset = ua_info_header_get(info, "x-ratelimit-reset");
  reset_after = ua_info_header_get(info, "x-ratelimit-reset-after");
  remaining = ua_info_header_get(info, "x-ratelimit-remaining");
  date = ua_info_header_get(info, "date");

  /* remaining requests before ratelimiting */
  _remaining = remaining.size ? strtol(remaining.start, NULL, 10) : 1;
  /* Discord's server time in milliseconds */
  _server = 1000 * curl_getdate(date.start, NULL);

  if (_remaining > b->remaining && _server <= b->server) {
    /* avoid populating bucket with out of order requests */
    return;
  }

  /* use X-Ratelimit-Reset-After if available, otherwise use
   * X-Ratelimit-Reset */
  if (reset_after.size) {
    struct sized_buffer global =
      ua_info_header_get(info, "x-ratelimit-global");
    u64_unix_ms_t reset_tstamp =
      cee_timestamp_ms() + 1000 * strtod(reset_after.start, NULL);

    if (global.size) {
      /* lock all buckets */
      pthread_rwlock_wrlock(&rlimit->global->rwlock);
      rlimit->global->wait_ms = reset_tstamp;
      pthread_rwlock_unlock(&rlimit->global->rwlock);
    }
    else {
      /* lock single bucket, timeout at discord_adapter_run() */
      b->reset_tstamp = reset_tstamp;
    }
  }
  else if (reset.size) {
    /* get approximate elapsed time since request */
    struct PsnipClockTimespec ts;
    /* the Discord time + request's elapsed time */
    u64_unix_ms_t offset;

    psnip_clock_wall_get_time(&ts);
    offset = _server + ts.nanoseconds / 1000000;
    /* reset timestamp =
     * (system time) + (diff between Discord's reset timestamp and offset) */
    b->reset_tstamp =
      cee_timestamp_ms() + (1000 * strtod(reset.start, NULL) - offset);
  }

  b->remaining = _remaining;
  b->server = _server;

  logconf_debug(&rlimit->conf, "[%.4s] Reset = %" PRIu64 " | Remaining = %d",
                b->hash, b->reset_tstamp, b->remaining);
}

/* Attempt to build and/or update bucket's rate limiting information. */
void
discord_bucket_build(struct discord_ratelimit *rlimit,
                     struct discord_bucket *b,
                     const char route[],
                     struct ua_info *info)
{
  if (b == rlimit->b_null) {
    struct sized_buffer hash = ua_info_header_get(info, "x-ratelimit-bucket");
    struct discord_route *r;

    if (!hash.size) {
      /* assign to a special bucket for leftover routes */
      r = _discord_route_init(rlimit, route, rlimit->b_miss);

      logconf_debug(&rlimit->conf, "[miss] Route '%s' doesn't include bucket",
                    r->route);

      return;
    }
    /* first time using route, try assigning a bucket to it */
    b = _discord_bucket_find(rlimit, &hash);
    if (!b) {
      /* bucket doesnt exist, create new */
      struct sized_buffer limit =
        ua_info_header_get(info, "x-ratelimit-limit");
      int _limit = limit.size ? strtol(limit.start, NULL, 10) : INT_MAX;

      b = _discord_bucket_init(rlimit, _limit, hash.start, hash.size);

      logconf_debug(&rlimit->conf, "[%.4s] Create bucket", b->hash);
    }
    /* assign bucket to route */
    r = _discord_route_init(rlimit, route, b);

    logconf_debug(&rlimit->conf, "[%.4s] Assign route '%s' to bucket", b->hash,
                  r->route);
  }
  else if (b == rlimit->b_miss) {
    /* leftover route, nothing to do in this case */
    return;
  }
  /* update the bucket rate limit values */
  _discord_bucket_populate(rlimit, b, info);
}
