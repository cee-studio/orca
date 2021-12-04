/* See:
https://discord.com/developers/docs/topics/rate-limits#rate-limits */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "discord.h"
#include "discord-internal.h"

#include "cee-utils.h"
#include "clock.h"

/* get client from ratelimit pointer */
#define CLIENT(p_rlimit)                                                      \
  ((struct discord *)((int8_t *)(p_rlimit)-offsetof(struct discord,           \
                                                    adapter.rlimit)))

/* in case 'endpoint' has a major param, it will be written into 'buf' */
static const char *
_discord_ratelimit_get_route(const char endpoint[], char buf[32])
{
  /* determine which ratelimit group (aka bucket) a request belongs to
   * by checking its route.
   * see:  https://discord.com/developers/docs/topics/rate-limits */
  if (STRNEQ(endpoint, "/channels/", sizeof("/channels/") - 1)
      || STRNEQ(endpoint, "/guilds/", sizeof("/guilds/") - 1)
      || STRNEQ(endpoint, "/webhooks/", sizeof("/webhooks/") - 1))
  {
    /* safe to assume strchr() won't return NULL */
    char *start = 1 + strchr(1 + endpoint, '/'), *end = strchr(start, '/');
    ptrdiff_t len = end - start;

    /* copy snowflake id over to buf */
    memcpy(buf, start, len);
    buf[len] = '\0';
    return buf;
  }
  return endpoint;
}

static struct discord_bucket *
_discord_bucket_init(struct discord_ratelimit *rlimit,
                     const char route[],
                     struct sized_buffer *hash,
                     const int limit)
{
  struct discord_bucket *b;
  int ret;

  b = calloc(1, sizeof(struct discord_bucket));

  b->remaining = 1;
  b->limit = limit;

  ret = snprintf(b->route, sizeof(b->route), "%s", route);
  ASSERT_S(ret < sizeof(b->route), "Out of bounds write attempt");

  ret =
    snprintf(b->hash, sizeof(b->hash), "%.*s", (int)hash->size, hash->start);
  ASSERT_S(ret < sizeof(b->hash), "Out of bounds write attempt");

  if (pthread_mutex_init(&b->lock, NULL))
    ERR("Couldn't initialize pthread mutex");

  QUEUE_INIT(&b->pending);

  pthread_mutex_lock(&rlimit->global->lock);
  HASH_ADD_STR(rlimit->buckets, route, b);
  pthread_mutex_unlock(&rlimit->global->lock);

  return b;
}

static struct discord_bucket *
_discord_bucket_find(struct discord_ratelimit *rlimit, const char route[])
{
  struct discord_bucket *b;

  /* attempt to find bucket with key 'route' */
  pthread_mutex_lock(&rlimit->global->lock);
  HASH_FIND_STR(rlimit->buckets, route, b);
  pthread_mutex_unlock(&rlimit->global->lock);

  return b;
}

static struct discord_bucket *
_discord_bucket_get_match(struct discord_ratelimit *rlimit,
                          const char endpoint[],
                          struct ua_info *info)
{
  char buf[32]; /* for reentrancy, stores 'major' parameter */
  const char *route = _discord_ratelimit_get_route(endpoint, buf);
  struct discord_bucket *b = _discord_bucket_find(rlimit, route);

  /* create bucket if it doesn't exist yet */
  if (!b) {
    struct sized_buffer hash, limit;
    int _limit;

    hash = ua_info_header_get(info, "x-ratelimit-bucket");
    if (!hash.size) return rlimit->b_null;

    limit = ua_info_header_get(info, "x-ratelimit-limit");
    _limit = limit.size ? strtol(limit.start, NULL, 10) : INT_MAX;

    b = _discord_bucket_init(rlimit, route, &hash, _limit);

    logconf_debug(&rlimit->conf, "[%.4s] Create bucket", b->hash);
  }

  return b;
}

static void
_discord_bucket_cleanup(struct discord_bucket *b)
{
  struct discord_request *cxt;
  QUEUE queue;

  pthread_mutex_destroy(&b->lock);
  /* cleanup leftover requests */
  QUEUE_MOVE(&b->pending, &queue);
  while (!QUEUE_EMPTY(&queue)) {
    QUEUE *q = QUEUE_HEAD(&queue);
    cxt = QUEUE_DATA(q, struct discord_request, entry);
    QUEUE_REMOVE(&cxt->entry);
    discord_request_cleanup(cxt);
  }
  free(b);
}

void
discord_ratelimit_init(struct discord_ratelimit *rlimit, struct logconf *conf)
{
  struct sized_buffer hash;

  logconf_branch(&rlimit->conf, conf, "DISCORD_RATELIMIT");

  /* global resources */
  rlimit->global = calloc(1, sizeof *rlimit->global);
  if (pthread_rwlock_init(&rlimit->global->rwlock, NULL))
    ERR("Couldn't initialize pthread rwlock");
  if (pthread_mutex_init(&rlimit->global->lock, NULL))
    ERR("Couldn't initialize pthread mutex");

  /* for routes that still haven't discovered a bucket match */
  hash.start = "null";
  hash.size = 4;
  rlimit->b_null = _discord_bucket_init(rlimit, "null", &hash, 1);

  /* initialize min-heap for handling request timeouts */
  heap_init(&rlimit->timeouts);
}

/* cleanup routes and buckets */
void
discord_ratelimit_cleanup(struct discord_ratelimit *rlimit)
{
  struct discord_bucket *b, *b_tmp;

  /* cleanup buckets */
  HASH_ITER(hh, rlimit->buckets, b, b_tmp)
  {
    HASH_DEL(rlimit->buckets, b);
    _discord_bucket_cleanup(b);
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

/* return ratelimit timeout timestamp for this bucket */
u64_unix_ms_t
discord_bucket_get_timeout(struct discord_ratelimit *rlimit,
                           struct discord_bucket *b)
{
  u64_unix_ms_t global = discord_ratelimit_get_global_wait(rlimit);
  u64_unix_ms_t reset = (b->remaining < 1) ? b->reset_tstamp : 0ULL;

  return (global > reset) ? global : reset;
}

void
discord_bucket_cooldown(struct discord_ratelimit *rlimit,
                        struct discord_bucket *b)
{
  u64_unix_ms_t now = discord_timestamp(CLIENT(rlimit));
  u64_unix_ms_t reset = discord_bucket_get_timeout(rlimit, b);
  long delay_ms = (long)(reset - now);

  if (delay_ms > 0) {
    /* block thread's runtime for delay amount */
    logconf_info(&rlimit->conf, "[%.4s] RATELIMITING (wait %ld ms)", b->hash,
                 delay_ms);
    cee_sleep_ms(delay_ms);
  }

  --b->remaining;
}

/* attempt to find a bucket associated with this route */
struct discord_bucket *
discord_bucket_get(struct discord_ratelimit *rlimit, const char endpoint[])
{
  char buf[32]; /* for reentrancy, stores 'major' parameter */
  const char *route = _discord_ratelimit_get_route(endpoint, buf);
  struct discord_bucket *b = _discord_bucket_find(rlimit, route);

  if (b) {
    logconf_debug(&rlimit->conf, "[%.4s] Found a bucket match for route '%s'!",
                  b->hash, b->route);

    return b;
  }

  logconf_debug(&rlimit->conf,
                "[null] Couldn't match any discovered bucket to route '%s'",
                route);

  return rlimit->b_null;
}

/* attempt to parse rate limit's header fields to the bucket
 *  linked with the connection which was performed */
static void
_discord_bucket_populate(struct discord_ratelimit *rlimit,
                         struct discord_bucket *b,
                         struct ua_info *info)
{
  /* fetch individual header fields */
  struct sized_buffer reset, remaining, reset_after, date;
  /* Discord's server time in milliseconds */
  u64_unix_ms_t _server;
  /* remaining requests before ratelimiting */
  int _remaining;

  reset = ua_info_header_get(info, "x-ratelimit-reset");
  reset_after = ua_info_header_get(info, "x-ratelimit-reset-after");
  remaining = ua_info_header_get(info, "x-ratelimit-remaining");
  date = ua_info_header_get(info, "date");

  _remaining = remaining.size ? strtol(remaining.start, NULL, 10) : 1;
  _server = 1000 * curl_getdate(date.start, NULL);

  /* skip populating bucket with unordered responses */
  if (_remaining > b->remaining && _server <= b->server) return;

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

/* in case of asynchronous requests, check if successive requests with
 * undefined buckets can be matched to a new route */
static void
_discord_bucket_undefined_filter(struct discord_ratelimit *rlimit,
                                 struct discord_bucket *b,
                                 const char endpoint[])
{
  struct discord_request *cxt;
  QUEUE queue;
  QUEUE *q;

  QUEUE_MOVE(&rlimit->b_null->pending, &queue);
  while (!QUEUE_EMPTY(&queue)) {
    q = QUEUE_HEAD(&queue);
    QUEUE_REMOVE(q);

    cxt = QUEUE_DATA(q, struct discord_request, entry);
    if (0 == strcmp(cxt->endpoint, endpoint)) {
      QUEUE_INSERT_TAIL(&b->pending, q);
      cxt->bucket = b;
    }
    else {
      QUEUE_INSERT_TAIL(&rlimit->b_null->pending, q);
    }
  }
}

/* attempt to create and/or update bucket's values */
void
discord_bucket_build(struct discord_ratelimit *rlimit,
                     struct discord_bucket *b,
                     const char endpoint[],
                     struct ua_info *info)
{
  /* if new route, find out its bucket */
  if (b == rlimit->b_null) {
    /* match bucket with hash (from discovered or create a new one) */
    b = _discord_bucket_get_match(rlimit, endpoint, info);
    if (b == rlimit->b_null) {
      logconf_debug(&rlimit->conf, "[null] No bucket match for route '%s'",
                    b->route);

      return;
    }

    logconf_debug(&rlimit->conf, "[%.4s] Match route '%s' to bucket", b->hash,
                  b->route);

    _discord_bucket_undefined_filter(rlimit, b, endpoint);
  }

  /* update bucket's values */
  _discord_bucket_populate(rlimit, b, info);
}
