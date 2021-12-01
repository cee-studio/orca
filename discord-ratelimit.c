/* See:
https://discord.com/developers/docs/topics/rate-limits#rate-limits */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "discord.h"
#include "discord-internal.h"

#include "cee-utils.h"
#include "clock.h"

static struct discord_route *
_discord_route_init(struct discord_ratelimit *ratelimit,
                    const char route[],
                    struct discord_bucket *b)
{
  struct discord_route *r;
  int ret;

  r = calloc(1, sizeof(struct discord_route));
  ret = snprintf(r->route, sizeof(r->route), "%s", route);
  ASSERT_S(ret < sizeof(r->route), "Out of bounds write attempt");
  r->bucket = b;

  pthread_mutex_lock(&ratelimit->lock);
  HASH_ADD_STR(ratelimit->routes, route, r);
  pthread_mutex_unlock(&ratelimit->lock);

  return r;
}

static void
_discord_route_cleanup(struct discord_route *r)
{
  free(r);
}

static struct discord_bucket *
_discord_bucket_init(struct discord_ratelimit *ratelimit,
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

  pthread_mutex_lock(&ratelimit->lock);
  HASH_ADD_STR(ratelimit->buckets, hash, b);
  pthread_mutex_unlock(&ratelimit->lock);

  return b;
}

static struct discord_bucket *
_discord_bucket_find(struct discord_ratelimit *ratelimit,
                     const struct sized_buffer *hash)
{
  struct discord_bucket *b;

  /* attempt to find bucket with key 'hash' */
  pthread_mutex_lock(&ratelimit->lock);
  HASH_FIND(hh, ratelimit->buckets, hash->start, hash->size, b);
  pthread_mutex_unlock(&ratelimit->lock);

  return b;
}

static void
_discord_bucket_cleanup(struct discord_bucket *b)
{
  pthread_mutex_destroy(&b->lock);
  free(b);
}

struct discord_ratelimit *
discord_ratelimit_init(struct logconf *conf)
{
  struct discord_ratelimit *ratelimit;

  ratelimit = calloc(1, sizeof *ratelimit);
  logconf_branch(&ratelimit->conf, conf, "DISCORD_RATELIMIT");
  if (pthread_rwlock_init(&ratelimit->rwlock, NULL))
    ERR("Couldn't initialize pthread rwlock");
  if (pthread_mutex_init(&ratelimit->lock, NULL))
    ERR("Couldn't initialize pthread mutex");
  /* for routes that still haven't discovered a bucket match */
  ratelimit->b_null = _discord_bucket_init(ratelimit, 1, "null", 4);
  /* for routes that can't be assigned to any existing bucket */
  ratelimit->b_miss = _discord_bucket_init(ratelimit, INT_MAX, "miss", 4);

  return ratelimit;
}

/* cleanup routes and buckets */
void
discord_ratelimit_cleanup(struct discord_ratelimit *ratelimit)
{
  struct discord_bucket *b, *b_tmp;
  struct discord_route *r, *r_tmp;

  /* cleanup buckets */
  HASH_ITER(hh, ratelimit->buckets, b, b_tmp)
  {
    HASH_DEL(ratelimit->buckets, b);
    _discord_bucket_cleanup(b);
  }
  /* cleanup routes */
  HASH_ITER(hh, ratelimit->routes, r, r_tmp)
  {
    HASH_DEL(ratelimit->routes, r);
    _discord_route_cleanup(r);
  }
  /* cleanup mutexes */
  pthread_rwlock_destroy(&ratelimit->rwlock);
  pthread_mutex_destroy(&ratelimit->lock);
  /* cleanup ratelimit handle */
  free(ratelimit);
}

/* return ratelimit cooldown for this bucket (in milliseconds) */
long
discord_bucket_get_cooldown(struct discord_ratelimit *ratelimit,
                            struct discord_bucket *b)
{
  /* current timestamp */
  u64_unix_ms_t now;
  /* global delay */
  u64_unix_ms_t global;
  /* total delay */
  long delay_ms = 0L;

  if (b == ratelimit->b_null) return 0L;

  now = cee_timestamp_ms();

  if (b->remaining < 1 && b->reset_tstamp > now) {
    delay_ms = (long)(b->reset_tstamp - now);
  }

  /* check global ratelimits */
  pthread_rwlock_rdlock(&ratelimit->rwlock);
  global = ratelimit->global;
  pthread_rwlock_unlock(&ratelimit->rwlock);
  if (now < global) delay_ms = (long)(global - now);

  return delay_ms;
}

struct discord_route *
discord_route_get(struct discord_ratelimit *ratelimit, const char route[])
{
  struct discord_route *r;
  pthread_mutex_lock(&ratelimit->lock);
  HASH_FIND_STR(ratelimit->routes, route, r);
  pthread_mutex_unlock(&ratelimit->lock);
  return r;
}

/* attempt to find a bucket associated with this route */
struct discord_bucket *
discord_bucket_get(struct discord_ratelimit *ratelimit, const char route[])
{
  struct discord_route *r;

  logconf_debug(&ratelimit->conf,
                "[null] Attempt to find matching bucket for route '%s'",
                route);

  r = discord_route_get(ratelimit, route);

  if (!r) {
    logconf_debug(
      &ratelimit->conf,
      "[null] Couldn't match bucket to route '%s', will attempt to "
      "create a new one",
      route);
    return ratelimit->b_null;
  }

  logconf_debug(&ratelimit->conf, "[%.4s] Found a match!", r->bucket->hash);

  return r->bucket;
}

/* attempt to parse rate limit's header fields to the bucket
 *  linked with the connection which was performed */
static void
_discord_bucket_populate(struct discord_ratelimit *ratelimit,
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
      pthread_rwlock_wrlock(&ratelimit->rwlock);
      ratelimit->global = reset_tstamp;
      pthread_rwlock_unlock(&ratelimit->rwlock);
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

  logconf_debug(&ratelimit->conf,
                "[%.4s] Reset = %" PRIu64 " | Remaining = %d", b->hash,
                b->reset_tstamp, b->remaining);
}

/* Attempt to build and/or update bucket's rate limiting information. */
void
discord_bucket_build(struct discord_ratelimit *ratelimit,
                     struct discord_bucket *b,
                     const char route[],
                     struct ua_info *info)
{
  if (b == ratelimit->b_null) {
    struct sized_buffer hash = ua_info_header_get(info, "x-ratelimit-bucket");
    struct discord_route *r;

    if (!hash.size) {
      /* assign to a special bucket for leftover routes */
      r = _discord_route_init(ratelimit, route, ratelimit->b_miss);

      logconf_debug(&ratelimit->conf,
                    "[miss] Route '%s' doesn't include bucket", r->route);

      return;
    }
    /* first time using route, try assigning a bucket to it */
    b = _discord_bucket_find(ratelimit, &hash);
    if (!b) {
      /* bucket doesnt exist, create new */
      struct sized_buffer limit =
        ua_info_header_get(info, "x-ratelimit-limit");
      int _limit = limit.size ? strtol(limit.start, NULL, 10) : INT_MAX;

      b = _discord_bucket_init(ratelimit, _limit, hash.start, hash.size);

      logconf_debug(&ratelimit->conf, "[%.4s] Create bucket", b->hash);
    }
    /* assign bucket to route */
    r = _discord_route_init(ratelimit, route, b);

    logconf_debug(&ratelimit->conf, "[%.4s] Assign route '%s' to bucket",
                  b->hash, r->route);
  }
  else if (b == ratelimit->b_miss) {
    /* leftover route, nothing to do in this case */
    return;
  }
  /* update the bucket rate limit values */
  _discord_bucket_populate(ratelimit, b, info);
}
