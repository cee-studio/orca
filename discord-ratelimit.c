/* See:
https://discord.com/developers/docs/topics/rate-limits#rate-limits */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "discord.h"
#include "discord-internal.h"

#include "cee-utils.h"
#include "clock.h"

static struct discord_bucket *
_discord_bucket_init(struct discord_ratelimit *ratelimit,
                     const char hash[],
                     const char route[])
{
  struct discord_bucket *b;
  struct discord_route *r;
  int ret;

  pthread_mutex_lock(&ratelimit->lock);
  HASH_FIND_STR(ratelimit->buckets, hash, b);
  pthread_mutex_unlock(&ratelimit->lock);

  if (!b) {
    /* couldn't find hash match, create new bucket */
    b = calloc(1, sizeof(struct discord_bucket));
    b->remaining = 1;
    ret = snprintf(b->hash, sizeof(b->hash), "%s", hash);
    ASSERT_S(ret < sizeof(b->hash), "Out of bounds write attempt");
    if (pthread_mutex_init(&b->lock, NULL))
      ERR("Couldn't initialize pthread mutex");

    pthread_mutex_lock(&ratelimit->lock);
    HASH_ADD_STR(ratelimit->buckets, hash, b);
    pthread_mutex_unlock(&ratelimit->lock);

    logconf_debug(&ratelimit->conf, "[%.4s] Create bucket", b->hash);
  }

  /* assign bucket to route */
  r = calloc(1, sizeof(struct discord_route));
  ret = snprintf(r->route, sizeof(r->route), "%s", route);
  ASSERT_S(ret < sizeof(r->route), "Out of bounds write attempt");
  r->bucket = b;

  pthread_mutex_lock(&ratelimit->lock);
  HASH_ADD_STR(ratelimit->routes, route, r);
  pthread_mutex_unlock(&ratelimit->lock);

  logconf_debug(&ratelimit->conf, "[%.4s] Assign route '%s' to bucket",
                b->hash, r->route);

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
  struct discord_ratelimit *ratelimit = calloc(1, sizeof *ratelimit);
  logconf_branch(&ratelimit->conf, conf, "DISCORD_RATELIMIT");
  if (pthread_rwlock_init(&ratelimit->rwlock, NULL))
    ERR("Couldn't initialize pthread rwlock");
  if (pthread_mutex_init(&ratelimit->lock, NULL))
    ERR("Couldn't initialize pthread mutex");
  ratelimit->undefined = _discord_bucket_init(ratelimit, "null", "@undefined");
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
    free(r);
  }
}

/* return ratelimit cooldown for this bucket (in milliseconds) */
long
discord_bucket_get_cooldown(struct discord_ratelimit *ratelimit,
                            struct discord_bucket *b)
{
  if (b == ratelimit->undefined) return 0L;

  u64_unix_ms_t now = cee_timestamp_ms();
  u64_unix_ms_t global = 0ULL;
  long delay_ms = 0L;

  if (b->remaining < 1 && b->reset_tstamp > now) {
    delay_ms = (long)(b->reset_tstamp - now);
  }

  /* check global ratelimits */
  pthread_rwlock_rdlock(&ratelimit->rwlock);
  global = ratelimit->global;
  pthread_rwlock_unlock(&ratelimit->rwlock);
  if (now < global) delay_ms = (long)(global - now);

  --b->remaining;

  return delay_ms;
}

/* attempt to find a bucket associated with this route */
struct discord_bucket *
discord_bucket_get(struct discord_ratelimit *ratelimit, const char route[])
{
  struct discord_route *r;

  logconf_debug(&ratelimit->conf,
                "[?] Attempt to find matching bucket for route '%s'", route);

  pthread_mutex_lock(&ratelimit->lock);
  HASH_FIND_STR(ratelimit->routes, route, r);
  pthread_mutex_unlock(&ratelimit->lock);

  if (!r) {
    logconf_debug(&ratelimit->conf,
                  "[?] Couldn't match bucket to route '%s', will attempt to "
                  "create a new one",
                  route);
    return ratelimit->undefined;
  }

  logconf_debug(&ratelimit->conf, "[%.4s] Found a match!", r->bucket->hash);

  return r->bucket;
}

/* attempt to parse rate limit's header fields to the bucket
 *  linked with the connection which was performed */
static void
_discord_bucket_populate(struct discord_ratelimit *ratelimit,
                         struct discord_bucket *b,
                         ORCAcode code,
                         struct ua_info *info)
{
  if (code != ORCA_OK) {
    logconf_debug(&ratelimit->conf, "[%.4s] Request failed", b->hash);
  }
  else if (b->update_tstamp <= info->req_tstamp) {
    /* fetch header individual fields */
    struct sized_buffer reset = ua_info_header_get(info, "x-ratelimit-reset"),
                        remaining =
                          ua_info_header_get(info, "x-ratelimit-remaining"),
                        reset_after =
                          ua_info_header_get(info, "x-ratelimit-reset-after");

    b->remaining = remaining.size ? strtol(remaining.start, NULL, 10) : 1;

    /* use X-Ratelimit-Reset-After if available, otherwise use
     * X-Ratelimit-Reset */
    if (reset_after.size) {
      struct sized_buffer global =
        ua_info_header_get(info, "x-ratelimit-global");
      u64_unix_ms_t reset =
        cee_timestamp_ms() + 1000 * strtod(reset_after.start, NULL);

      if (global.size) {
        /* lock all buckets */
        pthread_rwlock_wrlock(&ratelimit->rwlock);
        ratelimit->global = reset;
        pthread_rwlock_unlock(&ratelimit->rwlock);
      }
      else {
        /* lock single bucket */
        b->reset_tstamp = reset;
      }
    }
    else if (reset.size) {
      /* calculate the reset time with Discord's date header */
      struct sized_buffer date = ua_info_header_get(info, "date");
      u64_unix_ms_t server = 1000 * curl_getdate(date.start, NULL);
      u64_unix_ms_t offset;
      struct PsnipClockTimespec ts;

      psnip_clock_wall_get_time(&ts);
      offset = server + ts.nanoseconds / 1000000;
      b->reset_tstamp =
        cee_timestamp_ms() + 1000 * strtod(reset.start, NULL) - offset;
    }

    logconf_info(&ratelimit->conf,
                 "[%.4s] Reset = %" PRIu64 " ; Remaining = %d", b->hash,
                 b->reset_tstamp, b->remaining);

    b->update_tstamp = info->req_tstamp;
  }
}

/* Attempt to build and/or update bucket's rate limiting information. */
void
discord_bucket_build(struct discord_ratelimit *ratelimit,
                     struct discord_bucket *b,
                     const char route[],
                     ORCAcode code,
                     struct ua_info *info)
{
  /* undefined bucket means first time using this route.  attempt to
   *  establish a route between it and a bucket via its unique hash
   *  (will create a new bucket if it can't establish a route) */
  if (b == ratelimit->undefined) {
    struct sized_buffer hash = ua_info_header_get(info, "x-ratelimit-bucket");
    char _hash[64] = "null";
    if (!hash.size) strncpy(_hash, hash.start, hash.size);
    b = _discord_bucket_init(ratelimit, _hash, route);
  }
  /* update the bucket rate limit values */
  _discord_bucket_populate(ratelimit, b, code, info);
}
