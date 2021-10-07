/* See:
https://discord.com/developers/docs/topics/rate-limits#rate-limits */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "discord.h"
#include "discord-internal.h"

#include "cee-utils.h"


static struct discord_bucket*
bucket_init(struct sized_buffer *hash, const char route[])
{
  struct discord_bucket *new_bucket = calloc(1, sizeof *new_bucket);
  int ret = snprintf(new_bucket->hash, sizeof(new_bucket->hash), "%.*s", (int)hash->size, hash->start);
  ASSERT_S(ret < sizeof(new_bucket->hash), "Out of bounds write attempt");
  ret = snprintf(new_bucket->route, sizeof(new_bucket->route), "%s", route);
  ASSERT_S(ret < sizeof(new_bucket->route), "Out of bounds write attempt");
  if (pthread_mutex_init(&new_bucket->lock, NULL))
    ERR("Couldn't initialize pthread mutex");
  if (pthread_cond_init(&new_bucket->cond, NULL))
    ERR("Couldn't initialize pthread cond");

  return new_bucket;
}

static void
bucket_cleanup(struct discord_bucket *bucket) 
{
  pthread_mutex_destroy(&bucket->lock);
  pthread_cond_destroy(&bucket->cond);
  free(bucket);
}

/* clean routes and buckets */
void
discord_buckets_cleanup(struct discord_adapter *adapter)
{ 
  struct discord_bucket *bucket, *tmp;
  HASH_ITER(hh, adapter->ratelimit->buckets, bucket, tmp) {
    HASH_DEL(adapter->ratelimit->buckets, bucket);
    bucket_cleanup(bucket);
  }
}

/* sleep cooldown for a connection within this bucket in milliseconds */
void
discord_bucket_try_cooldown(struct discord_adapter *adapter, struct discord_bucket *bucket)
{
  if (!bucket) return;

  pthread_mutex_lock(&bucket->lock);
  ++bucket->busy;

  /* wait for a while if busy requests reach threshold */
  /** @todo? add pthread_broadcast() to avoid zombie threads */
  while (bucket->busy > bucket->remaining) {
    logconf_debug(&adapter->ratelimit->conf, 
      "[%.4s] Reach bucket's 'Remaining' threshold (%d)\n"
      "Transfer locked in queue.", 
      bucket->hash, bucket->remaining);

    /* wait for pthread_cond_signal() from parse_ratelimits() */
    pthread_cond_wait(&bucket->cond, &bucket->lock);

    logconf_debug(&adapter->ratelimit->conf, 
      "[%.4s] Transfer unlocked from queue", bucket->hash);
  }
  if (bucket->remaining > 1) {
    --bucket->remaining;
    logconf_debug(&adapter->ratelimit->conf,
      "[%.4s] %d remaining transfers before cooldown", bucket->hash, bucket->remaining);
    pthread_mutex_unlock(&bucket->lock);
    return; /* EARLY RETURN */
  }

  u64_unix_ms_t curr_tstamp = cee_timestamp_ms();
  int64_t delay_ms = (int64_t)(bucket->reset_tstamp - curr_tstamp);
  if (delay_ms <= 0) { /*no delay needed */
    logconf_debug(&adapter->ratelimit->conf,
      "[%.4s] Skipping cooldown because current timestamp"
      " exceeds bucket reset timestamp\n\t"
      "Reset At:\t%"PRIu64"\n\t"
      "Current:\t%"PRIu64"\n\t"
      "Delay:\t\t%"PRId64" ms", 
      bucket->hash, bucket->reset_tstamp, curr_tstamp, delay_ms);
    pthread_mutex_unlock(&bucket->lock);
    return; /* EARLY RETURN */
  }

  if (delay_ms > bucket->reset_after_ms) /*don't delay excessively */
    delay_ms = bucket->reset_after_ms;

  logconf_info(&adapter->ratelimit->conf,
    "[%.4s] RATELIMITING (wait %"PRId64" ms)", bucket->hash, delay_ms);

  cee_sleep_ms(delay_ms); /*sleep for delay amount (if any) */

  pthread_mutex_unlock(&bucket->lock);
}

/* attempt to find a bucket associated with this route */
struct discord_bucket*
discord_bucket_try_get(struct discord_adapter *adapter, const char route[]) 
{
  logconf_debug(&adapter->ratelimit->conf,
    "[?] Attempt to find matching bucket for route '%s'", route);
  struct discord_bucket *bucket;
  HASH_FIND_STR(adapter->ratelimit->buckets, route, bucket);
  if (!bucket)
    logconf_debug(&adapter->ratelimit->conf,
      "[?] Couldn't match bucket to route '%s', will attempt to create a new one", route);
  else
    logconf_debug(&adapter->ratelimit->conf,
      "[%.4s] Found a match!", bucket->hash);

  return bucket;
}

/* attempt to parse rate limit's header fields to the bucket
 *  linked with the connection which was performed */
static void
parse_ratelimits(struct discord_adapter *adapter, struct discord_bucket *bucket, ORCAcode code, struct ua_info *info)
{ 
  pthread_mutex_lock(&bucket->lock);

  if (code != ORCA_OK) {
    logconf_debug(&adapter->ratelimit->conf, "[%.4s] Request failed", bucket->hash);
  }
  else if (bucket->update_tstamp <= info->req_tstamp) {
    bucket->update_tstamp = info->req_tstamp;

    struct sized_buffer value; /* fetch header value as string */
    value = ua_info_respheader_field(info, "x-ratelimit-reset");
    if (value.size) bucket->reset_tstamp = 1000 * strtod(value.start, NULL);
    value = ua_info_respheader_field(info, "x-ratelimit-remaining");
    if (value.size) bucket->remaining = strtol(value.start, NULL, 10);
    value = ua_info_respheader_field(info, "x-ratelimit-reset-after");
    if (value.size) bucket->reset_after_ms = 1000 * strtod(value.start, NULL);

    logconf_info(&adapter->ratelimit->conf,
      "[%.4s] Reset-Timestamp = %"PRIu64" ; Remaining = %d ; Reset-After = %"PRId64" ms",
      bucket->hash, bucket->reset_tstamp, bucket->remaining, bucket->reset_after_ms);
  }

  --bucket->busy;
  pthread_cond_signal(&bucket->cond);
  pthread_mutex_unlock(&bucket->lock);
}

/* Attempt to find/link a route between route and a client bucket by
 *  comparing the hash retrieved from response header with discovered
 *  buckets hashes
 * If no match is found then a new bucket is created and linked to the
 *  route*/
static void
match_route(struct discord_adapter *adapter, const char route[], ORCAcode code, struct ua_info *info)
{
  struct sized_buffer hash = ua_info_respheader_field(info, "x-ratelimit-bucket");
  if (!hash.size) {
    logconf_debug(&adapter->ratelimit->conf,
      "[?] Missing bucket-hash from response header,"
      " route '%s' can't be assigned to a bucket", route);
    return;
  }

  struct discord_bucket *bucket=NULL, *iter, *tmp;
  /*attempt to match hash to client bucket hashes */
  HASH_ITER(hh, adapter->ratelimit->buckets, iter, tmp) {
    if (STRNEQ(iter->hash, hash.start, hash.size)) {
      bucket = iter;
      break;
    }
  }
  if (!bucket) bucket = bucket_init(&hash, route);

  /*assign new route and update bucket ratelimit fields */
  logconf_debug(&adapter->ratelimit->conf,
    "[%.4s] Assign new route '%s' to bucket", bucket->hash, bucket->route);
  HASH_ADD_STR(adapter->ratelimit->buckets, route, bucket);
  parse_ratelimits(adapter, bucket, code, info);
}

/* Attempt to build and/or update bucket's rate limiting information. */
void
discord_bucket_build(struct discord_adapter *adapter, struct discord_bucket *bucket, const char route[], ORCAcode code, struct ua_info *info)
{
  /* no bucket means first time using this route.  attempt to 
   *  establish a route between it and a bucket via its unique hash 
   *  (will create a new bucket if it can't establish a route) */
  if (!bucket)
    match_route(adapter, route, code, info);
  else /* update the bucket rate limit values */
    parse_ratelimits(adapter, bucket, code, info);
}
