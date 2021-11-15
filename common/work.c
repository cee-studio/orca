#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

#include "work.h"
#include "threadpool.h"
#include "pqueue.h"
#include "debug.h"

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
/** true after threadpool initialization */
static _Bool once;
/** stop listener loop */
static _Bool stop_listener;
/** request thread and optional callback execution thread */
static threadpool_t *tpool;
/** FIFO queue for pending requests and callbacks execution */
static pqueue_t *queue;

static int
_work_pqueue_cmp(pqueue_pri_t next, pqueue_pri_t curr)
{
  return next < curr;
}

static pqueue_pri_t
_work_pqueue_get(void *data)
{
  return ((struct work_task *)data)->pri;
}

static void
_work_pqueue_set(void *data, pqueue_pri_t pri)
{
  ((struct work_task *)data)->pri = pri;
}

static size_t
_work_pqueue_get_pos(void *data)
{
  return ((struct work_task *)data)->pos;
}

static void
_work_pqueue_set_pos(void *data, size_t pos)
{
  ((struct work_task *)data)->pos = pos;
}

ORCAcode
work_global_init(void)
{
  static int nthreads = 0;
  static int queue_size = 0;
  const char *val;
  char *p_end;

  if (once) return ORCA_GLOBAL_INIT;

  /* get threadpool thread amount */
  val = getenv("ORCA_THREADPOOL_SIZE");
  if (val != NULL) {
    nthreads = (int)strtol(val, &p_end, 10);
  }
  if (nthreads < 2 || ERANGE == errno || p_end == val) {
    nthreads = 2;
  }
  /* get threadpool queue size */
  val = getenv("ORCA_THREADPOOL_QUEUE_SIZE");
  if (val != NULL) {
    queue_size = (int)strtol(val, &p_end, 10);
  }
  if (0 == queue_size || ERANGE == errno || p_end == val) {
    queue_size = 8;
  }

  /* initialize FIFO queue for pending requests */
  queue =
    pqueue_init(10, &_work_pqueue_cmp, &_work_pqueue_get, &_work_pqueue_set,
                &_work_pqueue_get_pos, &_work_pqueue_set_pos);

  /* initialize threadpool */
  tpool = threadpool_create(nthreads, queue_size, 0);

  once = 1;

  return ORCA_OK;
}

static void
_work_worker(void *data)
{
  (void)data;
  struct work_task *task;

  while (1) {
    pthread_mutex_lock(&lock);

    if (stop_listener) {
      stop_listener = 0;
      pthread_mutex_unlock(&lock);
      break;
    }
    while (!(task = pqueue_pop(queue))) {
      pthread_cond_wait(&cond, &lock);
    }

    pthread_mutex_unlock(&lock);

    if (task->callback) task->callback(task->data);
  }
}

int
work_run(void (*callback)(void *data), void *data)
{
  return threadpool_add(tpool, callback, data, 0);
}

void
work_loop_start(void)
{
  /* create request's thread */
  int ret = threadpool_add(tpool, &_work_worker, NULL, 0);
  VASSERT_S(0 == ret, "Couldn't create request's thread (code %d)", ret);
}

void
work_loop_stop(void)
{
  pthread_mutex_lock(&lock);
  if (stop_listener) {
    pthread_mutex_unlock(&lock);
    return;
  }
  stop_listener = 1;
  pthread_mutex_unlock(&lock);
}

void
work_loop_emit(struct work_task *task)
{
  /* enqueue callback context */
  pthread_mutex_lock(&lock);
  pqueue_insert(queue, task);
  pthread_cond_signal(&cond);
  pthread_mutex_unlock(&lock);
}

void
work_global_cleanup(void)
{
  /* cleanup thread-pool manager */
  threadpool_destroy(tpool, threadpool_graceful);
  /* cleanup request queue */
  pqueue_free(queue);
  once = 0;
}
