/**
 * @file work.h
 */

#ifndef WORK_H
#define WORK_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "types.h" /* ORCAcode */

struct work_task {
  /** priority of this callback (0 is highest) */
  unsigned long long pri;
  /** queue'd position of this callback */
  size_t pos;
  /** user arbitrary data */
  void *data;
  /** user callback */
  void (*callback)(void *data);
};

/**
 * @brief Initialize global threadpool and priority queue
 * @return ORCAcode, ORCA_OK means nothing out of the ordinary
 * @warning ORCA_GLOBAL_INIT will be returned if this function is called more
 * than once
 */
ORCAcode work_global_init(void);

/**
 * @brief Cleanup global threadpool and priority queue
 */
void work_global_cleanup(void);

/**
 * @brief Run a callback from a worker thread
 *
 * @param callback user callback to be executed
 * @param data user data to be passed to callback
 * @return 0 if all goes well, negative values in case of error (see
 * threadpool.h for codes)
 */
int work_run(void (*callback)(void *data), void *data);

/**
 * @brief Create a callback loop from a threadpool thread
 * @note this loops forever until work_listener_stop() is called
 */
void work_loop_start(void);

/**
 * @brief Stop the callback loop
 */
void work_loop_stop(void);

/**
 * @brief Enqueue a task to be executed by the callback loop
 * @note the callback loop must have been initialized via work_loop_start()
 */
void work_loop_emit(struct work_task *task);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* WORK_H */
