/**
 * @file work.h
 */

#ifndef WORK_H
#define WORK_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "types.h" /* ORCAcode */

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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* WORK_H */
