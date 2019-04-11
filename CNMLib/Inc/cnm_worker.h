/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Copy & Make Common Library
 * *********************************************************************************************************************
 */

#ifndef CNM_WORKER_H
#define CNM_WORKER_H

#ifdef __cplusplus
extern "C" {
#endif

/* ****************************************************************************************************************** */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* ****************************************************************************************************************** */

//#define WORKER_WITHOUT_WAKEUP

/* ****************************************************************************************************************** */

enum WorkerPrio
{
    _WorkerPrio_Idle_,
    _WorkerPrio_UserLow_,
    _WorkerPrio_UserMid_,
    _WorkerPrio_UserHigh_,
};
typedef enum WorkerPrio     WorkerPrio;

typedef bool    (*WakeupFunc)(uint32_t now_ms, uint32_t wakeup_ms, uint32_t worker_ms, void *param);
typedef void    (*WorkerFunc)(uint32_t now_ms, uint32_t worker_ms, void *param);

/* ****************************************************************************************************************** */

void    worker_init(void);
void    worker_join(WakeupFunc wakeup, WorkerFunc worker, WorkerPrio prio, void *param);
void    worker_exec(void);
int8_t  worker_usage(void);

/* ****************************************************************************************************************** */

#ifdef __cplusplus
}
#endif

#endif  /* CNM_WORKER_H */

/* end of file ****************************************************************************************************** */
