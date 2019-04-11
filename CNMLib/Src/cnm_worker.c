/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Copy & Make Common Library
 * *********************************************************************************************************************
 */

#include <stdlib.h>
#include "cnm_worker.h"
#include "cnm_list.h"
#include "hwl_hal.h"

/* ****************************************************************************************************************** */
// IDLE worker
/* ****************************************************************************************************************** */

struct IdleData
{
    uint32_t    last_sec_;
    uint32_t    last_msec_;
    uint32_t    idle_count_;
    int8_t      idle_rate_;
};
typedef struct IdleData     IdleData;

/* ****************************************************************************************************************** */

static IdleData    _idle_data;

/* ****************************************************************************************************************** */

static bool idle_wakeup(uint32_t now_ms, uint32_t wakeup_ms, uint32_t worker_ms, void *param)
{
    return true;
}

static void idle_worker(uint32_t now_ms, uint32_t worker_ms, void *param)
{
    IdleData    *this = (IdleData*)param;

    if (now_ms != this->last_msec_)
    {
        this->last_msec_ = now_ms;
        this->idle_count_++;

        uint32_t    now_s = now_ms / 1000;

        if (this->last_sec_ != now_s)
        {
            this->idle_rate_ = this->idle_count_ * 100 / 1000;
            this->idle_count_ = 0;
            this->last_sec_ = now_s;
        }
    }
}

/* ****************************************************************************************************************** */
// WORKER
/* ****************************************************************************************************************** */

#define MAX_YIELDS      1

struct WorkerContext
{
    list_head   list_;

    WakeupFunc  wakeup_;
    WorkerFunc  worker_;
    void        *param_;
    uint32_t    worker_ms_;
    uint32_t    wakeup_ms_;
    WorkerPrio  prio_;
    int8_t      dyn_prio_;
    int8_t      n_yield_;
};
typedef struct WorkerContext    WorkerContext;

/* ****************************************************************************************************************** */

static list_head    _worker_list;

/* ****************************************************************************************************************** */

static void need_yield(WorkerContext *ctx)
{
    if ((ctx->prio_ != _WorkerPrio_Idle_) && (ctx->n_yield_++ >= MAX_YIELDS))
    {
        ctx->dyn_prio_++;
        ctx->n_yield_ = 0;
    }
}

void worker_init(void)
{
    INIT_LIST_HEAD(&_worker_list);

    worker_join(idle_wakeup, idle_worker, _WorkerPrio_Idle_, &_idle_data);
}

void worker_join(WakeupFunc wakeup, WorkerFunc worker, WorkerPrio prio, void *param)
{
    WorkerContext   *ctx = (WorkerContext*)calloc(1, sizeof(WorkerContext));

    list_add_tail(&ctx->list_, &_worker_list);

    ctx->wakeup_   = wakeup;
    ctx->worker_   = worker;
    ctx->param_    = param;
    ctx->prio_     = prio;
    ctx->dyn_prio_ = prio;
}

void worker_exec(void)
{
    uint32_t        now_ms = get_millis();
    WorkerContext   *choose, *tmp;
    WorkerContext   *select = NULL;

    list_for_each_entry_safe(choose, tmp, &_worker_list, list_)
    {
        /* check wakeup */

        if (choose->wakeup_(now_ms, choose->wakeup_ms_, choose->worker_ms_, choose->param_))
        {
            if (select == NULL)
            {
                select = choose;
            }
            else
            {
                if (choose->dyn_prio_ > select->dyn_prio_)
                {
                    need_yield(select);
                    select = choose;
                }
                else
                {
                    need_yield(choose);
                }
            }
        }

        choose->wakeup_ms_ = now_ms;
    }

    /* exec worker */

    if (select)
    {
        select->worker_(now_ms, select->worker_ms_, select->param_);

        select->dyn_prio_  = select->prio_;
        select->n_yield_   = 0;
        select->worker_ms_ = now_ms;
    }
}

int8_t worker_usage(void)
{
    return _idle_data.idle_rate_;
}

/* end of file ****************************************************************************************************** */
