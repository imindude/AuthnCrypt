/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#include <string.h>
#include "app_status.h"
#include "app_pin.h"
#include "cnm_worker.h"
#include "hwl_led.h"

/* ****************************************************************************************************************** */

struct StatusData
{
    AppStatus   status_;

    /* for BLUE led */

    int8_t   dimming_;
    int8_t   dimming_dir_;
    uint32_t dimming_ms_;

    /* for RED led */

    int8_t   blinky_on_;
    uint32_t blinky_ms_;
};
typedef struct StatusData   StatusData;

/* ****************************************************************************************************************** */

static StatusData   _status_data;

/* ****************************************************************************************************************** */

static bool wakeup_func(uint32_t now_ms, uint32_t wakeup_ms, uint32_t worker_ms, void *param)
{
    return ((worker_ms + 10) <= now_ms) ? true : false;
}

static void worker_func(uint32_t now_ms, uint32_t worker_ms, void *param)
{
    StatusData  *this = (StatusData*)param;

    switch (this->status_)
    {
    case _AppStatus_Idle_:

        if ((now_ms - this->dimming_ms_) >= 10)
        {
            this->dimming_ms_ = now_ms;

            if (this->dimming_ <= 0)
                this->dimming_dir_ = 1;
            else if (this->dimming_ >= 100)
                this->dimming_dir_ = -1;

            if (this->dimming_dir_ > 0)
                this->dimming_++;
            else
                this->dimming_--;
        }

        this->blinky_on_ = 0;
        this->blinky_ms_ = 0;

        break;

    case _AppStatus_Error_:

        if ((now_ms - this->dimming_ms_) >= 10)
        {
            this->dimming_ms_ = now_ms;

            if (this->dimming_ <= 0)
                this->dimming_dir_ = 1;
            else if (this->dimming_ >= 100)
                this->dimming_dir_ = -1;

            if (this->dimming_dir_ > 0)
                this->dimming_++;
            else
                this->dimming_--;
        }

        if ((now_ms - this->blinky_ms_) >= 200)
        {
            this->blinky_ms_ = now_ms;

            if (this->blinky_on_ > 0)
                this->blinky_on_ = 0;
            else
                this->blinky_on_ = 100;
        }

        break;

    case _AppStatus_Busy_:

        if ((now_ms - this->blinky_ms_) >= 200)
        {
            this->blinky_ms_ = now_ms;

            if (this->blinky_on_ > 0)
                this->blinky_on_ = 0;
            else
                this->blinky_on_ = 100;
        }

        this->dimming_     = 0;
        this->dimming_dir_ = 0;
        this->dimming_ms_  = 0;

        break;

    case _AppStatus_ManualLed_:

        if ((now_ms - this->dimming_ms_) >= 10)
        {
            this->dimming_ms_ = now_ms;

            if (this->dimming_ <= 0)
                this->dimming_dir_ = 1;
            else if (this->dimming_ >= 100)
                this->dimming_dir_ = -1;

            if (this->dimming_dir_ > 0)
                this->dimming_ += 10;
            else
                this->dimming_ -= 10;
        }

        break;
    }

    led_blue(this->dimming_);
    led_red(this->blinky_on_);
}

void status_init(void)
{
    worker_join(wakeup_func, worker_func, _WorkerPrio_UserLow_, &_status_data);
}

void status_reset(void)
{
    memset(&_status_data, 0, sizeof(StatusData));
}

bool status_postman(AppStatus status)
{
    memset(&_status_data, 0, sizeof(StatusData));
    _status_data.status_ = status;
    return true;
}

AppStatus status_get(void)
{
    return _status_data.status_;
}

bool status_manual_led(bool on)
{
    if (_status_data.status_ == _AppStatus_ManualLed_)
    {
        _status_data.blinky_on_ = on ? 100 : 0;
        return true;
    }

    return false;
}

/* end of file ****************************************************************************************************** */
