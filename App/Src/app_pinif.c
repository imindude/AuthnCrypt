/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#include <string.h>
#include "app_pinif.h"
#include "app_def.h"
#include "app_hidif.h"
#include "app_device.h"
#include "app_status.h"
#include "hwl_button.h"
#include "cnm_worker.h"
#include "cnm_buffer.h"

/* ****************************************************************************************************************** */

#define PIN_KEEPALIVE_INTERVAL_MS   400
#define PIN_TOUCH_INTERVAL_MS       50
#define PIN_TOUCH_TIMEOUT_MS        5000

#define PIN_DOT_MS              500

#define PIN_DOT_VAL             1
#define PIN_DOOOT_VAL           2

#define PIN_MAX_TOUCHES         6

#pragma pack(push, 1)

struct PinifRequest
{
    uint8_t cla_;
    uint8_t ins_;
    uint8_t p1_;
    uint8_t p2_;
    uint8_t dat_[1];
};
typedef struct PinifRequest     PinifRequest;

#pragma pack(pop)

struct PinifData
{
    uint32_t    cid_;
    uint8_t     command_;
    bool        last_touch_;
    int8_t      n_touch_;
    uint32_t    touch_ms_;
    uint8_t     touches_[PIN_MAX_TOUCHES];
    uint8_t     expected_[PIN_MAX_TOUCHES];
};
typedef struct PinifData    PinifData;

/* ****************************************************************************************************************** */

static PinifData    _pinif_data;

/**
 * TEST
 */
static uint8_t  _pin_buffer[PIN_MAX_TOUCHES] =
{
        PIN_DOT_VAL,
        PIN_DOT_VAL,
        PIN_DOT_VAL,
        PIN_DOOOT_VAL,
        PIN_DOOOT_VAL,
        PIN_DOOOT_VAL
};

/* ****************************************************************************************************************** */

static void append_sw(uint16_t sw)
{
    ba_hidif.add_byte(sw >> 8 & 0xFF);
    ba_hidif.add_byte(sw & 0xFF);
}

static void load_pincode(uint8_t *pin)
{
    /**
     * for test
     */
    for (int8_t i = 0; i < PIN_MAX_TOUCHES; i++)
        pin[i] = _pin_buffer[i];
}

static void save_pincode(uint8_t *pin)
{
    /**
     * for test
     */
    for (int8_t i = 0; i < PIN_MAX_TOUCHES; i++)
        _pin_buffer[i] = pin[i];
}
static void process_term(PinifData *this)
{
    if (ba_hidif.size() > 0)
        hidif_write(this->cid_, HIDIF_PIN, ba_hidif.head(), ba_hidif.size());
    memset(this, 0, sizeof(PinifData));
    status_postman(_AppStatus_Idle_);
}

static bool process_timeout(PinifData *this, uint32_t now_ms)
{
    if ((now_ms - this->touch_ms_) > PIN_TOUCH_TIMEOUT_MS)
    {
        append_sw(PIN_SW_TIMEOUT);
        process_term(this);

        return true;
    }

    return false;
}

static bool process_touch(PinifData *this, uint32_t now_ms)
{
    if (this->last_touch_)
    {
        this->touch_ms_ = now_ms;
        status_manual_led(true);
    }
    else
    {
        status_manual_led(false);

        uint32_t    dt = now_ms - this->touch_ms_;

        this->touches_[this->n_touch_++] = (dt < PIN_DOT_MS) ? PIN_DOT_VAL : PIN_DOOOT_VAL;

        if (this->n_touch_ == PIN_MAX_TOUCHES)
            return true;
    }

    return false;
}

static void process_get(PinifData *this, uint32_t now_ms)
{
    if (process_timeout(this, now_ms))
    {
        append_sw(PIN_SW_TIMEOUT);
        process_term(this);
    }
    else if (process_touch(this, now_ms))
    {
        if (memcmp(this->touches_, this->expected_, PIN_MAX_TOUCHES) == 0)
        {
            device_get_info()->pin_confirmed_ = true;
            append_sw(PIN_SW_CONFIRM);
        }
        else
        {
            device_get_info()->pin_confirmed_ = false;
            append_sw(PIN_SW_VERIFY_FAILED);
        }
        process_term(this);
    }
}

static void process_set(PinifData *this, uint32_t now_ms)
{
    if (process_timeout(this, now_ms))
    {
        append_sw(PIN_SW_TIMEOUT);
        process_term(this);
    }
    else if (process_touch(this, now_ms))
    {
        save_pincode(this->touches_);
        append_sw(PIN_SW_NO_ERROR);
        process_term(this);
    }
}

static bool wakeup_func(uint32_t now_ms, uint32_t wakeup_ms, uint32_t worker_ms, void *param)
{
    PinifData   *this = (PinifData*)param;
    bool    wakeup = false;

    switch (this->command_)
    {
    case PIN_INS_GET:
    case PIN_INS_SET:

        if ((now_ms - wakeup_ms) > PIN_KEEPALIVE_INTERVAL_MS)
        {
//            append_sw(PIN_SW_KEEPALIVE);
//            hidif_write(this->cid_, HIDIF_PIN, ba_hidif.head(), ba_hidif.size());
        }
        else if ((now_ms - worker_ms) > PIN_TOUCH_INTERVAL_MS)
        {
            bool    touched = button_pushed();

            if (this->last_touch_ != touched)
            {
                this->last_touch_ = touched;
                wakeup = true;
            }
        }

        break;

    default:

        // do nothing
        break;
    }

    return wakeup;
}

static void worker_func(uint32_t now_ms, uint32_t worker_ms, void *param)
{
    PinifData   *this = (PinifData*)param;

    if (this->command_ == PIN_INS_GET)
    {
        process_get(this, now_ms);
    }
    else if (this->command_ == PIN_INS_SET)
    {
        process_set(this, now_ms);
    }
    else
    {
        append_sw(PIN_SW_INVALID_PARAM);
        process_term(this);
    }
}

void pinif_init(void)
{
    worker_join(wakeup_func, worker_func, _WorkerPrio_UserMid_, &_pinif_data);
}

void pinif_reset(void)
{
    memset(&_pinif_data, 0, sizeof(PinifData));
}

bool pinif_postman(uint32_t cid, uint8_t *dat, uint16_t len, uint32_t now_ms)
{
    PinifRequest    *request = (PinifRequest*)dat;
    bool    result = false;

    memset(&_pinif_data, 0, sizeof(PinifData));

    if (request->cla_ == PIN_CLASS)
    {
        switch (request->ins_)
        {
        case PIN_INS_GET:

            load_pincode(_pinif_data.expected_);
            if (_pinif_data.expected_[0] != 0)
            {
                status_postman(_AppStatus_ManualLed_);
                _pinif_data.cid_      = cid;
                _pinif_data.command_  = PIN_INS_GET;
                _pinif_data.touch_ms_ = now_ms;
                result = true;
            }
            else
            {
                append_sw(PIN_SW_NOT_SATISFIED);
                process_term(&_pinif_data);
            }
            break;

        case PIN_INS_SET:

            load_pincode(_pinif_data.expected_);
            if ((_pinif_data.expected_[0] == 0) || device_get_info()->pin_confirmed_)
            {
                status_postman(_AppStatus_ManualLed_);
                _pinif_data.cid_      = cid;
                _pinif_data.command_  = PIN_INS_SET;
                _pinif_data.touch_ms_ = now_ms;
                result = true;
            }
            else
            {
                append_sw(PIN_SW_VERIFY_FAILED);
                process_term(&_pinif_data);
            }
            break;

        default:

            append_sw(PIN_SW_INVALID_INS);
            process_term(&_pinif_data);
            break;
        }
    }
    else
    {
        append_sw(PIN_SW_INVALID_CLA);
        process_term(&_pinif_data);
    }

    return result;
}

/* end of file ****************************************************************************************************** */
