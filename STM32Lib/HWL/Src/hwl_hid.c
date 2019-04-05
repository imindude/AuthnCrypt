/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Hardware Wrapping Layer
 * *********************************************************************************************************************
 */

#include "stm32f4xx.h"
#include "usbd_hid.h"
#include "usbd_desc.h"
#include "hwl_hal.h"
#include "hwl_hid.h"
#include "cnm_buffer.h"

/* ****************************************************************************************************************** */

#define SEND_TIMEOUT_MS         300

/* ****************************************************************************************************************** */

static USBD_HandleTypeDef   _husbd;

/* ****************************************************************************************************************** */

void hid_init(void)
{
    USBD_Init(&_husbd, &usbd_fs_desc, USBD_FS);
    USBD_RegisterClass(&_husbd, &USBD_HID);
    USBD_Start(&_husbd);
}

uint16_t hid_send(uint8_t *dat, uint16_t len)
{
    uint16_t    sent_len = 0;
    uint16_t    act_len;
    uint8_t     report[HID_PACKET_SIZE];
    uint32_t    to_ms;

    while (sent_len < len)
    {
        act_len = len - sent_len;
        if (act_len > HID_PACKET_SIZE)
            act_len = HID_PACKET_SIZE;

        memcpy(report, dat + sent_len, act_len);
        to_ms = get_millis() + SEND_TIMEOUT_MS;

        while (USBD_HID_SendReport(&_husbd, report, act_len) != USBD_OK)
        {
            if (to_ms < get_millis())
                return sent_len;
        }

        sent_len += act_len;
    }

    return sent_len;
}

uint16_t hid_recv(uint8_t *dat, uint16_t len)
{
    uint16_t    read_len = 0;
    uint16_t    act_len;
    uint8_t     report[HID_PACKET_SIZE];

    while (read_len < len)
    {
        if (bf_usbhid.size() > 0)
        {
            act_len = len - read_len;
            if (act_len > HID_PACKET_SIZE)
                act_len = HID_PACKET_SIZE;

            bf_usbhid.take(report);
            memcpy(dat + read_len, report, act_len);
            read_len += act_len;
        }
        else
        {
            break;
        }
    }

    return read_len;
}

bool hid_check_empty(void)
{
    return (bf_usbhid.size() == 0) ? true : false;
}

/* end of file ****************************************************************************************************** */
