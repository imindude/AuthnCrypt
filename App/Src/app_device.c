/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#include "stm32f4xx.h"
#include "app_device.h"
#include "app_def.h"

/* ****************************************************************************************************************** */

static DeviceInfo   _device_info;

/* ****************************************************************************************************************** */

void device_init(void)
{
    uint32_t    *uid_base = (uint32_t*)UID_BASE;

    _device_info.uid_.words_[0] = uid_base[0];
    _device_info.uid_.words_[1] = uid_base[1];
    _device_info.uid_.words_[2] = uid_base[2];

    _device_info.ver_.major_ = VERSION_MAJOR;
    _device_info.ver_.minor_ = VERSION_MINOR;
    _device_info.ver_.build_ = BUILD_NUMBER;

    _device_info.pin_confirmed_ = false;
}

DeviceInfo* device_get_info(void)
{
    return &_device_info;
}

/* end of file ****************************************************************************************************** */
