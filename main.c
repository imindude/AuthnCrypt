/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Entry Point
 * *********************************************************************************************************************
 */

#include "stm32f4xx.h"
#include "hwl_button.h"
#include "hwl_led.h"
#include "hwl_rng.h"
#include "hwl_hid.h"
#include "cnm_worker.h"
#include "app_device.h"
#include "app_status.h"
#include "app_pinif.h"
#include "app_hidif.h"

/* ****************************************************************************************************************** */

int main(void)
{
    HAL_Init();

    button_init();
    led_init();
    rng_init();
    hid_init();

    worker_init();

    device_init();
    status_init();
    pinif_init();
    hidif_init();

    while (1)
        worker_exec();

    return 0;
}

/* end of file ****************************************************************************************************** */
