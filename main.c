/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Entry Point
 * *********************************************************************************************************************
 */

#include "stm32f4xx.h"
#include "cnm_worker.h"
#include "app_device.h"
#include "app_status.h"
#include "app_pin.h"
#include "app_ctap1.h"
#include "app_ctap2.h"
#include "app_hidif.h"

/* ****************************************************************************************************************** */

int main(void)
{
    HAL_Init();
    device_init();
    worker_init();
    status_init();
    pin_init();
    ctap1_init();
    ctap2_init();
    hidif_init();

    while (1)
        worker_exec();

    return 0;
}

/* end of file ****************************************************************************************************** */
