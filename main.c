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
#include "app_pin.h"
#include "app_ctap1.h"
#include "app_hidif.h"

/* ****************************************************************************************************************** */
#include "fidodef.h"
#include "app_misc.h"
#include "mbedtls/md.h"
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
    pin_init();
    ctap1_init();
    hidif_init();


//    uint8_t seed[32];
//    uint8_t data[64];
//    uint8_t hash1[32];
//    uint8_t hash2[32];
//
//    for (int8_t i = 0; i < 32; i++)
//        seed[i] = 1 + i;
//    for (int8_t i = 0; i < 64; i++)
//        data[i] = 40 + i;
//
//    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
//    mbedtls_md_context_t    md_ctx;
//    mbedtls_md_init(&md_ctx);
//    mbedtls_md_setup(&md_ctx, md_info, 1);
//
//    mbedtls_md_hmac_starts(&md_ctx, seed, 32);
//    mbedtls_md_hmac_update(&md_ctx, data, 32);
//    mbedtls_md_hmac_update(&md_ctx, data + 32, 32);
//    mbedtls_md_hmac_finish(&md_ctx, hash1);
//
//    mbedtls_md_hmac(md_info, seed, 32, data, 64, hash2);

    uint8_t pub_x[32];
    uint8_t pub_y[32];
    uint8_t shared_secret[32];

    make_secp256r1_public_key(device_get_auth()->key_agreement_pri_, pub_x, pub_y);
    get_authenticator_secret(pub_x, pub_y, shared_secret);



    while (1)
        worker_exec();

    return 0;
}

/* end of file ****************************************************************************************************** */
