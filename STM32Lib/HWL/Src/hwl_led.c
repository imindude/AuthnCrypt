/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Hardware Wrapping Layer
 * *********************************************************************************************************************
 */

#include "stm32f4xx.h"
#include "hwl_led.h"

/* ****************************************************************************************************************** */

extern TIM_HandleTypeDef    htim4;

/* ****************************************************************************************************************** */

#define LED_FREQ_HZ         100
#define LED_RED_CHANNEL     TIM_CHANNEL_3
#define LED_BLUE_CHANNEL    TIM_CHANNEL_4

/* ****************************************************************************************************************** */

void led_init(void)
{
    uint32_t    clock_hz = HAL_RCC_GetPCLK1Freq() * 2;
    uint32_t    prescalar = 1;

    while (((clock_hz / prescalar) / LED_FREQ_HZ) > 0xFFFF)
        prescalar++;

    clock_hz /= prescalar;

    htim4.Init.Prescaler = prescalar - 1;
    htim4.Init.Period    = (clock_hz / LED_FREQ_HZ) - 1;

    HAL_TIM_OC_Init(&htim4);

    TIM_MasterConfigTypeDef master_config_param =
    {
            .MasterOutputTrigger = TIM_TRGO_RESET,
            .MasterSlaveMode     = TIM_MASTERSLAVEMODE_DISABLE,
    };
    TIM_OC_InitTypeDef      oc_init_param =
    {
            .OCMode     = TIM_OCMODE_PWM1,
            .Pulse      = 0,
            .OCPolarity = TIM_OCPOLARITY_HIGH,
            .OCFastMode = TIM_OCFAST_ENABLE,
    };

    HAL_TIMEx_MasterConfigSynchronization(&htim4, &master_config_param);
    HAL_TIM_OC_ConfigChannel(&htim4, &oc_init_param, LED_RED_CHANNEL);
    HAL_TIM_OC_ConfigChannel(&htim4, &oc_init_param, LED_BLUE_CHANNEL);
    HAL_TIM_OC_Start(&htim4, LED_RED_CHANNEL);
    HAL_TIM_OC_Start(&htim4, LED_BLUE_CHANNEL);
}

void led_red(uint8_t brightness_percent)
{
    uint32_t    period = (uint32_t)((float)(htim4.Init.Period + 1) * ((float)brightness_percent / 100.0f));

    __HAL_TIM_SET_COMPARE(&htim4, LED_RED_CHANNEL, period);
}

void led_blue(uint8_t brightness_percent)
{
    uint32_t    period = (uint32_t)((float)(htim4.Init.Period + 1) * ((float)brightness_percent / 100.0f));

    __HAL_TIM_SET_COMPARE(&htim4, LED_BLUE_CHANNEL, period);
}

/* end of file ****************************************************************************************************** */
