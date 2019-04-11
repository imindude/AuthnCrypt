/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Hardware Wrapping Layer
 * *********************************************************************************************************************
 */

#include "stm32f4xx.h"
#include "hwl_hal.h"

/* ****************************************************************************************************************** */

RNG_HandleTypeDef   hrng =
{
        .Instance = RNG
};
TIM_HandleTypeDef   htim4 =
{
        .Instance = TIM4,
        .Init.Prescaler     = 0,
        .Init.CounterMode   = TIM_COUNTERMODE_UP,
        .Init.Period        = 0,
        .Init.ClockDivision = TIM_CLOCKDIVISION_DIV1
};
PCD_HandleTypeDef   hpcd_usbd_fs;

/* ****************************************************************************************************************** */

static uint32_t _micros_ticks;

/* ****************************************************************************************************************** */

static void init_system_clock(void)
{
    RCC_OscInitTypeDef  osc_init_param =
    {
            .OscillatorType = RCC_OSCILLATORTYPE_HSE,
            .HSEState       = RCC_HSE_ON,
            .PLL.PLLState   = RCC_PLL_ON,
            .PLL.PLLSource  = RCC_PLLSOURCE_HSE,
            .PLL.PLLM       = 4,
            .PLL.PLLN       = 168,
            .PLL.PLLP       = RCC_PLLP_DIV2,
            .PLL.PLLQ       = 7,
    };
    RCC_ClkInitTypeDef  clk_init_param =
    {
            .ClockType      = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2,
            .SYSCLKSource   = RCC_SYSCLKSOURCE_PLLCLK,
            .AHBCLKDivider  = RCC_SYSCLK_DIV1,
            .APB1CLKDivider = RCC_HCLK_DIV4,
            .APB2CLKDivider = RCC_HCLK_DIV2,
    };

    __HAL_RCC_PWR_CLK_ENABLE();
    __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

    HAL_RCC_OscConfig(&osc_init_param);
    HAL_RCC_ClockConfig(&clk_init_param, FLASH_LATENCY_5);

    HAL_SYSTICK_Config(HAL_RCC_GetHCLKFreq() / 1000);
    HAL_SYSTICK_CLKSourceConfig(SYSTICK_CLKSOURCE_HCLK);

    _micros_ticks = HAL_RCC_GetSysClockFreq() / 1000000;
}

uint32_t get_millis(void)
{
    return HAL_GetTick();
}

uint32_t get_micros(void)
{
    volatile uint32_t   now_ticks = SysTick->VAL;   // down counter
    return HAL_GetTick() * 1000 + (1000 - (now_ticks / _micros_ticks));
}

void delay_millis(uint32_t ms)
{
    HAL_Delay(ms);
}

void delay_micros(uint32_t us)
{
    volatile uint32_t   to_us = get_micros() + us;
    while (get_micros() < to_us)
        __asm("nop");
}

/* MSP ************************************************************************************************************** */

void HAL_MspInit(void)
{
    __HAL_RCC_SYSCFG_CLK_ENABLE();
    __HAL_RCC_PWR_CLK_ENABLE();

    HAL_NVIC_SetPriorityGrouping(NVIC_PRIORITYGROUP_4);

    HAL_NVIC_SetPriority(MemoryManagement_IRQn, 0, 0);
    HAL_NVIC_SetPriority(BusFault_IRQn, 0, 0);
    HAL_NVIC_SetPriority(UsageFault_IRQn, 0, 0);
    HAL_NVIC_SetPriority(SVCall_IRQn, 0, 0);
    HAL_NVIC_SetPriority(DebugMonitor_IRQn, 0, 0);
    HAL_NVIC_SetPriority(PendSV_IRQn, 0, 0);
    HAL_NVIC_SetPriority(SysTick_IRQn, 0, 0);

    init_system_clock();
}

void HAL_RNG_MspInit(RNG_HandleTypeDef *h)
{
    if (h->Instance == RNG)
    {
        __HAL_RCC_RNG_CLK_ENABLE();
    }
}

void HAL_TIM_OC_MspInit(TIM_HandleTypeDef *h)
{
    if (h->Instance == TIM4)
    {
        __HAL_RCC_TIM4_CLK_ENABLE();
        __HAL_RCC_GPIOD_CLK_ENABLE();

        /**
         * PD14 : TIM4_CH3
         * PD15 : TIM4_CH4
         */

        GPIO_InitTypeDef gpio_init_param =
        {
                .Pin       = GPIO_PIN_14 | GPIO_PIN_15,
                .Mode      = GPIO_MODE_AF_PP,
                .Pull      = GPIO_NOPULL,
                .Speed     = GPIO_SPEED_FREQ_LOW,
                .Alternate = GPIO_AF2_TIM4,
        };

        HAL_GPIO_Init(GPIOD, &gpio_init_param);
    }
}

void HAL_PCD_MspInit(PCD_HandleTypeDef *h)
{
    if (h->Instance == USB_OTG_FS)
    {
        __HAL_RCC_GPIOA_CLK_ENABLE();

        /**
         * PA9  : USB_OTG_FS_VBUS
         * PA11 : USB_OTG_FS_DM
         * PA12 : USB_OTG_FS_DP
         */

        GPIO_InitTypeDef gpio_init_param =
        {
                .Pin       = GPIO_PIN_12,
                .Mode      = GPIO_MODE_OUTPUT_OD,
                .Pull      = GPIO_NOPULL,
                .Speed     = GPIO_SPEED_FREQ_LOW,
                .Alternate = 0,
        };

        HAL_GPIO_Init(GPIOA, &gpio_init_param);

        /* USB reset */

        HAL_GPIO_WritePin(GPIOA, gpio_init_param.Pin, GPIO_PIN_RESET);
        HAL_Delay(50);
        HAL_GPIO_WritePin(GPIOA, gpio_init_param.Pin, GPIO_PIN_SET);
        HAL_Delay(50);
        HAL_GPIO_DeInit(GPIOA, gpio_init_param.Pin);

        /* USB init */

        gpio_init_param.Pin       = GPIO_PIN_9;
        gpio_init_param.Mode      = GPIO_MODE_INPUT;
        gpio_init_param.Pull      = GPIO_NOPULL;
        gpio_init_param.Speed     = GPIO_SPEED_FREQ_VERY_HIGH;
        gpio_init_param.Alternate = 0;

        HAL_GPIO_Init(GPIOA, &gpio_init_param);

        gpio_init_param.Pin       = GPIO_PIN_11 | GPIO_PIN_12;
        gpio_init_param.Mode      = GPIO_MODE_AF_PP;
        gpio_init_param.Pull      = GPIO_NOPULL;
        gpio_init_param.Speed     = GPIO_SPEED_FREQ_VERY_HIGH;
        gpio_init_param.Alternate = GPIO_AF10_OTG_FS;

        HAL_GPIO_Init(GPIOA, &gpio_init_param);

        __HAL_RCC_USB_OTG_FS_CLK_ENABLE();

        HAL_NVIC_SetPriority(OTG_FS_IRQn, 0, 0);
        HAL_NVIC_EnableIRQ(OTG_FS_IRQn);
    }
}

/* INT ************************************************************************************************************** */

void SysTick_Handler(void)
{
    HAL_IncTick();
}

void OTG_FS_IRQHandler(void)
{
    HAL_PCD_IRQHandler(&hpcd_usbd_fs);
}

/* end of file ****************************************************************************************************** */
