/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Hardware Wrapping Layer
 * *********************************************************************************************************************
 */

#include "stm32f4xx.h"
#include "hwl_button.h"

/* ****************************************************************************************************************** */

#define BUTTON_GPIO     GPIOA
#define BUTTON_PIN      GPIO_PIN_0

/* ****************************************************************************************************************** */

void button_init(void)
{
    __HAL_RCC_GPIOA_CLK_ENABLE();

    GPIO_InitTypeDef    gpio_init_param =
    {
            .Pin       = BUTTON_PIN,
            .Mode      = GPIO_MODE_INPUT,
            .Pull      = GPIO_NOPULL,
            .Speed     = 0,
            .Alternate = 0,
    };

    HAL_GPIO_Init(BUTTON_GPIO, &gpio_init_param);
}

bool button_pushed(void)
{
    return (HAL_GPIO_ReadPin(BUTTON_GPIO, BUTTON_PIN) == GPIO_PIN_SET) ? true : false;
}

/* end of file ****************************************************************************************************** */
