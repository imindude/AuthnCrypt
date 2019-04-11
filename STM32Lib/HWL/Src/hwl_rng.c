/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Hardware Wrapping Layer
 * *********************************************************************************************************************
 */

#include "stm32f4xx.h"
#include "hwl_rng.h"

/* ****************************************************************************************************************** */

extern RNG_HandleTypeDef    hrng;

/* ****************************************************************************************************************** */

void rng_init(void)
{
    HAL_RNG_Init(&hrng);
}

void rng_bytes(uint8_t *dst, uint32_t len)
{
    union
    {
        uint32_t    word_;
        uint8_t     byte_[4];
    }
    digit;
    uint32_t    n = len / 4;
    uint32_t    i;

    for (i = 0; i < n; i++)
    {
        HAL_RNG_GenerateRandomNumber(&hrng, &digit.word_);
        *(uint32_t*)(&dst[4 * i]) = digit.word_;
    }

    n = len % 4;
    if (n > 0)
    {
        HAL_RNG_GenerateRandomNumber(&hrng, &digit.word_);
        for (uint8_t k = 0; k < n; k++)
            dst[i * 4 + k] = digit.byte_[k];
    }
}

void rng_words(uint32_t *dst, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++)
        HAL_RNG_GenerateRandomNumber(&hrng, &dst[i]);
}

/* end of file ****************************************************************************************************** */
