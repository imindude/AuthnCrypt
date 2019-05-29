/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Hardware Wrapping Layer
 * *********************************************************************************************************************
 * @brief       FLASH memory map
 *
 *              Sector  0 : 0x08000000 : 16KB
 *              Sector  1 : 0x08004000 : 16KB
 *              Sector  2 : 0x08008000 : 16KB
 *              Sector  3 : 0x0800C000 : 16KB
 *              Sector  4 : 0x08010000 : 64KB
 *              Sector  5 : 0x08020000 : 128KB
 *              Sector  6 : 0x08040000 : 128KB
 *              Sector  7 : 0x08060000 : 128KB
 *              Sector  8 : 0x08080000 : 128KB
 *              Sector  9 : 0x080A0000 : 128KB
 *              Sector 10 : 0x080C0000 : 128KB
 *              Sector 11 : 0x080E0000 : 128KB
 * *********************************************************************************************************************
 */

#include "stm32f4xx.h"
#include "hwl_flash.h"

/* ****************************************************************************************************************** */

#define FLASH_USER_SECTOR       FLASH_SECTOR_10
#define FLASH_USER_ADDRESS      0x080C0000
#define FLASH_USER_SIZE         (128 * 1024)

#define FLASH_BACKUP_SECTOR     FLASH_SECTOR_11
#define FLASH_BACKUP_ADDRESS    0x080E0000
#define FLASH_BACKUP_SIZE       (128 * 1024)

union FlashWord
{
    uint32_t    word_;
    uint8_t     byte_[4];
};
typedef union FlashWord     FlashWord;

/* ****************************************************************************************************************** */

static bool check_address(uint32_t address, uint32_t element_size)
{
    if ((address >= FLASH_USER_ADDRESS) && (address <= (FLASH_USER_ADDRESS + FLASH_USER_SIZE + element_size)))
        return true;
    return false;
}

static bool program_flash(uint32_t address, uint8_t *element, uint32_t element_size)
{
    FlashWord   *flash_word = (FlashWord*)element;
    uint32_t    written = 0;
    bool        result = true;

    HAL_FLASH_Unlock();

    for (uint32_t i = 0; i < element_size / 4; i++)
    {
        if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, address + written, flash_word[i].word_) != HAL_OK)
        {
            result = false;
            break;
        }

        written += sizeof(flash_word[i].word_);
    }

    if (result)
    {
        for (uint8_t i = 0; i < element_size % 4; i++)
        {
            if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, address + written, element[written]) != HAL_OK)
            {
                result = false;
                break;
            }
            written++;
        }
    }

    HAL_FLASH_Lock();

    return result;
}

static bool read_flash(uint32_t address, uint8_t *element, uint32_t element_size)
{
    FlashWord   *flash_word = (FlashWord*)element;
    uint32_t    read = 0;

    for (uint32_t i = 0; i < element_size / 4; i++)
    {
        flash_word[i].word_ = *(uint32_t*)(address + read);
        read += sizeof(flash_word[i].word_);
    }

    for (uint8_t i = 0; i < element_size % 4; i++)
    {
        element[read] = *(uint8_t*)(address + read);
        read++;
    }

    return true;
}

void flash_init(void)
{
    if (*(uint32_t*)FLASH_BACKUP_ADDRESS != 0xFFFFFFFF)
    {
        FLASH_EraseInitTypeDef  erase_init =
        {
                .TypeErase    = FLASH_TYPEERASE_SECTORS,
                .Banks        = 0,
                .Sector       = FLASH_BACKUP_SECTOR,
                .NbSectors    = 1,
                .VoltageRange = FLASH_VOLTAGE_RANGE_3
        };
        uint32_t    dummy;

        HAL_FLASH_Unlock();
        HAL_FLASHEx_Erase(&erase_init, &dummy);
        HAL_FLASH_Lock();
    }
}

bool flash_write(uint32_t index, uint8_t *element, uint32_t element_size)
{
    uint32_t    address = FLASH_USER_ADDRESS + (element_size * index);

    if (check_address(address, element_size) == false)
        return false;

    return program_flash(address, element, element_size);
}

bool flash_read(uint32_t index, uint8_t *element, uint32_t element_size)
{
    uint32_t    address = FLASH_USER_ADDRESS + (element_size * index);

    if (check_address(address, element_size) == false)
        return false;

    return read_flash(address, element, element_size);
}

void flash_erase(void)
{
    FLASH_EraseInitTypeDef  erase_init =
    {
            .TypeErase    = FLASH_TYPEERASE_SECTORS,
            .Banks        = 0,
            .Sector       = FLASH_USER_SECTOR,
            .NbSectors    = 1,
            .VoltageRange = FLASH_VOLTAGE_RANGE_3
    };
    uint32_t    dummy;

    HAL_FLASH_Unlock();
    HAL_FLASHEx_Erase(&erase_init, &dummy);
    HAL_FLASH_Lock();
}

bool flash_backup_write(uint32_t index, uint8_t *element, uint32_t element_size)
{
    return program_flash(FLASH_BACKUP_ADDRESS + (element_size * index), element, element_size);
}

bool flash_backup_read(uint32_t index, uint8_t *element, uint32_t element_size)
{
    return read_flash(FLASH_BACKUP_ADDRESS + (element_size * index), element, element_size);
}
/* end of file ****************************************************************************************************** */
