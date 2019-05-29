/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Hardware Wrapping Layer
 * *********************************************************************************************************************
 */

#ifndef HWL_FLASH_H
#define HWL_FLASH_H

/* ****************************************************************************************************************** */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* ****************************************************************************************************************** */

void    flash_init(void);
bool    flash_write(uint32_t index, uint8_t *element, uint32_t element_size);
bool    flash_read(uint32_t index, uint8_t *element, uint32_t element_size);
void    flash_erase(void);
bool    flash_backup_write(uint32_t index, uint8_t *element, uint32_t element_size);
bool    flash_backup_read(uint32_t index, uint8_t *element, uint32_t element_size);

/* ****************************************************************************************************************** */

#endif  /* HWL_FLASH_H */

/* end of file ****************************************************************************************************** */
