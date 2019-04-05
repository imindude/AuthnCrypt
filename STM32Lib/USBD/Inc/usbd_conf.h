/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        USB Device
 * *********************************************************************************************************************
 */

#ifndef USBD_CONF_H
#define USBD_CONF_H

/* ****************************************************************************************************************** */

#include "stm32f4xx.h"
#include <stdlib.h>
#include <string.h>

/* ****************************************************************************************************************** */

#define USBD_FS             0

/* Memory management macros */
#define USBD_malloc         malloc
#define USBD_free           free
#define USBD_memset         memset
#define USBD_memcpy         memcpy

#define USBD_UsrLog(...)    do {} while (0)
#define USBD_ErrLog(...)    do {} while (0)
#define USBD_DbgLog(...)    do {} while (0)

/* ****************************************************************************************************************** */

#endif  /* USBD_CONF_H */

/* end of file ****************************************************************************************************** */