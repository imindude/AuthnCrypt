/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#ifndef APP_STATUS_H
#define APP_STATUS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ****************************************************************************************************************** */

#include <stddef.h>
#include <stdbool.h>

/* ****************************************************************************************************************** */

enum AppStatus
{
    _AppStatus_Idle_,
    _AppStatus_Error_,
    _AppStatus_Busy_,
    _AppStatus_ManualLed_
};
typedef enum AppStatus  AppStatus;

/* ****************************************************************************************************************** */

void        status_init(void);
void        status_reset(void);
bool        status_postman(AppStatus status);
AppStatus   status_get(void);
bool        status_manual_led(bool on);

/* ****************************************************************************************************************** */

#ifdef __cplusplus
}
#endif

#endif  /* APP_STATUS_H */

/* end of file ****************************************************************************************************** */
