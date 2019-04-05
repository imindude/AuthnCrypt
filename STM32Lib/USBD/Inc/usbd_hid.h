/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        USB Device
 * *********************************************************************************************************************
 */

#ifndef USBD_HID_H
#define USBD_HID_H

/* ****************************************************************************************************************** */

#include "usbd_ioreq.h"

/* ****************************************************************************************************************** */

#define HID_EPI_ADDR                    0x81U
#define HID_EPO_ADDR                    0x01
#define HID_EPI_SIZE                    USB_FS_MAX_PACKET_SIZE
#define HID_EPO_SIZE                    USB_FS_MAX_PACKET_SIZE

#define USB_HID_CONFIG_DESC_SIZ         41
#define USB_HID_DESC_SIZ                9
#define USB_HID_REPORT_DESC_SIZE        34

#define HID_DESCRIPTOR_TYPE             0x21U
#define HID_REPORT_DESC                 0x22U

#define HID_FS_BINTERVAL                5
#define HID_FS_POLLINGINTERVAL          0x0A

#define HID_REQ_SET_PROTOCOL            0x0B
#define HID_REQ_GET_PROTOCOL            0x03

#define HID_REQ_SET_IDLE                0x0A
#define HID_REQ_GET_IDLE                0x02

#define HID_REQ_SET_REPORT              0x09
#define HID_REQ_GET_REPORT              0x01

typedef enum
{
    HID_IDLE = 0,
    HID_BUSY,
}
HID_StateTypeDef;

typedef struct
{
    uint32_t            Protocol;
    uint32_t            IdleState;
    uint32_t            AltSetting;
    HID_StateTypeDef    state;
}
USBD_HID_HandleTypeDef;

/* ****************************************************************************************************************** */

extern USBD_ClassTypeDef  USBD_HID;
#define USBD_HID_CLASS    &USBD_HID

/* ****************************************************************************************************************** */

uint8_t USBD_HID_SendReport(USBD_HandleTypeDef *pdev, uint8_t *report, uint16_t len);
void    USBD_HID_RecvCallback(USBD_HandleTypeDef *pdev, uint8_t epnum);

/* ****************************************************************************************************************** */

#endif  /* USBD_HID_H */

/* end of file ****************************************************************************************************** */
