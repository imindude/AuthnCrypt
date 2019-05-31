/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        USB Device
 * *********************************************************************************************************************
 */

#include "usbd_core.h"
#include "usbd_desc.h"
#include "usbd_conf.h"

/* ****************************************************************************************************************** */

#define USBD_VID                        0x31CB
#define USBD_PID                        0xF001
#define USBD_LANGID_STRING              0x0409
#define USBD_MANUFACTURER_STRING        "Copy&Make"
#define USBD_PRODUCT_FS_STRING          "Authn&Crypt"
#define USBD_CONFIGURATION_FS_STRING    "HID Config"
#define USBD_INTERFACE_FS_STRING        "HID Interface"
#define USBD_SIZ_BOS_DESC               0x0C

/* ****************************************************************************************************************** */

#pragma pack(push, 4)

static uint8_t  USBD_DeviceDesc[USB_LEN_DEV_DESC] =
{
        0x12,                       /* bLength */
        USB_DESC_TYPE_DEVICE,       /* bDescriptorType */
        0x00,                       /* bcdUSB */
        0x02,
        0x00,                       /* bDeviceClass */
        0x00,                       /* bDeviceSubClass */
        0x00,                       /* bDeviceProtocol */
        USB_MAX_EP0_SIZE,           /* bMaxPacketSize */
        LOBYTE(USBD_VID),           /* idVendor */
        HIBYTE(USBD_VID),           /* idVendor */
        LOBYTE(USBD_PID),           /* idVendor */
        HIBYTE(USBD_PID),           /* idVendor */
        0x00,                       /* bcdDevice rel. 2.00 */
        0x02,
        USBD_IDX_MFC_STR,           /* Index of manufacturer string */
        USBD_IDX_PRODUCT_STR,       /* Index of product string */
        USBD_IDX_SERIAL_STR,        /* Index of serial number string */
        USBD_MAX_NUM_CONFIGURATION  /* bNumConfigurations */
};

static uint8_t  USBD_LangIDDesc[USB_LEN_LANGID_STR_DESC] =
{
    USB_LEN_LANGID_STR_DESC,
    USB_DESC_TYPE_STRING,
    LOBYTE(USBD_LANGID_STRING),
    HIBYTE(USBD_LANGID_STRING),
};

static uint8_t  USBD_StrDesc[USBD_MAX_STR_DESC_SIZ];

#pragma pack(pop)

static uint8_t  USBD_StringSerial[USBD_MAX_STR_DESC_SIZ] =
{
        USB_SIZ_STRING_SERIAL,
        USB_DESC_TYPE_STRING,
};

/* ****************************************************************************************************************** */

static void int_to_unicode(uint32_t value , uint8_t *pbuf , uint8_t len)
{
    for (uint8_t idx = 0; idx < len; idx ++)
    {
        if ((value >> 28) < 0xA)
            pbuf[2 * idx] = (value >> 28) + '0';
        else
            pbuf[2 * idx] = (value >> 28) + 'A' - 10;

        value <<= 4;
        pbuf[2 * idx + 1] = 0;
    }
}

static void get_serial_no(void)
{
    uint32_t    *uid_base = (uint32_t*)UID_BASE;
    uint32_t    device_serial[3];

    device_serial[0] = uid_base[0];
    device_serial[1] = uid_base[1];
    device_serial[2] = uid_base[2];

    device_serial[0] += device_serial[2];

    if (device_serial[0] != 0)
    {
        int_to_unicode(device_serial[0], &USBD_StringSerial[2], 8);
        int_to_unicode(device_serial[1], &USBD_StringSerial[18], 4);
    }
}

static uint8_t* USBD_FS_DeviceDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    *length = sizeof(USBD_DeviceDesc);
    return (uint8_t*)USBD_DeviceDesc;
}

static uint8_t* USBD_FS_LangIDStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    *length = sizeof(USBD_LangIDDesc);
    return (uint8_t*)USBD_LangIDDesc;
}

static uint8_t* USBD_FS_ProductStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    USBD_GetString((uint8_t*)USBD_PRODUCT_FS_STRING, USBD_StrDesc, length);
    return USBD_StrDesc;
}

static uint8_t* USBD_FS_ManufacturerStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    USBD_GetString((uint8_t*)USBD_MANUFACTURER_STRING, USBD_StrDesc, length);
    return USBD_StrDesc;
}

static uint8_t* USBD_FS_SerialStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    get_serial_no();
    *length = USB_SIZ_STRING_SERIAL;
    return (uint8_t*)USBD_StringSerial;
}

static uint8_t* USBD_FS_ConfigStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    USBD_GetString((uint8_t *)USBD_CONFIGURATION_FS_STRING, USBD_StrDesc, length);
    return USBD_StrDesc;
}

static uint8_t* USBD_FS_InterfaceStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
    USBD_GetString((uint8_t *)USBD_INTERFACE_FS_STRING, USBD_StrDesc, length);
    return USBD_StrDesc;
}

/* ****************************************************************************************************************** */

USBD_DescriptorsTypeDef usbd_fs_desc =
{
        USBD_FS_DeviceDescriptor,
        USBD_FS_LangIDStrDescriptor,
        USBD_FS_ManufacturerStrDescriptor,
        USBD_FS_ProductStrDescriptor,
        USBD_FS_SerialStrDescriptor,
        USBD_FS_ConfigStrDescriptor,
        USBD_FS_InterfaceStrDescriptor,
};

/* end of file ****************************************************************************************************** */
