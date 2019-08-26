/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        USB Device
 * *********************************************************************************************************************
 */

#include "usbd_hid.h"
#include "usbd_ctlreq.h"
#include "cnm_buffer.h"

/* ****************************************************************************************************************** */

#pragma pack(push, 4)

static uint8_t  USBD_HID_CfgFSDesc[USB_HID_CONFIG_DESC_SIZ] =
{
        0x09,                           /* bLength: Configuration Descriptor size */
        USB_DESC_TYPE_CONFIGURATION,    /* bDescriptorType: Configuration */
        USB_HID_CONFIG_DESC_SIZ, 0x00,  /* wTotalLength: Bytes returned */

        0x01,                           /*bNumInterfaces: 1 interface*/
        0x01,                           /*bConfigurationValue: Configuration value*/
        0x00,                           /*iConfiguration: Index of string descriptor describing the configuration*/
        0x80,                           /*bmAttributes: bus powered and Support Remote Wake-up */
        0xFA,                           /*MaxPower 100 mA: this current is used for detecting Vbus*/

        /* Descriptor of FIDO interface [9] */
        0x09,                           /*bLength: Interface Descriptor size*/
        USB_DESC_TYPE_INTERFACE,        /*bDescriptorType: Interface descriptor type*/
        0x00,                           /*bInterfaceNumber: Number of Interface*/
        0x00,                           /*bAlternateSetting: Alternate setting*/
        0x02,                           /*bNumEndpoints*/
        0x03,                           /*bInterfaceClass: HID*/
        0x00,                           /*bInterfaceSubClass : 1=BOOT, 0=no boot*/
        0x00,                           /*nInterfaceProtocol : 0=none, 1=keyboard, 2=mouse*/
        0,                              /*iInterface: Index of string descriptor*/
        /* Descriptor of FIDO HID [18] */
        0x09,                           /*bLength: HID Descriptor size*/
        HID_DESCRIPTOR_TYPE,            /*bDescriptorType: HID*/
        0x11, 0x01,                     /*bcdHID: HID Class Spec release number*/
        0x00,                           /*bCountryCode: Hardware target country*/
        0x01,                           /*bNumDescriptors: Number of HID class descriptors to follow*/
        0x22,                           /*bDescriptorType*/
        USB_HID_REPORT_DESC_SIZE, 0x00, /*wItemLength: Total length of Report descriptor*/
        /* Descriptor of EPI endpoint [27] */
        0x07,                           /*bLength: Endpoint Descriptor size*/
        USB_DESC_TYPE_ENDPOINT,         /*bDescriptorType:*/
        HID_EPI_ADDR,                   /*bEndpointAddress: Endpoint Address (IN)*/
        0x03,                           /*bmAttributes: Interrupt endpoint*/
        HID_EPI_SIZE, 0x00,             /*wMaxPacketSize: 64 Byte max */
        HID_FS_BINTERVAL,               /*bInterval: Polling Interval */
        /* Descriptor of EPO endpoint [34] */
        0x07,                           /*bLength: Endpoint Descriptor size*/
        USB_DESC_TYPE_ENDPOINT,         /*bDescriptorType:*/
        HID_EPO_ADDR,                   /*bEndpointAddress: Endpoint Address (OUT)*/
        0x03,                           /*bmAttributes: Interrupt endpoint*/
        HID_EPO_SIZE, 0x00,             /*wMaxPacketSize: 64 Byte max */
        HID_FS_BINTERVAL,               /*bInterval: Polling Interval */
};

static uint8_t  USBD_HID_Desc[USB_HID_DESC_SIZ] =
{
        0x09,                           /*bLength: HID Descriptor size*/
        HID_DESCRIPTOR_TYPE,            /*bDescriptorType: HID*/
        0x11, 0x01,                     /*bcdHID: HID Class Spec release number*/
        0x00,                           /*bCountryCode: Hardware target country*/
        0x01,                           /*bNumDescriptors: Number of HID class descriptors to follow*/
        0x22,                           /*bDescriptorType*/
        USB_HID_REPORT_DESC_SIZE, 0x00, /*wItemLength: Total length of Report descriptor*/
};

static uint8_t  USBD_HID_DeviceQualifierDesc[USB_LEN_DEV_QUALIFIER_DESC] =
{
        USB_LEN_DEV_QUALIFIER_DESC,
        USB_DESC_TYPE_DEVICE_QUALIFIER,
        0x00,
        0x02,
        0x00,
        0x00,
        0x00,
        0x40,
        0x01,
        0x00,
};

static uint8_t  USBD_HID_ReportDesc[USB_HID_REPORT_DESC_SIZE] =
{
        0x06, 0xD1, 0xF1,       // USAGE PAGE (FIDO Alliance)
        0x09, 0x01,             // USAGE (U2F Authenticator Device)
        0xA1, 0x01,             // COLLECTION (Application)

        0x09, 0x20,             // USAGE (Input Report Data)
        0x15, 0x00,             // LOGICAL_MININUM (0)
        0x26, 0xFF, 0x00,       // LOGICAL_MAXIMUM (255)
        0x75, 0x08,             // REPORT SIZE (8)
        0x95, HID_EPI_SIZE,     // REPORT COUNT (64)
        0x81, 0x02,             // INPUT (Data, Var, Abs)

        0x09, 0x21,             // USAGE (Output Report Data)
        0x15, 0x00,             // LOGICAL_MININUM (0)
        0x26, 0xFF, 0x00,       // LOGICAL_MAXIMUM (255)
        0x75, 0x08,             // REPORT SIZE (8)
        0x95, HID_EPO_SIZE,     // REPORT COUNT (64)
        0x91, 0x02,             // OUTPUT (Data, Ver, Abs)

        0xC0,                   // END COLLECTION
};

#pragma pack(pop)

static uint8_t  _usbd_hid_rxbuf[HID_EPO_SIZE];

/* ****************************************************************************************************************** */

static uint8_t USBD_HID_Init(USBD_HandleTypeDef *pdev, uint8_t cfgidx)
{
    USBD_LL_OpenEP(pdev, HID_EPI_ADDR, USBD_EP_TYPE_INTR, HID_EPI_SIZE);
    USBD_LL_OpenEP(pdev, HID_EPO_ADDR, USBD_EP_TYPE_INTR, HID_EPO_SIZE);

    pdev->ep_in[HID_EPI_ADDR & 0xFU].is_used = 1U;
    pdev->ep_in[HID_EPO_ADDR & 0xFU].is_used = 1U;

    pdev->pClassData = USBD_malloc(sizeof(USBD_HID_HandleTypeDef));
    if (pdev->pClassData == NULL)
    {
        return USBD_FAIL;
    }

    ((USBD_HID_HandleTypeDef*)pdev->pClassData)->state = HID_IDLE;
    USBD_LL_PrepareReceive(pdev, HID_EPO_ADDR, _usbd_hid_rxbuf, HID_EPO_SIZE);

    return USBD_OK;
}

static uint8_t USBD_HID_DeInit(USBD_HandleTypeDef *pdev, uint8_t cfgidx)
{
    USBD_LL_CloseEP(pdev, HID_EPI_ADDR);
    USBD_LL_CloseEP(pdev, HID_EPO_ADDR);

    pdev->ep_in[HID_EPI_ADDR & 0xFU].is_used = 0U;
    pdev->ep_in[HID_EPO_ADDR & 0xFU].is_used = 0U;

    if(pdev->pClassData != NULL)
    {
        USBD_free(pdev->pClassData);
        pdev->pClassData = NULL;
    }

    return USBD_OK;
}

static uint8_t USBD_HID_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req)
{
    USBD_HID_HandleTypeDef  *hhid = (USBD_HID_HandleTypeDef*) pdev->pClassData;
    USBD_StatusTypeDef      ret = USBD_OK;
    uint16_t    len = 0U;
    uint8_t     *pbuf = NULL;
    uint16_t    status_info = 0U;

    switch (req->bmRequest & USB_REQ_TYPE_MASK)
    {
    case USB_REQ_TYPE_CLASS :

        switch (req->bRequest)
        {
        case HID_REQ_SET_PROTOCOL:
            hhid->Protocol = (uint8_t)(req->wValue);
            break;
        case HID_REQ_GET_PROTOCOL:
            USBD_CtlSendData(pdev, (uint8_t*)&hhid->Protocol, 1U);
            break;
        case HID_REQ_SET_IDLE:
            hhid->IdleState = (uint8_t)(req->wValue >> 8);
            break;
        case HID_REQ_GET_IDLE:
            USBD_CtlSendData(pdev, (uint8_t*)&hhid->IdleState, 1U);
            break;
        default:
            USBD_CtlError(pdev, req);
            ret = USBD_FAIL;
            break;
        }

        break;

    case USB_REQ_TYPE_STANDARD:

        switch (req->bRequest)
        {
        case USB_REQ_GET_STATUS:
            if (pdev->dev_state == USBD_STATE_CONFIGURED)
            {
                USBD_CtlSendData (pdev, (uint8_t*)&status_info, 2U);
            }
            else
            {
                USBD_CtlError(pdev, req);
                ret = USBD_FAIL;
            }
            break;
        case USB_REQ_GET_DESCRIPTOR:
            if(req->wValue >> 8 == HID_REPORT_DESC)
            {
                len = MIN(USB_HID_REPORT_DESC_SIZE , req->wLength);
                pbuf = USBD_HID_ReportDesc;
            }
            else if(req->wValue >> 8 == HID_DESCRIPTOR_TYPE)
            {
                pbuf = USBD_HID_Desc;
                len = MIN(USB_HID_DESC_SIZ, req->wLength);
            }
            else
            {
                USBD_CtlError(pdev, req);
                ret = USBD_FAIL;
                break;
            }
            USBD_CtlSendData(pdev, pbuf, len);
            break;
        case USB_REQ_GET_INTERFACE :
            if (pdev->dev_state == USBD_STATE_CONFIGURED)
            {
                USBD_CtlSendData(pdev, (uint8_t*)&hhid->AltSetting, 1U);
            }
            else
            {
                USBD_CtlError(pdev, req);
                ret = USBD_FAIL;
            }
            break;
        case USB_REQ_SET_INTERFACE :
            if (pdev->dev_state == USBD_STATE_CONFIGURED)
            {
                hhid->AltSetting = (uint8_t)(req->wValue);
            }
            else
            {
                USBD_CtlError(pdev, req);
                ret = USBD_FAIL;
            }
            break;
        default:
            USBD_CtlError(pdev, req);
            ret = USBD_FAIL;
            break;
        }

        break;

    default:

        USBD_CtlError(pdev, req);
        ret = USBD_FAIL;
        break;
  }

  return ret;
}

static uint8_t *USBD_HID_GetFSCfgDesc(uint16_t *length)
{
    *length = sizeof(USBD_HID_CfgFSDesc);
    return USBD_HID_CfgFSDesc;
}

static uint8_t *USBD_HID_GetHSCfgDesc(uint16_t *length)
{
    *length = sizeof (USBD_HID_CfgFSDesc);
    return USBD_HID_CfgFSDesc;
}

static uint8_t *USBD_HID_GetOtherSpeedCfgDesc(uint16_t *length)
{
    *length = sizeof (USBD_HID_CfgFSDesc);
    return USBD_HID_CfgFSDesc;
}

static uint8_t USBD_HID_DataIn(USBD_HandleTypeDef *pdev, uint8_t epnum)
{
    ((USBD_HID_HandleTypeDef*)pdev->pClassData)->state = HID_IDLE;
    return USBD_OK;
}

static uint8_t USBD_HID_DataOut(USBD_HandleTypeDef *pdev, uint8_t epnum)
{
    ((USBD_HID_HandleTypeDef*)pdev->pClassData)->state = HID_IDLE;
    return USBD_OK;
}

static uint8_t  *USBD_HID_GetDeviceQualifierDesc (uint16_t *length)
{
    *length = sizeof(USBD_HID_DeviceQualifierDesc);
    return USBD_HID_DeviceQualifierDesc;
}

uint8_t USBD_HID_SendReport(USBD_HandleTypeDef *pdev, uint8_t *report, uint16_t len)
{
    if (pdev->dev_state == USBD_STATE_CONFIGURED)
    {
        USBD_HID_HandleTypeDef  *h = (USBD_HID_HandleTypeDef*)pdev->pClassData;

        if (h->state == HID_IDLE)
        {
            h->state = HID_BUSY;
            return USBD_LL_Transmit(pdev, HID_EPI_ADDR, report, len);
        }
    }

    return USBD_BUSY;
}

void USBD_HID_RecvCallback(USBD_HandleTypeDef *pdev, uint8_t epnum)
{
    bf_usbhid.push(_usbd_hid_rxbuf);
    memset(_usbd_hid_rxbuf, 0, HID_EPO_SIZE);
    USBD_LL_PrepareReceive(pdev, HID_EPO_ADDR, _usbd_hid_rxbuf, HID_EPO_SIZE);
}

/* ****************************************************************************************************************** */

USBD_ClassTypeDef   USBD_HID =
{
        USBD_HID_Init,
        USBD_HID_DeInit,
        USBD_HID_Setup,
        NULL,               /*EP0_TxSent*/
        NULL,               /*EP0_RxReady*/
        USBD_HID_DataIn,    /*DataIn*/
        USBD_HID_DataOut,   /*DataOut*/
        NULL,               /*SOF */
        NULL,
        NULL,
        USBD_HID_GetHSCfgDesc,
        USBD_HID_GetFSCfgDesc,
        USBD_HID_GetOtherSpeedCfgDesc,
        USBD_HID_GetDeviceQualifierDesc,
};

/* end of file ****************************************************************************************************** */
