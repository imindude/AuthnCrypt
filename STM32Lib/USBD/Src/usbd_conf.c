/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        USB Device
 * *********************************************************************************************************************
 */

#include "stm32f4xx.h"
#include "usbd_core.h"
#include "usbd_hid.h"

/* ****************************************************************************************************************** */

extern PCD_HandleTypeDef    hpcd_usbd_fs;

/* ****************************************************************************************************************** */

void HAL_PCD_SetupStageCallback(PCD_HandleTypeDef *h)
{
    USBD_LL_SetupStage((USBD_HandleTypeDef*)h->pData, (uint8_t*)h->Setup);
}

void HAL_PCD_DataInStageCallback(PCD_HandleTypeDef *h, uint8_t epnum)
{
    USBD_LL_DataInStage((USBD_HandleTypeDef*)h->pData, epnum, h->IN_ep[epnum].xfer_buff);
}

void HAL_PCD_DataOutStageCallback(PCD_HandleTypeDef *h, uint8_t epnum)
{
    USBD_LL_DataOutStage((USBD_HandleTypeDef*)h->pData, epnum, h->OUT_ep[epnum].xfer_buff);
    if (epnum == HID_EPO_ADDR)
        USBD_HID_RecvCallback((USBD_HandleTypeDef*)h->pData, epnum);
}

void HAL_PCD_SOFCallback(PCD_HandleTypeDef *h)
{
    USBD_LL_SOF((USBD_HandleTypeDef*)h->pData);
}

void HAL_PCD_ResetCallback(PCD_HandleTypeDef *h)
{
    USBD_LL_SetSpeed((USBD_HandleTypeDef*)h->pData, USBD_SPEED_FULL);
    USBD_LL_Reset((USBD_HandleTypeDef*)h->pData);
}

void HAL_PCD_ISOOUTIncompleteCallback(PCD_HandleTypeDef *hpcd, uint8_t epnum)
{
    USBD_LL_IsoOUTIncomplete((USBD_HandleTypeDef*) hpcd->pData, epnum);
}

void HAL_PCD_ISOINIncompleteCallback(PCD_HandleTypeDef *h, uint8_t epnum)
{
    USBD_LL_IsoINIncomplete((USBD_HandleTypeDef*)h->pData, epnum);
}

void HAL_PCD_ConnectCallback(PCD_HandleTypeDef *h)
{
    USBD_LL_DevConnected((USBD_HandleTypeDef*)h->pData);
}

void HAL_PCD_DisconnectCallback(PCD_HandleTypeDef *h)
{
    USBD_LL_DevDisconnected((USBD_HandleTypeDef*)h->pData);
}

void HAL_PCD_SuspendCallback(PCD_HandleTypeDef *hh)
{
}

void HAL_PCD_ResumeCallback(PCD_HandleTypeDef *h)
{
}

#if (USBD_LPM_ENABLED == 1)
void HAL_PCDEx_LPM_Callback(PCD_HandleTypeDef *hpcd, PCD_LPM_MsgTypeDef msg)
{
    switch (msg)
    {
    case PCD_LPM_L0_ACTIVE:

        if (hpcd->Init.low_power_enable)
        {
            SystemClock_Config();
            SCB->SCR &= (uint32_t)~((uint32_t)(SCB_SCR_SLEEPDEEP_Msk | SCB_SCR_SLEEPONEXIT_Msk));
        }

        __HAL_PCD_UNGATE_PHYCLOCK(hpcd);
        USBD_LL_Resume(hpcd->pData);

        break;

    case PCD_LPM_L1_ACTIVE:

        __HAL_PCD_GATE_PHYCLOCK(hpcd);
        USBD_LL_Suspend(hpcd->pData);

        if (hpcd->Init.low_power_enable)
        {
            SCB->SCR |= (uint32_t)((uint32_t)(SCB_SCR_SLEEPDEEP_Msk | SCB_SCR_SLEEPONEXIT_Msk));
        }

        break;
    }
}
#endif

/* ****************************************************************************************************************** */

USBD_StatusTypeDef USBD_LL_Init(USBD_HandleTypeDef *pdev)
{
    if (pdev->id == USBD_FS)
    {
        hpcd_usbd_fs.pData = pdev;
        pdev->pData = &hpcd_usbd_fs;

        hpcd_usbd_fs.Instance                     = USB_OTG_FS;
        hpcd_usbd_fs.Init.dev_endpoints           = 4;
        hpcd_usbd_fs.Init.speed                   = PCD_SPEED_FULL;
        hpcd_usbd_fs.Init.dma_enable              = DISABLE;
        hpcd_usbd_fs.Init.ep0_mps                 = DEP0CTL_MPS_64;
        hpcd_usbd_fs.Init.phy_itface              = PCD_PHY_EMBEDDED;
        hpcd_usbd_fs.Init.Sof_enable              = DISABLE;
        hpcd_usbd_fs.Init.low_power_enable        = DISABLE;
        hpcd_usbd_fs.Init.lpm_enable              = DISABLE;
        hpcd_usbd_fs.Init.vbus_sensing_enable     = DISABLE;
        hpcd_usbd_fs.Init.use_dedicated_ep1       = DISABLE;
        hpcd_usbd_fs.Init.battery_charging_enable = DISABLE;

        HAL_PCD_Init(&hpcd_usbd_fs);

        /**
         * real size   : given size * 4 byte
         * max. of sum : 320 => 320 * 4 = 1280 byte
         */
        HAL_PCDEx_SetRxFiFo(&hpcd_usbd_fs, 128);
        HAL_PCDEx_SetTxFiFo(&hpcd_usbd_fs, 0, 64);
        HAL_PCDEx_SetTxFiFo(&hpcd_usbd_fs, 1, 64);
    }

    return USBD_OK;
}

USBD_StatusTypeDef USBD_LL_DeInit(USBD_HandleTypeDef *pdev)
{
    HAL_PCD_DeInit(pdev->pData);
    return USBD_OK;
}

USBD_StatusTypeDef USBD_LL_Start(USBD_HandleTypeDef *pdev)
{
    HAL_PCD_Start(pdev->pData);
    return USBD_OK;
}

USBD_StatusTypeDef USBD_LL_Stop(USBD_HandleTypeDef *pdev)
{
    HAL_PCD_Stop(pdev->pData);
    return USBD_OK;
}

USBD_StatusTypeDef USBD_LL_OpenEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr, uint8_t ep_type, uint16_t ep_mps)
{
    HAL_PCD_EP_Open(pdev->pData, ep_addr, ep_mps, ep_type);
    return USBD_OK;
}

USBD_StatusTypeDef USBD_LL_CloseEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr)
{
    HAL_PCD_EP_Close(pdev->pData, ep_addr);
    return USBD_OK;
}

USBD_StatusTypeDef USBD_LL_FlushEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr)
{
    HAL_PCD_EP_Flush(pdev->pData, ep_addr);
    return USBD_OK;
}

USBD_StatusTypeDef USBD_LL_StallEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr)
{
    HAL_PCD_EP_SetStall(pdev->pData, ep_addr);
    return USBD_OK;
}

USBD_StatusTypeDef USBD_LL_ClearStallEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr)
{
    HAL_PCD_EP_ClrStall(pdev->pData, ep_addr);
    return USBD_OK;
}

uint8_t USBD_LL_IsStallEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr)
{
    PCD_HandleTypeDef *hpcd = (PCD_HandleTypeDef*) pdev->pData;

    if ((ep_addr & 0x80) == 0x80)
    {
        return hpcd->IN_ep[ep_addr & 0x7F].is_stall;
    }
    else
    {
        return hpcd->OUT_ep[ep_addr & 0x7F].is_stall;
    }
}

USBD_StatusTypeDef USBD_LL_SetUSBAddress(USBD_HandleTypeDef *pdev, uint8_t dev_addr)
{
    HAL_PCD_SetAddress(pdev->pData, dev_addr);
    return USBD_OK;
}

USBD_StatusTypeDef USBD_LL_Transmit(USBD_HandleTypeDef *pdev, uint8_t ep_addr, uint8_t *pbuf, uint16_t size)
{
    HAL_PCD_EP_Transmit(pdev->pData, ep_addr, pbuf, size);
    return USBD_OK;
}

USBD_StatusTypeDef USBD_LL_PrepareReceive(USBD_HandleTypeDef *pdev, uint8_t ep_addr, uint8_t *pbuf, uint16_t size)
{
    HAL_PCD_EP_Receive(pdev->pData, ep_addr, pbuf, size);
    return USBD_OK;
}

uint32_t USBD_LL_GetRxDataSize(USBD_HandleTypeDef *pdev, uint8_t ep_addr)
{
    return HAL_PCD_EP_GetRxCount((PCD_HandleTypeDef*)pdev->pData, ep_addr);
}

void USBD_LL_Delay(uint32_t Delay)
{
    HAL_Delay(Delay);
}

/* end of file ****************************************************************************************************** */
