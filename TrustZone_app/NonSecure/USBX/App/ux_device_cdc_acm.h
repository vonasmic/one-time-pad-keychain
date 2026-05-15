/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    ux_device_cdc_acm.h
  * @author  MCD Application Team
  * @brief   USBX Device CDC ACM interface header
  ******************************************************************************
  */
/* USER CODE END Header */

#ifndef UX_DEVICE_CDC_ACM_H
#define UX_DEVICE_CDC_ACM_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ux_api.h"

VOID USBD_CDC_ACM_Activate(VOID *cdc_acm_instance);
VOID USBD_CDC_ACM_Deactivate(VOID *cdc_acm_instance);
VOID USBD_CDC_ACM_ParameterChange(VOID *cdc_acm_instance);

/* USER CODE BEGIN EFP */

/* USER CODE END EFP */

#ifdef __cplusplus
}
#endif

#endif /* UX_DEVICE_CDC_ACM_H */
