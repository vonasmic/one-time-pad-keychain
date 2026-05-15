/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    ux_device_cdc_acm.c
  * @author  MCD Application Team
  * @brief   USBX Device applicative file
  ******************************************************************************
    * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "ux_device_cdc_acm.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "ux_api.h"
#include "ux_device_class_cdc_acm.h"
#include <string.h>
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* USER CODE BEGIN PV */
static UX_SLAVE_CLASS_CDC_ACM *s_cdc_acm = UX_NULL;
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
  * @brief  USBD_CDC_ACM_Activate
  *         This function is called when insertion of a CDC ACM device.
  * @param  cdc_acm_instance: Pointer to the cdc acm class instance.
  * @retval none
  */
VOID USBD_CDC_ACM_Activate(VOID *cdc_acm_instance)
{
  /* USER CODE BEGIN USBD_CDC_ACM_Activate */
  s_cdc_acm = (UX_SLAVE_CLASS_CDC_ACM *)cdc_acm_instance;
  /* USER CODE END USBD_CDC_ACM_Activate */

  return;
}

/**
  * @brief  USBD_CDC_ACM_Deactivate
  *         This function is called when extraction of a CDC ACM device.
  * @param  cdc_acm_instance: Pointer to the cdc acm class instance.
  * @retval none
  */
VOID USBD_CDC_ACM_Deactivate(VOID *cdc_acm_instance)
{
  /* USER CODE BEGIN USBD_CDC_ACM_Deactivate */
  UX_PARAMETER_NOT_USED(cdc_acm_instance);
  s_cdc_acm = UX_NULL;
  /* USER CODE END USBD_CDC_ACM_Deactivate */

  return;
}

/**
  * @brief  USBD_CDC_ACM_ParameterChange
  *         This function is invoked to manage the CDC ACM class requests.
  * @param  cdc_acm_instance: Pointer to the cdc acm class instance.
  * @retval none
  */
VOID USBD_CDC_ACM_ParameterChange(VOID *cdc_acm_instance)
{
  /* USER CODE BEGIN USBD_CDC_ACM_ParameterChange */
  UX_PARAMETER_NOT_USED(cdc_acm_instance);
  /* USER CODE END USBD_CDC_ACM_ParameterChange */

  return;
}

/* USER CODE BEGIN 1 */
void USB_CdcHello_Poll(void)
{
  UCHAR rx[32];
  ULONG actual = 0;
  UINT st;

  ux_system_tasks_run();

  if (s_cdc_acm == UX_NULL)
  {
    return;
  }

  st = ux_device_class_cdc_acm_read_run(s_cdc_acm, rx, sizeof(rx), &actual);
  if (st == UX_STATE_NEXT && actual >= 5U && memcmp(rx, "hello", 5) == 0)
  {
    static UCHAR reply[] = "Hello\r\n";
    ULONG wrote = 0;
    UINT ws;

    do
    {
      ux_system_tasks_run();
      ws = ux_device_class_cdc_acm_write_run(s_cdc_acm, reply, sizeof(reply) - 1U, &wrote);
    } while (ws != UX_STATE_NEXT && ws != UX_STATE_ERROR && ws != UX_STATE_EXIT);
  }
}
/* USER CODE END 1 */

/* USER CODE BEGIN 2 */
/* Pull in USBX CDC ACM class sources here so the managed build (USBX/App only) links
   _ux_device_class_cdc_acm_* without relying on Debug makefile regen for linked resources. */
#include "../../../Middlewares/ST/usbx/common/usbx_device_classes/src/ux_device_class_cdc_acm_activate.c"
#include "../../../Middlewares/ST/usbx/common/usbx_device_classes/src/ux_device_class_cdc_acm_bulkin_thread.c"
#include "../../../Middlewares/ST/usbx/common/usbx_device_classes/src/ux_device_class_cdc_acm_bulkout_thread.c"
#include "../../../Middlewares/ST/usbx/common/usbx_device_classes/src/ux_device_class_cdc_acm_control_request.c"
#include "../../../Middlewares/ST/usbx/common/usbx_device_classes/src/ux_device_class_cdc_acm_deactivate.c"
#include "../../../Middlewares/ST/usbx/common/usbx_device_classes/src/ux_device_class_cdc_acm_entry.c"
#include "../../../Middlewares/ST/usbx/common/usbx_device_classes/src/ux_device_class_cdc_acm_initialize.c"
#include "../../../Middlewares/ST/usbx/common/usbx_device_classes/src/ux_device_class_cdc_acm_ioctl.c"
#include "../../../Middlewares/ST/usbx/common/usbx_device_classes/src/ux_device_class_cdc_acm_read.c"
#include "../../../Middlewares/ST/usbx/common/usbx_device_classes/src/ux_device_class_cdc_acm_read_run.c"
#include "../../../Middlewares/ST/usbx/common/usbx_device_classes/src/ux_device_class_cdc_acm_tasks_run.c"
#include "../../../Middlewares/ST/usbx/common/usbx_device_classes/src/ux_device_class_cdc_acm_unitialize.c"
#include "../../../Middlewares/ST/usbx/common/usbx_device_classes/src/ux_device_class_cdc_acm_write.c"
#include "../../../Middlewares/ST/usbx/common/usbx_device_classes/src/ux_device_class_cdc_acm_write_run.c"
#include "../../../Middlewares/ST/usbx/common/usbx_device_classes/src/ux_device_class_cdc_acm_write_with_callback.c"
/* USER CODE END 2 */
