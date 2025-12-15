/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    Secure/Src/secure_nsc.c
  * @author  MCD Application Team
  * @brief   This file contains the non-secure callable APIs (secure world)
  ******************************************************************************
    * @attention
  *
  * Copyright (c) 2025 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* USER CODE BEGIN Non_Secure_CallLib */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "secure_nsc.h"
/** @addtogroup STM32U5xx_HAL_Examples

  * @{
  */

/** @addtogroup Templates
  * @{
  */

/* Global variables ----------------------------------------------------------*/
void *pSecureFaultCallback = NULL;   /* Pointer to secure fault callback in Non-secure */
void *pSecureErrorCallback = NULL;   /* Pointer to secure error callback in Non-secure */

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/**
  * @brief  Simple LED blink implemented in Secure world.
  *         Uses PA9 as in the minimal test app, toggling with a delay.
  *         Callable from Non-secure via secure veneer.
  */
CMSE_NS_ENTRY void SECURE_LED_Blink(void)
{
  /* Enable GPIOA clock */
  RCC->AHB2ENR1 |= RCC_AHB2ENR1_GPIOAEN;
  (void)RCC->AHB2ENR1; /* Ensure clock is taken into account */

  /* Configure PA9 as output, push-pull, no pull */
  GPIOA->MODER &= ~(3U << (9U * 2U));
  GPIOA->MODER |=  (1U << (9U * 2U));
  GPIOA->OTYPER &= ~(1U << 9U);
  GPIOA->PUPDR  &= ~(3U << (9U * 2U));

  /* One visible on/off toggle */
  GPIOA->BSRR = (1U << 9);          /* Set PA9 */
  for (volatile uint32_t d = 0; d < 400000; d++) { __NOP(); }
  GPIOA->BSRR = (1U << (9 + 16));   /* Reset PA9 */
  for (volatile uint32_t d = 0; d < 400000; d++) { __NOP(); }
}

/**
  * @brief  Secure registration of non-secure callback.
  * @param  CallbackId  callback identifier
  * @param  func        pointer to non-secure function
  * @retval None
  */
    CMSE_NS_ENTRY void SECURE_RegisterCallback(SECURE_CallbackIDTypeDef CallbackId, void *func)
    {
      if(func != NULL)
      {
        switch(CallbackId)
        {
          case SECURE_FAULT_CB_ID:           /* SecureFault Interrupt occurred */
          pSecureFaultCallback = func;
          break;
          case GTZC_ERROR_CB_ID:             /* GTZC Interrupt occurred */
          pSecureErrorCallback = func;
          break;
          default:
          /* unknown */
          break;
        }
      }
    }

/**
  * @}
  */

/**
  * @}
  */
/* USER CODE END Non_Secure_CallLib */

