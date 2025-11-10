#include "os.h"
#include "common.h"
#include "hardware.h"
#include "gpio.h"

// Custom HardFault handler to help debug crashes
void HardFault_Handler(void)
{
    OS_PRINTF("\r\n*** HARD FAULT ***\r\n");
    OS_FLUSH();
    
    // Blink LED rapidly to indicate fault
    while(1)
    {
        HW_LED1_ON;
        for(volatile int i=0; i<1000000; i++);
        HW_LED1_OFF;
        for(volatile int i=0; i<1000000; i++);
    }
}

