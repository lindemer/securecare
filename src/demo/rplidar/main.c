/**
 * Copyright (c) 2020, RISE Research Institutes of Sweden AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 **/

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "app_uart.h"
#include "app_error.h"
#include "nrf_delay.h"
#include "nrf_gpio.h"
#include "rplidar.h"
#include "nrf.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
#include "boards.h"
#if defined (UART_PRESENT)
#include "nrf_uart.h"
#endif
#if defined (UARTE_PRESENT)
#include "nrf_uarte.h"
#endif

// Thingy:91 GPIO pins
#define SPARE1 NRF_GPIO_PIN_MAP(0, 6)
#define SPARE2 NRF_GPIO_PIN_MAP(0, 5)
#define SPARE3 NRF_GPIO_PIN_MAP(0, 26)
#define SPARE4 NRF_GPIO_PIN_MAP(0, 27)

#define UART_TX_BUF_SIZE 256
#define UART_RX_BUF_SIZE 256

void uart_error_handle(app_uart_evt_t * p_event)
{
    if (p_event->evt_type == APP_UART_COMMUNICATION_ERROR)
    {
        APP_ERROR_HANDLER(p_event->data.error_communication);
    }
    else if (p_event->evt_type == APP_UART_FIFO_ERROR)
    {
        APP_ERROR_HANDLER(p_event->data.error_code);
    }
}

int main(void)
{
    uint32_t err_code;
    err_code = NRF_LOG_INIT(NULL);
    APP_ERROR_CHECK(err_code);

    NRF_LOG_DEFAULT_BACKENDS_INIT();

    NRF_LOG_INFO("main()");

    const app_uart_comm_params_t comm_params =
    {
        SPARE4, SPARE3,  
        RTS_PIN_NUMBER,
        CTS_PIN_NUMBER,
        APP_UART_FLOW_CONTROL_DISABLED,
        false,
#ifdef UART_PRESENT
        NRF_UART_BAUDRATE_115200
#else
        NRF_UARTE_BAUDRATE_115200
#endif // UART_PRESENT
    };

    APP_UART_FIFO_INIT(&comm_params,
                       UART_RX_BUF_SIZE,
                       UART_TX_BUF_SIZE,
                       uart_error_handle,
                       APP_IRQ_PRIORITY_LOWEST,
                       err_code);
    APP_ERROR_CHECK(err_code);

    rplidar_response_device_info_t info;
    err_code = rplidar_get_device_info(&info);
    APP_ERROR_CHECK(err_code);

    rplidar_response_device_health_t health;
    err_code = rplidar_get_device_health(&health);
    APP_ERROR_CHECK(err_code);

    err_code = rplidar_start_scan(false);
    APP_ERROR_CHECK(err_code);

    nrf_gpio_cfg_output(SPARE2);
    nrf_gpio_pin_set(SPARE2);
    nrf_delay_ms(100);

    int loops = 0;

    rplidar_point_t point;
    rplidar_sweep_t sweep;
    rplidar_init_sweep(&sweep);

    while (true)
    {

        err_code = rplidar_get_point(&point);
        rplidar_push_sweep(&sweep, &point, false);

	if (loops == 1000)
	{
            float mean = rplidar_get_mean(&sweep);
	    NRF_LOG_INFO("%d hits, %d mean", sweep.hits, mean);
            rplidar_clear_sweep(&sweep);
            loops = 0;
	}
        else
        {
            loops++;
        }

	NRF_LOG_PROCESS();

    }
}
