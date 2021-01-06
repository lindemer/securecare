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

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "app_scheduler.h"
#include "app_util.h"
#include "app_timer.h"
#include "boards.h"
#include "bsp_thread.h"
#include "nrf_delay.h"
#include "mem_manager.h"
#include "nrf_assert.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
#include "sdk_config.h"
#include "nrf_dfu_utils.h"
#include "coaps_dfu.h"
#include "background_dfu_state.h"
#include "thread_utils.h"
#include "project-conf.h"
/*
 * Lidar
 */
#include "app_uart.h"
#include "rplidar.h"


#if defined (UART_PRESENT)
#include "nrf_uart.h"
#elif defined (UARTE_PRESENT)
#include "nrf_uarte.h"
#endif

// Thingy:91 GPIO pins
#define SPARE1 NRF_GPIO_PIN_MAP(0, 6)
#define SPARE2 NRF_GPIO_PIN_MAP(0, 5)
#define SPARE3 NRF_GPIO_PIN_MAP(0, 26)
#define SPARE4 NRF_GPIO_PIN_MAP(0, 27)

#define UART_TX_BUF_SIZE 256
#define UART_RX_BUF_SIZE 256

/*
 * Sensor data container
 */
rplidar_sweep_t global_sweep;
int lidar_is_running = 0;
int loop = 0;
#define LOOP_THRESHOLD 1000
/*
 * Lidar stuff
 */

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


/***************************************************************************************************
 * @section init_lidar
 **************************************************************************************************/

void init_lidar() {

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

  uint32_t err_code;
  APP_UART_FIFO_INIT(&comm_params,
                     UART_RX_BUF_SIZE,
                     UART_TX_BUF_SIZE,
                     uart_error_handle,
                     APP_IRQ_PRIORITY_LOWEST,
                     err_code);
  //APP_ERROR_CHECK(err_code);
  
  rplidar_response_device_info_t info;
  err_code = rplidar_get_device_info(&info);
  //APP_ERROR_CHECK(err_code);

  rplidar_response_device_health_t health;
  err_code = rplidar_get_device_health(&health);
  //APP_ERROR_CHECK(err_code);

  err_code = rplidar_start_scan(false);
  //APP_ERROR_CHECK(err_code);
  NRF_LOG_INFO("err_code %d", err_code);

  nrf_gpio_cfg_output(SPARE2);
  nrf_gpio_pin_set(SPARE2);
  nrf_delay_ms(100);

  rplidar_init_sweep(&global_sweep);
  lidar_is_running = 1;

}

/***************************************************************************************************
 * @section lidar stop
 **************************************************************************************************/
void stop_lidar() {
  lidar_is_running = 0;
  rplidar_stop_scan();

}

/***************************************************************************************************
 * @section lidar status
 **************************************************************************************************/
inline int lidar_active() {
  return lidar_is_running;
}

/***************************************************************************************************
 * @section lidar update if active
 **************************************************************************************************/
int lidar_update() {
  if(lidar_is_running) {
    rplidar_point_t point;
    rplidar_get_point(&point);
    //NRF_LOG_INFO("deg=%d, mm %d", point.deg, point.mm);
    rplidar_push_sweep(&global_sweep, &point, false);
    return 0;
  }
  return -1;
}

int lidar_get_data(uint32_t *mean, uint32_t *hits, uint32_t *readings) {
  *mean = rplidar_get_mean(&global_sweep);
  *hits = global_sweep.hits;
  *readings = global_sweep.readings;
  rplidar_clear_sweep(&global_sweep);
  return 0;
}

