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
#include "app_uart.h"
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
#include "rplidar.h"
#ifdef UART_PRESENT
#include "nrf_uart.h"
#endif
#ifdef UARTE_PRESENT
#include "nrf_uarte.h"
#endif
#include "nrf_gpio.h"

#include <openthread/thread.h>
#include <openthread/thread_ftd.h>
#include <openthread/dataset_ftd.h>
#include <openthread/platform/alarm-micro.h>
#include <openthread/platform/alarm-milli.h>

#define ENABLE_COAPS_DFU 
//#define ENABLE_RPLIDAR

// Thingy:91 GPIO pins
#define SPARE1 NRF_GPIO_PIN_MAP(0, 6)
#define SPARE2 NRF_GPIO_PIN_MAP(0, 5)
#define SPARE3 NRF_GPIO_PIN_MAP(0, 26)
#define SPARE4 NRF_GPIO_PIN_MAP(0, 27)

// Maximum number of events in the scheduler queue.
#define SCHED_QUEUE_SIZE 32

// Maximum app_scheduler event size.
#define SCHED_EVENT_DATA_SIZE APP_TIMER_SCHED_EVENT_DATA_SIZE

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

/***************************************************************************************************
 * @section OpenThread DFU configuration
 **************************************************************************************************/

/* Override default network settings with the OpenThread border router defaults. This is for
 * development purposes only. Commissioning should be used to add devices to the network in
 * production use cases.
 */
static uint8_t otbr_channel = 15;

static uint16_t otbr_pan_id = 0x1234;

static uint8_t otbr_ext_pan_id[OT_EXT_PAN_ID_SIZE] =
    { 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22 };

static uint8_t otbr_master_key[OT_MASTER_KEY_SIZE] =
    { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

static uint8_t otbr_mesh_local_prefix[OT_MESH_LOCAL_PREFIX_SIZE] =
    { 0xfd, 0x11, 0x11, 0x11, 0x11, 0x22, 0x00, 0x00 };

void coaps_dfu_handle_error(void)
{
    coaps_dfu_reset_state();
}

static void state_changed_callback(uint32_t aFlags, void *aContext)
{
    otDeviceRole role = otThreadGetDeviceRole(thread_ot_instance_get());
    NRF_LOG_INFO("New role: %d\r\n", role);

    if (aFlags & OT_CHANGED_THREAD_ROLE)
    {
        switch(role)
        {
            case OT_DEVICE_ROLE_DISABLED:
                break;
            case OT_DEVICE_ROLE_DETACHED:
                break;
            case OT_DEVICE_ROLE_CHILD:
#ifdef ENABLE_COAPS_DFU
                coaps_dfu_start();
#endif
                break;
            case OT_DEVICE_ROLE_ROUTER:
                break;
            case OT_DEVICE_ROLE_LEADER:
                break;
            default:
                break;
        }
    }
}

// Function for initializing the Thread Board Support Package.
static void thread_bsp_init(void)
{
    uint32_t err_code = bsp_init(BSP_INIT_LEDS, NULL);
    APP_ERROR_CHECK(err_code);

    err_code = bsp_thread_init(thread_ot_instance_get());
    APP_ERROR_CHECK(err_code);
}

// Function for initializing the Thread Stack.
static void thread_instance_init(void)
{
    thread_configuration_t thread_configuration =
    {
        .radio_mode        = THREAD_RADIO_MODE_RX_ON_WHEN_IDLE,
        .autocommissioning = false,
    };

    thread_init(&thread_configuration);
    
    otInstance * aInstance = thread_ot_instance_get();
    otOperationalDataset aDataset;
    memset(&aDataset, 0, sizeof(otOperationalDataset));
    aDataset.mActiveTimestamp = 1;
    aDataset.mComponents.mIsActiveTimestampPresent = true;

    // Thread network channel
    aDataset.mChannel = otbr_channel;
    aDataset.mComponents.mIsChannelPresent = true;

    // Thread netork PAN ID
    aDataset.mPanId = (otPanId) otbr_pan_id;
    aDataset.mComponents.mIsPanIdPresent = true;

    // Thread network extended PAN ID
    memcpy(aDataset.mExtendedPanId.m8, otbr_ext_pan_id, sizeof(aDataset.mExtendedPanId));
    aDataset.mComponents.mIsExtendedPanIdPresent = true;

    // Thread network master key
    memcpy(aDataset.mMasterKey.m8, otbr_master_key, sizeof(aDataset.mMasterKey));
    aDataset.mComponents.mIsMasterKeyPresent = true;

    // Thread network mesh local prefix
    memcpy(aDataset.mMeshLocalPrefix.m8, otbr_mesh_local_prefix, sizeof(aDataset.mMeshLocalPrefix));
    aDataset.mComponents.mIsMeshLocalPrefixPresent = true;
    
    // FIXME: Force permanent child state for debugging purposes.
    otThreadSetRouterEligible(aInstance, false);
    
    // Start OpenThread. 
    otDatasetSetActive(aInstance, &aDataset);
    otError error = otThreadSetEnabled(aInstance, true);
    ASSERT(error == OT_ERROR_NONE);
    NRF_LOG_INFO("Thread interface has been enabled.");
    NRF_LOG_INFO("802.15.4 Channel : %d", otLinkGetChannel(aInstance));
    NRF_LOG_INFO("802.15.4 PAN ID  : 0x%04x", otLinkGetPanId(aInstance));
    NRF_LOG_INFO("Radio mode       : %s", otThreadGetLinkMode(aInstance).mRxOnWhenIdle ?
                                    "rx-on-when-idle" : "rx-off-when-idle");

    thread_state_changed_callback_set(state_changed_callback);
}

// Function for initializing the nrf log module.
static void log_init(void)
{
    ret_code_t err_code = NRF_LOG_INIT(NULL);
    APP_ERROR_CHECK(err_code);

    NRF_LOG_DEFAULT_BACKENDS_INIT();
}

/***************************************************************************************************
 * @section Main
 **************************************************************************************************/

int main(int argc, char *argv[])
{
    log_init();

    NRF_LOG_INFO("Hello from original firmware image!");

    uint32_t err_code = nrf_mem_init();
    APP_ERROR_CHECK(err_code);

    APP_SCHED_INIT(SCHED_EVENT_DATA_SIZE, SCHED_QUEUE_SIZE);

    err_code = app_timer_init();
    APP_ERROR_CHECK(err_code);

    thread_instance_init();

#ifdef ENABLE_COAPS_DFU
    err_code = coaps_dfu_init(thread_ot_instance_get());
    APP_ERROR_CHECK(err_code);
#endif // ENABLE_COAPS_DFU

    thread_bsp_init();

#ifdef ENABLE_RPLIDAR
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
    //APP_ERROR_CHECK(err_code);

    rplidar_response_device_health_t health;
    err_code = rplidar_get_device_health(&health);
    //APP_ERROR_CHECK(err_code);

    err_code = rplidar_start_scan(false);
    //APP_ERROR_CHECK(err_code);

    nrf_gpio_cfg_output(SPARE2);
    nrf_gpio_pin_set(SPARE2);
    nrf_delay_ms(100);

#endif // ENABLE_RPLIDAR

    while (true)
    {
        thread_process();
        app_sched_execute();

        if (NRF_LOG_PROCESS() == false)
        {
            thread_sleep();
        }
    }
}
