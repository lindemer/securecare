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
#include "sdk_config.h"
//#include "nrf_dfu_utils.h"
#include "coaps_dfu.h"
//#include "background_dfu_state.h"
#include "thread_utils.h"

#include "nrf.h"
#include "nrf_drv_timer.h"
#include "nrfx_rtc.h"
#include "soc_error_handler.h"
#include "soc_logger.h"
#include "lidar_lite_interface.h"

#define NRF_LOG_MODULE_NAME main
#define NRF_LOG_LEVEL       3
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
NRF_LOG_MODULE_REGISTER();

#include <openthread/thread.h>
#include <openthread/thread_ftd.h>
#include <openthread/dataset_ftd.h>
#include <openthread/platform/alarm-micro.h>
#include <openthread/platform/alarm-milli.h>

#include "nrf_drv_clock.h"

// Maximum number of events in the scheduler queue.
//#define SCHED_QUEUE_SIZE                32
#define SCHED_QUEUE_SIZE                32

// Maximum app_scheduler event size.
//#define SCHED_EVENT_DATA_SIZE           APP_TIMER_SCHED_EVENT_DATA_SIZE
#define SCHED_EVENT_DATA_SIZE           32

APP_TIMER_DEF(m_sensor_timer);

/***************************************************************************************************
 * @section OpenThread configuration
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
                //app_timer_stop(m_sensor_timer);
                coaps_dfu_start();
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

/**@brief Function for initializing the Thread Board Support Package.
 */
/*
static void thread_bsp_init(void)
{
    uint32_t err_code = bsp_init(BSP_INIT_LEDS, NULL);
    APP_ERROR_CHECK(err_code);

    err_code = bsp_thread_init(thread_ot_instance_get());
    APP_ERROR_CHECK(err_code);
}
*/

/***************************************************************************************************
 * @section Garmin LIDAR Lite
 **************************************************************************************************/

//const nrf_drv_timer_t TIMER_MEASURE = NRF_DRV_TIMER_INSTANCE(0);
//const nrfx_rtc_t RTC0 = NRFX_RTC_INSTANCE(0);
//const nrfx_rtc_t RTC1 = NRFX_RTC_INSTANCE(1);
//const nrfx_rtc_t RTC2 = NRFX_RTC_INSTANCE(2);

static void sensor_handler(void * p_context)
//static void timer_measurement_event_handler(nrf_timer_event_t event_type, void * p_context)
{
//   NRF_LOG_INFO("RTC0: %d, RTC1: %d, RTC2: %d", 
//                   nrfx_rtc_counter_get(&RTC0),
//                   nrfx_rtc_counter_get(&RTC1),
//                   nrfx_rtc_counter_get(&RTC2));
    lidar_lite_return_t ret_code = lidar_lite_request_measurement(true);
    APP_ERROR_CHECK(ret_code);
}

/**@brief Function for handling Lidar Lite Library events.
 *
 * @param[in] p_event  Lidar Lite Library Event.
 */
static void lidar_lite_evt_handler(lidar_lite_evt_t * p_event)
{

    lidar_lite_evt_type_t event_type = p_event->type;
    lidar_lite_evt_response_code_t response_code = p_event->response_code;

    switch(event_type)
    {
        case LIDAR_LITE_EVT_POWER_UP_COMPLETE:
            if(response_code != LIDAR_LITE_COMMAND_SUCCESSFUL)
            {
                NRF_LOG_ERROR("FPGA Power Complete Event failed with response_code %d.", response_code);
                return;
            }
            NRF_LOG_INFO("FPGA Power up cycle complete, the FPGA is ready to accept commands.");
            break;

        case LIDAR_LITE_EVT_MEASUREMENT_COMPLETE:
            {
                uint16_t distance_cm;
                if(response_code != LIDAR_LITE_COMMAND_SUCCESSFUL)
                {
                    NRF_LOG_WARNING("Measurement failed with response code %d", response_code);
                }
                else
                {
                    distance_cm = p_event->data.distance_cm;
                    NRF_LOG_INFO("Measured Distance: %d", distance_cm);
                }
            }
            break;

        default:
            NRF_LOG_WARNING("Received unexpected Lidar Lite Event Type: %d Response Code: %d", event_type, response_code);
            break;
    }
}
// Handle all LOG "strings" from the Lidar Lite Library.
void log_handler(uint32_t LEVEL, const char* string, ...)
{
#if defined(DEBUG)
    va_list argptr;
    va_start(argptr, string);
    switch (LEVEL)
    {
        case SOC_LOG_LEVEL_ERROR:
            NRF_LOG_ERROR("%s", string);
            break;

        case SOC_LOG_LEVEL_WARN:
            NRF_LOG_WARNING("%s", string);
            break;

        case SOC_LOG_LEVEL_INFO:
            NRF_LOG_INFO("%s", string);
            break;

        case SOC_LOG_LEVEL_DEBUG:
            NRF_LOG_DEBUG("%s", string);
            break;

        default:  NRF_LOG_ERROR("<%d> Log Level not recognized", __LINE__);
            break;
    }
    NRF_LOG_FLUSH();
#endif
}

void library_error_handler(uint32_t error_code, uint32_t line_num, const uint8_t * p_file_name)
{
    NRF_LOG_INFO("Library Error: Code: %d, Line: %d, File: %s", error_code, line_num, p_file_name);

    __disable_irq();
    NRF_LOG_FINAL_FLUSH();

#ifndef DEBUG
    NRF_LOG_WARNING("System reset");
    NVIC_SystemReset();
#else
    volatile bool loop = true;
    while(loop);
#endif // DEBUG
}

/*
void spim_handler(nrfx_spim_evt_t const *p_event, void *p_context)
{
    NRF_LOG_INFO("SPIM event.");
    nrfx_spim_evt_t evt;
    memcpy(&evt, p_event, sizeof(nrfx_spim_evt_t));
    lidar_lite_serial_fpga_event_handler(&evt, sizeof(nrfx_spim_evt_t));
}

void gpiote_handler(nrfx_gpiote_pin_t pin, nrf_gpiote_polarity_t action)
{
    NRF_LOG_INFO("GPIOTE event.");
    lidar_lite_serial_fpga_interrupt_event_handler(&pin, sizeof(nrfx_gpiote_pin_t));
    lidar_lite_trace_fpga_interrupt_event_handler(&pin, sizeof(nrfx_gpiote_pin_t));
}
*/

/***************************************************************************************************
 * @section Other
 **************************************************************************************************/

// Function for initializing the nrf log module.
static void log_init(void)
{
    ret_code_t err_code = NRF_LOG_INIT(NULL);
    APP_ERROR_CHECK(err_code);

    NRF_LOG_DEFAULT_BACKENDS_INIT();
}

void coaps_dfu_handle_error(void)
{
    coaps_dfu_reset_state();
}

/***************************************************************************************************
 * @section Main
 **************************************************************************************************/

int main(int argc, char *argv[])
{
    log_init();

    NRF_LOG_INFO("Hello from firmware image A!");

    uint32_t err_code = nrf_mem_init();
    APP_ERROR_CHECK(err_code);

    app_timer_create(&m_sensor_timer, APP_TIMER_MODE_REPEATED, sensor_handler);

    APP_SCHED_INIT(SCHED_EVENT_DATA_SIZE, SCHED_QUEUE_SIZE);

    err_code = app_timer_init();
    APP_ERROR_CHECK(err_code);

    // Garmin LIDAR Lite
    err_code = lidar_lite_init(true, lidar_lite_evt_handler, library_error_handler, log_handler);
    APP_ERROR_CHECK(err_code);

    //lidar_lite_serial_fpga_init(spim_handler, gpiote_handler);

    // OpenThread
    thread_instance_init();

    //thread_bsp_init();

    //app_timer_start(m_sensor_timer, APP_TIMER_TICKS(200), sensor_handler);

    //nrfx_clock_lfclk_start();

    /*
    uint32_t time_ms = 2500;    // 2.5 seconds
    uint32_t time_ticks;
    nrf_drv_timer_config_t timer_cfg = NRF_DRV_TIMER_DEFAULT_CONFIG;
    err_code = nrf_drv_timer_init(&TIMER_MEASURE, &timer_cfg, timer_measurement_event_handler);
    APP_ERROR_CHECK(err_code);
    time_ticks = nrf_drv_timer_ms_to_ticks(&TIMER_MEASURE, time_ms);
    nrf_drv_timer_extended_compare(&TIMER_MEASURE, NRF_TIMER_CC_CHANNEL0, time_ticks, NRF_TIMER_SHORT_COMPARE0_CLEAR_MASK, true);
    nrf_drv_timer_enable(&TIMER_MEASURE);
    */
    
    err_code = coaps_dfu_init(thread_ot_instance_get());
    APP_ERROR_CHECK(err_code);

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
