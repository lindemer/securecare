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
#include "lidar-wrapper.h"
//#include "app_uart.h"
//#include "rplidar.h"

//#if defined (UART_PRESENT)
//#include "nrf_uart.h"
//#elif defined (UARTE_PRESENT)
//#include "nrf_uarte.h"
//#endif

//// Thingy:91 GPIO pins
//#define SPARE1 NRF_GPIO_PIN_MAP(0, 6)
//#define SPARE2 NRF_GPIO_PIN_MAP(0, 5)
//#define SPARE3 NRF_GPIO_PIN_MAP(0, 26)
//#define SPARE4 NRF_GPIO_PIN_MAP(0, 27)
//
//#define UART_TX_BUF_SIZE 256
//#define UART_RX_BUF_SIZE 256

/*
 * Openthread
 */
#include <openthread/cli.h>
#include <openthread/thread.h>
#include <openthread/thread_ftd.h>
#include <openthread/dataset_ftd.h>
#include <openthread/platform/alarm-micro.h>
#include <openthread/platform/alarm-milli.h>

// Maximum number of events in the scheduler queue.
#define SCHED_QUEUE_SIZE                32

// Maximum app_scheduler event size.
//#define SCHED_EVENT_DATA_SIZE           APP_TIMER_SCHED_EVENT_DATA_SIZE

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

#if TEST_ENROLL_SUBJECT
const char client_mac_id[] = "RISE Demo Server";//{ 0xe,0x9,0xa,0xc,0x8,0x7,0xb,0x1 }; //TODO read from HW
#else
const uint8_t client_mac_id[] = { 0xe,0x9,0xa,0xc,0x8,0x7,0xb,0x1 }; //TODO read from HW
#endif


void coaps_dfu_handle_error(void)
{
    coaps_dfu_reset_state();
}


static void address_print(const otIp6Address *addr)
{
    char ipstr[40];
    snprintf(ipstr, sizeof(ipstr), "%x:%x:%x:%x:%x:%x:%x:%x",
             uint16_big_decode((uint8_t *)(addr->mFields.m16 + 0)),
             uint16_big_decode((uint8_t *)(addr->mFields.m16 + 1)),
             uint16_big_decode((uint8_t *)(addr->mFields.m16 + 2)),
             uint16_big_decode((uint8_t *)(addr->mFields.m16 + 3)),
             uint16_big_decode((uint8_t *)(addr->mFields.m16 + 4)),
             uint16_big_decode((uint8_t *)(addr->mFields.m16 + 5)),
             uint16_big_decode((uint8_t *)(addr->mFields.m16 + 6)),
             uint16_big_decode((uint8_t *)(addr->mFields.m16 + 7)));

    NRF_LOG_INFO("%s\r\n", (uint32_t)ipstr);
}

static void addresses_print(otInstance * aInstance)
{
    for (const otNetifAddress *addr = otIp6GetUnicastAddresses(aInstance); addr; addr = addr->mNext)
    {
        address_print(&addr->mAddress);
    }
}

// Function for initializing scheduler module.
static void scheduler_init(void)
{
    APP_SCHED_INIT(SCHED_EVENT_DATA_SIZE, SCHED_QUEUE_SIZE);
}

static void state_changed_callback(uint32_t aFlags, void *aContext)
{
    otDeviceRole role = otThreadGetDeviceRole(thread_ot_instance_get());
    if (42 == role)//(aFlags & OT_CHANGED_THREAD_NETDATA) //TODO, currently prints garbage
    {
       addresses_print(thread_ot_instance_get());
    }
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

/**@brief Function for initializing the Thread Board Support Package.
 */
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

    //thread_cli_init();
    thread_state_changed_callback_set(state_changed_callback);

    //otCliSetUserCommands(m_user_commands, sizeof(m_user_commands) / sizeof(otCliCommand));
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

    scheduler_init();

    err_code = app_timer_init();
    APP_ERROR_CHECK(err_code);

    thread_instance_init();

    /*
     * Check if enrollment has been done:
     * if so, the enrolled trust store and certificate have been written to flash
     * @EST_FLASH_START_ADDRESS
     */
    background_dfu_state_t initial_state = BACKGROUND_EST_IDLE;

    if (*(uint32_t *)EST_FLASH_START_ADDRESS == EST_DONE_SYMBOL) {
      initial_state = CONFIG_STATE_AFTER_EST;
    }

    err_code = coaps_dfu_init(thread_ot_instance_get(), initial_state);
    APP_ERROR_CHECK(err_code);

    thread_bsp_init();

    while (true)
    {
        thread_process();
        app_sched_execute();

        lidar_update();

        if (NRF_LOG_PROCESS() == false)
        {
            thread_sleep();
        }
    }
}
