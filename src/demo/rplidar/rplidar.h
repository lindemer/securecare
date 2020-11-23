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

#ifndef RPLIDAR_H
#define RPLIDAR_H

#include <stdbool.h>

#define RPLIDAR_SUCCESS                 0x0
#define RPLIDAR_ALREADY_DONE            0x20
#define RPLIDAR_FAIL                    0x80000000
#define RPLIDAR_INVALID_DATA            (0x8000 | RPLIDAR_FAIL)
#define RPLIDAR_OPERATION_FAIL          (0x8001 | RPLIDAR_FAIL)
#define RPLIDAR_OPERATION_TIMEOUT       (0x8002 | RPLIDAR_FAIL)
#define RPLIDAR_OPERATION_STOP          (0x8003 | RPLIDAR_FAIL)
#define RPLIDAR_OPERATION_NOT_SUPPORT   (0x8004 | RPLIDAR_FAIL)
#define RPLIDAR_FORMAT_NOT_SUPPORT      (0x8005 | RPLIDAR_FAIL)
#define RPLIDAR_INSUFFICIENT_MEMORY     (0x8006 | RPLIDAR_FAIL)

#define RPLIDAR_CMD_SYNC_BYTE           0xa5
#define RPLIDAR_CMD_STOP                0x25
#define RPLIDAR_CMD_SCAN                0x20
#define RPLIDAR_CMD_FORCE_SCAN          0x21
#define RPLIDAR_CMD_RESET               0x40
#define RPLIDAR_CMD_GET_DEVICE_INFO     0x50
#define RPLIDAR_CMD_GET_DEVICE_HEALTH   0x52

#define RPLIDAR_ANS_SYNC_BYTE0          0xa5
#define RPLIDAR_ANS_SYNC_BYTE1          0x5a
#define RPLIDAR_ANS_TYPE_MEASUREMENT    0x81
#define RPLIDAR_ANS_TYPE_DEVINFO        0x4
#define RPLIDAR_ANS_TYPE_DEVHEALTH      0x6

#define RPLIDAR_ANS_SYNC_MEASUREMENT    0x3e

/* Range (in degrees) in which statistics will be computed on the scan data.
 *
 *                359   1
 *    |-------------| 0 |-------------|
 *    ^                               ^
 *    360 - RPLIDAR_APERTURE          RPLIDAR_APERTURE
 *
 * The effective width of this range is 1 + RPLIDAR_APERTURE * 2.
 */
#define RPLIDAR_APERTURE                15
#define RPLIDAR_HIT_THRESHOLD           30 // [mm]    

typedef struct rplidar_point_t
{
    uint8_t  sync; // sync byte (0x3e)
    uint16_t deg;  // angle in degrees
    uint16_t mm;   // distance in millimeters
} rplidar_point_t;

typedef struct rplidar_cmd_packet_t
{
    uint8_t sync_byte; // must be RPLIDAR_CMD_SYNC_BYTE
    uint8_t cmd_flag; 
} __attribute__((packed)) rplidar_cmd_packet_t;

typedef struct rplidar_ans_header_t
{
    uint8_t  sync_byte_0; // must be RPLIDAR_ANS_SYNC_BYTE0
    uint8_t  sync_byte_1; // must be RPLIDAR_ANS_SYNC_BYTE1
    uint32_t size_and_subtype; // size[29:0] | (subtype << 30) 
    uint8_t  type;
} __attribute__((packed)) rplidar_ans_header_t;

typedef struct rplidar_response_measurement_t
{
    uint8_t  sync;  // should be 0x3e in simplest use case
    uint16_t angle; // ((angle[14:0] * 64) << 1) | checkbit
    uint16_t dist;  // distance * 4
} __attribute__((packed)) rplidar_response_measurement_t;

typedef struct rplidar_response_device_info_t
{
    uint8_t   model;
    uint16_t  firmware_version;
    uint8_t   hardware_version;
    uint8_t   serialnum[16];
} __attribute__((packed)) rplidar_response_device_info_t;

typedef struct rplidar_response_device_health_t
{
    uint8_t   status;
    uint16_t  error_code;
} __attribute__((packed)) rplidar_response_device_health_t;

typedef struct rplidar_sweep_t
{
    bool swap;
    int swap0[360];
    int swap1[360];
    int delta[360]; 
    int hits;
} rplidar_sweep_t;

uint32_t rplidar_get_device_info(rplidar_response_device_info_t * info);

uint32_t rplidar_get_device_health(rplidar_response_device_health_t * health);

void rplidar_stop_scan();

uint32_t rplidar_start_scan(bool force);

uint32_t rplidar_get_point(rplidar_point_t * point);

void rplidar_init_sweep(rplidar_sweep_t * sweep);

void rplidar_clear_sweep(rplidar_sweep_t * sweep);

uint16_t rplidar_push_sweep(rplidar_sweep_t * sweep,
         rplidar_point_t * point, bool accummulate);

uint32_t rplidar_get_mean(rplidar_sweep_t * sweep);

#endif
