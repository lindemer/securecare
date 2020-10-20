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

/**
 * Adapted from the C++ code by RoboPeak.
 * https://github.com/robopeak/rplidar_arduino
 **/

#define RPLIDAR_SERIAL_BAUDRATE         115200
#define RPLIDAR_SERIAL_TIMEOUT          500

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
#define RPLIDAR_CMD_HAS_PAYLOAD         0x80
#define RPLIDAR_CMD_STOP                0x25
#define RPLIDAR_CMD_SCAN                0x20
#define RPLIDAR_CMD_FORCE_SCAN          0x21
#define RPLIDAR_CMD_RESET               0x40
#define RPLIDAR_CMD_GET_DEVICE_INFO     0x50
#define RPLIDAR_CMD_GET_DEVICE_HEALTH   0x52

#define RPLIDAR_ANS_SYNC_BYTE0          0xa5
#define RPLIDAR_ANS_SYNC_BYTE1          0x5a
#define RPLIDAR_ANS_PKTFLAG_LOOP        0x1
#define RPLIDAR_ANS_TYPE_MEASUREMENT    0x81

#define RPLIDAR_ANS_TYPE_DEVINFO        0x4
#define RPLIDAR_ANS_TYPE_DEVHEALTH      0x6

#define RPLIDAR_STATUS_OK               0x0
#define RPLIDAR_STATUS_WARNING          0x1
#define RPLIDAR_STATUS_ERROR            0x2

#define RPLIDAR_RESP_MEASUREMENT_SYNCBIT        1
#define RPLIDAR_RESP_MEASUREMENT_QUALITY_SHIFT  2
#define RPLIDAR_RESP_MEASUREMENT_CHECKBIT       1
#define RPLIDAR_RESP_MEASUREMENT_ANGLE_SHIFT    1

typedef struct rplidar_point_t
{
    float distance;
    float angle;
    uint8_t quality;
    bool start_bit;
} rplidar_point_t;

typedef struct rplidar_cmd_packet_t {
    uint8_t sync_byte; //must be RPLIDAR_CMD_SYNC_BYTE
    uint8_t cmd_flag; 
} __attribute__((packed)) rplidar_cmd_packet_t;

typedef struct rplidar_ans_header_t {
    uint8_t  sync_byte_0; // must be RPLIDAR_ANS_SYNC_BYTE0
    uint8_t  sync_byte_1; // must be RPLIDAR_ANS_SYNC_BYTE1
    uint32_t size;      // 30
    uint32_t subType;   // 2
    uint8_t  type;
} __attribute__((packed)) rplidar_ans_header_t;

typedef struct rplidar_response_measurement_node_t {
    uint8_t    sync_quality;      // syncbit:1;syncbit_inverse:1;quality:6;
    uint16_t   angle_q6_checkbit; // check_bit:1;angle_q6:15;
    uint16_t   distance_q2;
} __attribute__((packed)) rplidar_response_measurement_node_t;

typedef struct rplidar_response_device_info_t {
    uint8_t   model;
    uint16_t  firmware_version;
    uint8_t   hardware_version;
    uint8_t   serialnum[16];
} __attribute__((packed)) rplidar_response_device_info_t;

typedef struct rplidar_response_device_health_t {
    uint8_t   status;
    uint16_t  error_code;
} __attribute__((packed)) rplidar_response_device_health_t;
