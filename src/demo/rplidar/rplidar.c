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
#include "app_uart.h"
#include "rplidar.h"
#include "nrf_delay.h"

#ifdef UART_PRESENT
#include "nrf_uart.h"
#endif
#ifdef UARTE_PRESENT
#include "nrf_uarte.h"
#endif

uint32_t rplidar_send_command(uint8_t command)
{
    rplidar_cmd_packet_t pkt;
    pkt.sync_byte = RPLIDAR_CMD_SYNC_BYTE;
    pkt.cmd_flag = command;
    uint8_t * buffer = (uint8_t *)&pkt;

    for (uint32_t i = 0; i < sizeof(pkt); i++)
    {
	while (app_uart_put(buffer[i]) != NRF_SUCCESS);
    }
    
    return RPLIDAR_SUCCESS;
}

uint32_t rplidar_wait_response_header(rplidar_ans_header_t * header)
{
    uint32_t recv_pos = 0;
    uint8_t * buffer = (uint8_t *)header;

    uint32_t max_gets = 128 * sizeof(rplidar_ans_header_t);
    for (uint32_t i = 0; i < max_gets; i++)
    {
        uint8_t byte;
        uint32_t err_code = app_uart_get(&byte);
        if (!err_code)
        {
            switch (recv_pos)
            {
            case 0:
                if (byte == RPLIDAR_ANS_SYNC_BYTE0)
                {
                    buffer[recv_pos++] = byte;
                }
                break;
            
            case 1:
                if (byte == RPLIDAR_ANS_SYNC_BYTE1)
                {
                    buffer[recv_pos++] = byte;
                }
                break;

            default:
                buffer[recv_pos++] = byte;
            }
        }

	if (recv_pos == sizeof(rplidar_ans_header_t)) return RPLIDAR_SUCCESS;
    } 

    return RPLIDAR_OPERATION_TIMEOUT;
}

uint32_t rplidar_get_bytes(uint8_t * buffer, uint32_t size)
{
    uint32_t recv_pos = 0;
    uint32_t max_gets = 128 * size;

    for (uint32_t i = 0; i < max_gets; i++)
    {
        uint8_t byte;
        uint32_t err_code = app_uart_get(&byte);
        if (!err_code)
        {
            buffer[recv_pos++] = byte;
        }
	    if (recv_pos == size) return RPLIDAR_SUCCESS;
    } 

    return RPLIDAR_OPERATION_TIMEOUT;
}

uint32_t rplidar_get_device_info(rplidar_response_device_info_t * info)
{
    rplidar_send_command(RPLIDAR_CMD_GET_DEVICE_INFO);
    rplidar_ans_header_t header;
    uint32_t err_code = rplidar_wait_response_header(&header);

    if (err_code) return err_code;
    if ((header.type) != RPLIDAR_ANS_TYPE_DEVINFO) return RPLIDAR_FAIL;

    return rplidar_get_bytes((uint8_t *)info, sizeof(rplidar_response_device_info_t));
}

uint32_t rplidar_get_device_health(rplidar_response_device_health_t * health)
{
    rplidar_send_command(RPLIDAR_CMD_GET_DEVICE_HEALTH);
    rplidar_ans_header_t header;
    uint32_t err_code = rplidar_wait_response_header(&header);

    if (err_code) return err_code;
    if ((header.type) != RPLIDAR_ANS_TYPE_DEVHEALTH) return RPLIDAR_FAIL;

    return rplidar_get_bytes((uint8_t *)health, sizeof(rplidar_response_device_health_t));
}

void rplidar_stop_scan()
{
   rplidar_send_command(RPLIDAR_CMD_STOP);
}

uint32_t rplidar_start_scan(bool force)
{
    rplidar_stop_scan();
    rplidar_send_command(force ? RPLIDAR_CMD_FORCE_SCAN : RPLIDAR_CMD_SCAN);

    nrf_delay_ms(100);
    rplidar_ans_header_t header;
    uint32_t err_code = rplidar_wait_response_header(&header);

    if (err_code) return err_code;
    if ((header.type) != RPLIDAR_ANS_TYPE_MEASUREMENT) return RPLIDAR_INVALID_DATA;
    return RPLIDAR_SUCCESS;
}

uint32_t rplidar_get_point(rplidar_point_t * point)
{
    uint32_t recv_pos = 0;
    rplidar_response_measurement_t measurement;
    uint8_t * buffer = (uint8_t *)&measurement;

    uint32_t max_gets = 128 * sizeof(rplidar_response_measurement_t);
    for (uint32_t i = 0; i < max_gets; i++)
    {
        uint8_t byte;
        uint32_t err_code = app_uart_get(&byte);
        if (!err_code)
        {
            switch (recv_pos)
            {
            case 0:
                if (byte != RPLIDAR_ANS_SYNC_MEASUREMENT)
                {
                    continue;
                }
            default:
                buffer[recv_pos++] = byte;
            }
        }

	    if (recv_pos == sizeof(rplidar_response_measurement_t)) 
        {
            point->sync = measurement.sync;
            point->deg = (measurement.angle >> 1) / 64;
            point->mm = measurement.dist / 4;
            return RPLIDAR_SUCCESS;       
        }
    } 

    return RPLIDAR_OPERATION_TIMEOUT;
}

void rplidar_init_sweep(rplidar_sweep_t * sweep)
{
    sweep->swap = false;
    sweep->hits = 0;
    for (int i = 0; i < 360; i++)
    {
        sweep->swap0[i] = 0;
        sweep->swap1[i] = 0;
        sweep->delta[i] = 0;
    }
}

void rplidar_clear_sweep(rplidar_sweep_t * sweep)
{
    for (int i = 0; i < 360; i++)
    {
        sweep->delta[i] = 0;
        if (sweep->swap)
        {
            sweep->swap0[i] = sweep->swap1[i]; 
        }
        else
        {
            sweep->swap1[i] = sweep->swap0[i]; 
        }
    }
    sweep->swap = !sweep->swap;
    sweep->hits = 0;
}

uint16_t rplidar_push_sweep(rplidar_sweep_t * sweep,
         rplidar_point_t * point, bool accumulate)
{
    int delta = 0;
    if (point->deg < 360 && point->deg >= 0)
    {
        if (sweep->swap)
        {
            delta = abs(sweep->swap0[point->deg] - (int)(point->mm));
            if (delta > sweep->delta[point->deg] &&
                (point->deg >= (360 - RPLIDAR_APERTURE) || 
                (point->deg <= RPLIDAR_APERTURE)))
            {
                sweep->swap1[point->deg] = (int)point->mm;
                if (!accumulate) sweep->delta[point->deg] = delta;
                if (delta > RPLIDAR_HIT_THRESHOLD) sweep->hits++;
            }
            if (accumulate) sweep->delta[point->deg] += delta;
        }
        else
        {
            delta = abs(sweep->swap1[point->deg] - (int)(point->mm));
            if (delta > sweep->delta[point->deg] &&
                (point->deg >= (360 - RPLIDAR_APERTURE) || 
                (point->deg <= RPLIDAR_APERTURE)))
            {
                sweep->swap0[point->deg] = (int)point->mm;
                if (!accumulate) sweep->delta[point->deg] = delta;
                if (delta > RPLIDAR_HIT_THRESHOLD) sweep->hits++;
            }
            if (accumulate) sweep->delta[point->deg] += delta;
        }
    }
    return delta;
}

uint32_t rplidar_get_mean(rplidar_sweep_t * sweep)
{
    uint32_t mean = 0;

    for (int i = 0; i <= RPLIDAR_APERTURE; i++)
    {
        mean += sweep->delta[i]; 
    }
    for (int j = 360 - RPLIDAR_APERTURE; j < 360; j++) 
    {
        mean += sweep->delta[j]; 
    }
    mean /= RPLIDAR_APERTURE * 2 + 1;
    return mean;
}

