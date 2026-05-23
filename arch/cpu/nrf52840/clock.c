/*
 * Copyright (c) 2015 Nordic Semiconductor. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \addtogroup nrf52840
 * @{
 *
 * \addtogroup nrf52840-dev Device drivers
 * @{
 *
 * \addtogroup nrf52840-clock Clock driver
 * @{
 *
 * \file
 *         Software clock implementation for the nRF52.
 * \author
 *         Wojciech Bober <wojciech.bober@nordicsemi.no>
 *
 */
/*---------------------------------------------------------------------------*/
#include "contiki.h"
#include <stdint.h>
#include <stdbool.h>
#include "nrf.h"
#include "sdk_config.h"
#include "nrf_drv_rtc.h"
#include "nrf_drv_clock.h"
#include "nrf_delay.h"
#include "app_error.h"

/*---------------------------------------------------------------------------*/
const nrf_drv_rtc_t rtc = NRF_DRV_RTC_INSTANCE(PLATFORM_RTC_INSTANCE_ID); /**< RTC instance used for platform clock */
/*---------------------------------------------------------------------------*/
static volatile uint32_t ticks;
void clock_update(void);
/*---------------------------------------------------------------------------*/
/*
 * RTC prescaler is set to 255, giving LFCLK (32768 Hz) / 256 = 128 Hz.
 * CLOCK_CONF_SECOND is 128 on ARM targets, so one RTC counter unit equals
 * exactly one Contiki clock tick.
 *
 * The CC0 COMPARE channel is used instead of the TICK interrupt because some
 * simulators (including Renode) do not implement the TICK event in the RTC
 * peripheral model.  COMPARE events are universally supported.
 */
#define RTC_CC_INTERVAL 1
/*---------------------------------------------------------------------------*/
/**
 * \brief Handle RTC compare interrupts and advance the Contiki clock.
 * \param int_type Type of interrupt delivered by the nrf_drv_rtc driver.
 */
static void
rtc_handler(nrf_drv_rtc_int_type_t int_type)
{
  if(int_type == NRF_DRV_RTC_INT_COMPARE0) {
    /* Reload CC0 relative to the current counter value to stay phase-accurate
     * across the 24-bit counter wrap boundary. */
    uint32_t next = nrf_drv_rtc_counter_get(&rtc) + RTC_CC_INTERVAL;
    nrf_drv_rtc_cc_set(&rtc, 0, next & 0xFFFFFF, true);
    clock_update();
  }
}
/*---------------------------------------------------------------------------*/
/**
 * \brief Start the internal LFCLK crystal oscillator.
 */
static void
lfclk_config(void)
{
  ret_code_t err_code = nrf_drv_clock_init();
  APP_ERROR_CHECK(err_code);
  nrf_drv_clock_lfclk_request(NULL);
}
/*---------------------------------------------------------------------------*/
/**
 * \brief Initialise and start the RTC driver instance used for the platform
 *        clock.
 */
static void
rtc_config(void)
{
  uint32_t err_code;

  /* Prescaler 255 -> 32768/256 = 128 Hz; priority 6 is below SoftDevice. */
  nrf_drv_rtc_config_t config = NRF_DRV_RTC_DEFAULT_CONFIG;
  config.prescaler = 255;
  config.interrupt_priority = 6;
  config.reliable = 0;

  err_code = nrf_drv_rtc_init(&rtc, &config, rtc_handler);
  APP_ERROR_CHECK(err_code);

  /* Arm the first CC0 compare event to fire after one counter unit. */
  nrf_drv_rtc_cc_set(&rtc, 0, RTC_CC_INTERVAL, true);

  /* Power on RTC instance */
  nrf_drv_rtc_enable(&rtc);
}
/*---------------------------------------------------------------------------*/
void
clock_init(void)
{
  ticks = 0;
  lfclk_config();
  rtc_config();
}
/*---------------------------------------------------------------------------*/
clock_time_t
clock_time(void)
{
  return (clock_time_t)(ticks & 0xFFFFFFFF);
}
/*---------------------------------------------------------------------------*/
void
clock_update(void)
{
  ticks++;
  if(etimer_pending()) {
    etimer_request_poll();
  }
}
/*---------------------------------------------------------------------------*/
unsigned long
clock_seconds(void)
{
  return (unsigned long)ticks / CLOCK_CONF_SECOND;
}
/*---------------------------------------------------------------------------*/
void
clock_wait(clock_time_t i)
{
  clock_time_t start;
  start = clock_time();
  while(clock_time() - start < (clock_time_t)i) {
    __WFE();
  }
}
/*---------------------------------------------------------------------------*/
void
clock_delay_usec(uint16_t dt)
{
  nrf_delay_us(dt);
}
/*---------------------------------------------------------------------------*/
/**
 * \brief Obsolete delay function but we implement it here since some code
 * still uses it
 */
void
clock_delay(unsigned int i)
{
  clock_delay_usec(i);
}
/*---------------------------------------------------------------------------*/
/**
 * @}
 * @}
 * @}
 */
