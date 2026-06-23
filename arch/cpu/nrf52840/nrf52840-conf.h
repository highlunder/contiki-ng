/*---------------------------------------------------------------------------*/
#ifndef NRF52840_CONF_H_
#define NRF52840_CONF_H_
/*---------------------------------------------------------------------------*/
/*
 * Guarded so an application can override the radio driver from its project conf
 * or Makefile (e.g. nullradio for a tun/SLIP build, slip-radio for a border
 * router, or a no-radio RTT-diagnostic firmware used during CC310 bring-up).
 * Defaults to the IEEE 802.15.4 driver when no override is supplied.
 */
#ifndef NETSTACK_CONF_RADIO
#define NETSTACK_CONF_RADIO        nrf52840_ieee_driver
#endif
/*---------------------------------------------------------------------------*/
#ifndef UART0_CONF_BAUD_RATE
#define UART0_CONF_BAUD_RATE       NRF_UART_BAUDRATE_115200
#endif
/*---------------------------------------------------------------------------*/
#if NRF52840_NATIVE_USB

#ifndef DBG_CONF_USB
#define DBG_CONF_USB 1
#endif

#ifndef SLIP_ARCH_CONF_USB
#define SLIP_ARCH_CONF_USB 1
#endif

#endif
/*---------------------------------------------------------------------------*/
#endif /* NRF52840_CONF_H_ */
/*---------------------------------------------------------------------------*/
