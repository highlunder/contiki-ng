/*
 * Copyright (c) 2010, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#ifdef CONTIKI_TARGET_SKY
/* Save some RAM and ROM */
#define QUEUEBUF_CONF_NUM              4
#define UIP_CONF_BUFFER_SIZE         140
#define BORDER_ROUTER_CONF_WEBSERVER   0
#else
/* This router forwards large fragmented datagrams to the mesh — e.g. a DTLS
 * X.509 certificate flight is ~11 6LoWPAN fragments. The default pool of 8
 * queue buffers cannot hold a single such burst, so it silently drops
 * fragments and the mote's reassembly never completes (deterministic, even at
 * close range). Size the pool for a full ~1280 B datagram (~16 fragments) plus
 * headroom. Costs ~a few KB RAM; fine on CC2538/nRF52840. */
#ifndef QUEUEBUF_CONF_NUM
#define QUEUEBUF_CONF_NUM             24
#endif

/* --- TSCH buffer over-provisioning for the certificate flight (TSCH builds only)
 * -----------------------------------------------------------------------------
 * As the RPL root / 6LoWPAN forwarder for a DTLS mutual-auth handshake, this
 * router must RECEIVE + reassemble the client's ~11-fragment certificate record
 * and QUEUE the server's back. On minimal-schedule TSCH the stock pools
 * (per-neighbor TX queue 4-8, inbound 4, 6LoWPAN 12 buffers) are all smaller than
 * one cert flight, so fragments are dropped and the handshake is "repeatedly
 * lost". Enlarge to hold a full flight -- the border-router half of the same
 * bump applied on the DK client (dtls-{x509,c509}-bench/project-conf.h). This is
 * NEEDED ONLY by certificate DTLS; EDHOC (message-oriented) and PSK-DTLS complete
 * over this router on the stock TSCH config, so the bump is transparent to them.
 * See paper_space/LICE-followup/NOTES-robustness-under-loss.md (successor of the
 * former PLAN-cd-robustness-tradeoff.md) + autoPKI.tex (§TSCH). */
#if MAC_CONF_WITH_TSCH
#ifndef TSCH_QUEUE_CONF_NUM_PER_NEIGHBOR
#define TSCH_QUEUE_CONF_NUM_PER_NEIGHBOR 16
#endif
#ifndef TSCH_CONF_MAX_INCOMING_PACKETS
#define TSCH_CONF_MAX_INCOMING_PACKETS   8
#endif
#ifndef SICSLOWPAN_CONF_FRAGMENT_BUFFERS
#define SICSLOWPAN_CONF_FRAGMENT_BUFFERS 24
#endif
/* THE ROOT-CAUSE FIX (must match the DK bench): the default 6LoWPAN reassembly
 * window is only 0.5 s (SICSLOWPAN_REASS_MAXAGE=8 -> MAXAGE*CLOCK_SECOND/16). On
 * the slot-paced TSCH uplink the DK's ~11-fragment certificate flight dribbles in
 * over >1 s, so this router discards the half-assembled datagram before it can
 * forward it. 160 => a 10 s window. See dtls-x509-bench/project-conf.h. */
#ifndef SICSLOWPAN_CONF_MAXAGE
#define SICSLOWPAN_CONF_MAXAGE 160
#endif
#endif /* MAC_CONF_WITH_TSCH */
#endif

#ifndef WEBSERVER_CONF_CFS_CONNS
#define WEBSERVER_CONF_CFS_CONNS 2
#endif

#ifndef BORDER_ROUTER_CONF_WEBSERVER
#define BORDER_ROUTER_CONF_WEBSERVER 1
#endif

#if BORDER_ROUTER_CONF_WEBSERVER
#define UIP_CONF_TCP 1
#endif

/* When the native BR build includes the NAT64 module, register the
 * NAT64 prefix as a 6LoWPAN compression context so its IPHC encoder
 * matches IoT nodes that include the same header in their own
 * project-conf.h. */
#ifdef BUILD_WITH_NAT64
#include "services/nat64/nat64-6lowpan.h"
#endif

#endif /* PROJECT_CONF_H_ */
