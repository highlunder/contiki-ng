/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden.
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
 * \file
 *         Minimal RPL routing node for the cross-platform multi-hop test.
 *
 *         Used for the BR (border-router-adjacent relay) and I (intermediate)
 *         nodes in the 3-hop topology:
 *
 *           slip-radio ↔ BR(nRF) ↔ I(nRF) ↔ C(nRF)
 *
 *         The Contiki-NG network stack handles all RPL routing and 6LoWPAN
 *         forwarding automatically.  No application logic is needed here.
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "sys/log.h"

#define LOG_MODULE "RPL Router"
#define LOG_LEVEL  LOG_LEVEL_INFO

PROCESS(rpl_router_process, "RPL Router");
AUTOSTART_PROCESSES(&rpl_router_process);

PROCESS_THREAD(rpl_router_process, ev, data)
{
  PROCESS_BEGIN();

  LOG_INFO("RPL routing node started\n");

  /* The network stack runs in parallel processes; nothing else to do here. */
  PROCESS_END();
}
