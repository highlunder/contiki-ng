/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Secure-world firmware for the P2 attestation example. It runs a minimal
 *   Contiki instance; the attestation Root of Trust is exposed to the normal
 *   world as secure-gateway veneers in tz-attest.c (tz_attest_build_evidence,
 *   tz_attest_public_key). This process just keeps the secure world alive.
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include "contiki.h"
#include "trustzone/tz-api.h"
#include "sys/log.h"

#define LOG_MODULE "SecureAttest"
#define LOG_LEVEL LOG_LEVEL_INFO
/*---------------------------------------------------------------------------*/
PROCESS(secure_attest_process, "Secure attestation RoT");
AUTOSTART_PROCESSES(&secure_attest_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(secure_attest_process, ev, data)
{
  PROCESS_BEGIN();
  PROCESS_WAIT_EVENT_UNTIL(ev == trustzone_init_event);
  LOG_INFO("Attestation RoT ready (tz_attest_* veneers available)\n");
  for(;;) {
    PROCESS_WAIT_EVENT();
  }
  PROCESS_END();
}
