/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 *
 * Rung 1: plain RPL node, no crypto. Logging only.
 */
#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#define LOG_CONF_LEVEL_APP LOG_LEVEL_INFO

#ifdef LOCAL_TEST_DEBUG
#define LOG_CONF_LEVEL_RPL     LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_MAC     LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_6LOWPAN LOG_LEVEL_INFO
#else
#define LOG_CONF_LEVEL_RPL     LOG_LEVEL_WARN
#endif

#endif /* PROJECT_CONF_H_ */
