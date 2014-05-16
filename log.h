/*
 * ipxbox - Userspace IPX adapter for DOSBox
 *
 * Copyright (c) 2014 Vitaly Sinilin
 */

#ifndef LOG_H
#define LOG_H

#include <string.h>
#include <errno.h>

#ifdef DEBUG
#define debug(fmt, ...) warn(fmt, ##__VA_ARGS__)
#else
#define debug(fmt, ...)
#endif

#define warn_errno(fmt, ...) warn(fmt ": %s", ##__VA_ARGS__, strerror(errno))
#define crit_errno(fmt, ...) crit(fmt ": %s", ##__VA_ARGS__, strerror(errno))

#define info(fmt, ...) warn(fmt, ##__VA_ARGS__)
#define warn(fmt, ...) raw_warn(fmt "\n", ##__VA_ARGS__)
#define crit(fmt, ...) raw_crit(fmt "\n", ##__VA_ARGS__)

void raw_warn(const char *fmt, ...);
void raw_crit(const char *fmt, ...);

#endif
