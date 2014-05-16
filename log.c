/*
 * ipxbox - Userspace IPX adapter for DOSBox
 *
 * Copyright (c) 2014 Vitaly Sinilin
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "log.h"

void raw_warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
}

void raw_crit(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    exit(EXIT_FAILURE);
}
