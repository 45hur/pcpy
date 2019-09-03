#pragma once

#ifndef LOG_H
#define LOG_H

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#define C_MOD_MUTEX "mutex.pcpy\0"
#define C_MOD_LOGFILE "/var/log/pcpy/pcpylog.log\0"
#define C_MOD_LOGDEBUG "/var/log/pcpy/pcpydebug.log\0"

void debugLog(const char *format, ...);
void fileLog(const char *format, ...);

#endif