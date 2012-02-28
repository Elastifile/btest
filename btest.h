/*
 * Block test/exerciser utility header
 *
 * Copyright (c) 2008-2009 Shahar Frank, Qumranet (Redhat)
 * Copyright (c) 2009-2010 Shahar Frank, Xtremio
 * Copyright (c) 2010 Koby Luz, Xtremio
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef _BTEST_H
#define	_BTEST_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef int8_t          int8;
typedef uint8_t         uint8;
typedef int16_t         int16;
typedef uint16_t        uint16;
typedef int32_t         int32;
typedef uint32_t        uint32;
typedef int64_t         int64;
typedef uint64_t        uint64;

typedef enum IOModel {
        IO_MODEL_INVALID = 0,
        IO_MODEL_SYNC,
        IO_MODEL_ASYNC,
        IO_MODEL_SGIO,
        IO_MODEL_SGIO_DIRECT,
        IO_MODEL_WRITE_BEHIND,
        IO_MODEL_DIRECT,
        IO_MODEL_DIRECT_SYNC,
                
        IO_MODEL_LAST
} IOModel;

extern char *iomodel_str[IO_MODEL_LAST];

/**
 * Common configuration variables
 */
typedef struct BtestConf {
        int secs;                       /** requested time limit in seconds */
        int nthreads;                   /** requested number of threads */
        int nfiles;                     /** given number of files */
        int def_blocksize;
        int diff_interval;
        int subtotal_interval;
        int timeout_ms;                 /**< timeout value in msec and also interval to check for timedout IOs */
        int warmup_sec;
        int rseed;
        uint64 num_op_limit;            /**< requested op limit */
        int exit_eof;
        char *block_md_base;
        int stampblock;                 /**< stamp block size, if it is -1 == "not set", the block size is used */
        int compression;                /**< compression rate */
        int aio_window_size;
        
        /* configuration flags */
        int preformat;
        int pretrim;
        int write_behind;
        int report_workers;
        int activity_check;
        int verify;
        int verification_mode;
        int ignore_errors;
        int debug;
        
        /* long options */
        char *csv_report;
        IOModel iomodel;
        
        int force_md_init;
} BtestConf;

extern BtestConf conf;

/** printf style debugging MACRO, conmmon header includes name of function */
#undef WARN
#define WARN(fmt, args...)	warn(__FUNCTION__, fmt, ## args)

/** printf style abort MACRO, conmmon header includes name of function */
#ifdef PANIC
#undef PANIC
#endif
#define PANIC(fmt, args...)	panic(__FUNCTION__, fmt, ## args)

#define DEBUG(fmt, args...)	do { if (conf.debug) warn(__FUNCTION__, fmt, ## args); } while (0)
#define DEBUG2(fmt, args...)	do { if (conf.debug > 1) warn(__FUNCTION__, fmt, ## args); } while (0)
#define DEBUG3(fmt, args...)	do { if (conf.debug > 2) warn(__FUNCTION__, fmt, ## args); } while (0)

/* btest.c */
void panic(const char *fn, char *msg, ...); 
void warn(const char *fn, char *msg, ...);

void xdump(void const *p, int size, char *msg);

extern char *prog;

uint64 saferandom64(struct drand48_data * buffer);
uint32 saferandom(struct drand48_data * buffer);

#ifdef	__cplusplus
}
#endif
#endif				/* _BTEST_H */
