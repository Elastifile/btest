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

#ifndef BTEST_EXT_H
#define BTEST_EXT_H

#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

typedef struct btest_extension {
        void (*copy)(struct btest_extension *dest, struct btest_extension *src);  /**<
                        copy ext struct utility func */

        int (*stamp_buffer)(void *buf, int len, long long offset, void *arg);      /**<
                        stamp buffer, arg is worker_ctx, return is the number of bytes used from buf, such that the
                        other possible stamp functions will not override it. */

        int (*check_buffer)(void *buf, int len, long long offset, void *arg);      /**<
                        check buffer that was previously stamped by stamp_buffer.
                        Arg is worker_ctx. return is the number of bytes used from buf, such that the
                        other possible stamp functions will not override it. */

        int (*ref_buffer)(void *buf, int len, long long offset, void *arg);      /**<
                        reference buffer before read. Function must return how many bytes will it check.
                        After read is finished check_buffer is called. Arg is worker_ctx.*/

        int (*unref_buffer)(void *buf, int len, long long offset, void *arg);      /**<
                        reference buffer before read. Function must return how many bytes will it check.
                        After read is finished check_buffer is called. Arg is worker_ctx.*/

        int (*open_failure)(const char *filename, int openflags, mode_t mode);    /**<
                        called if open failed to try to recover from it. Return an open df or -1 if failed */
} btest_extension;

/**
 * @brief initialize the extension specific struct.
 *
 * At the bare minimum, the btest_ext_init should initialize a ext copy function. If not, a trivial memcopy will be done
 * and in this case the ext_size field is mandatory.
 * 
 * @note called from the main func during init.
 */
void btest_ext_init(btest_extension *ext);

/**
 * @brief Let extensions add their options.
 *
 * @return Return the unified short str, and unified long options (ala getopt_long()) in unified_long_options.
 *
 * @note called before the main options parsing.
 */
char *btest_ext_opt_str(char *default_opt_str, struct option *long_options, struct option **unified_long_options);

/**
 * @brief Let extensions process an option.
 *
 * @return the modified (or not) options char. '\0' should be returned if no more processing is required.
 *
 * The passed ext is the main args ext struct.
 *
 * @note called from the main options parsing loop \b before the default parsing.
 */
int btest_ext_get_opt(int opt, const char const *optarg, btest_extension *ext);

/**
 * @brief Let extensions process an workload option.
 *
 * @return the modified (or not) options char. '\0' should be returned if no more processing is required.
 *
 * The passed ext is the workload args ext struct (@see parse_workload())
 *
 * @note called from the main workload options parsing loop \b before the default parsing.
 */
int btest_ext_workload_get_opt(int opt, const char const *optarg, btest_extension *ext);

/**
 * @brief cover the extention usage options (if any)
 */
void btest_ext_usage(void);

#endif /* BTEST_EXT_H */
