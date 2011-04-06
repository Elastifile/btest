/*
 * Block test/exerciser utility
 *
 * Copyright (c) 2008-2009 Shahar Frank, Qumranet (Redhat)
 * Copyright (c) 2009-2010 Shahar Frank, Xtremio
 * Copyright (c) 2010 Koby Luz, Xtremio (AIO and other features)
 * Copyright (c) 2010 Gadi Oxman, Xtremio (SGIO)
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

#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "btest_ext.h"

void btest_ext_init(btest_extension *ext)
{
        memset(ext, 0, sizeof *ext);
        return;
}

char *btest_ext_opt_str(char *default_opt_str, struct option *long_options, struct option **unified_long_options)
{
        *unified_long_options = long_options;
        return default_opt_str;
}

int btest_ext_get_opt(int opt, const char const *optarg, btest_extension *ext)
{
        return opt;
}

int btest_ext_workload_get_opt(int opt, const char const *optarg, btest_extension *ext)
{
        return opt;
}

void btest_ext_usage(void)
{
}
