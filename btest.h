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

#ifdef	__cplusplus
extern "C" {
#endif

/** printf style debugging MACRO, conmmon header includes name of function */
#undef WARN
#define WARN(fmt, args...)	warn(__FUNCTION__, fmt, ## args)

/** printf style abort MACRO, conmmon header includes name of function */
#ifdef PANIC
#undef PANIC
#endif
#define PANIC(fmt, args...)	panic(__FUNCTION__, fmt, ## args)

#define DEBUG(fmt, args...)	if (debug) warn(__FUNCTION__, fmt, ## args)
#define DEBUG2(fmt, args...)	if (debug > 1) warn(__FUNCTION__, fmt, ## args)
#define DEBUG3(fmt, args...)	if (debug > 2) warn(__FUNCTION__, fmt, ## args)

/* btest.c */
void panic(const char *fn, char *msg, ...); 
void warn(const char *fn, char *msg, ...);

/* ata */

struct sector_range_s {
	uint64_t lba;
	uint64_t nsectors;
};

#define SECTOR_RANGES_MAX	(16)
//#define SECTOR_RANGES_MAX	(4096/sizeof (struct sector_range_s))
int ata_init(char *devname);
int ata_trim_sector_ranges(int fd, struct sector_range_s *ranges, int nranges);
int ata_trim_sectors(int fd, uint64_t lba, uint64_t nsectors);

extern char *prog;
extern int debug;

typedef int8_t          int8;
typedef uint8_t         uint8;
typedef int16_t         int16;
typedef uint16_t        uint16;
typedef int32_t         int32;
typedef uint32_t        uint32;
typedef int64_t         int64;
typedef uint64_t        uint64;

#ifdef	__cplusplus
}
#endif
#endif				/* _BTEST_H */
