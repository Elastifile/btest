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

/**
 * Implementation Details
 *
 * Btest utility provides a tool for testing and benchmarking storage systems by creating workloads of read/write
 * operations on provided devices. The different options for usage of this tool are described in the usage message.
 * In this section we detail some of the implementation details of this tool in case one wants to understand or
 * modify the code. We touch several areas in this section, without any importance to their order. 
 *
 * The test supports 2 modes of operation: sync, async. Sync is the default mode, using standard OS APIs for
 * synchronous I/Os (pread, pwrite). To achieve better performance the number of threads can be enlarged. Async mode
 * is using the Linux libaio for asynchronous I/Os. To achieve better performance it is recommended to use number of
 * threads as the number of core processors and enlarge the window size. How to switch between the modes is detailed in
 * the usage message.
 *
 * To allow as much code sharing between modes as possible there are several functions that are defined as generic
 * and each mode has a different implementation for it (for example read, write, busywait, lock, etc.). The function
 * table is filled up at system initialization according to the mode chosen. 
 *
 * The I/O operations we perform are handled in 3 dimensions. First dimension is a device or file descriptor. Second
 * dimension are work-threads and third dimension is workload definition. In other words
 * for each file we work on we have one thread or more working on that file (exact number is specified by the user) and
 * each such work thread is performing one or more workloads on that file. The default is one global workload but the
 * user can specify more than one (see usage message for more details on how to do this).
 * The object types that are important to get familiar with to understand the implementation are the worker and the
 * file_ctx.
 * The worker represents one thread performing I/Os (the "second" dimension described above). Each such thread
 * is the basic unit for providing the statistics on the I/O performance that are printed during the btest operation.
 * In the sync each worker is synchornous, while in async mode each such worker is operating on a
 * "window" of async I/Os.
 * The file_ctx represents one workload that a worker thread is performing. Workload definition includes things like
 * block size offset range, as well as flavor of I/O - read or write, sequential or random. But file_ctx holds not only
 * defintion it also holds fields that are used during workload I/Os such as AIO context or I/O buffers. Each worker
 * thread can run one or more workloads. If it is running more than one it will switch between them randomly. 
 * How are the file_ctx organized in memory? We hold one array for all file_ctxs. The order in this array is according
 * to the three dimensions described above. First according to devices, then according to threads and then according
 * to workloads. For example, if we have 3 devices, 2 threads and 2 workloads, the array will look like this:
 *
 *         ------------ device 0 ----------- ---------- device 1 -------------
 *         --- thread 0 --- --- thread 1 --- --- thread 0 --- --- thread 1 ---
 *         fc_wl_0  fc_wl_1 fc_wl_0  fc_wl_1 fc_wl_0  fc_wl_1 fc_wl_0  fc_wl_1
 * index:     0         1      2        3       4        5       6        7
 *
 * So, if you are a working thread and you want to look at your workloads for a specfic device you have them consecutive
 * in th array. If you want to jump to your workloads for the next device you need to jump in the array N entries where
 * N is the nuber of devices.
 * The reason for the devices being the first dimensions is related to an implementatino assumption that relates to
 * devices initializiation. 
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <sys/syscall.h>	/* For SYS_xxx definitions */
#include <linux/fs.h>
#include <libaio.h>

#include "btest.h"
#include "sg_read.h"

#define BTEST_VERSION 1
#define xstr(s) str(s)
#define str(s) #s
#define BTEST_COMMIT xstr(COMMIT)

#define MAX_WORKLOADS   10
#define MAX_LINE_SIZE   256

/**
 * Common global variables
 */
int secs = 60;
int threads = 1;
int def_blocksize = 4 * 1024;
int stampblock;
int diff_interval = 10;
int subtotal_interval = 60;
int nfiles = 0;
char *prog;
int debug;
int rseed;
int nworkloads = 0;
int activity_check = 0;
unsigned char workload_weights[MAX_WORKLOADS * 100];
int total_workload_weights = 0;

volatile int started;
volatile int finished;
volatile int stall;

void(*th_busywait)();

/**
 * Global variables for Sync + Async
 */ 
int openflags_block = O_CREAT | O_LARGEFILE | O_NOATIME | O_SYNC;
int write_behind = 0;

#define FORMAT_IOSZ (1 << 20)
#define TRIM_FORMAT_IOSZ (10 << 20)
char formatbuf[FORMAT_IOSZ];

/**
 * Global variables for Async IO only
 */
int aio_window_size = 0;
io_context_t* aio_ctxt_array = NULL;

/**
 * Global variables for SCSI
 */
int openflags_sg = O_RDWR;

typedef enum HickupLevel {
        HICKUP_LEVEL_1_MILLI,
        HICKUP_LEVEL_2TO10_MILLI,
        HICKUP_LEVEL_11TO100_MILLI,
        HICKUP_LEVEL_101ANDUP_MILLI,
        HICKUP_LEVEL_NUM_OF
} HickupLevel;

static char* hickup_level_strings[HICKUP_LEVEL_NUM_OF] =
{
        [HICKUP_LEVEL_1_MILLI] "1ms",
        [HICKUP_LEVEL_2TO10_MILLI] "2-10ms",
        [HICKUP_LEVEL_11TO100_MILLI] "11-100ms",
        [HICKUP_LEVEL_101ANDUP_MILLI] ">100ms"
};

/**
 * Data types
 */ 
typedef struct IOStats {
	char *title;
	uint64 duration;
	uint64 sduration;	/* sync duration */
	uint64 lat;
	uint64 ops;
	uint64 bytes;
	uint64 errors;
        uint32 hickup_histogram[HICKUP_LEVEL_NUM_OF];
        uint32 max_duration;
        uint32 last_max_duration;
} IOStats;

struct shared {
        pthread_cond_t start_cond;
	pthread_mutex_t lock;

        void(*init_func)();
        void(*destroy_func)();
        void(*lock_func)();
        void(*unlock_func)();
        void(*cond_wait_func)();
        void(*cond_broadcast_func)(int n);

	int started;
        int finished; 
	IOStats total;
} shared = {PTHREAD_COND_INITIALIZER, PTHREAD_MUTEX_INITIALIZER,};

typedef struct worker_params {
	char *file;		/**< File name */
	int blocksize;		/**< IO block size */
        int seq_io_sz;          /**< Sequencial IO size in blocks. Applicable for random ratio use case - every
                                     sequencial IO will be built from this number of blocks. */
	int alignsize;		/**< IO block size */
	int randomratio;	/**< random IO ratio: 0 is pure sequential, 100 is pure random */
	int readratio;		/**< Read IO ratio: 0 is pure write, 100 pure read */
	loff_t startoffset;	/**< Offset of first byte in the IO region within the file/dev */
	uint64 len;		/**< Length of IO region (starting at 'startoffset' */
        int64 dedup_stamp_modulu; /**< Modulul stamp in this value to enlarge dedup likelihood */
        int weight;             /**< Weight of this workload in case of multiple ones */
        
      	int format;		/**< Flag: should format the IO region? */
	int trimformat;		/**< Flag: should trim the IO region of the device? */
	int trimsize;		/**< Trim block size in bytes */

        io_context_t* aio_ctxt_p; /**< AsyncIO context */
} worker_params;


typedef struct file_ctx {
	worker_params;		/**< unnamed structure - requires gcc -fms-extensions flag*/

	int num;		/**< id number of thread or file context */
        int fd;                 /**< File descriptor */
	int64 size;		/**< Total size of device/file in bytes */
	loff_t offset;		/**< Offset of next IO in bytes */
	loff_t endoffset;	/**< Offset of last byte +1 of the IO region within the file/dev */
        int atafd;		/**< fd for ATA specific opertaions, e.g. trim */
        
        /* low level IO functions */
        void *(*prepare_buf)(struct file_ctx*);
        ssize_t (*read)(struct file_ctx* ctx, int fd, void *buf, size_t count, off_t offset);
        ssize_t (*write)(struct file_ctx* ctx, int fd, void *buf, size_t count, off_t offset);

	/* Internal - Common */
	void *buf;
	struct drand48_data rbuf;
        struct timespec start_time; /**< Start time of last IO */
        struct timespec end_time;   /**< End time of last IO */
	IOStats stats;              /**< Accumulative statistics from the start */
	IOStats last;               /**< Accumulative statistics from the last diff report */
        int seq_io_count;           /**< In case seq_io_sz is not 1, we count the number of blocks we did */

        /* Internal - Sync/Async */
        pid_t tid;
        /* Internal - Async */
        void **aio_bufs;
        int aio_index;
        struct iocb** aio_batch;
        struct iocb* aio_batch_data;

        /* linked list */
	struct file_ctx *next;
} file_ctx;

typedef enum IOModel {
        IO_MODEL_INVALID = 0,
        IO_MODEL_SYNC,
        IO_MODEL_ASYNC,
} IOModel;

file_ctx *workers;
pthread_t *thread_list;
file_ctx *file_ctx_list;
int file_ctx_list_size = 0;

/**********************************************************************************************************************
 * Common Utility Functions
 **********************************************************************************************************************/
uint64 timestamp(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000000 + tv.tv_usec;
}

/**
 * Show a message and abort the probram.
 * @param fn the name of the calling function
 * @param msg printf style message string
 */
void panic(const char *fn, char *msg, ...)
{
	char buf[512];
	va_list va;
	int n;

	va_start(va, msg);
	n = vsprintf(buf, msg, va);
	va_end(va);
	buf[n] = 0;

	fflush(stdout);		/* flush stdout to ensure the stderr is last mesg */
	fprintf(stderr, "PANIC: [%s:%" PRId64 "] %s: %s%s%s\n", prog,
		timestamp(), fn, buf, errno ? ": " : "", errno ? strerror(errno) : "");

	exit(-1);
}

/**
 * Print a message to the stderr.
 * @param fn the name of the calling function
 * @param msg printf style message string
 */
void warn(const char *fn, char *msg, ...)
{
	char buf[512];
	va_list va;
	int n;

	va_start(va, msg);
	n = vsprintf(buf, msg, va);
	va_end(va);
	buf[n] = 0;

	fprintf(stderr, "[%s:%" PRId64 "]: %s: %s\n", prog, timestamp(), fn, buf);
}

uint64 parse_storage_size(char *arg)
{
	int l = strlen(arg);
	uint64 factor = 1;

	arg = strdupa(arg);
	switch (arg[l - 1]) {
	case 'G':
	case 'g':
		factor = 1 << 30;
		break;
	case 'M':
	case 'm':
		factor = 1 << 20;
		break;
	case 'K':
	case 'k':
		factor = 1 << 10;
		break;
	case 'B':
	case 'b':
		factor = 512;
		break;
	default:
		l++;
	}
	arg[l] = 0;
	return strtoull(arg, 0, 0) * factor;
}

uint64 comp_bw(IOStats * stats)
{
	if (stats->duration == 0)
		return 0;
	return (uint64) (stats->bytes * 1000000.0 / stats->duration / (1 << 10));
}

float comp_iops(IOStats * stats)
{
	if (stats->duration <= 0)
		return 0;
	return (stats->ops * 1000000.0) / stats->duration;
}

uint64 comp_lat(IOStats * stats)
{
	if (stats->ops <= 0)
		return 0;
        return stats->duration / stats->ops;
}

void stampbuffer(char *buf, int len, long long offset)
{
	char *s = buf;

	while (s - buf < len) {
		snprintf(s, len - (s - buf), "%016llx", offset);
		offset += stampblock;
		s += stampblock;
	}
}

uint64 saferandom(struct drand48_data * buffer)
{
	long int l;

	lrand48_r(buffer, &l);

	return (uint64) l;
}

void stamp_dedup(char* buf, int64 modulu, struct drand48_data * rand_buff)
{
        uint64 stamp;

        if (modulu == -1)
                return;
        
        stamp = saferandom(rand_buff);
        if (modulu > 0)
                stamp = stamp % modulu;
        memcpy(buf, &stamp, sizeof(uint64)); 
}

void summary(char *title, IOStats * stats)
{
        uint i;
        
	printf("%s: %.3f seconds, %.3f iops, avg latency %"
	       PRIu64 " usec, bandwidth %" PRIu64 " KB/s, errors %" PRIu64
	       "\n", title, stats->duration * 1.0 / (double) 1000000.0, comp_iops(stats), stats->lat,
	       comp_bw(stats), stats->errors);

        /* latency histograms are not supported in async mode */
        if (aio_window_size == 0) {
                printf("%s: %.3f seconds, %u max_latency, hickups levels:",
                       title,
                       stats->duration * 1.0 / (double) 1000000.0,
                       stats->max_duration);
                for (i = 0; i < HICKUP_LEVEL_NUM_OF; i++)
                        printf(" %s: %u", hickup_level_strings[i], stats->hickup_histogram[i]);
                printf("\n");
        }
        fflush(stdout);
}

char *randomratio_str(int ratio, char *buf)
{
	if (ratio == 0)
		return "S";
	if (ratio == 100)
		return "R";
	else
		sprintf(buf, "%d", ratio);
	return buf;
}

char *readratio_str(int ratio, char *buf)
{
	if (ratio == 0)
		return "W";
	if (ratio == 100)
		return "R";
	else
		sprintf(buf, "%d", ratio);
	return buf;
}

void worker_subtotal(IOStats * stats, char *title, int n)
{
        uint i;
        
	printf("%s: %d threads, %.3f seconds (%.3f), %.3f"
	       " iops, avg latency %" PRIu64 " usec, bandwidth %" PRIu64
	       " KB/s, errors %" PRIu64 "\n",
	       title, n,
	       stats->duration * 1.0 / (double) 1000000.0 / n,
	       stats->sduration * 1.0 / (double) 1000000.0,
	       comp_iops(stats) * n, comp_lat(stats), comp_bw(stats) * n, stats->errors);

        /* latency histograms are not supported in async mode */
        if (aio_window_size == 0) {
                printf("%s: %d threads, %.3f seconds (%.3f), %u max_latency, hickups levels:",
                       title, n,
                       stats->duration * 1.0 / (double) 1000000.0 / n,
                       stats->sduration * 1.0 / (double) 1000000.0,
                       stats->max_duration);
                for (i = 0; i < HICKUP_LEVEL_NUM_OF; i++)
                        printf(" %s: %u", hickup_level_strings[i], stats->hickup_histogram[i]);
                printf("\n");
        }
}

uint64 worker_summary_diff(file_ctx * arg, IOStats * subtotal)
{
	IOStats *stats = &arg->stats;
	IOStats *last = &arg->last;
	IOStats diff;
        uint i;
        
	if (last) {
		diff = *stats;
		diff.duration = diff.duration - last->duration;
		diff.ops = diff.ops - last->ops;
		diff.lat = comp_lat(&diff);
		diff.errors = diff.errors - last->errors;
		diff.bytes = diff.bytes - last->bytes;
                for (i = 0; i < HICKUP_LEVEL_NUM_OF; i++)
                        diff.hickup_histogram[i] = diff.hickup_histogram[i] - last->hickup_histogram[i]; 
                diff.max_duration = diff.last_max_duration;                
		*last = *stats;
                stats->last_max_duration = 0;
		stats = &diff;
	}
	if (subtotal) {
		subtotal->duration += stats->duration;
		subtotal->sduration = arg->stats.duration;
		subtotal->ops += stats->ops;
		subtotal->bytes += stats->bytes;
		subtotal->errors += stats->errors;
                for (i = 0; i < HICKUP_LEVEL_NUM_OF; i++)
                        subtotal->hickup_histogram[i] += stats->hickup_histogram[i];
                if (stats->max_duration > subtotal->max_duration)
                        subtotal->max_duration = stats->max_duration; 
	}
	printf("Thread %d: %s %s %s %d %" PRIu64 " %" PRIu64
	       ": last %.3f seconds (%.3f), %.3f" " iops, avg latency %"
	       PRIu64 " usec, bandwidth %" PRIu64 " KB/s, errors %" PRIu64
	       "\n", arg->num, arg->file, randomratio_str(arg->randomratio,
							  alloca(8)),
	       readratio_str(arg->readratio, alloca(8)), arg->blocksize,
	       arg->startoffset, arg->endoffset,
	       stats->duration * 1.0 / (double) 1000000.0,
	       arg->stats.duration * 1.0 / (double) 1000000.0,
	       comp_iops(stats), stats->lat, comp_bw(stats), stats->errors);

        return stats->ops; 
}

void worker_summary(file_ctx * arg, IOStats * subtotal)
{
	IOStats *stats = &arg->stats;
        uint i;

	stats->lat = comp_lat(stats);
	if (subtotal) {
		subtotal->duration += stats->duration;
		subtotal->sduration = arg->stats.duration;
		subtotal->ops += stats->ops;
		subtotal->bytes += stats->bytes;
		subtotal->errors += stats->errors;
                for (i = 0; i < HICKUP_LEVEL_NUM_OF; i++)
                        subtotal->hickup_histogram[i] += stats->hickup_histogram[i];
                if (stats->max_duration > subtotal->max_duration)
                        subtotal->max_duration = stats->max_duration; 
	}
	printf("Thread %d: %s %s %s %d %" PRIu64 " %" PRIu64
	       ": %.3f seconds, %.3f" " iops, avg latency %" PRIu64
	       " usec, bandwidth %" PRIu64 " KB/s, errors %" PRIu64 "\n",
	       arg->num, arg->file, randomratio_str(arg->randomratio,
						    alloca(8)),
	       readratio_str(arg->readratio, alloca(8)), arg->blocksize,
	       arg->startoffset, arg->endoffset,
	       stats->duration * 1.0 / (double) 1000000.0,
	       comp_iops(stats), stats->lat, comp_bw(stats), stats->errors);
}

void dostats(int sig)
{
	IOStats subtotal = { 0 };
	file_ctx *worker;
	int n = 0;

        shared.lock_func(); 
	for (worker = workers; worker; worker = worker->next, n++)
		worker_summary(worker, &subtotal);
	shared.unlock_func();
	worker_subtotal(&subtotal, "Subtotal", n);
	fflush(stdout);
}

void dostats_diff(int sig)
{
	IOStats subtotal = { 0 };
	file_ctx *worker;
	int n = 0, n_idle = 0;
        
	shared.lock_func(); 
	for (worker = workers; worker; worker = worker->next, n++) {
		if (worker_summary_diff(worker, &subtotal) == 0)
                        n_idle++; 
        }
	shared.unlock_func();
	worker_subtotal(&subtotal, "Subtotal (diff)", n);
	fflush(stdout);

        if (activity_check && n_idle >= n) {
                printf("All %d workers are idle in the last interval - exiting", n);
                exit(1); 
        }
}

void update_shared_stats(IOStats *stats)
{
        uint i; 
        shared.lock_func(); 
        shared.finished++;
        shared.total.errors += stats->errors;
        shared.total.ops += stats->ops;
        shared.total.duration += stats->duration;
        shared.total.bytes += stats->bytes;
        shared.total.lat += stats->lat;
        for (i=0; i<HICKUP_LEVEL_NUM_OF; i++)
                shared.total.hickup_histogram[i] += stats->hickup_histogram[i];
        if (stats->max_duration > shared.total.max_duration)
                shared.total.max_duration = stats->max_duration; 
        shared.unlock_func();
}

int start(int n)
{
	time_t t;

	shared.lock_func();
	while (n > shared.started) {
		DEBUG("wait: n %d started %d", n, shared.started);
		shared.unlock_func();
		th_busywait();
		shared.lock_func();
	}
	shared.unlock_func();

	time(&t);
	printf("%d threads are ready, starting test at %s", n, ctime(&t));
	shared.cond_broadcast_func(n);
        started = 1;
	return 0;
}

void flush()
{
	file_ctx *w;
	struct timespec t1, t2;
	IOStats *stats;

	for (w = workers; w; w = w->next) {
                int wl, ctxno;

		stats = &w->stats;
		clock_gettime(CLOCK_REALTIME, &t1);
                ctxno = w->num * nworkloads;
                for (wl = 0; wl < nworkloads; wl++) {
                        file_ctx *ctx = &(file_ctx_list[ctxno + wl]);

                        fsync(ctx->fd);
                        close(ctx->fd);
                }
		clock_gettime(CLOCK_REALTIME, &t2);
		stats->sduration =
		    (t2.tv_sec - t1.tv_sec) * 1000000llu + (t2.tv_nsec - t1.tv_nsec) / 1000.0;
		shared.total.sduration += stats->sduration;
	}
}

int finish(int n)
{
        shared.lock_func();
	while (n > shared.finished) {
		DEBUG("wait: n %d finished %d", n, shared.finished);
		shared.unlock_func();
		th_busywait();
		shared.lock_func();
	}
	shared.unlock_func();

	shared.total.duration /= n;
	shared.total.lat /= n;
	return 0;
}

void exit_signal(int sig)
{
        finished = 1;
}

void doexit()
{
	time_t t;

	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);
	finish(shared.started);
	summary("Total", &shared.total);
	if (write_behind) {
		flush();
		shared.total.duration += shared.total.sduration;
		shared.total.lat = shared.total.duration / shared.total.ops;
		summary("Synced", &shared.total);
	}
	time(&t);
	printf("Test is done at %s", ctime(&t));

        if (!stall) {
                exit(0);
        }
}

void check_interval_ratio(void)
{
	int ratio;

	if (!diff_interval || !subtotal_interval)
		return;
	ratio = subtotal_interval / diff_interval;
	if (diff_interval * ratio != subtotal_interval)
		PANIC
		    ("subtotal report interval %d must be a factor off diff interval %d\n",
		     subtotal_interval, diff_interval);
}

void disable_signals()
{
	signal(SIGTERM, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);
}

void enable_signals()
{
	signal(SIGTERM, exit_signal);
	signal(SIGINT, exit_signal);
	signal(SIGUSR1, dostats);
	signal(SIGUSR2, dostats_diff);
}

void realtime_reports(int left)
{
	struct timespec duration = {0}, remaining = {0};
	int ratio = 0, diffs = 0;
	int tick;

	if (diff_interval > 0 && diff_interval < left) {
		tick = diff_interval;
		ratio = subtotal_interval / diff_interval;
	} else if (subtotal_interval > 0 && subtotal_interval < left) {
		tick = subtotal_interval;
		ratio = 1;
	} else {
		tick = left;
		ratio = 0;
	}

	for (; left > 0; left -= tick) {

		if (tick > left)
			tick = left;
		duration.tv_sec = tick;

                if (finished) {
                        break;
                }

		while (nanosleep(&duration, &remaining) < 0)
			duration = remaining;

		if (left == tick)
			break;	/* no need for report, the Summary report is printed upon exit */

		disable_signals();
		if (diff_interval >= 0) {
			dostats_diff(0);
			diffs++;
		}
		if (ratio && !(diffs % ratio))
			dostats(0);

		enable_signals();
	}
}

int get_rand_workloadno(file_ctx* ctx)
{
        int workloadno = (saferandom(&ctx->rbuf)) % total_workload_weights;
        workloadno = workload_weights[workloadno];
        if ((workloadno < 0) || (workloadno > nworkloads)) {
                PANIC("reached invalids workloadno value %d", workloadno);
        }
        return workloadno;
}

/**********************************************************************************************************************
 * Shared Sync - Sync/Async
 **********************************************************************************************************************/
void sync_shared_init()
{
        /* NOP */
}

void sync_shared_destroy()
{
        /* NOP */
}

void sync_lock()
{
	pthread_mutex_lock(&(shared.lock));
}

void sync_unlock()
{
	pthread_mutex_unlock(&(shared.lock));
}

void sync_cond_wait_func()
{
        pthread_cond_wait(&shared.start_cond, &shared.lock);
}

void sync_cond_broadcast_func(int n)
{
       	pthread_cond_broadcast(&shared.start_cond);
}

/**********************************************************************************************************************
 * Thread sleep - Sync/Async IO
 **********************************************************************************************************************/
void sync_th_busywait()
{
        sleep(1); 
}


/**********************************************************************************************************************
 * IO Functions - AsyncIO
 **********************************************************************************************************************/
void *aio_prepare_buf(file_ctx* ctx)
{
        struct iocb* aio_iocb;
        void *aio_buf;

        aio_buf = ctx->aio_bufs[ctx->aio_index];
        aio_iocb = &(ctx->aio_batch_data[ctx->aio_index]);
        ctx->aio_batch[ctx->aio_index] = aio_iocb;
        return aio_buf;
}

ssize_t aio_read(file_ctx* ctx, int fd, void *buf, size_t count, off_t offset)
{
        struct iocb* aio_iocb = &(ctx->aio_batch_data[ctx->aio_index]);
        int res;

        io_prep_pread(aio_iocb, fd, buf, count, offset);
        /* data field must be set after the io_prep call because the last clears the strucutre */
        aio_iocb->data = (void*)ctx;

        res = io_submit(*(ctx->aio_ctxt_p),
                        1,
                        &(ctx->aio_batch[ctx->aio_index]));

        ctx->aio_index = (ctx->aio_index + 1) % aio_window_size;

        if (res < 0) {
                WARN("AyncIO submittion failed (%d requests). rc=%d %s \n", 1, res, strerror(-res));
                return -1;
        }

        return count;
}

ssize_t aio_write(file_ctx* ctx, int fd, void *buf, size_t count, off_t offset)
{
        struct iocb* aio_iocb = &(ctx->aio_batch_data[ctx->aio_index]);
        int res;

        io_prep_pwrite(aio_iocb, fd, buf, count, offset);
        /* data field must be set after the io_prep call because the last clears the strucutre */
        aio_iocb->data = (void*)ctx;

        res = io_submit(*(ctx->aio_ctxt_p),
                        1,
                        &(ctx->aio_batch[ctx->aio_index]));

        ctx->aio_index = (ctx->aio_index + 1) % aio_window_size;

        if (res < 0) {
                WARN("AyncIO submittion failed (%d requests). rc=%d %s \n", 1, res, strerror(-res));
                return -1;
        }

        return count;
}

/**********************************************************************************************************************
 * IO Functions - SyncIO
 **********************************************************************************************************************/
void *sync_prepare_buf(file_ctx* ctx)
{
        return ctx->buf;
}

ssize_t sync_read(file_ctx* ctx, int fd, void *buf, size_t count, off_t offset)
{
        return pread(fd, buf, count, offset);
}

ssize_t sync_write(file_ctx* ctx, int fd, void *buf, size_t count, off_t offset)
{
        return pwrite(fd, buf, count, offset);
}

ssize_t sg_read(file_ctx* ctx, int fd, void *buf, size_t count, off_t offset)
{
        if (sg_rw(fd, 0, buf, count/512, offset/512, 512, 10, 0, 0, NULL, 0, 0) == 0)
		return count;
	return -1;
}

ssize_t sg_write(file_ctx* ctx, int fd, void *buf, size_t count, off_t offset)
{
        if (sg_rw(fd, 1, buf, count/512, offset/512, 512, 10, 0, 0, NULL, 0, 0) == 0)
		return count;
	return -1;
}

/**********************************************************************************************************************
 * Sync/Async IO Utility functions
 **********************************************************************************************************************/
int gettid(void)
{
	return syscall(__NR_gettid);
}

static int64_t blockdev_getsize(int fd)
{
	int64_t b;
	long sz;
	int err;

	err = ioctl(fd, BLKGETSIZE, &sz);
	if (err)
		return err;

	err = ioctl(fd, BLKGETSIZE64, &b);
	if (err || b == 0 || b == sz)
		b = sz << 9;
	return b;
}

static int64_t getsize(int is_sg, int fd, uint64_t requested, int doformat)
{
	struct stat st;

	if (is_sg)
		return sg_getsize(fd);

	if (fstat(fd, &st) < 0) {
		WARN("fstat failed: %m");
		return -1;
	}

	if (S_ISBLK(st.st_mode))
		return blockdev_getsize(fd);

	if (S_ISREG(st.st_mode)) {
		if (st.st_size >= requested)
			return st.st_size;
		/*
		* if format is requested, and the object is a file,
		* extend its size to the requested offs+len
		*/
		if (doformat)
			return requested;
		return st.st_size;
	}

	WARN("unsupported file type");
	return -1;
}

int do_rand_trim(file_ctx * arg)
{
	uint64_t trimoffset = saferandom(&arg->rbuf) * arg->trimsize;
	struct sector_range_s ranges[SECTOR_RANGES_MAX];
	int left = arg->blocksize;
	int r;

	while (left > 0) {
		for (r = 0; r < SECTOR_RANGES_MAX && left > 0; r++) {
			trimoffset = saferandom(&arg->rbuf) * arg->alignsize;
			if (trimoffset + arg->trimsize > arg->endoffset)
				trimoffset = arg->startoffset + trimoffset % (arg->endoffset -
						      arg->startoffset - arg->trimsize);
			DEBUG3("file %s fd %d trim at offset %"PRId64" size %d",
                                arg->file, arg->fd, arg->offset, arg->trimsize);
			ranges[r].lba = trimoffset / 512;
			ranges[r].nsectors = arg->trimsize / 512;
			left -= arg->trimsize;
		}
		if (ata_trim_sector_ranges(arg->atafd, ranges, r) < 0) {
			WARN("file %s trim (%d ranges) failed on atafd %d", arg->file, r, arg->atafd);
			return -1;
		}
	}
	return 0;
}

void do_format(char *file, uint64_t start, uint64_t size)
{
	int ios = 0;
	int iosize;
	int fd;
	int is_sg;

	is_sg = sg_is_sg(file);

	if ((fd = open(file, O_RDWR | O_CREAT | O_LARGEFILE | O_NOATIME, 0600)) < 0)
		PANIC("open '%s' failed", file);

	printf("Start formating %s at %" PRId64 ", %" PRId64 " bytes:", file, start, size);
	while (size) {
		iosize = FORMAT_IOSZ;
		if (iosize > size)
			iosize = size;
		DEBUG("format IO: %s offs %" PRId64 " iosize %d", file, start, iosize);
                if (is_sg) {
                        if (sg_write(NULL, fd, formatbuf, iosize, start) != iosize)
                                PANIC("io failed on %s during format offset %" PRId64, file, start);
                } else {
                        if (sync_write(NULL, fd, formatbuf, iosize, start) != iosize)
                                PANIC("io failed on %s during format offset %" PRId64, file, start);
                }
		size -= iosize;
		start += iosize;
		ios++;
		if (!(ios % (1 << 10))){
			printf(".");
			fflush(stdout);
		}
	}

	printf(" - done.\n");
	fflush(stdout);

	fsync(fd);
	close(fd);
}

void do_trimformat(int atafd, uint64_t start, int64_t size)
{
	int ios = 0;
	int iosize = TRIM_FORMAT_IOSZ;

	fsync(atafd);
	sync();

	printf("Start trimming fd %d at %" PRId64 ", %" PRId64 " bytes:", atafd, start, size);
	while (size > 0) {
		if (iosize > size)
			iosize = size;
		DEBUG("format Trim IO: fd %d offs %" PRId64 " iosize %d", atafd, start, iosize);
		if (ata_trim_sectors(atafd, start / 512, iosize / 512) < 0)
			PANIC("trim failed on fd %d during format offset %" PRId64, atafd, start);
		size -= iosize;
		start += iosize;
		ios++;
		if (!(ios % (1 << 10))) {
			printf(".");
			fflush(stdout);
		}
	}

	printf(" - done.\n");
	fflush(stdout);

	fsync(atafd);
}

/**********************************************************************************************************************
 * IO Functions Common 
 **********************************************************************************************************************/
static void calc_dedup_stamp_modulu(file_ctx *arg)
{
        if (arg->dedup_stamp_modulu > 0)
                arg->dedup_stamp_modulu = (int64)(((double)arg->len) / ((double)arg->dedup_stamp_modulu));
}


/**
 * Offset resoluton functions
 */
uint64 next_seq_offset(file_ctx *arg)
{
       /* wrap around */
       if (arg->offset + arg->blocksize > arg->endoffset)
		return arg->startoffset;
       return arg->offset;
}

uint64 next_rand_offset(file_ctx *arg)
{
        uint64 offset = saferandom(&arg->rbuf) * arg->alignsize;

	if (offset + arg->blocksize > arg->endoffset)
		offset = arg->startoffset + offset %
                                (arg->endoffset - arg->startoffset - arg->blocksize);
        return offset;
}

/*
 * IO Logic functions
 */
int do_seq_read(file_ctx * arg)
{
        void *buf;

	arg->offset = next_seq_offset(arg);
        buf = arg->prepare_buf(arg);

	DEBUG3("file %s fd %d seek to offset %" PRIu64, arg->file, arg->fd, arg->offset);
	if (arg->read(arg, arg->fd, buf, arg->blocksize, arg->offset) != arg->blocksize)
		return -1;
	arg->offset += arg->blocksize;

	return 0;
}

int do_seq_write(file_ctx * arg)
{
        void *buf;

	arg->offset = next_seq_offset(arg);
        buf = arg->prepare_buf(arg);

        stamp_dedup(buf, arg->dedup_stamp_modulu, &arg->rbuf);
	if (stampblock)
		stampbuffer(buf, arg->blocksize, arg->offset);

	DEBUG3("file %s fd %d seek to offset %" PRIu64, arg->file, arg->fd, arg->offset);
	if (arg->write(arg, arg->fd, buf, arg->blocksize, arg->offset) != arg->blocksize)
		return -1;
	arg->offset += arg->blocksize;
        
	return 0;
}

int do_rand_read(file_ctx * arg)
{
        void *buf;

	arg->offset = next_rand_offset(arg);
        buf = arg->prepare_buf(arg);

	DEBUG3("file %s fd %d seek to offset %" PRIu64, arg->file, arg->fd, arg->offset);
	if (arg->read(arg, arg->fd, buf, arg->blocksize, arg->offset) != arg->blocksize)
		return -1;
	arg->offset += arg->blocksize;

	return 0;
}

int do_rand_write(file_ctx * arg)
{
        void *buf;

	arg->offset = next_rand_offset(arg);
        buf = arg->prepare_buf(arg);

        stamp_dedup(buf, arg->dedup_stamp_modulu, &arg->rbuf); 
	if (stampblock)
		stampbuffer(arg->buf, arg->blocksize, arg->offset);

	DEBUG3("file %s fd %d seek to offset %" PRIu64, arg->file, arg->fd, arg->offset);
	if (arg->write(arg, arg->fd, buf, arg->blocksize, arg->offset) != arg->blocksize)
		return -1;
	arg->offset += arg->blocksize;

	return 0;
}

/**
 * @brief Main function for single IO operation - Sync/Async 
 * This function decide which of the IO logic function is should call: read/write, random/sequential.
 * @return staus (0 OK, -1 error)
 */
int do_io(file_ctx * arg)
{
	int (*io) (struct file_ctx *) = NULL;
	int doread = 0, dorandom = 0;

	if (arg->readratio == 100)
		doread = 1;
	else if (arg->readratio == 0)
		doread = 0;
	else
		doread = (saferandom(&arg->rbuf) % 100) < arg->readratio;

	if (arg->randomratio == 100)
		dorandom = 1 << 1;
	else if (arg->randomratio == 0)
		dorandom = 0 << 1;
	else {
                int seq = 0;

                if (arg->seq_io_count >= arg->seq_io_sz)
                        PANIC("Internal error: seq_io_count %d larger than seq_io_sz.",
                                arg->seq_io_count, arg->seq_io_sz);

                if (arg->seq_io_count == 0) {
                        /* we are not in the "middle" of an sequencial big block - random decision */
                        seq = ((saferandom(&arg->rbuf) % 100) < arg->randomratio) ? 0 : 1;
                } else {
                        /* we are in the midst of a sequencial big block */
                        seq = 1;
                }

                if (seq) {
                        dorandom = 0 << 1;

                        arg->seq_io_count++;
                        if (arg->seq_io_count == arg->seq_io_sz) {
                                arg->seq_io_count = 0;
                        }
                } else {
                        dorandom = 1 << 1;
                }
        }

	switch (doread | dorandom) {
	case 0:
		DEBUG3("%s %d: seq write: block size %d", arg->file, arg->tid, arg->blocksize);
		io = do_seq_write;
		break;
	case 1:
		DEBUG3("%s %d: seq read: block size %d", arg->file, arg->tid, arg->blocksize);
		io = do_seq_read;
		break;
	case 2:
		DEBUG3("%s %d: random write: block size %d", arg->file, arg->tid, arg->blocksize);
		io = do_rand_write;
		break;
	case 3:
		DEBUG3("%s %d: random read: block size %d", arg->file, arg->tid, arg->blocksize);
		io = do_rand_read;
		break;
	}

	return io(arg);
}

/**********************************************************************************************************************
 * Sync + Async IO init 
 **********************************************************************************************************************/
void init_file_ctx(worker_params *params, file_ctx *arg)
{
        static char *lastfile = 0;
	uint64_t requested_size;
	int fd = 0;
	int is_sg;
        int openflags;

        openflags_block |= (params->readratio == 100) ? O_RDONLY : O_RDWR;

        is_sg = sg_is_sg(params->file);
        openflags = is_sg ? openflags_sg : openflags_block;
        openflags = openflags_block;
        
        DEBUG("open flags: 0x%x", openflags);
        if ((fd = open(params->file, openflags, 0600)) < 0)
                PANIC("open '%s' failed", params->file);

	/* copy params to worker context - assume params in first field in context */
	*(worker_params *)arg = *params;

        arg->fd = fd;
        arg->file = strdup(params->file);

        /* calc the expected minimal dev/file size */
        requested_size = arg->startoffset + params->len;

        arg->trimsize = params->trimsize < params->blocksize ? params->trimsize : params->blocksize;

        /*
         * If the file/device size is 0 and we are doing only writes or format is requested
         * we assume that the size can be resize to requested size, if the device supports it.
         */
        if ((arg->size = getsize(is_sg, fd, requested_size, params->format || params->readratio == 0))
                                  < arg->startoffset)
                PANIC("can't get size of '%s' sz %"PRId64", or size < start offset %"PRId64,
                        params->file, arg->size, arg->startoffset);

        if (arg->len == 0 && arg->size > arg->startoffset + arg->blocksize)
                arg->len = arg->size - arg->startoffset;

        arg->endoffset = arg->startoffset + arg->len;
        if (arg->size < arg->endoffset)
                PANIC("size of '%s' - %"PRId64 " is smaller then end offset %"PRId64"\n",
                        params->file, arg->size, arg->endoffset);

        DEBUG("'%s' size is %" PRId64 " using blocksize %d aligned to %d",
                params->file, arg->size, arg->blocksize, arg->alignsize);

        if (arg->trimsize)
                DEBUG("'%s' trim  %d random bytes after each write using trim block size %d",
                        params->file, arg->blocksize, arg->trimsize);

        if (!params->format && arg->endoffset - arg->startoffset < arg->blocksize)
                PANIC("file '%s' is too small, min size is one block (%d)", arg->file, arg->blocksize);

        if (arg->endoffset > arg->size)
                PANIC("file '%s' offset %" PRId64
                      " is out of file/device size range (%" PRId64 ")",
                      params->file, arg->endoffset, arg->size);

        calc_dedup_stamp_modulu(arg);

        /* Make only first thread to operate on a specific file/dev to do the format/trim.
         * Note that this assume that all threads operating on a specific file are created
         * one after another in one sequence
         */
        if ((lastfile == NULL) || (strcmp(lastfile, params->file) != 0)) {
                arg->atafd = -1;
                /* ata fd must be initialized for format or real time trim */
                if (arg->trimformat || arg->trimsize)
                        arg->atafd = ata_init(arg->file);

                if (arg->trimformat)
                        do_trimformat(arg->atafd, arg->startoffset, arg->endoffset - arg->startoffset);

                if (arg->format)
                        do_format(arg->file, arg->startoffset, arg->endoffset - arg->startoffset);
        }
        lastfile = params->file;
}

/**********************************************************************************************************************
 * Worker main and init - AsyncIO
 **********************************************************************************************************************/
void* aio_worker(file_ctx * arg)
{
	IOStats *stats = &arg->stats;
        int i, ctxno, workloadno;
        int aiores;
        int inflight_ios_count = 0;
        int total_ios_count = 0;
        struct io_event *events = calloc(aio_window_size * file_ctx_list_size, sizeof(struct io_event));
        struct io_event *event;
        struct iocb *completed_iocb; 
        file_ctx* ctx; 

	arg->tid = gettid();

        if (aio_window_size == 0)
                PANIC("AsyncIO completion thread started and window size is 0");

	/* Init worker seed */
	srand48_r(rseed + arg->num * 10, &arg->rbuf);

        shared.lock_func(); 
	shared.started++;
	shared.cond_wait_func(); 
        shared.unlock_func(); 

        clock_gettime(CLOCK_REALTIME, &(arg->start_time));

        /* bootstrap - set the random seed to file_ctx */
        for (ctxno = arg->num * nworkloads; ctxno < file_ctx_list_size; ctxno += (threads * nworkloads)) {
                for (workloadno = 0; workloadno < nworkloads; workloadno++) {
                        ctx = &(file_ctx_list[ctxno + workloadno]);

                        srand48_r(rseed + (ctxno + workloadno) * 1000, &ctx->rbuf);
                }
        }

        /* bootstrap - send window size IOs on all file */
        for (ctxno = arg->num * nworkloads; ctxno < file_ctx_list_size; ctxno += (threads * nworkloads)) {
                for (i = 0; i < aio_window_size; i++) {
                        if (nworkloads == 1) {
                                workloadno = 0;
                        } else {
                                workloadno = get_rand_workloadno(arg);
                        }
                        
                        ctx = &(file_ctx_list[ctxno + workloadno]);
                        if (do_io(ctx) < 0) {
                                WARN("%d: IO error on '%s': %m", ctx->tid, ctx->file);
                                stats->errors++;
                                continue;
                        }
                        inflight_ios_count++;
                        total_ios_count++;
                }
        }

        /* start completion loop, and trade each completed IO with a new IO */
        while (inflight_ios_count > 0) {
                aiores = io_getevents(*(arg->aio_ctxt_p),
                                      1 /* min events */,
                                      aio_window_size * file_ctx_list_size /* max events */,
                                      events,
                                      NULL /* timeout */);
                if (aiores <= 0)
                        PANIC("AsyncIO io_getevents failed with error: %d (%s)", aiores, strerror(-aiores));

                inflight_ios_count -= aiores;

                /* TODO - howto calc stats now when we have workloads with different block size??? */
                clock_gettime(CLOCK_REALTIME, &(arg->end_time));
                stats->duration +=
                    (arg->end_time.tv_sec - arg->start_time.tv_sec) * 1000000llu +
                    (arg->end_time.tv_nsec - arg->start_time.tv_nsec) / 1000.0;
                stats->ops = total_ios_count - inflight_ios_count;
                stats->bytes = (stats->ops * arg->blocksize);
                clock_gettime(CLOCK_REALTIME, &(arg->start_time));

                for (i = 0, event = events; i < aiores; i++, event++) {
                        completed_iocb = (struct iocb *)event->obj;
                        ctx = (file_ctx*)event->data;

                        if ((completed_iocb == NULL) || (ctx == NULL)) {
                                PANIC("AyncIO completion no data - event %d out of %d.", i, aiores);
                                continue;
                        }

                        /* verify the IO result code and size */
                        if (event->res2 != 0 || event->res != completed_iocb->u.c.nbytes) {
                                WARN("%d: IO error on '%s (event %d out of %d). return code %d. number of bytes "
                                        "processed is %d out of %d.",
                                        ctx->tid, ctx->file, i, aiores,
                                        event->res2, event->res, completed_iocb->u.c.nbytes);
                        }

                        if ((ctx->fd != completed_iocb->aio_fildes) || (ctx->blocksize != completed_iocb->u.c.nbytes)) {
                                WARN("AsyncIO completion mismatch (event %d out of %d): fd is %d, expected %d. "
                                        "blocksize is %d expected %d",
                                        i, aiores,
                                        completed_iocb->aio_fildes, ctx->fd,
                                        completed_iocb->u.c.nbytes, ctx->blocksize);
                        }

                        /*printf("-- AsyncIO completion details: fd=%d buf=%p nbytes=%d offset=%d. rc=%d nbytes=%d. \n",
                                completed_iocb->aio_fildes, completed_iocb->u.c.buf, completed_iocb->u.c.nbytes,
                                completed_iocb->u.c.offset,
                                event->res2, event->res);*/

                        if (finished)
                                continue;

                        /* send another io */
                        if (nworkloads > 1) {
                                workloadno = get_rand_workloadno(arg);
                                ctx -= (ctx->num % nworkloads); 
                                ctx += workloadno;
                        }
                        if (do_io(ctx) < 0) {
                                WARN("%d: IO error on '%s': %m", ctx->tid, ctx->file);
                                stats->errors++;
                                continue;
                        }
                        inflight_ios_count++;
                        total_ios_count++;
                }
        }

        stats->lat = comp_lat(stats);

        worker_summary(arg, 0);

        update_shared_stats(stats);

	return 0;
}

void init_aio_file_ctx(file_ctx *arg)
{
        int bufnum;

        if (!(arg->aio_bufs = (void**)calloc(aio_window_size, sizeof(void*))))
                PANIC("can't alloc buf pointers sized %d ", aio_window_size);

        for (bufnum = 0; bufnum < aio_window_size; bufnum++) {
                if (!(arg->aio_bufs[bufnum] = (void*)valloc(arg->blocksize)))
                            PANIC("can't alloc buf sized %d bytes", arg->blocksize);
                memset(arg->aio_bufs[bufnum], 0, arg->blocksize);
        }

        if (!(arg->aio_batch = (struct iocb **)calloc(aio_window_size, sizeof(struct iocb*))))
                PANIC("no mem for AsyncIO batch array (%d contextes)", aio_window_size);

        if (!(arg->aio_batch_data = (struct iocb *)calloc(aio_window_size, sizeof(struct iocb))))
                PANIC("no mem for AsyncIO batch array (%d contextes)", aio_window_size);

        arg->aio_index = 0;

        arg->prepare_buf = aio_prepare_buf;
        arg->read = aio_read;
        arg->write = aio_write;
}

pthread_t new_aio_dispatcher(worker_params *params)
{
       	static int num = 0;
        file_ctx *arg;
      	pthread_t thid = 0;

      	if (!(arg = calloc(1, sizeof *arg)))
		PANIC("out of mem - alloc arg");

	/* copy params to worker context - assume params in first field in context */
	*(worker_params *)arg = *params;

        shared.lock_func(); 
        arg->next = workers;
        arg->num = num++;
        workers = arg;
        shared.unlock_func();

        if (pthread_create(&thid, NULL, (void *(*)(void *))aio_worker, arg))
                PANIC("AIO dispatcher thread creation failed");

        DEBUG("thread %d created", thid);
	return thid;
}

void new_aio_file_ctx(worker_params *params, int file_ctx_ix)
{
        file_ctx *ctx = &(file_ctx_list[file_ctx_ix]);
        ctx->num = file_ctx_ix; 
        init_file_ctx(params, ctx);
        init_aio_file_ctx(ctx);
}

/**********************************************************************************************************************
 * Worker main and init - sync IO
 **********************************************************************************************************************/
void* sync_worker(file_ctx * arg)
{
	IOStats *stats = &arg->stats;
        file_ctx* ctx; 
        int ctxno, workloadno;        
        uint64 duration, duration_milli;
        
	arg->tid = gettid();

	/* Init worker seed */
	srand48_r(rseed + arg->num * 10, &arg->rbuf);

	DEBUG("%d: starting worker thread on '%s' using rseed %d",
                      arg->tid, arg->file, rseed + arg->num * 10);

        shared.lock_func(); 
	shared.started++;
	shared.cond_wait_func(); 
        shared.unlock_func(); 

        /* bootstrap - set the random seed to file_ctx */
        ctxno = arg->num * nworkloads; 
        for (workloadno = 0; workloadno < nworkloads; workloadno++) {
                ctx = &(file_ctx_list[ctxno + workloadno]);

                srand48_r(rseed + (ctxno + workloadno) * 1000, &ctx->rbuf);
        }

        while (!finished) {
                if (nworkloads == 1) {
                        workloadno = 0;
                } else {
                        workloadno = get_rand_workloadno(arg);
                }
                ctx = &(file_ctx_list[ctxno + workloadno]);
                
                clock_gettime(CLOCK_REALTIME, &(arg->start_time));
                if (do_io(ctx) < 0) {
                        //if (debug)
                        WARN("%d: IO error on '%s': %m", arg->tid, arg->file);
                        stats->errors++;
                        continue;
                }
                clock_gettime(CLOCK_REALTIME, &(arg->end_time));

                duration = (arg->end_time.tv_sec - arg->start_time.tv_sec) * 1000000llu +
                           (arg->end_time.tv_nsec - arg->start_time.tv_nsec) / 1000.0;
                if (duration > stats->max_duration) 
                        stats->max_duration = duration;
                if (duration > stats->last_max_duration)
                        stats->last_max_duration = duration;
                duration_milli = duration / 1000;
                if (duration_milli == 1)
                        stats->hickup_histogram[HICKUP_LEVEL_1_MILLI]++;
                else if ((duration_milli >= 2) && (duration_milli <= 10))
                        stats->hickup_histogram[HICKUP_LEVEL_2TO10_MILLI]++;
                else if ((duration_milli >= 11) && (duration_milli <= 100))
                        stats->hickup_histogram[HICKUP_LEVEL_11TO100_MILLI]++;
                else if (duration_milli > 100)
                        stats->hickup_histogram[HICKUP_LEVEL_101ANDUP_MILLI]++;

                stats->duration += duration;
                stats->ops++;
                stats->bytes += ctx->blocksize;
        }

        stats->lat = comp_lat(stats);

        worker_summary(arg, 0);

        update_shared_stats(stats);

	return 0;
}

void init_sync_file_ctx(file_ctx *arg)
{
        int is_sg = sg_is_sg(arg->file);

        if (!(arg->buf = valloc(arg->blocksize)))
                PANIC("can't alloc buf sized %d bytes", arg->blocksize);
        memset(arg->buf, 0, arg->blocksize);

        if (is_sg) {
                arg->prepare_buf = sync_prepare_buf;
                arg->read = sg_read;
                arg->write = sg_write;
        } else {
                arg->prepare_buf = sync_prepare_buf;
                arg->read = sync_read;
                arg->write = sync_write;
        }
}

pthread_t new_sync_dispatcher(worker_params *params)
{
       	static int num = 0;
        file_ctx *arg;
      	pthread_t thid = 0;

      	if (!(arg = calloc(1, sizeof *arg)))
		PANIC("out of mem - alloc arg");

	/* copy params to worker context - assume params in first field in context */
	*(worker_params *)arg = *params;

        shared.lock_func();
        arg->next = workers;
        arg->num = num++;
        workers = arg;
        shared.unlock_func();

        if (pthread_create(&thid, NULL, (void *(*)(void *))sync_worker, arg))
                PANIC("thread creation failed [file %s]", arg->file);

        DEBUG("thread %d created", thid);
	return thid;
}

void new_sync_file_ctx(worker_params *params, int file_ctx_ix)
{
        file_ctx *ctx = &(file_ctx_list[file_ctx_ix]);
        ctx->num = file_ctx_ix; 
        init_file_ctx(params, ctx);
        init_sync_file_ctx(ctx);
}

/**********************************************************************************************************************
 * Main
 **********************************************************************************************************************/
void usage(void)
{
	printf
	    ("Usage: %s [-hdV -W -D -f <workloads filename> -b <blksz> -B <seq-io-size> -a <alignsize> -t <sec> "
             "-T <threds> -o <start> -l <length> -S <seed> -w <window-size> -p <dedup_likelihood> -P <stampsz> "
                "-r <sec> -R <sec>] <S|R|rand-ratio> <R|W|read-ratio> <dev/file> ...\n", prog);
        printf("\n\tOperation Modes:\n");
        printf("\t\t: Sync/Async - If -w is specified async is enabled, if not sync is used.\n");
        printf("\n\tMain options:\n");
        printf("\t\t-f Accept multiple workloads per thread from file See 'Mutiple Workloads From File' below. \n");
	printf("\t\t Size options support prefixes b (block) K (KB) M (MB) G (GB) T (TB)\n");
	printf("\t\t-b <IO Block size> [%d]\n", def_blocksize);
        printf("\t\t-B <Sequencial IO size in blocks. Applicable for random ratio use case - every sequencial "
                "IO will be built from this number of blocks.> [1]\n");
	printf("\t\t-a <IO alignment size> [by default same as block size]\n");
	printf("\t\t-t <duration in seconds, 0 for inifinity> [%d]\n", secs);
	printf("\t\t-T <For sync IO: number of threads per file. For AsyncIO: total number of "
                "working threads> [%d]\n", threads);
	printf("\t\t-o <start offset> [0]\n");
	printf("\t\t-l <size of area in file/device to use for IO> [full]\n");
	printf("\t\t-S <random seed> [current time]\n");
        printf("\t\t-w <AsyncIO: window size in blocks per file per worker thread. The total number of "
                "inflight IOs is #threads*#files*window_size. > [0]\n");
        printf("\t\t-P <stamp each buffer at each multiplication of the specified offsets. Stamp is the offset "
                "on the write.> [disabled]\n");
        printf("\t\t-p <dedup likelihood. The larger the value, the larger the chances for deduplication. "
                "-1 for zero block write, 0 for no dedup.> [0]\n");
	printf("\tOpen flags options:\n");
	printf("\t\t(Default -  O_CREAT | O_LARGEFILE | O_NOATIME | O_SYNC)\n");
	printf("\t\t-W : Write behind mode : O_CREAT | O_LARGEFILE | O_NOATIME \n");
	printf("\t\t-D Direct IO mode : O_CREAT | O_LARGEFILE | O_NOATIME | O_DIRECT \n");
	printf("\tReal Time Reports:\n");
	printf("\t\tsignal SIGUSR1 prints reports until now\n");
	printf("\t\tsignal SIGUSR2 prints reports from last report\n");
	printf("\t\t-r <diff report interval in seconds> [%d], set to 0 to disable\n", diff_interval);
	printf("\t\t-R <subtotal report interval in seconds> [%d], set to 0 to disable\n", subtotal_interval);
	printf("\tFormat/Trim options:\n");
	printf("\t\t-F : Preformat test area (using writes)\n");
	printf("\t\t-X : Pre-Trim test area (SSD)\n");
	printf("\t\t-x <trim block size> : After each write, trim blocks of \"trim block size\" at random \n"
		"\t\t\tlocations such that write block size data is trimmed\n");
	printf("\tSG support:\n");
	printf("\t\ttarget files that are formated as /dev/sgX are accessed using raw generic scsi calls\n");
	printf("\tMisc:\n");
	printf("\t\t-h : show this help and exit\n");
	printf("\t\t-V : show the program version and exit\n");
	printf("\t\t-d : increase the debugging level\n");
        printf("\n\tMutiple Workloads From File:\n");
        printf("\t\tIf -f option for workloads configuration from file is set, the following parameters must not be \n");
        printf("\t\tconfigured in the commands line: -b -B -a -o -l <S|R|rand-ratio> <R|W|read-ratio>\n");
        printf("\t\tIn the configuration file, each line represents a workload. \n");
        printf("\t\tEach line begins with a weight of this workload, must be a number betweem 1 and 100. \n");
        printf("\t\tThe weight is followed by -b <blksz> -B <seq-io-size> -a <alignsize> -o <start> -l <length> "
                "<S|R|rand-ratio> <R|W|read-ratio> \n");
        printf("\t\tMaximal number of workloads is 16.\n");
        printf("\t\tExample of a configuration file content:\n");
        printf("\t\t10 -b 4k -l 100m R W\n");
        printf("\t\t50 -b 32k -l 100m R W\n");
        printf("\t\t20 -b 8k -l 100m R R\n");
	exit(1);
}

typedef struct main_args {
	int blocksize;
        int seq_io_sz;
        int alignsize;
	uint64 len;
        uint64 startoffset;
        int64 dedup_stamp_modulu; 
        int dorandom;
        int doread;
        int weight; 
       	int trimformat;
	int trimsize;
	int format;
        char** filenames; 
} main_args;

void *stats_main(void* arg)
{
        while (!started) {
                usleep(100 * 1000);
        }

	enable_signals();

	realtime_reports(secs);

	disable_signals();

        finished = 1;

        return NULL; 
}

void *async_main(void* arg)
{
        int i, t, w, nthreads;
        main_args* margs_arr = (main_args*)arg;
        main_args* margs = NULL;
        main_args avg_args; 
        int aiores;
        
        DEBUG("using random seed %d", rseed);

        shared.init_func();
        
        nthreads = threads;

        file_ctx_list_size = nfiles * threads * nworkloads;

        if (!(file_ctx_list = calloc(file_ctx_list_size, sizeof(*file_ctx_list))))
                PANIC("no mem for worker context list (%d contextes)", file_ctx_list_size);

        if (!(aio_ctxt_array = calloc(threads, sizeof(io_context_t))))
                PANIC("no mem for aio context array (%d contextes)", threads);

	if (!(thread_list = calloc(nthreads, sizeof(*thread_list))))
		PANIC("no mem for thread list (threads %d)", nthreads);

        bzero(&avg_args, sizeof(main_args));
        for (w = 0; w < nworkloads; w++) {
                avg_args.blocksize += margs_arr[w].blocksize;
                avg_args.seq_io_sz += margs_arr[w].seq_io_sz;
                avg_args.alignsize += margs_arr[w].alignsize;
                avg_args.len += margs_arr[w].len;
                avg_args.startoffset += margs_arr[w].startoffset;
                avg_args.dedup_stamp_modulu += margs_arr[w].dedup_stamp_modulu;
                avg_args.dorandom += margs_arr[w].dorandom;
                avg_args.doread += margs_arr[w].doread;
                avg_args.format += margs_arr[w].format;
                avg_args.trimformat += margs_arr[w].trimformat;
                avg_args.trimsize += margs_arr[w].trimsize;
        }
        avg_args.blocksize /= w;
        avg_args.seq_io_sz /= w;
        avg_args.alignsize /= w;
        avg_args.len /= w;
        avg_args.startoffset /= w;
        avg_args.dedup_stamp_modulu /= w;
        avg_args.dorandom /= w;
        avg_args.doread /= w;
        avg_args.format /= w;
        avg_args.trimformat /= w;
        avg_args.trimsize /= w;

        margs = &avg_args;
        for (t = 0; t < threads; t++) {
                worker_params params;

                /* initialize AsyncIO global context the kernel */
                bzero(&(aio_ctxt_array[t]), sizeof(io_context_t));
                aiores = io_setup(nfiles * aio_window_size * 2, &(aio_ctxt_array[t]));
                if (aiores < 0) {
                        PANIC("AsyncIO io_setup failed with error: %d (%s)\n", aiores, strerror(-aiores));
                }

                /* create one worker for the AsyncIO completion port,
                 * basically these parameters are required only for statistics printouts */
                params.file = "Async";          /* Thread are not per file in async mode */
                params.blocksize = margs->blocksize;
                params.seq_io_sz = margs->seq_io_sz;
                params.alignsize = margs->alignsize;
                params.randomratio = margs->dorandom;
                params.readratio = margs->doread;
                params.startoffset = margs->startoffset;
                params.dedup_stamp_modulu = margs->dedup_stamp_modulu;
                params.len = margs->len;
                params.weight = margs->weight; 
                params.trimsize = margs->trimsize;
                params.format = margs->format;
                params.trimformat = margs->trimformat;
                params.aio_ctxt_p = &(aio_ctxt_array[t]);
                thread_list[t] = new_aio_dispatcher(&params);
        }

	for (i = 0; i < nfiles; i++) {
                for (t = 0; t < threads; t++) {
                        for (w = 0; w < nworkloads; w++) {
                                worker_params params;

                                margs = &(margs_arr[w]);

                                params.file = margs->filenames[i];
                                params.blocksize = margs->blocksize;
                                params.seq_io_sz = margs->seq_io_sz;
                                params.alignsize = margs->alignsize;
                                params.randomratio = margs->dorandom;
                                params.readratio = margs->doread;
                                params.startoffset = margs->startoffset;
                                params.dedup_stamp_modulu = margs->dedup_stamp_modulu;
                                params.len = margs->len;
                                params.trimsize = margs->trimsize;
                                params.format = margs->format;
                                params.trimformat = margs->trimformat;
                                params.aio_ctxt_p = &(aio_ctxt_array[t]);
                                new_aio_file_ctx(&params,
                                                 i * threads * nworkloads + t * nworkloads + w);
                        }
		}
        }

	start(nthreads);

        while (!finished) {
                th_busywait();
        }

	doexit();

	return NULL;
}

void *sync_main(void* arg)
{
        int i, t, w, nthreads;
        main_args* margs_arr = (main_args*)arg;
        main_args* margs = NULL;
        main_args avg_args; 

        DEBUG("using random seed %d", rseed);

        shared.init_func();
        
        nthreads = nfiles * threads;        

        file_ctx_list_size = nfiles * threads * nworkloads;

        if (!(file_ctx_list = calloc(file_ctx_list_size, sizeof(*file_ctx_list))))
                PANIC("no mem for worker context list (%d contextes)", file_ctx_list_size);

	if (!(thread_list = calloc(nthreads, sizeof(*thread_list))))
		PANIC("no mem for thread list (threads %d)", nthreads);

        bzero(&avg_args, sizeof(main_args)); 
        for (w = 0; w < nworkloads; w++) {
                avg_args.blocksize += margs_arr[w].blocksize;
                avg_args.seq_io_sz += margs_arr[w].seq_io_sz;
                avg_args.alignsize += margs_arr[w].alignsize;
                avg_args.len += margs_arr[w].len;
                avg_args.startoffset += margs_arr[w].startoffset;
                avg_args.dedup_stamp_modulu += margs_arr[w].dedup_stamp_modulu;
                avg_args.dorandom += margs_arr[w].dorandom;
                avg_args.doread += margs_arr[w].doread;
                avg_args.format += margs_arr[w].format;
                avg_args.trimformat += margs_arr[w].trimformat;
                avg_args.trimsize += margs_arr[w].trimsize;
        }
        avg_args.blocksize /= w;
        avg_args.seq_io_sz /= w;
        avg_args.alignsize /= w;
        avg_args.len /= w;
        avg_args.startoffset /= w;
        avg_args.dedup_stamp_modulu /= w;
        avg_args.dorandom /= w;
        avg_args.doread /= w;
        avg_args.format /= w;
        avg_args.trimformat /= w;
        avg_args.trimsize /= w;
        
        margs = &avg_args; 
	for (i = 0; i < nfiles; i++) {
                for (t = 0; t < threads; t++) {
			worker_params params;
			params.file = margs_arr[0].filenames[i];
			params.blocksize = margs->blocksize;
                        params.seq_io_sz = margs->seq_io_sz; 
			params.alignsize = margs->alignsize;
			params.randomratio = margs->dorandom;
			params.readratio = margs->doread;
			params.startoffset = margs->startoffset;
                        params.dedup_stamp_modulu = margs->dedup_stamp_modulu;
			params.len = margs->len;
                        params.weight = margs->weight; 
			params.trimsize = margs->trimsize;
			params.format = margs->format;
			params.trimformat = margs->trimformat;
                        thread_list[i * threads + t] = new_sync_dispatcher(&params);
		}
        }

	for (i = 0; i < nfiles; i++) {
                for (t = 0; t < threads; t++) {
                        for (w = 0; w < nworkloads; w++) {
                                worker_params params;

                                margs = &(margs_arr[w]);
                                
                                params.file = margs->filenames[i];
                                params.blocksize = margs->blocksize;
                                params.seq_io_sz = margs->seq_io_sz;
                                params.alignsize = margs->alignsize;
                                params.randomratio = margs->dorandom;
                                params.readratio = margs->doread;
                                params.startoffset = margs->startoffset;
                                params.dedup_stamp_modulu = margs->dedup_stamp_modulu;
                                params.len = margs->len;
                                params.trimsize = margs->trimsize;
                                params.format = margs->format;
                                params.trimformat = margs->trimformat;
                                new_sync_file_ctx(&params,
                                                  i * threads * nworkloads + t * nworkloads + w);
                        }
		}
        }

        start(nthreads);

        while (!finished) {
                th_busywait();
        }

	doexit();

	return NULL;
}

static void parse_alignsize(main_args* margs, char* optarg)
{
        margs->alignsize = parse_storage_size(optarg);
        if (!margs->alignsize)
                PANIC("invalid align size parameter: -a %s", optarg);
        printf("IO alignment size is %d\n", margs->alignsize);
}

static void parse_blocksize(main_args* margs, char* optarg)
{
        margs->blocksize = parse_storage_size(optarg);
        if (!margs->blocksize)
                PANIC("invalid blocksize parameter: -b %s", optarg);
        printf("IO Block size is %d\n", margs->blocksize);
}

static void parse_seq_io_sz(main_args* margs, char* optarg)
{
        margs->seq_io_sz = parse_storage_size(optarg);
        if (!margs->seq_io_sz)
                PANIC("invalid sequencial io size parameter: -B %s", optarg);
        printf("Sequencial IO size is %d\n", margs->seq_io_sz);
}

static void parse_startoffset(main_args* margs, char* optarg)
{
        margs->startoffset = parse_storage_size(optarg);
        printf("File start offset is %" PRId64 "\n", margs->startoffset);
}

static void parse_len(main_args* margs, char* optarg)
{
        margs->len = parse_storage_size(optarg);
        if (!margs->len)
                PANIC("invalid len size parameter: -l %s", optarg);
        printf("Limit IO space to %s (%" PRId64 " bytes) per file\n", optarg, margs->len);
}

static void parse_weight(main_args* margs, char* optarg)
{
        margs->weight = atoi(optarg);
        if ((margs->weight < 0) || (margs->weight > 100))
                PANIC("invalid workload weight, should be number larger than 0, smaller than 100: %s", optarg);
        printf("Workload weight is %d\n", margs->weight);
}

static void parse_dedup_likelihood(main_args* margs, char* optarg)
{
        margs->dedup_stamp_modulu = (uint64)atoi(optarg);
        if ((margs->dedup_stamp_modulu < -1) || (margs->dedup_stamp_modulu > 10000))
                PANIC("invalid dedup likelihood, should be number between 0 and 10000: %s", optarg);
        printf("Dedup rate is %ld\n", margs->dedup_stamp_modulu);
}

static void parse_dorandom(main_args* margs, char* optarg)
{
        switch (optarg[0]) {
        case 'R':
        case 'r':
                margs->dorandom = 100;
                if (margs->seq_io_sz != 1) {
                       printf("Sequencial IO size is ignored since random ratio is 100 precent.\n");
                }
                break;
        case 'S':
        case 's':
                margs->dorandom = 0;
                if (margs->seq_io_sz != 1) {
                       printf("Sequencial IO size is ignored since random ratio is 0 precent.\n");
                       margs->seq_io_sz = 1;
                }
                break;
        default:
                margs->dorandom = atoi(optarg);

                if (margs->dorandom < 0 || margs->dorandom > 100)
                        PANIC("bad random/sequencial parameter: should be R|S|0-100");

                if (margs->seq_io_sz != 1) {
                        if ((margs->dorandom == 100) || (margs->dorandom == 0)) {
                                printf("Sequencial IO size is ignored since random ratio is 0 precent.\n");
                                margs->seq_io_sz = 1;
                        } else {
                                /* random ratio should be recalculated acording to seq_io_sz */
                                float rr = (float)(margs->dorandom) / 100.0;
                                int new_dorandom;

                                rr = (rr / (1.0 -rr)) * margs->seq_io_sz;
                                rr = rr / (rr + 1.0) * 100.0;

                                new_dorandom = (int)rr;
                                printf("Random ratio actual value is cahnged to %d (was %d), following adjustments "
                                        "to sequencial io size (%d).\n",
                                        new_dorandom, margs->dorandom, margs->seq_io_sz);

                                margs->dorandom = new_dorandom;
                        }
                }
        }
}

static void parse_doread(main_args* margs, char* optarg)
{
        switch (optarg[0]) {
        case 'R':
        case 'r':
                margs->doread = 100;
                break;
        case 'W':
        case 'w':
                margs->doread = 0;
                break;
        default:
                margs->doread = atoi(optarg);
                if (margs->doread < 0 || margs->doread > 100)
                        PANIC("bad read/write parameter: should be R|W|0-100");
        }
}

static void verify_sizes(main_args* margs)
{
        if (!margs->alignsize)
                margs->alignsize = margs->blocksize;
        if (margs->startoffset % margs->alignsize) {
                margs->startoffset = (margs->startoffset + margs->alignsize - 1) % margs->alignsize;
                printf("startoffset is changed to %"PRId64" to match alignment size %d\n",
                        margs->startoffset, margs->alignsize);
        }
}

static void init_margs(main_args* margs)
{
        bzero(margs, sizeof(main_args));
        margs->blocksize = def_blocksize;
        margs->seq_io_sz = 1;
}

static int parse_workload(char const *workload_filename, main_args *margs_arr)
{
        char readline[MAX_LINE_SIZE];
        char *parseline, *parseopt, *parseoptarg;
        main_args* curr_margs;
        FILE *workload_file;
        uint workload = 0;

        workload_file = fopen(workload_filename, "r");
        if (workload_file == NULL)
                PANIC("Workload file cannot be opened: %s", optarg);

        bzero(readline, MAX_LINE_SIZE);

        while (fgets(readline, MAX_LINE_SIZE, workload_file) != NULL) {

                parseline = readline;
                parseopt = strtok(parseline, " ");

                if ((parseopt == NULL) || (parseopt[0] == '\n'))
                        continue;

                if (workload >= MAX_WORKLOADS)
                        PANIC("Too many workloads. Maximum is %d", MAX_WORKLOADS);

                curr_margs = &(margs_arr[workload++]);
                init_margs(curr_margs);

                parse_weight(curr_margs, parseopt);

                parseopt = strtok(NULL, " ");
                while ((parseopt != NULL) && (parseopt[0] == '-')) {
                        parseoptarg = strtok(NULL, " ");
                        switch (parseopt[1]) {
                        case 'a':
                                parse_alignsize(curr_margs, parseoptarg);
                                break;
                        case 'b':
                                parse_blocksize(curr_margs, parseoptarg);
                                break;
                        case 'B':
                                parse_seq_io_sz(curr_margs, parseoptarg);
                                break;
                        case 'o':
                                parse_startoffset(curr_margs, parseoptarg);
                                break;
                        case 'l':
                                parse_len(curr_margs, parseoptarg);
                                break;
                        case 'p':
                                parse_dedup_likelihood(curr_margs, parseoptarg);
                                break;
                        }
                        parseopt = strtok(NULL, " ");
                }

                verify_sizes(curr_margs);

                parse_dorandom(curr_margs, parseopt);

                parseopt = strtok(NULL, " ");
                parse_doread(curr_margs, parseopt);
        }

        return workload;
}

int main(int argc, char **argv)
{
	int i, j, opt, workload_defined = 0;
        main_args margs;
        main_args margs_arr[MAX_WORKLOADS];        
        pthread_t thid = 0;
        IOModel model = IO_MODEL_INVALID;
        char *workload_filename = NULL;
        
        model = IO_MODEL_SYNC; /* default */
        stall = 0;

        init_margs(&margs);
        setlinebuf(stdout);

        /* find the base name of the exec name */
	prog = strchr(argv[0], '/');
	if (!prog)
		prog = argv[0];
	else
		prog++;

	rseed = time(0);

        optind = 0; 
	while ((opt = getopt(argc, argv, "+hVdf:t:T:b:B:s:o:l:S:w:DWP:p:r:R:FXx:a:")) != -1) {
		switch (opt) {
		default:
		case 'h':
			usage();
			break;
		case 'V':
			printf("%s version %d commit %s\n", prog, BTEST_VERSION, BTEST_COMMIT);
			exit(0);
                case 'f':
                        if (workload_defined)
                                PANIC("workload file (-f) can be specified only if "
                                      "these command line switches are not set: -a,-b,-B,-o,-l");
                        if (workload_filename != NULL)
                                PANIC("only one workload file can be specified");

                        if (argc - optind < 1)
                                usage();
                        workload_filename = optarg;
                        break; 
		case 'd':
			debug++;
			break;
		case 'a': 
                        if (workload_filename != NULL)
                                PANIC("alignsize (-a) cannot be set from command line if "
                                      "workload file (-f) was specified");
			parse_alignsize(&margs, optarg);
                        workload_defined = 1; 
			break;
                case 'A':
                        activity_check = 1;
                        printf("Turn on activity check\n");
                        break;
		case 'b': 
                        if (workload_filename != NULL)
                                PANIC("blocksize (-b) cannot be set from command line if "
                                        "workload file (-f) was specified");
                        parse_blocksize(&margs, optarg);
                        workload_defined = 1; 
			break;
		case 'B': 
                        if (workload_filename != NULL)
                                PANIC("seq_io_sz (-B) cannot be set from command line if "
                                        "workload file (-f) was specified");
                        parse_seq_io_sz(&margs, optarg); 
                        workload_defined = 1;
			break;
		case 'o': 
                        if (workload_filename != NULL)
                                PANIC("startoffset (-o) cannot be set from command line if "
                                        "workload file (-f) was specified");
                        parse_startoffset(&margs, optarg); 
                        workload_defined = 1; 
			break;
		case 'l': 
                        if (workload_filename != NULL)
                                PANIC("file length (-l) cannot be set from command line if "
                                        "workload file (-f) was specified");
                        parse_len(&margs, optarg); 
                        workload_defined = 1; 
			break;
		case 'S':
			rseed = atoi(optarg);
			printf("Use random seed %d\n", rseed);
			break;
		case 'w':
			aio_window_size = atoi(optarg);
                        if (!aio_window_size)
                                PANIC("aio_window_size (-w) must be > 0");
                        model = IO_MODEL_ASYNC;
			printf("Use AsyncIO with window size of %d requests per thread\n", aio_window_size);
			break;
		case 't':
			secs = atoi(optarg);
			if (!secs) {
                                secs = 2000000; 
				printf("Infinity time requested. time set to %d seconds\n", secs);
                        }
			break;
		case 'T':
			threads = atoi(optarg);
			if (!threads)
				PANIC("invalid threads parameter: -T %s", optarg);
			break;
		case 'W':
			printf("Allow write behind\n");
			openflags_block &= ~(O_SYNC | O_DIRECT);
			write_behind = 1;
			break;
		case 'D':
			printf("Use direct IO\n");
			openflags_block &= ~O_SYNC;
			openflags_block |= O_DIRECT;
			break;
		case 'P':
			stampblock = parse_storage_size(optarg);
			if (stampblock < 16)
				PANIC("can't use stampblock < 16 (%d)\n", stampblock);
			printf("Use stamps each %d bytes\n", stampblock);
			break;
		case 'p':
                        if (workload_filename != NULL)
                                PANIC("dedup likelihood (-p) cannot be set from command line if "
                                        "workload file (-f) was specified");
                        parse_dedup_likelihood(&margs, optarg);
                        workload_defined = 1;
			break;
		case 'r':
			diff_interval = atoi(optarg);
			printf("Diff report interval %d sec\n", diff_interval);
			break;
		case 'R':
			subtotal_interval = atoi(optarg);
			printf("Subtotal report interval %d sec\n", subtotal_interval);
			break;
		case 'F':
			margs.format = 1;
			printf("Format the disk before the test\n");
			break;
		case 'X':
			margs.trimformat = 1;
			printf("Format the disk using trim before the test\n");
			break;
		case 'x':
			margs.trimsize = parse_storage_size(optarg);
			printf("Time mode: for each write trim same data using random blocks of %d bytes\n",
			     margs.trimsize);
			break;
		}
	}

        if (workload_filename == NULL) {
                nworkloads = 1;
                
                if (argc - optind < 3)
                        usage();        	

                verify_sizes(&margs);
                
                parse_dorandom(&margs, argv[optind]);
                optind++;

                parse_doread(&margs, argv[optind]);
                optind++;
        } else
                nworkloads = parse_workload(workload_filename, margs_arr);

        if (nworkloads == 0)
                PANIC("no workload is defined");

        check_interval_ratio();
        
        nfiles = argc - optind;
       	if (!(margs.filenames = calloc(nfiles, sizeof(char*))))
		PANIC("no mem for file names array");

        for (i = 0; i < nfiles; i++)
                margs.filenames[i] = strdup(argv[optind + i]);

        finished = started = 0;

        if (pthread_create(&thid, NULL, (void *(*)(void *))stats_main, NULL))
                PANIC("Stats main thread creation failed");

        if (workload_filename == NULL) {
                margs_arr[0] = margs;
        } else {
                int workload_weight_ix = 0;
                
                /**
                 * Duplicate the fields that were taken from command line,
                 * and init the weights. 
                 */
                for (i = 0; i < nworkloads; i++) {
                        margs_arr[i].format = margs.format;
                        margs_arr[i].trimformat = margs.trimformat; 
                        margs_arr[i].trimsize = margs.trimsize; 
                        margs_arr[i].filenames = margs.filenames;

                        total_workload_weights += margs_arr[i].weight; 
                        
                        for (j = 0; j < margs_arr[i].weight; j++) {
                                workload_weights[workload_weight_ix++] = i;
                        }
                }
        }

        switch (model) {
        case IO_MODEL_SYNC:
                th_busywait = sync_th_busywait;

                shared.init_func = sync_shared_init;
                shared.destroy_func = sync_shared_destroy;
                shared.lock_func = sync_lock;
                shared.unlock_func = sync_unlock;
                shared.cond_wait_func = sync_cond_wait_func;
                shared.cond_broadcast_func = sync_cond_broadcast_func;                

                /* Load main thread */
                if (pthread_create(&thid, NULL, (void *(*)(void *))sync_main, &margs_arr))
                        PANIC("Stats main thread creation failed");

                while (1) {
                        th_busywait();
                }
                break;

        case IO_MODEL_ASYNC:
                th_busywait = sync_th_busywait;

                shared.init_func = sync_shared_init;
                shared.destroy_func = sync_shared_destroy;
                shared.lock_func = sync_lock;
                shared.unlock_func = sync_unlock;
                shared.cond_wait_func = sync_cond_wait_func;
                shared.cond_broadcast_func = sync_cond_broadcast_func;

                /* Load main thread */
                if (pthread_create(&thid, NULL, (void *(*)(void *))async_main, &margs_arr))
                        PANIC("Stats main thread creation failed");

                while (1) {
                        th_busywait();
                }
                break;

        default:
                PANIC("btest unknown IO model %d", model);
        }
        
        return 0;
}

