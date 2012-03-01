/*
 * Block test/exerciser utility
 *
 * Copyright (c) 2008-2009 Shahar Frank, Qumranet (Redhat)
 * Copyright (c) 2009-2011 Shahar Frank, Xtremio
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
 * and each mode has a different implementation for it (for example read, write, busy-wait, lock, etc.). The function
 * table is filled up at system initialization according to the mode chosen. 
 *
 * The I/O operations we perform are handled in 3 dimensions. First dimension is a device or file descriptor. Second
 * dimension are IO-threads and third dimension is workload definition. In other words
 * for each file we work on we have one thread or more working on that file (exact number is specified by the user) and
 * each such IO thread is performing one or more workloads on that file. The default is one global workload but the
 * user can specify more than one (see usage message for more details on how to do this).
 * The object types that are important to get familiar with to understand the implementation are the worker context,
 * the workload, the workload context, and the file context.
 * 
 * The worker represents one context performing I/Os (the "second" dimension described above). Each such worker
 * is the basic unit for providing the statistics on the I/O performance that are printed during the btest operation.
 * In the sync mode each IO thread has a single synchronous worker, while in async mode each such threads is
 * maintaining a "window" of such async workers.
 * 
 * The workload represents one workload that a worker thread is performing. Workload definition includes things like
 * block size offset range, as well as flavor of I/O - read or write, sequential or random. Each worker
 * can use one or more workloads (one at a time). If it is using more than one it will switch between them randomly,
 * using the user defined weights.
 * 
 * Workload context represents the file specific variables after a workload is applied on it. In most cases these
 * variables are size oriented.
 * 
 * The file context structure is used to maintain all variables concerning a specific file (fd, name, verification data,
 * size, type, etc). This context is shared among all threads and workers using that file.
 * 
 * Verification mode:
 * In this mode, a stamp is written to each stampblock section in the data, and also kept in memory. Once the
 * block is read, its stamp is checked against the core memory version, and if it doesn't match, it is considered as an
 * validation error. The verification memory structures are shared memory such that many threads may operate on it in
 * parallel. The concurrent threads are synchronizing the data patten among themselves using an wait free algorithm
 * to minimize the verification effect on the test flow.
 *
 * Verification patterns
 * The default verification stamp is selected according to the dedup rate set by the -p option, to enable using
 * the verification mode with dedupable data. A data that was never written is marked with a special zero mark to denote
 * that it is in unknown state.
 * Note that this stamp uses the first 64 bit of each stamp block section (the section size is controlled
 * by the -P option). If full data stamping is required, the offset stamps option (-O) may be used in addition to the
 * default stamp. Note that the offset stamps are not dedup aware, and should not be used if dedup control is important
 * (i.e. if you need to generate a data that has a predicted and controlled dedup factor).
 * In addition, a btest extention may implement an data stamping method in addition or instead the default dedup/offset
 * stamps.
 * Note that all data stamping methods may be used without the verification mode, but then they will affect only
 * the write path only.
 *
 * Verification meta-data files
 * The core stamps (the dedup aware 32 bit stamps) may be loaded/saved from/to a file before/after the test to allow
 * passing the stamps data to future btest sessions. This may be useful for scenarios such as snapshot testing: the
 * first btest is started on the "parent" LUN, then it is stopped (and the stamps md are saved), a snapshot of the LUN
 * is taken, the md files are copied and then a different btest session is started on each LUN (the parent
 * and the child). This way you can check that the snapshot is a true "copy" of the parent, and that it is independent
 * (i.e. further changes to the parent will not affect the child), and vice versa.
 * The md files are used via the mmap mechanism, such that btests may be added on run time using the same md file(s).
 * The downside of this is that if a btest panics, it may leave the md referenced and/or corrupted.
 *
 * Check mode
 * When -C <md base> is used, a special running mode is activated, where the given files/devices are sequentially
 * scanned and each stamp block that has verification md is read and checked.
 *
 * debug lines mechanism
 * the "debug lines" feature controlled via the -L option is a special binary tracing feature to track verification stamps
 * creation and checking using efficient binary logging. This log is converted to human readable format and written to
 * a file once the process exits. This features is required to debug high rate IO devices.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
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
#include <ctype.h>
#include <sys/mman.h>

#include "btest.h"
#include "btest_data_struct.h"
#include "sg_read.h"

#define BTEST_VERSION 153
#define xstr(s) str(s)
#define str(s) #s
#define BTEST_COMMIT xstr(COMMIT)

#define MAX_LINE_SIZE   256

#define DEFAULT_TIME_LIMIT      60

BtestConf conf = {
        .secs = -1,                     /** default == DEFAULT_TIME_LIMIT one minute test */
        .nthreads = 1,                  /** default is single threaded test */
        .nfiles = 0,                    /** number of files is always set by command line */
        .def_blocksize = 4 * 1024,      /** default is 4k */
        .diff_interval = 10,            /** default diff report interval is 10 seconds */
        .subtotal_interval = 0,         /** by default subtotal report interval is off */
        .timeout_ms = 5000,             /** by default check for stale IOs each second */
        .warmup_sec = 0,                /** no warmup */
        .rseed = 0,                     /** default rseed is set by main (time) */
        .num_op_limit = 0,              /** by default the test is not operation number limited */
        .exit_eof = 0,                  /** exit on end of file? */
        .block_md_base = NULL,          /** by default no md file is used */
        .stampblock = -1,               /** by default stamp block is set to the block size */
        .compression = 0,               /** by default - no compression */
        .aio_window_size = 0,           /** by default aio mode is not used (window == 0) */

        .preformat = 0,                 /** by default no preformating is done */
        .pretrim = 0,                   /** by default no pre-trimming is done */

        .report_workers = 0,            /** by default per worker reports are not producted */
        .activity_check = 0,            /** by default activity check is not performed */
        .verify = 0,                    /** by default data is not verified */
        .verification_mode = 0,         /** by default verification mode is off */
        .ignore_errors = 0,             /** by default errors are not ignored, and the first one lead to panic */
        .debug = 0,                     /** by default debug level is 0 (none) */
        
        .csv_report = 0,                /** by default no CSV report are produced */
        .iomodel = IO_MODEL_INVALID,    /** by default SYNC IO is used */
        
        .force_md_init = 0,             /** by default do not force */
};


/* globals */
char *prog;

FILE *csv_file;

char            *filenames[MAX_FILES];
workload        workloads[MAX_WORKLOADS];
file_ctx        *files;
shared_file_ctx *shared_file_ctx_arr;
worker_ctx      *workers;
aio_thread_ctx  *aio_ctx;
io_thread_ctx   *io_ctx;

int total_nworkers;                             /**< total number of workers */
int total_nthreads;                             /**< total number of threads */
int total_nfiles;                               /**< total number of files/devs */
int total_nworkloads;                           /**< total number of defined workloads */
int max_nworkers;                               /**< max number of workers */
int max_nthreads;                               /**< max number of threads */
int max_nfiles;                                 /**< max number of files/devs */
int devs_per_thread;                           /**< number of devices per thread */

unsigned char workload_weights[MAX_WORKLOADS * 100];
int total_workload_weights = 0;

uint64 total_ops;           /**< number of total ops until now */
int maxblocksize;           /**< max block size among all workloads */
int minblocksize;           /**< min block size among all workloads */
loff_t startoffset;         /**< Offset of first byte of the IO region within the file/dev */
loff_t endoffset;           /**< Offset of last byte +1 of the IO region within the file/dev. 0 is use dev size */
int readonly;               /**< we are read only if we do not have a writing workload */
int use_stamps;             /**< do we use dedup stamps? 1 is random fill, 2 is progress fill */
uint64 fixstamp;            /**< used for "-p -1 " */


void(*th_busywait)();

/**
 * Global variables for Sync + Async
 */ 
#define FORMAT_IOSZ (1 << 20)
#define TRIM_FORMAT_IOSZ (10 << 20)
char formatbuf[FORMAT_IOSZ];

#define DEDUP_STAMP_SIZE (2 * sizeof (uint64))

/**
 * Global variables for Async IO only
 */
io_context_t* aio_ctxt_array = NULL;

static char* hickup_level_strings[HICCUP_LEVEL_NUM_OF] =
{
        [HICKUP_LEVEL_0_MILLI] "<1ms",
        [HICKUP_LEVEL_1_MILLI] "1ms",
        [HICKUP_LEVEL_2TO10_MILLI] "2-10ms",
        [HICKUP_LEVEL_11TO100_MILLI] "11-100ms",
        [HICKUP_LEVEL_101ANDUP_MILLI] ">100ms"
};

char *iomodel_str[] = {
        [IO_MODEL_INVALID] "???",
        [IO_MODEL_SYNC] "sync",
        [IO_MODEL_ASYNC] "async",
        [IO_MODEL_SGIO] "sgio",
        [IO_MODEL_SGIO_DIRECT] "sgio_direct",
        [IO_MODEL_WRITE_BEHIND] "write_behind",
        [IO_MODEL_DIRECT] "direct",    
        [IO_MODEL_DIRECT_SYNC] "direct_sync",    
};

int openflags_iomodel[] = {
        [IO_MODEL_INVALID] 0,
        [IO_MODEL_SYNC] O_CREAT | O_LARGEFILE | O_NOATIME | O_SYNC,
        [IO_MODEL_ASYNC] O_CREAT | O_LARGEFILE | O_NOATIME | O_DIRECT,
        [IO_MODEL_SGIO] O_RDWR,
        [IO_MODEL_SGIO_DIRECT] O_RDWR | O_DIRECT,      
        [IO_MODEL_WRITE_BEHIND] O_CREAT | O_LARGEFILE | O_NOATIME,
        [IO_MODEL_DIRECT] O_CREAT | O_LARGEFILE | O_NOATIME | O_DIRECT,      
        [IO_MODEL_DIRECT_SYNC] O_CREAT | O_LARGEFILE | O_NOATIME | O_DIRECT | O_SYNC,      
};
/**
 * Global shared functions and flags
 */
struct shared {
        pthread_cond_t start_cond;
	pthread_mutex_t lock;

        void(*init_func)();
        void(*destroy_func)();
        void(*lock_func)();
        void(*unlock_func)();
        void(*cond_wait_func)();
        void(*cond_broadcast_func)(int n);

        void *(*prepare_buf)(worker_ctx *worker);
        ssize_t (*read)(worker_ctx *worker, int fd, void *buf, size_t count, off_t offset);
        ssize_t (*write)(worker_ctx *worker, int fd, void *buf, size_t count, off_t offset);
        void(*write_completed)(worker_ctx *worker, void *buf, uint64 offset, int size);
        void(*read_completed)(worker_ctx *worker, void *buf, uint64 offset, int size);

	int started;
        int finished; 

        btest_extension ext;

} shared = {PTHREAD_COND_INITIALIZER, PTHREAD_MUTEX_INITIALIZER,};

/*************************************************************************
 * Global state functions and enums
 ************************************************************************/

typedef enum BtestStates {
        INVALID,
        STARTING,
        WARMINGUP,
        RUNNING,
        FINISHED,
        SUMMARY,
        LAST_STATE
} BtestStates;

volatile BtestStates btest_state;

char *btest_state_str[] = {
        [INVALID] "invalid",
        [STARTING] "starting",
        [WARMINGUP] "warming up",
        [RUNNING] "running",
        [FINISHED] "finishing",
        [SUMMARY] "end",
        [LAST_STATE] 0
};

static char *state_str(BtestStates state)
{
        if (state > INVALID && state <= LAST_STATE)
                return btest_state_str[state];
        return "???";
}

static int state_reached(BtestStates state)
{
        return (int)state <= (int)btest_state;
}

static int state_set(BtestStates state, int force)
{
        if (!force && ((int)state != (int)btest_state + 1) && (state != btest_state))
                PANIC("bad state transition: %s (%d) to %s (%d)", state_str(btest_state), btest_state,
                        state_str(state), state);
        DEBUG("Btest state has changed to %s (%d)", state_str(state), state);
        return btest_state = state;
}

/**********************************************************************************************************************
 * Common Utility Functions
 **********************************************************************************************************************/

/**
 * atomically increment 'ref' by one and return previous value
 */
inline uint32 atomic_fetch_and_inc32(volatile uint32 *ref)
{
        return __sync_fetch_and_add(ref, (uint32)1);
}

/**
 * atomically decrement 'ref' by one and return previous value
 */
inline uint32 atomic_fetch_and_dec32(volatile uint32 *ref)
{
        /* attomically incref and return previous value */
        return __sync_fetch_and_sub(ref, (uint32)1);
}

/**
 * atomically increment 'ref' by one and return previous value
 */
inline uint64 atomic_fetch_and_inc64(volatile uint64 *ref)
{
        /* attomically incref and return previous value */
        return __sync_fetch_and_add(ref, (uint64)1);
}

/**
 * atomically increment 'ref' by one and return previous value
 */
inline uint64 atomic_add64_and_fetch(volatile uint64 *ref, uint64 value)
{
        /* attomically incref and return previous value */
        return __sync_add_and_fetch(ref, value);
}

/**
 * atomically increment 'ref' by one and return previous value
 */
inline uint64 atomic_fetch_and_add64(volatile uint64 *ref, uint64 value)
{
        /* attomically incref and return previous value */
        return __sync_fetch_and_add(ref, value);
}

/**
 * atomically decrement 'ref' by one and return previous value
 */
inline uint64 atomic_fetch_and_dec64(volatile uint64 *ref)
{
        /* attomically incref and return previous value */
        return __sync_fetch_and_sub(ref, (uint64)1);
}

/**
 * get tid system call wrapper - missing in some libc
 */
int gettid(void)
{
	return syscall(__NR_gettid);
}

/**
 * return 64 bit timestamp (usec resolution)
 * 
 * Note timestamp has full order (can be compared, added, ...)
 */
uint64 timestamp(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000000 + tv.tv_usec;
}

/*********************************************************************************************
 * The following mechanism is a binary trace system meant to catch internal validation bugs.
 * It is left here because in some cases it can help to debug devices
 *********************************************************************************************/
typedef struct debugline {
        char type;
        char iswrite;
        uint32 tid;
        uint32 mdid;
        uint64 verref;
        uint64 blockid;
        uint64 old;
        uint64 stamp;
        uint64 timestamp;
} debugline;

uint ndebuglines;
debugline *debuglines;
volatile uint curdebugline, debugdump;

/**
 * Initialize the binary debug log
 */
void init_debug_lines(void)
{
        if (!ndebuglines)
                return;

        if (!(debuglines = calloc(ndebuglines, sizeof *debuglines)))
                PANIC("can't alloc %u debug lines", ndebuglines);
}

/**
 * Add a debug for a block worker md struct "owner"
 */
#define ADD_DEBUG_LINE(type, tid, owner) do {if (debuglines) add_debug_line((type), (tid), (owner)); } while(0)

/**
 * Allocates a debug line in the binary debug log and sets its data.
 * @note the line is not locked so if another thread is wrapping around to fast, it may collide with the current line
 * holder and the results may be undefined.
 */
void add_debug_line(char type, uint tid, block_worker_md *owner)
{
        debugline tmpline;
        debugline *line = &tmpline;

        if (!debuglines || debugdump)
                return;

        line = debuglines + (atomic_fetch_and_inc32(&curdebugline) % ndebuglines);

        if (line == debuglines)
                DEBUG2("debug lines wraparound");
        
        line->type = type;
        line->mdid = owner->id;
        line->blockid = owner->blockid;
        line->tid = tid;
        line->old = owner->old;
        line->stamp = owner->stamp;
        line->timestamp = timestamp();
        line->verref = owner->verref;
        line->iswrite = owner->dowrite;

}

/**
 * Convert the binary log to human readable format and write it to a file.
 */
void dump_debug_line(char *basename)
{
        char filename[256];
        uint curno, n;
        FILE *f;

        snprintf(filename, sizeof filename, "%s-%d.log", basename, gettid());
        filename[sizeof filename -1] = 0;

        if (!debuglines)
                return;
        
        if (atomic_fetch_and_inc32(&debugdump)) {
                /* dump in progress, just delay thread until it is finished... */
                while (debugdump)
                        sleep(1);
                return;
        }

        printf("flushing debug lines to '%s' please wait\n", filename);

        if (!(f = fopen(filename, "w")))
                WARN("can't dump debug lines %m to '%s'", filename);

        for (curno = 0, n = 0; curno < ndebuglines; curno++) {
                debugline *line = debuglines + ((curdebugline + curno) % ndebuglines);

                if (!line->type)
                        continue;
                n++;
                fprintf(f, "[%lx:%x] %c block %ld mdid %d old %016lx stamp %016lx version %lx ref %ld (%c)\n",
                        line->timestamp, line->tid, line->type, line->blockid, (int)line->mdid, line->old, line->stamp,
                        BLOCK_MD_VERSION(line->verref), BLOCK_MD_REF(line->verref), line->iswrite ? 'W' : 'R');
        }

        fflush(f);
        printf("flushed debug lines to '%s', %u lines flushed\n", filename, n);
        fclose(f);
        
        /* let waiter know we are done */
        atomic_fetch_and_dec32(&debugdump);
}

/***********************************************************************
 * Generic utilities
 **********************************************************************/

static void md_flush();

/**
 * Show a message and abort the program.
 * @param fn the name of the calling function
 * @param msg printf style message string
 */
void panic(const char *fn, char *msg, ...)
{
	char buf[512];
	va_list va;
	int n;
        static int reenter = 0;

	va_start(va, msg);
	n = vsprintf(buf, msg, va);
	va_end(va);
	buf[n] = 0;

	fflush(stdout);		/* flush stdout to ensure the stderr is last message */
	fprintf(stderr, "PANIC: [%s:%d:%" PRIx64 "] %s: %s%s%s\n", prog, gettid(),
		timestamp(), fn, buf, errno ? ": " : "", errno ? strerror(errno) : "");

        dump_debug_line("/tmp/debuglines");

        /* if we are using verification md files - attempt to flush them. Avoid re-entrance on panic */
        if (!reenter && conf.block_md_base) {
                reenter = 1;
                md_flush();
        }

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

	fprintf(stderr, "[%s(%d):%019" PRId64 "]: %s: %s\n", prog, gettid(), timestamp(), fn, buf);
}

/**********************************************************************************
 * XDump utility - print hex in human readable format with ascii dump (ala xxd)
 *********************************************************************************/
#define XDUMP_ASCIIOFF   44
#define XDUMP_LINESZ   74
#define HEX(x)  ((x) < 10 ? '0' + (x) : 'a' + ((x) -10))
void _xdump_line_start(void *start, uint offset, char **hex, char **ascii)
{
        char *s = start;

        memset(start, ' ', XDUMP_LINESZ);
        *s++ = HEX((offset >> 28) & 0xf);
        *s++ = HEX((offset >> 24) & 0xf);
        *s++ = HEX((offset >> 20) & 0xf);
        *s++ = HEX((offset >> 16) & 0xf);
        *s++ = HEX((offset >> 12) & 0xf);
        *s++ = HEX((offset >> 8) & 0xf);
        *s++ = HEX((offset >> 4) & 0xf);
        *s++ = HEX((offset >> 0) & 0xf);
        *s++ = ':';
        *s++ = ' ';

        *hex = s;
        *ascii = s + XDUMP_ASCIIOFF;

}

/**
 * @brief print the \b msg and hex-dumps the buffer to stderr
 * @param p pointer to dumped buffer
 * @param size number of bytes to dump
 * @param msg to print before the dump
 */
void xdump(void const *p, int size, char *msg)
{
        uint8_t const *cp = p;
        char buf[4096], *s = buf, *ascii;
        int i;

        s += snprintf(buf, sizeof(buf)-XDUMP_LINESZ-1, "xdump: %s\n", msg);
        _xdump_line_start(s, 0, &s, &ascii);

        for (i = 0; i < size;) {
                *s++ = HEX(*cp >> 4);
                *s++ = HEX(*cp & 0xf);

                if (isgraph(*cp))
                        *ascii++ = *cp;
                else
                        *ascii++ = '.';

                if (++i >= size)
                        break;

                *s++ = HEX(cp[1] >> 4);
                *s++ = HEX(cp[1] & 0xf);

                if (isgraph(cp[1]))
                        *ascii++ = cp[1];
                else
                        *ascii++ = '.';

                if (++i % 16)
                        *s++ = ' ';
                else {
                        *ascii++ = '\n';
                        /* if we are too close to the end of buffer, flush it out */
                        if (s - buf >= (sizeof(buf) - XDUMP_LINESZ)) {
                                *ascii = 0;
                                fputs(buf, stderr);
                                ascii = buf;
                        }
                        _xdump_line_start(ascii, i, &s, &ascii);
                }
                cp += 2;
        }
        if (i % 20)
                *ascii++ = '\n';

        *ascii = 0;

        fputs(buf, stderr);
}

/**
 * Parse storage size strings, i.e. numbers with storage related postfixes:
 * B|b for blocks (512 bytes), k|K for KB (1024) bytes, and so one (m = MB, g = GB, t = TB, p = PB)
 */
uint64 parse_storage_size(char *arg)
{
	int l = strlen(arg);
	uint64 factor = 1;

	arg = strdupa(arg);
	switch (arg[l - 1]) {
        case 'P':
        case 'p':
                factor = 1lu << 50;
                break;
        case 'T':
        case 't':
                factor = 1lu << 40;
                break;
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

/**
 * Compute bandwidth
 */
uint64 comp_bw(IOStats * stats)
{
	if (stats->duration == 0)
		return 0;
	return (uint64) (((double)stats->bytes) * 1000000 / ((double)stats->duration) / (1 << 10));
}

/**
 * Compute number of I/Os per seconds
 */
float comp_iops(IOStats * stats)
{
	if (stats->duration <= 0)
		return 0;
	return ((double)stats->ops) * 1000000 / stats->duration;
}

/**
 * Compute latency
 */
uint64 comp_lat(IOStats * stats)
{
	if (stats->ops <= 0)
		return 0;
        return stats->duration / stats->ops;
}

/***********************************************************************************************************************
 * Verification functions
***********************************************************************************************************************/

/**
 * Reference a block md struct.
 *
 * This must be called by any thread that needs access to a block md struct. The same thread must call unref_block_md()
 * when it doesn't need such access anymore.
 *
 * Implementation:
 * The first thread to reach a free (non refed) stamp, is trying set its own block_worker_md as the shared working
 * md for this stamp. This working md will be freed by the last thread unrefing it.
 * Further threads that need a reference to this block md/working block md will find the md reffered, and add a ref
 * on the working md.
 *
 * In most cases, a single atomic op is required to ref the md. In case of contention,
 * several iteration may be required, but it is always guaranteed that at least one thread is making progress. In
 * reality, even under heavy contention, few few attempts are required, if at all.
 *
 * (There is one exception to the above - a thread may hold a block_worker_md unrefed but the block_md may still point
 * to it. To be able to fix that, we need another sync session with the unref. This is currently avoided.)
 */
block_worker_md *ref_block_md(worker_ctx *worker, block_md *md, block_worker_md *wmd)
{
        md_file_hdr *hdr = worker->fctx->shared.hdr;
        block_worker_md *owner;

        DEBUG3("worker %p md %p (id %d)", worker, md, md - worker->fctx->shared.md);
        
        while (1) {
                uint64 prev;
                uint refed;
                
                prev = md->stamp;
                refed = BLOCK_STAMP_IS_REFED(prev);

                DEBUG3("file %s md %p prev %lx refed %d", worker->fctx->file, md, prev, refed);
                if (!refed) {
                        uint64 stamp;
                        uint64 version;

                        /* stamp is "free" - try to set our own wmd */
                        version = BLOCK_MD_VERSION(wmd->verref);
                        stamp = BLOCK_STAMP_REFED(wmd->id, version);

                        wmd->old = BLOCK_STAMP(prev);        /* ensure it is updated */

                        ADD_DEBUG_LINE('L', worker->tid, wmd);     /* "lock" */

                        if (__sync_bool_compare_and_swap(&md->stamp, prev, stamp)) {
                                worker->worker_md = NULL;  /* owner md is shared */
                                DEBUG3("set stamp to refed: %lx version %ld id %ld", prev, version, wmd->id);
                                return wmd;     /* we won - we are the new owner */
                        }
                        DEBUG2("lost race on non refed stamp %lx prev %lx", md->stamp, prev);
                } else {
                        uint64 old, new, ref, version;
                        /*
                         * Stamp is refed (in use).Ref block worker_md by changing the version + ref
                         */
                        owner = hdr->workers_mds + BLOCK_STAMP_ID(prev);
                        version = BLOCK_STAMP_VERSION(prev);
                        ref = BLOCK_MD_REF(owner->verref);

                        /* version & old are build as follows: 32 ref msb bits | 32 bits version */
                        old = BLOCK_MD_VERREF(version, ref);    /* build version from stamp to ensure consistency */
                        new = BLOCK_MD_VERREF(version, ref+1);

                        ADD_DEBUG_LINE('R', worker->tid, owner);   /* "reference" */

                        if (__sync_bool_compare_and_swap(&owner->verref, old, new))
                                return owner;

                        /*
                         * If we lost we are probably in race with unref block md - retry.
                         */
                        DEBUG2("lost race on refed stamp - can't ref block_worker_md %p %u - version %lx, old %lx new %lx",
                                owner, owner->id, owner->verref, old, new);
                }

        }

}

/**
 * Get the working md struct for a block md that has IO(s) in progress.
 *
 * Note that this function will panic if it is called on non refed block md.
 */
block_worker_md *get_block_worker(worker_ctx *worker, block_md *md)
{
        md_file_hdr *hdr = worker->fctx->shared.hdr;
        uint64 ref, version, verref, prev;
        block_worker_md *owner;
        uint refed;

        prev = md->stamp;
        refed = BLOCK_STAMP_IS_REFED(prev);

        if (!refed)
                PANIC("not reffred !");

        /*
         * Stamp is refed (in use).Ref block worker_md by changing the version + ref + writer bit
         */
        owner = hdr->workers_mds + BLOCK_STAMP_ID(prev);
        verref = owner->verref;
        ref = BLOCK_MD_REF(verref);
        version = BLOCK_MD_VERSION(verref);

        ADD_DEBUG_LINE('G', worker->tid, owner);

        if (!ref)
                PANIC("block_worker_md %p %d (%ld) has ref count 0!", owner, owner->id, owner - hdr->workers_mds);
        if (BLOCK_STAMP_VERSION(prev) != version) {
                ADD_DEBUG_LINE('E', worker->tid, owner);
                PANIC("block_worker_md %p %d version mismatch: 0x%lx != 0x%lx",
                        owner, owner->id, BLOCK_STAMP_VERSION(prev), version);
        }


        return owner;
}

/**
 * Release (unref) a working block md, optionally free its corresponding block md if it is the last ref.
 *
 * See the note in ref_block_md().
 */
int unref_block_md(worker_ctx *worker, block_md *md, int writer)
{
        md_file_hdr *hdr = worker->fctx->shared.hdr;
        block_worker_md *owner;
        uint64 ref, stamp, prev;

        while (1) {
                uint refed;
                uint64 new, verref, version;

                prev = md->stamp;
                refed = BLOCK_STAMP_IS_REFED(prev);

                if (!refed)
                        PANIC("got non refed stamp!");
                /*
                 * Stamp is refed (in use). Ref block worker_md by changing the version + ref (verref) field
                 */
                owner = hdr->workers_mds + BLOCK_STAMP_ID(prev);
                verref = owner->verref;
                ref = BLOCK_MD_REF(verref);
                version = BLOCK_STAMP_VERSION(prev);
                DEBUG3("file %s ref %ld version %ld old %lx stamp %lx writer %d",
                        worker->fctx->file, ref, version, owner->old, owner->stamp, writer);

                if (!ref)
                        PANIC("block_worker_md %p %d has ref count 0!", owner, owner->id);
                if (BLOCK_STAMP_VERSION(prev) != version)
                        PANIC("block_worker_md %p %d version mismatch: 0x%lx != 0x%lx",
                                owner, owner->id, BLOCK_STAMP_VERSION(prev), version);

                /* reader will restore old stamp, writer will change owner->old to owner->stamp */
                if (writer)
                        owner->dowrite = 1;     /* at least one writer is acting on this stamp,
                                                 * new stamp is to be set once the ref is zeroed */

                if (ref == 1)
                        new = BLOCK_MD_VERREF(version+1, 0);        /* last ref, change version */
                else
                        new = BLOCK_MD_VERREF(version, ref-1);      /* just unref */

                ADD_DEBUG_LINE('U', worker->tid, owner);   /* unref */

                if (__sync_bool_compare_and_swap(&owner->verref, verref, new))
                        break;
                /*
                 * If we lost we are probably in race with ref block md - retry.
                 */
                DEBUG2("lost race on refed stamp - can't unref block_worker_md %u old %lx verref %lx ref %ld, stamp %lx old %lx",
                        owner->id, verref, owner->verref, ref, owner->stamp, owner->old);
        }

        if (ref != 1)
                return ref-1;

        /* Don't hang here too much - me may cause other thread to spin - see note. */
        
        /* Here we are with the owner alone - the version is changed such that no more refs man be added */
        if (owner->dowrite)
                stamp = owner->stamp;
        else
                stamp = owner->old;

        DEBUG3("last ref on entry %d, free worker md and worker map, set stamp to %lx", owner->id, BLOCK_STAMP(stamp));

        /* we are last refered - free the stamp */
        stamp = BLOCK_STAMP(stamp);

        /*
         * This is just for precaution - a simple assignment will do - may be
         * expended to support full non locking path.
         */
        if (!__sync_bool_compare_and_swap(&md->stamp, prev, stamp))
                PANIC("Someone stole my stamp! md %p stamp %p prev %p my stamp %p", md, md->stamp, prev, stamp);

        /* free the block_worker_md */
        ADD_DEBUG_LINE('F', worker->tid, owner);   /* free */

        hdr->workers_map[owner->id] = 0;

        return 0;
}

static uint64 alloc_block_spinning;

/**
 * Allocate a working block md
 *
 * This function try hard to avoid contention.
 */
block_worker_md *alloc_block_worker_md(worker_ctx *worker, uint64 stamp, uint64 blockid)
{
        block_worker_md *wmd = worker->worker_md;
        md_file_hdr *hdr = worker->fctx->shared.hdr;
        uint tid = worker->tid;
        int retry = 0;

        DEBUG3("cached wmd %p", wmd);
        for (retry = 0; !wmd && retry < 5; retry++) {
                int e, i;
                uint *map = hdr->workers_map;

                for (i = 0, e = hdr->max_mds; i < e; i++) {
                        int id;
                        id = (alloc_block_spinning + tid * 6991) % hdr->max_mds;
                        atomic_fetch_and_inc64(&alloc_block_spinning);
                        
                        if (map[id])
                                continue;
                        if (__sync_bool_compare_and_swap(hdr->workers_map + id, 0, tid)) {
                                wmd = hdr->workers_mds + id;
                                wmd->id = id;
                                worker->worker_md = wmd;
                                DEBUG3("alloced %d %p: tid %u map %p", id, wmd, tid, map);
                                break;
                        }
                }
        }

        if (!wmd)
                PANIC("couldn't alloc worker md (max mds %d) "
                        "-- Please reduce number of threads/workers or lower"
                        "the max bloc size/stamp block ratio", hdr->max_mds);
                
        DEBUG3("alloced %p id %d", wmd, wmd->id);
        wmd->verref = BLOCK_MD_VERREF(saferandom64(&worker->rbuf), 1); /* new version, set ref to 1 */
        wmd->old = 0;         /* will be set again in ref_block_md */
        wmd->stamp = BLOCK_STAMP(stamp);
        wmd->dowrite = 0;
        wmd->blockid = blockid;

        ADD_DEBUG_LINE('A', worker->tid, wmd);     /* allocate */

        return wmd;

}

/***********************************************************************************************************************
 * Block stamping and checking functions
***********************************************************************************************************************/

/**
 * Generate a 64 bit stamp to control data dedup.
 * 
 * @param rand_buff  - drand48 buffer to use to generate random base
 * @param space_size - size of symbols space
 * 
 * The stamp is computed such that in the infinity (or just after enough
 * writes) we should reach the requested dedup factor.
 * 
 * space_size is used as modulu on the base random 64 bit.
 *
 * A zero space size means we don't wont dedup at all, and in such case we try to create a unique stamp using random
 * numbers - so we do not guarantee that it will be unique, but in practice it will be unique short of very few
 * cases.
 *
 * This stamp is also used for verification (see the header notes).
 */
uint64 generate_dedup_stamp(struct drand48_data * rand_buff, int64 space_size, int dedup_likehood, uint32 *counter)
{
        uint64 stamp;
        static uint64 last = 1;         /* just in case last is used before first init */
        
        /* fixed stamp "-p -2" */
        if (dedup_likehood < 0)
                return fixstamp;
        
        /* Progressive fill, use same stamp 'dedup_likehood' times */
        if (use_stamps > 1) {
                if (dedup_likehood > 0 && (atomic_fetch_and_inc32(counter) % dedup_likehood))
                        return last;
                /* races may happen, but how cares? */
                last = saferandom64(rand_buff);
                if (last == 0)
                        last++;
                return last;
        }

        stamp = saferandom64(rand_buff);
        /* module == 0 means no dedup - keep stamp as it is */
        if (space_size > 0)
                stamp = (stamp % space_size) + 1; /* +1 to reserve 0 as special case */

        /* reserve 0 as a special - do not check stamp */
        if (stamp == 0)
                stamp++;

        DEBUG3("dedup stamp 0x%lx", stamp);

        return stamp;
}

/**
 * Put a verification/dedup control stamp on the given stamp block.
 *
 * If the writer flag is on, set the working block md writer flag such that the generated (or the existing owner one)
 * stamp will be the next stable stamp after all pending IOs are done.
 * 
 * The process is as follows:
 * - Allocate a block working md is allocated just in case I will be the owner.
 * - Try to get the md and set my working md as the current one.
 *   - If I succeeded I the working md is shared and I can use it anymore.
 *   - If not, I just joined to an existing working md and refed it. In this case the previously allocated working md
 *      is cached for later use.
 * - If I am a writer, ensure that the block working md writer flag is on. This makes the last referer to swtich
 *  the original MD stamp to the one recorded in the working md (->stamp). Note that this stamp is set by the first
 *  IO to get hold on this md - even if it is a reader. If the IO ends and the writer flag is not on, the old stamp is
 *  restored (because the data didn't change).
 */
int stamp_block(worker_ctx *worker, char *buf, int len, uint64 offset, int writer)
{
        block_worker_md *wmd, *owner = 0;
        file_ctx *fctx = worker->fctx;
        workload_ctx *wlctx = worker->wlctx;
        uint64 blockid, stamp;
        block_md *md;

        if (wlctx->dedup_stamp_modulo < 0 || len < sizeof(uint64))
                return 0;

        blockid = offset / conf.stampblock;
        md = fctx->shared.md + blockid;
        stamp = generate_dedup_stamp(&worker->rbuf, wlctx->dedup_stamp_modulo,
                                     wlctx->wl->dedup_likehood, &wlctx->dedup_fill_counter);
        
        if (conf.verify) {
                /*
                 * Alloc block worker md because I may end to be the owner.
                 */
                wmd = alloc_block_worker_md(worker, stamp, blockid);

                /* Loop until we succeed to ref an owner block_worker_md */
                while (!(owner = ref_block_md(worker, md, wmd)))
                        ;
                stamp = owner->stamp;
                if (writer)
                        owner->dowrite = 1;

                DEBUG2("%s[%ld] offset 0x%lx stamp 0x%lx ref %ld",
                        fctx->file, blockid, offset, owner->stamp, owner->verref >> 32);
        } else {
                DEBUG3("%s[%ld] offset 0x%lx stamp 0x%lx ref %ld", fctx->file, blockid, offset, stamp);
        }

        ADD_DEBUG_LINE('S', worker->tid, owner);   /* stamp */

        ((uint64 *)buf)[0] = BLOCK_STAMP(stamp);
        ((uint64 *)buf)[1] = fctx->num;         /* ensure each device gets its own symbol space */

        return DEDUP_STAMP_SIZE;
}

/**
 * Perform the action requested for verification errors.
 *
 * Possible actions: count errors (-v) or panic on errors (-c).
 */
int verify_error(worker_ctx *worker, block_worker_md *owner, char *msg, ...)
{
	char buf[512];
	va_list va;
	int n;

	va_start(va, msg);
	n = vsprintf(buf, msg, va);
	va_end(va);
	buf[n] = 0;

        if (owner)
                ADD_DEBUG_LINE('E', worker->tid, owner);   /* error */

        if (conf.verify < 0)
                PANIC("%s", buf);

        DEBUG("%s", buf);
        worker->stats.verify_errors++;
        return -1;
}

/**
 * Reset range of block MD structures to its initial "unknown" state.
 * In this state read verification will always succeed.
 *
 * @note: do not call this function when a test is in progress!
 */
void reset_block_md(file_ctx *ctx, uint64 offset, size_t end)
{
        uint64 blockid, e;

        if (!conf.verify)
                return;

        blockid = offset / conf.stampblock;
        
        if (!ctx->shared.md)                           /* no md */
                return;

        if (end > ctx->size)
                end = ctx->size;

        printf("reset md of %s from %lu to %lu\n", ctx->file, offset, end);

        for (e = end / conf.stampblock; blockid < e; blockid++)
                ctx->shared.md[blockid].stamp = 0;
}

/**
 * Check if we have a valid md for this stamp block (offset).
 */
int has_stamp(file_ctx *fctx, uint64 offset)
{
        uint64 blockid = offset / conf.stampblock;

        if (!fctx->shared.md)                           /* no md */
                return 0;

        return fctx->shared.md[blockid].stamp != 0;
}

/**
 * Check dedup/verification stamps that are created by the stamp_block() function.
 *
 * This function uses the core block_md/working_block_md structures.
 */
int check_stamp(worker_ctx *worker, char *buf, int len, uint64 offset)
{
        uint64 blockid = offset / conf.stampblock;
        block_md *md = worker->fctx->shared.md + blockid;
        block_worker_md *owner;
        uint64 stamp, old, data, version;
        int ref;

        if (!worker->fctx->shared.md)                           /* no md */
                return 0;
        if (len < DEDUP_STAMP_SIZE)         /* no stamp or no space - can't check */
                return 0;

        owner = get_block_worker(worker, md);

        stamp = owner->stamp;
        old = owner->old;
        version = BLOCK_MD_VERSION(owner->verref);
        data = *(uint64 *)buf;

        ADD_DEBUG_LINE('C', worker->tid, owner);   /* check */
        
        if (old && data != stamp && data != old)
                return verify_error(worker, owner, "file %s[%ld] offset 0x%lx data stamp is %lx "
                        "but core stamp is %lx (old %lx) md %lx owner %p %d ref %ld version %lx dowrite %d",
                        worker->fctx->file, blockid, offset, data,
                        stamp, old, md->stamp, owner, owner->id,
                        BLOCK_MD_REF(owner->verref), version, owner->dowrite);

        ref = unref_block_md(worker, md, 0);

        DEBUG2("%s[%ld] offset 0x%lx stamp 0x%lx ref %d", worker->fctx->file, blockid, offset, stamp, ref);

        if (old == 0)   /* new block, nothing to check */
                return -1;
        
        return DEDUP_STAMP_SIZE;
}

/**
 * Check any data stamps that are created by the stampbuffer() function.
 */
void checkbuffer(worker_ctx *worker, char *buf, int len, long long offset)
{
        workload_ctx *wlctx = worker->wlctx;
        int used = 0, left = len, c, b;
	char *s = buf, tmp[32];

        if (!conf.verify)
                return;
        
        /* let extensions do their magic... */
        if (shared.ext.check_buffer)
                used = shared.ext.check_buffer(buf, len, offset, worker);

        if (!conf.stampblock)
                return;

        if (used) {
                used = ((used + conf.stampblock -1) / conf.stampblock) * conf.stampblock;

                /* update left and check if there is space enough for other stamps */
                left -= used;
                if (left <= 0)
                        return;
        }

        DEBUG3("file %s offset 0x%lx used %d conf.stampblock %d", worker->fctx->file, offset, used, conf.stampblock);

        /* process each conf.stampblock and validate write/dedup stamps + offset stamps */
        for (s = buf + used, offset += used; left > 0; s += conf.stampblock, left -= conf.stampblock, offset += conf.stampblock) {
                c = 0;
                /* build write id/dedup stamp */
                if (wlctx->dedup_stamp_modulo >= 0)
                        if ((c = check_stamp(worker, s, left, offset)) < 0)
                                continue;

                if (wlctx->wl->use_offset_stamps) {
                        b = snprintf(tmp, sizeof tmp, "%016llx", offset);
                        uint e = conf.stampblock;

                        if (e > left)
                                e = left;

                        /* s = stampbuffer start, c = write version count, b = tmp bufer len */
                        for (;c < e; c += b) {
                                if (c + b > e)
                                        b = e - c;
                                if (memcmp(tmp, s + c, b)) {
                                        verify_error(worker, NULL, "file %s offset 0x%lx failed on offset pattern "
                                                                "check '%s' != '%s' (b = %d)",
                                                     worker->fctx->file, offset, strndupa(tmp, b), strndupa(s+c, b), b);
                                        return;
                                }
                        }
                }
	}
}

/**
 * Reference all stamp blocks in the given range.
 */
void refbuffer(worker_ctx *worker, char *buf, int len, long long offset)
{
        workload_ctx *wlctx = worker->wlctx;
        int used = 0, left = len;
	char *s = buf;

        /* let extensions do their magic... */
        if (shared.ext.ref_buffer)
                used = shared.ext.ref_buffer(buf, len, offset, worker);

        if (!conf.stampblock)
                return;

        if (used) {
                used = ((used + conf.stampblock -1) / conf.stampblock) * conf.stampblock;

                /* update left and check if there is space enough for other stamps */
                left -= used;
                if (left <= 0)
                        return;
        }

        DEBUG3("file %s offset 0x%lx used %d conf.stampblock %d", worker->fctx->file, offset, used, conf.stampblock);

        /* process each conf.stampblock and validate write/dedup stamps + offset stamps */
        for (s = buf + used, offset += used; left > 0; s += conf.stampblock, left -= conf.stampblock, offset += conf.stampblock) {
                /*
                 * Build write id/dedup stamp.
                 * Note that this used the full write path because we may race with writers -
                 * so we need to provide stamps that might be written if a writer will share our IO...
                 */
                if (wlctx->dedup_stamp_modulo >= 0)
                        stamp_block(worker, s, len, offset, 0);
	}
}

/**
 * Un-reference all stamp blocks in the given range.
 */
void unrefbuffer(worker_ctx *worker, char *buf, int len, long long offset)
{
        workload_ctx *wlctx = worker->wlctx;
        int used = 0, left = len;
	char *s = buf;

        /* let extensions do their magic... */
        if (shared.ext.unref_buffer)
                used = shared.ext.unref_buffer(buf, len, offset, worker);

        if (!conf.stampblock)
                return;

        if (used) {
                used = ((used + conf.stampblock -1) / conf.stampblock) * conf.stampblock;

                /* update left and check if there is space enough for other stamps */
                left -= used;
                if (left <= 0)
                        return;
        }

        DEBUG3("file %s offset 0x%lx used %d conf.stampblock %d", worker->fctx->file, offset, used, conf.stampblock);

        /* process each conf.stampblock and validate write/dedup stamps + offset stamps */
        for (s = buf + used, offset += used; left > 0; s += conf.stampblock, left -= conf.stampblock, offset += conf.stampblock) {
                /*
                 * Build write id/dedup stamp.
                 * Note that this used the full write path because we may race with writers -
                 * so we need to provide stamps that might be written if a writer will share our IO...
                 */
                if (wlctx->dedup_stamp_modulo >= 0)
                        check_stamp(worker, s, len, offset);
	}
}

/**
 * Stamp a data buffer according to options.
 *
 * First the extension will be called (if any), then the dedup/verification stamp is generated (if applicable), then
 * the offset stamps are generated (if requested).
 */
void stampbuffer(worker_ctx *worker, char *buf, int len, long long offset)
{
        workload_ctx *wlctx = worker->wlctx;
        int used = 0, left = len, c, b;
	char *s = buf, tmp[32];

        /* let extensions do their magic... */
        if (shared.ext.stamp_buffer)
                used = shared.ext.stamp_buffer(buf, len, offset, worker);

        if (!conf.stampblock)
                return;
        
        if (used) {
                used = ((used + conf.stampblock -1) / conf.stampblock) * conf.stampblock;

                /* update left and check if there is space enough for other stamps */
                left -= used;
                if (left <= 0)
                        return;
        }

        DEBUG3("file %s offset 0x%lx used %d conf.stampblock %d", worker->fctx->file, offset, used, conf.stampblock);

        /* process each conf.stampblock and generate write/dedup stamps + offset stamps */
        for (s = buf + used, offset += used; left > 0; s += conf.stampblock, left -= conf.stampblock, offset += conf.stampblock) {
                c = 0;
                /* build write id/dedup stamp */
                if (wlctx->dedup_stamp_modulo >= 0)
                        c = stamp_block(worker, s, len, offset, 1);

                if (wlctx->wl->use_offset_stamps) {
                        b = snprintf(tmp, sizeof tmp, "%016llx", offset);
                        uint e = conf.stampblock;

                        if (e > left)
                                e = left;

                        /* s = stampbuffer start, c = write version count, b = tmp bufer len */
                        for (;c < e; c += b) {
                                if (c + b > e)
                                        b = e - c;
                                memcpy(s + c, tmp, b);
                        }
                }
	}
}

/**
 * Return a thread safe 32 bit random number
 */
uint32 saferandom(struct drand48_data * buffer)
{
	long int l;

        /* lrand48_r returns an integer between zero and 2^31 */
	lrand48_r(buffer, &l);

	return (uint32)l;
}

/**
 * Return a thread safe 64 bit random number
 */
uint64 saferandom64(struct drand48_data * buffer)
{
	long int lh, ll;
        
        /* lrand48_r returns an integer between zero and 2^31 */
	lrand48_r(buffer, &lh);
	lrand48_r(buffer, &ll);

        return (((uint64)lh) << 32) | (ll & 0xffffffff);
}

/**
 * Print out summary reports
 */
void summary(char *title, IOStats * stats, int n)
{
        char verr[32] = "";
        uint i;
        
        if (conf.verify)
        	snprintf(verr, sizeof verr, ", verification errors %" PRIu64, stats->verify_errors);

        printf("%s: %.3f seconds, %.3f iops, avg latency %"
	       PRIu64 " usec, bandwidth %" PRIu64 " KB/s, errors %" PRIu64 "%s, total ops %lu\n",
               title,
               ((double)stats->duration) / ((double)1000000.0) / n,
               comp_iops(stats) * n,
               comp_lat(stats),
	       comp_bw(stats) * n,
               stats->errors,verr, stats->ops);
        /* latency histograms are not supported in async mode */
        printf("%s: %.3f seconds, %u max_latency, hiccups levels:",
               title,
               ((double)stats->duration) / ((double)1000000.0) / n,
               stats->max_duration);
        for (i = 0; i < HICCUP_LEVEL_NUM_OF; i++)
                printf(" %s: %u", hickup_level_strings[i], stats->hickup_histogram[i]);
        printf("\n");
        if (conf.num_op_limit)
                printf("%s: Performed %lu ops out of %lu requested ops\n", title, total_ops, conf.num_op_limit);
        if (conf.verification_mode)
                printf("%s: Performed %lu verification IOs, %"PRIu64" errors found\n", title, total_ops, stats->verify_errors);

        fflush(stdout);
}

/**
 * Human readable encoding of the random ratio parameter - support 1-99 integer and S == 0, R == 100
 */
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

/**
 * Human readable encoding of the read ratio parameter - support 1-99 integer and W == 0, R == 100
 */
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

/**
 * Print out CSV headers to file
 */
void csv_headers(void)
{
        int i;
        
        if (!csv_file)
                return;
        
        fprintf(csv_file, "\"Title\",\"# workers\",\"seconds\",\"total seconds\",\"avg iops\",\"avg latency usec \","
                "\"bandwidth (KB/s)\",\"# errors\",\"# verification errors\",\"ops\"");
        for (i = 0; i < HICCUP_LEVEL_NUM_OF; i++)
                        fprintf(csv_file, ",\"%s\"", hickup_level_strings[i]);
        fprintf(csv_file, "\n");
}
/**
 * Print out subtotal reports
 * @param stats the aggregated statistics
 * @param title string to print on the start of the line (header part)
 * @param n  number of aggregated entities
 * 
 * @note all relevant average statistics are computed using the 'n' parameter.
 */
void worker_subtotal(IOStats * stats, char *title, int n)
{
        char verr[32] = "0";
        uint i;

        if (conf.verify)
        	snprintf(verr, sizeof verr, ", verification errors %" PRIu64, stats->verify_errors);

        if (csv_file)
                fprintf(csv_file, "\"%s\",%d,%.3f,%.3f,%.3f,%" PRIu64 ",%" PRIu64",%" PRIu64 ",%s,%"PRIu64,
                        title, n,
                        ((double)stats->duration) / ((double)1000000.0) / n,
                        ((double)stats->sduration) / ((double)1000000.0),
                        comp_iops(stats) * n, comp_lat(stats), comp_bw(stats) * n, stats->errors, verr, stats->ops);
        else
                printf("%s: %d workers, %.3f seconds (%.3f), %.3f"
                        " iops, avg latency %" PRIu64 " usec, bandwidth %" PRIu64
                        " KB/s, errors %" PRIu64 "%s, ops %lu\n",
                        title, n,
                        ((double)stats->duration) / ((double)1000000.0) / n,
                        ((double)stats->sduration) / ((double)1000000.0),
                        comp_iops(stats) * n, comp_lat(stats), comp_bw(stats) * n, stats->errors, verr, stats->ops);
        
        if (!csv_file)
                printf("%s: %d workers, %.3f seconds (%.3f), %u max_latency, hiccups levels:",
                        title, n,
                        ((double)stats->duration) / ((double) 1000000.0) / n,
                        ((double)stats->sduration) / ((double)1000000.0),
                        stats->max_duration);
        
        for (i = 0; i < HICCUP_LEVEL_NUM_OF; i++) {
                if (csv_file)
                        fprintf(csv_file, ",%u", stats->hickup_histogram[i]);
                else
                        printf(" %s: %u", hickup_level_strings[i], stats->hickup_histogram[i]);
        }
        if (csv_file)
                fprintf(csv_file, "\n");
        else
                printf("\n");
}

/**
 * Aggregate and/or print out differential report for this worker.
 * 
 * @note this function uses the last field in the worker struct to maintain the last diff report.
 * @note unless the report workers option (-z) is used, this function will not print out the worker report.
 */
uint64 worker_summary_diff(worker_ctx * worker, IOStats * subtotal)
{
	IOStats *stats = &worker->stats;
	IOStats *last = &worker->last;
	IOStats diff;
        char verr[32] = "";
        uint i;

	if (last) {
		diff = *stats;
		diff.duration = diff.duration - last->duration;
		diff.ops = diff.ops - last->ops;
		diff.lat = comp_lat(&diff);
		diff.errors = diff.errors - last->errors;
		diff.verify_errors = diff.verify_errors - last->verify_errors;
		diff.bytes = diff.bytes - last->bytes;
                for (i = 0; i < HICCUP_LEVEL_NUM_OF; i++)
                        diff.hickup_histogram[i] = diff.hickup_histogram[i] - last->hickup_histogram[i]; 
                diff.max_duration = diff.last_max_duration;                
		*last = *stats;
                stats->last_max_duration = 0;
		stats = &diff;
	}
	if (subtotal) {
		subtotal->duration += stats->duration;
		subtotal->sduration = worker->stats.duration;
		subtotal->ops += stats->ops;
		subtotal->bytes += stats->bytes;
		subtotal->errors += stats->errors;
		subtotal->verify_errors += stats->verify_errors;
                for (i = 0; i < HICCUP_LEVEL_NUM_OF; i++)
                        subtotal->hickup_histogram[i] += stats->hickup_histogram[i];
                if (stats->max_duration > subtotal->max_duration)
                        subtotal->max_duration = stats->max_duration; 
	}

	if (conf.report_workers) {
                if (conf.verify)
                        snprintf(verr, sizeof verr, ", verification errors %" PRIu64, stats->verify_errors);

		printf("Worker %d: %s %" PRIu64 " %" PRIu64
		       ": last %.3f seconds (%.3f), %.3f" " iops, avg latency %"
		       PRIu64 " usec, bandwidth %" PRIu64 " KB/s, errors %" PRIu64 "%s, ops %lu\n",
	               worker->num, worker->fctx->file, startoffset, endoffset,
		       stats->duration * 1.0 / (double) 1000000.0,
		       worker->stats.duration * 1.0 / (double) 1000000.0,
		       comp_iops(stats), stats->lat, comp_bw(stats), stats->errors, verr, stats->ops);
	}
        return stats->ops; 
}

/**
 * Aggregate and/or print out (absolute) subtotal report for this worker.
 * 
 * @note unless the report workers option (-z) is used, this function will not print out the worker report.
 */
void worker_summary(worker_ctx * worker, IOStats * subtotal)
{
	IOStats *stats = &worker->stats;
        char verr[32] = "";
        uint i;

	stats->lat = comp_lat(stats);
        
	if (subtotal) {
		subtotal->duration += stats->duration;
		subtotal->sduration = worker->stats.duration;
		subtotal->ops += stats->ops;
		subtotal->bytes += stats->bytes;
		subtotal->errors += stats->verify_errors;
		subtotal->verify_errors += stats->errors;
                for (i = 0; i < HICCUP_LEVEL_NUM_OF; i++)
                        subtotal->hickup_histogram[i] += stats->hickup_histogram[i];
                if (stats->max_duration > subtotal->max_duration)
                        subtotal->max_duration = stats->max_duration; 
	}

	if (!conf.report_workers)
		return;

        if (conf.verify)
        	snprintf(verr, sizeof verr, ", verification errors %" PRIu64, stats->verify_errors);

	printf("Worker %d: %s %" PRIu64 " %" PRIu64
	       ": %.3f seconds, %.3f" " iops, avg latency %" PRIu64
	       " usec, bandwidth %" PRIu64 " KB/s, errors %" PRIu64 "%s, ops %lu\n",
	       worker->num, worker->fctx->file, startoffset, endoffset,
	       stats->duration * 1.0 / (double) 1000000.0,
	       comp_iops(stats), stats->lat, comp_bw(stats), stats->errors, verr, stats->ops);
}

/**
 * Main subtotal statistics generation function.
 * 
 * This function is called by the real time reports thread using the option -R frequency, or by the signal USR1
 */
void dostats(int sig)
{
	IOStats subtotal = { 0 };
	worker_ctx *worker, *e;
	int n = 0;

        shared.lock_func(); 
	for (worker = workers, e = worker + total_nworkers; worker < e; worker++) {
                worker_summary(worker, &subtotal);
                n++;
        }
	shared.unlock_func();
	worker_subtotal(&subtotal, "Subtotal", n);
	fflush(stdout);
}

/**
 * Check for timeouts - scan all workers and search for a worker that exceeded the timeout.
 * Panic if such worker is found
 */
void do_timeout_check()
{
	worker_ctx *worker, *e;
        struct timespec now, start;
        uint64 duration;
        
        DEBUG2("timeout check");
        clock_gettime(CLOCK_REALTIME, &now);

        shared.lock_func(); 
	for (worker = workers, e = worker + total_nworkers; worker < e; worker++) {
                /* skip worker that are done - IO is not in progress */
                if (worker->end_time.tv_nsec || worker->end_time.tv_sec)
                        continue;
                start = worker->start_time;
                /* skip worker that started after 'now' */
                if (start.tv_sec > now.tv_sec || (start.tv_sec == now.tv_sec && start.tv_nsec > now.tv_nsec))
                        continue;
                duration = (now.tv_sec - worker->start_time.tv_sec) * 1000000llu +
                           (now.tv_nsec - worker->start_time.tv_nsec) / 1000;
                if (duration/1000 > conf.timeout_ms)
                        PANIC("IO (worker %d) on '%s' offset %ld block size %d didn't complete after %ld micro seconds",
                                worker->num, worker->fctx->file, worker->offset, worker->wlctx->wl->blocksize,
                                duration);
        }
	shared.unlock_func();
}

/**
 * Main differential subtotal statistics generation function.
 * 
 * This function is called by the real time reports thread using the option -r frequency or by the signal USR2
 * 
 * @note takes the global lock to avoid worker array changes
 */
void dostats_diff(int sig)
{
	IOStats subtotal = { 0 };
	worker_ctx *worker, *e;
	int n = 0, n_idle = 0;
        
	shared.lock_func();
        for (worker = workers, e= worker + total_nworkers; worker < e; worker++) {
                if (worker_summary_diff(worker, &subtotal) == 0)
                        n_idle++;
                n++;
        }
	shared.unlock_func();
        
	worker_subtotal(&subtotal, "Subtotal (diff)", n);
	fflush(stdout);

        if (conf.activity_check && n_idle >= n) {
                printf("All %d workers are idle in the last interval - exiting", n);
                exit(1); 
        }
}

/**
 * Update the global test state.
 * 
 * @note takes the shared global lock to provide thread safeness.
 */
void thread_finished(void)
{
        shared.lock_func();        
        shared.finished++;
        if (shared.finished >= shared.started)
                state_set(FINISHED, 0);        
        shared.unlock_func();
}

/**
 * Start barrier function - every thread calling this function will wait until all threads reach this point.
 */
int start(int n)
{
	time_t t;

        DEBUG2("wait for %d threads", n);
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
        if (conf.warmup_sec)
                state_set(WARMINGUP, 0);
        else
                state_set(RUNNING, 1);
                
	return 0;
}

/**
 * Force all files to flush and update the related stats.
 * 
 * @note this function may take a while if used write behind cache is large.
 * 
 * @todo: enable concurrent flush using several threads (one per file?)
 */
void flush()
{
	file_ctx *ctx, *e;
	struct timespec t1, t2;
	IOStats *stats;

	for (ctx = files, e = ctx + total_nfiles; ctx < e; ctx++) {
		stats = &ctx->stats;
		clock_gettime(CLOCK_REALTIME, &t1);
                fsync(ctx->fd);
                close(ctx->fd);
		clock_gettime(CLOCK_REALTIME, &t2);
		stats->sduration =
		    (t2.tv_sec - t1.tv_sec) * 1000000llu + (t2.tv_nsec - t1.tv_nsec) / 1000.0;
	}
}

/**
 * Finish barrier function - every thread calling this function will wait until all threads reach this point.
 */
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

	return 0;
}

/**
 * handle termination request signal
 */
void exit_signal(int sig)
{
        state_set(FINISHED, 1);
}

/**
 * Perform the actual on exit actions
 * 
 * Generate summary reports, flush write behind data, flush verification md file, and exit process.
 */
void doexit()
{
	IOStats total = { 0 };
	time_t t;
	int n = 0;

	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);
	finish(shared.started);
        
	worker_ctx *worker, *e;

	for (worker = workers, e = worker + total_nworkers; worker < e; worker++) {
                worker_summary(worker, &total);
                n++;
        }
        
	summary("Total", &total, n);
        if (csv_file)
                worker_subtotal(&total, "Summary", n);
        
	if (conf.iomodel == IO_MODEL_WRITE_BEHIND) {
		flush();
                
                for (n = 0, worker = workers, e = worker + total_nworkers; worker < e; worker++) {
                        worker_summary(worker, &total);
                        n++;
                }
		summary("Synced", &total, n);
                if (csv_file)
                        worker_subtotal(&total, "Synced", n);
	}

        if (csv_file) {
                fflush(csv_file);
                fclose(csv_file);
        }

        if (conf.block_md_base)
                md_flush();
        if (alloc_block_spinning)
                DEBUG("alloc block spinning %lu ops %lu avg per op: %.2f",
                        alloc_block_spinning, total_ops, (double)alloc_block_spinning / (double)total_ops);

        dump_debug_line("/tmp/debuglines");

	time(&t);
	printf("Test is done at %s", ctime(&t));
        
        exit(total.verify_errors);
}

/**
 * Verify that report interval values are sane - panic if not.
 */
static void check_interval_ratio(void)
{
	int ratio;

	if (!conf.diff_interval || !conf.subtotal_interval)
		return;
	ratio = conf.subtotal_interval / conf.diff_interval;
	if (conf.diff_interval * ratio != conf.subtotal_interval)
		PANIC("subtotal report interval %d must be a factor off diff interval %d\n",
		     conf.subtotal_interval, conf.diff_interval);
}

/**
 * Disable (ignore) relevant signals
 */
void disable_signals()
{
	signal(SIGTERM, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);
}

/**
 * (Re)Enable relevant signals
 */
void enable_signals()
{
	signal(SIGTERM, exit_signal);
	signal(SIGINT, exit_signal);
	signal(SIGUSR1, dostats);
	signal(SIGUSR2, dostats_diff);
}

/**
 * Real time report main thread loop
 * 
 * Repeatedly sleep until next report has to be generated, generate the required report(s) and so on.
 */
static void realtime_reports(int left)
{
	struct timespec duration = {0}, remaining = {0};
	int ratio = 0, diffs = 0;
	int tick;

        csv_headers();
        
        if (conf.diff_interval > 0 && conf.diff_interval < left) {
		tick = conf.diff_interval;
		ratio = conf.subtotal_interval / conf.diff_interval;
	} else if (conf.subtotal_interval > 0 && conf.subtotal_interval < left) {
		tick = conf.subtotal_interval;
		ratio = 1;
	} else {
		tick = left;
		ratio = 0;
	}

	for (; left > 0; left -= tick) {

		if (tick > left)
			tick = left;
		duration.tv_sec = tick;

                if (state_reached(FINISHED))
                        break;

		while (nanosleep(&duration, &remaining) < 0)
			duration = remaining;

		if (left == tick)
			break;	/* no need for report, the Summary report is printed upon exit */

		disable_signals();
		if (conf.diff_interval >= 0) {
			dostats_diff(0);
			diffs++;
		}
		if (ratio && !(diffs % ratio))
			dostats(0);

		enable_signals();
	}
}

/**
 * Real time report main thread loop
 * 
 * Repeatedly sleep until next report has to be generated, generate the required report(s) and so on.
 */
static void timeout_check(int tick)
{
	struct timespec duration = {0}, remaining = {0};

        DEBUG2("timeout check starting. Check interval %d seconds", tick);
	while (!state_reached(FINISHED)) {

		duration.tv_sec = tick;

		while (nanosleep(&duration, &remaining) < 0)
			duration = remaining;

                do_timeout_check();
	}
}

/**
 * Return the next workload to be used a worker.
 * 
 * Selects by random & weights defined by workload file or just return the single workload defined on the command line.
 */
workload_ctx *next_workload_ctx(worker_ctx* worker)
{
        int workloadno;
        
        if (total_nworkloads == 1)
                return worker->fctx->wlctxs + 0;
        
        workloadno = (saferandom(&worker->rbuf)) % total_workload_weights;

        workloadno = workload_weights[workloadno];
        if ((workloadno < 0) || (workloadno > total_nworkloads)) {
                PANIC("reached invalids workloadno value %d", workloadno);
        }
        return worker->fctx->wlctxs + workloadno;
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
 * IO completion function - currently shared for both Sync/Async IO
 **********************************************************************************************************************/
void io_write_completed(worker_ctx *worker, void *buf, uint64 offset, int size)
{
        if (conf.verify)
                unrefbuffer(worker, buf, size, offset);
}

void io_read_completed(worker_ctx *worker, void *buf, uint64 offset, int size)
{
        if (conf.verify)
                checkbuffer(worker, buf, size, offset);
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
void *aio_prepare_buf(worker_ctx* worker)
{
        return worker->buf;
}

ssize_t aio_read(worker_ctx* worker, int fd, void *buf, size_t count, off_t offset)
{
        struct iocb* aio_iocb = worker->aio_cb;
        int res;

        io_prep_pread(aio_iocb, fd, buf, count, offset);

        /* data field must be set after the io_prep call because the last clears the structure */
        aio_iocb->data = (void*)worker;

        res = io_submit(worker->io_context, 1, &worker->aio_cb);

        if (res < 0) {
                WARN("AyncIO submittion failed (%d requests). rc=%d %s \n", 1, res, strerror(-res));
                return -1;
        }

        return count;
}

ssize_t aio_write(worker_ctx* worker, int fd, void *buf, size_t count, off_t offset)
{
        struct iocb* aio_iocb = worker->aio_cb;
        int res;

        io_prep_pwrite(aio_iocb, fd, buf, count, offset);

        /* data field must be set after the io_prep call because the last clears the structure */
        aio_iocb->data = (void*)worker;

        res = io_submit(worker->io_context, 1, &worker->aio_cb);

        if (res < 0) {
                WARN("AyncIO submittion failed (%d requests). rc=%d %s \n", 1, res, strerror(-res));
                return -1;
        }

        return count;
}

/**********************************************************************************************************************
 * IO Functions - SyncIO
 **********************************************************************************************************************/
void *sync_prepare_buf(worker_ctx *worker)
{
        return worker->buf;
}

ssize_t sync_read(worker_ctx *worker, int fd, void *buf, size_t count, off_t offset)
{
        ssize_t r = pread(fd, buf, count, offset);

        if (conf.verify && worker)
                shared.read_completed(worker, buf, offset, count);

        return r;
}

ssize_t sync_write(worker_ctx *worker, int fd, void *buf, size_t count, off_t offset)
{
        ssize_t r = pwrite(fd, buf, count, offset);

        if (conf.verify && worker)
                shared.write_completed(worker, buf, offset, count);

        return r;
}

/**********************************************************************************************************************
 * IO Functions - SCSI Generic IO
 **********************************************************************************************************************/
ssize_t sg_read(worker_ctx *worker, int fd, void *buf, size_t count, off_t offset)
{
        int r = sg_rw(fd, 0, buf, count/512, offset/512, 512, 10, 0, 0, NULL, 0, 0);

        if (conf.verify && worker)
                shared.read_completed(worker, buf, offset, count);

        if (r == 0)
		return count;
	return -1;
}

ssize_t sg_write(worker_ctx* worker, int fd, void *buf, size_t count, off_t offset)
{
        int r = sg_rw(fd, 1, buf, count/512, offset/512, 512, 10, 0, 0, NULL, 0, 0);

        if (conf.verify && worker)
                shared.write_completed(worker, buf, offset, count);

        if (r == 0)
		return count;
	return -1;
}

/**********************************************************************************************************************
 * Sync/Async IO Utility functions
 **********************************************************************************************************************/

/**
 * Return the block device size in sectors (512 bytes).
 */
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

/**
 * Return the size of the file/block object or the expected file in case of future format.
 */
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

/**
 * Perform the random trim per write (option -x)
 * 
 * Attempts to use large sector range to reduce the overhead
 * 
 * @note this is an IDE specific feature
 * 
 * file context's ata fd must be already initialized.
 */
int do_rand_trim(worker_ctx * worker)
{
        workload *wl = worker->wlctx->wl;
	uint64_t trimoffset = saferandom64(&worker->rbuf) * wl->trimsize;
	struct sector_range_s ranges[SECTOR_RANGES_MAX];
	int left = wl->blocksize;
	int r;

	while (left > 0) {
		for (r = 0; r < SECTOR_RANGES_MAX && left > 0; r++) {
			trimoffset = wl->startoffset +
                                ((saferandom64(&worker->rbuf) * wl->alignsize) % worker->wlctx->len);
			DEBUG3("file %s fd %d trim at offset %"PRId64" size %d",
                                worker->fctx->file, worker->fctx->fd, worker->offset, wl->trimsize);
			ranges[r].lba = trimoffset / 512;
			ranges[r].nsectors = wl->trimsize / 512;
			left -= wl->trimsize;
		}
		if (ata_trim_sector_ranges(worker->fctx->atafd, ranges, r) < 0) {
			WARN("file %s trim (%d ranges) failed on atafd %d", worker->fctx->file, r, worker->fctx->atafd);
			return -1;
		}
	}
	return 0;
}


/**
 * Format the requested data range on the specified file by writing zeros blocks on that range.
 * 
 * The format is done by sequentially writing large blocks (1MB) of zeros.
 * 
 * @note if the device is sg, sg_write is used, otherwise, sync_write is used.
 * 
 * This function is not thread safe and doesn't handle md reseting.
 */
void do_format(char *file, uint64_t start, uint64_t size, IOModel iomodel)
{
	int ios = 0;
	int iosize;
	int fd;

        ssize_t (*writefn)(worker_ctx *worker, int fd, void *buf, size_t count, off_t offset) = shared.write;

        /* we don't have worker struct here, so use sync io for format */
        if (iomodel == IO_MODEL_ASYNC)
                writefn = sync_write;
        
        fd = open(file, O_RDWR | O_CREAT | O_LARGEFILE | O_NOATIME, 0600);
        if (fd < 0 && shared.ext.open_failure)
                fd = shared.ext.open_failure(file, O_RDWR | O_CREAT | O_LARGEFILE | O_NOATIME, 0600);
        if (fd < 0)
		PANIC("open '%s' failed", file); 

	printf("Start formating %s at %" PRId64 ", %" PRId64 " bytes:", file, start, size);
        fflush(stdout);
	while (size) {
		iosize = FORMAT_IOSZ;
		if (iosize > size)
			iosize = size;
		DEBUG2("format IO: %s offs %" PRId64 " iosize %d", file, start, iosize);
                if (writefn(NULL, fd, formatbuf, iosize, start) != iosize) 
                                PANIC("io failed on %s during format offset %" PRId64, file, start);
		size -= iosize;
		start += iosize;
		ios++;
                /* pretty print '.' every 1k IOs */
		if (!(ios % (1 << 10))) {
			printf(".");
			fflush(stdout);
		}
	}

	printf(" - done.\n");
        fflush(stdout);

	fsync(fd);
	close(fd);
}

/**
 * Initialize the requested data range on the specified file by issuing IDE Trim requests for that range.
 * 
 * @note The outcome of the trim is device specific. Most modern device will probably return zero blocks for ranges
 * that are trimmed and never written.
 * 
 * This function is not thread safe and doesn't handle md reseting.
 */
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

/**
 * Calculate the size of the symbol range to be used for data stamping (see -p option).
 * 
 * @note dedup_likehood 0 => no dedup at all, -1 => no stamps. modulo
 */
static int64 calc_dedup_stamp_modulo(uint64 span, int dedup_likehood)
{
        double blocks = span / conf.stampblock;
        uint64 dedup_stamp_modulo;

        if (dedup_likehood == 0)
                return 0;       /* no dedup - use full symbol range */

        if (dedup_likehood == -1)
                return -1;      /* do not use stamps at all */

        if (dedup_likehood == -2)
                return 1;      /* use fixed stamps at all */
        
        DEBUG2("blocks for dedup calc %f", blocks);

        dedup_stamp_modulo = (blocks / dedup_likehood);
        if (!dedup_stamp_modulo)
                dedup_stamp_modulo = 1;

        DEBUG("dedup stamp likehood %d modulu %lu", dedup_likehood, dedup_stamp_modulo);
        return dedup_stamp_modulo;
}

/**********************************************************************************************************************
 * Offset resolution functions
 **********************************************************************************************************************/

/**
 * In 'exit_eof' mode - check if we reached the end.
 */
int eof_reached(worker_ctx *worker)
{
        workload *wl = worker->wlctx->wl;

        if (worker->offset == ~0ul || worker->offset + wl->blocksize > worker->wlctx->end) {
                DEBUG("reached EOF (offset %lu)", worker->offset);
                return 1;
        }
        return 0;
}

uint64 next_validation_offset(worker_ctx *worker)
{
        file_ctx *fctx = worker->fctx;
        workload *wl = worker->wlctx->wl;
        uint64 offset = worker->fctx->seq_offset;

        
        for (;offset != ~0ul;) {
                /* skip (block * threads) on this file to keep in sync with other threads */
                offset += wl->blocksize;

                if (offset + wl->blocksize > worker->wlctx->end)
                        return ~0ul;

                if (has_stamp(fctx, offset))
                        break;
        };
       return offset;        /* validation not finished */
}

/**
 * Get next sequential offset for this worker
 */
uint64 seq_offset(worker_ctx *worker)
{
       return worker->wlctx->start + ((worker->offset - worker->wlctx->start) % worker->wlctx->len);
}
        
/**
 * Set next sequential offset for this worker
 */
uint64 next_seq_offset(worker_ctx *worker)
{        
        if (conf.verification_mode) {
                uint64 next, old;
                do {
                        old = worker->fctx->seq_offset;
                        next = next_validation_offset(worker);
                } while (next != ~0ul && !__sync_bool_compare_and_swap(&worker->fctx->seq_offset, old, next));
                return next;
        } else {
                DEBUG3("file %s: seq offset 0x%lx", worker->fctx->file, worker->fctx->seq_offset);
        	return atomic_fetch_and_add64(&worker->fctx->seq_offset, worker->wlctx->wl->blocksize);
        }
}

/**
 * Set next random offset for this worker
 */
uint64 next_rand_offset(worker_ctx *worker)
{
        workload *wl = worker->wlctx->wl;
        
        DEBUG3("worker %p wl %p wl->len %ul blocksize %d", worker, wl, worker->wlctx->len, wl->blocksize);
        uint64 block = saferandom64(&worker->rbuf) % (worker->wlctx->len / wl->blocksize);

	return wl->startoffset + block * wl->blocksize;
}

/**********************************************************************************************************************
 * IO Logic functions
 **********************************************************************************************************************/
#define XDUMP4(buf, size, msg)       do { if (conf.debug > 3) xdump(buf, size, msg); } while (0)

int do_seq_read(worker_ctx *worker)
{
        file_ctx *fctx = worker->fctx;
        workload *wl = worker->wlctx->wl;
        void *buf;

	worker->offset = seq_offset(worker);
        buf = shared.prepare_buf(worker);
        
	DEBUG3("file %s fd %d seek to offset %" PRIu64, fctx->file, fctx->fd, worker->offset);
        refbuffer(worker, buf, wl->blocksize, worker->offset);
        
	if (shared.read(worker, fctx->fd, buf, wl->blocksize, worker->offset) != wl->blocksize)
		return -1;
	worker->offset = next_seq_offset(worker);        /* update offset for next (seq) operation */

        XDUMP4(buf, wl->blocksize, "rand_read");

        return 0;
}

int do_seq_write(worker_ctx * worker)
{
        file_ctx *fctx = worker->fctx;
        workload *wl = worker->wlctx->wl;
        void *buf;

	worker->offset = seq_offset(worker);
        buf = shared.prepare_buf(worker);

        stampbuffer(worker, buf, wl->blocksize, worker->offset);
        
	DEBUG3("file %s fd %d seek to offset %" PRIu64, fctx->file, fctx->fd, worker->offset);
        XDUMP4(buf, wl->blocksize, "seq_write");

	if (shared.write(worker, fctx->fd, buf, wl->blocksize, worker->offset) != wl->blocksize)
		return -1;
	worker->offset = next_seq_offset(worker);        /* update offset for next (seq) operation */
        
	return 0;
}

int do_rand_read(worker_ctx * worker)
{
        file_ctx *fctx = worker->fctx;
        workload *wl = worker->wlctx->wl;
        void *buf;

	worker->offset = next_rand_offset(worker);
        buf = shared.prepare_buf(worker);

	DEBUG3("file %s fd %d seek to offset %" PRIu64, fctx->file, fctx->fd, worker->offset);
        refbuffer(worker, buf, wl->blocksize, worker->offset);

        if (shared.read(worker, fctx->fd, buf, wl->blocksize, worker->offset) != wl->blocksize)
		return -1;
        XDUMP4(buf, wl->blocksize, "rand_read");

	worker->offset = next_seq_offset(worker);        /* update offset for next (possibly seq) operation */

	return 0;
}

int do_rand_write(worker_ctx * worker)
{
        file_ctx *fctx = worker->fctx;
        workload *wl = worker->wlctx->wl;
        void *buf;

	worker->offset = next_rand_offset(worker);
        buf = shared.prepare_buf(worker);

        stampbuffer(worker, buf, wl->blocksize, worker->offset);

	DEBUG3("file %s fd %d seek to offset %" PRIu64, fctx->file, fctx->fd, worker->offset);
        XDUMP4(buf, wl->blocksize, "rand_write");

        if (shared.write(worker, fctx->fd, buf, wl->blocksize, worker->offset) != wl->blocksize)
		return -1;
	worker->offset = next_seq_offset(worker);        /* update offset for next (possibly seq) operation */

	return 0;
}

/**
 * @brief Main function for single IO operation - Sync/Async 
 * 
 * This function selects which of the IO logic function is should called: read/write, random/sequential.
 * 
 * @return 0 for OK, 1 for stop (number of ops is reached), and -1 for errors
 */
int do_io(worker_ctx *worker)
{
	int (*io) (struct worker_ctx *) = NULL;
        file_ctx *fctx = worker->fctx;
        workload_ctx *wlctx = worker->wlctx;
        workload *wl = wlctx->wl;
	int doread = 0, dorandom = 0;

        memset(&worker->end_time, 0, sizeof worker->end_time);  /* mark as not finished */
        clock_gettime(CLOCK_REALTIME, &(worker->start_time));
        
        if (conf.num_op_limit && state_reached(RUNNING)) {
                if (total_ops >= conf.num_op_limit) {
                        state_set(FINISHED, 1);
                        return 1;
                }
                atomic_fetch_and_inc64(&total_ops);
        } else
                DEBUG3("Ignoring IO during warmup");
        
        if (conf.exit_eof && eof_reached(worker))
                return 1;
        
        if (conf.verification_mode)
                atomic_fetch_and_inc64(&total_ops);

	if (wl->readratio == 100)
		doread = 1;
	else if (wl->readratio == 0)
		doread = 0;
	else
		doread = (saferandom(&worker->rbuf) % 100) < wl->readratio;

	if (wl->randomratio == 100)
		dorandom = 1;
	else if (wl->randomratio == 0)
		dorandom = 0;
	else 
		dorandom = (saferandom(&worker->rbuf) % 100) < wl->randomratio;
        
        DEBUG3("read ratio %d - %d random ratio %d - %d", wl->readratio, doread, wl->randomratio, dorandom);

	switch (doread | (dorandom << 1)) {
	case 0:
		DEBUG3("%s %d: seq write: block size %d", fctx->file, worker->tid, wl->blocksize);
		io = do_seq_write;
		break;
	case 1:
		DEBUG3("%s %d: seq read: block size %d", fctx->file, worker->tid, wl->blocksize);
		io = do_seq_read;
		break;
	case 2:
		DEBUG3("%s %d: random write: block size %d", fctx->file, worker->tid, wl->blocksize);
		io = do_rand_write;
		break;
	case 3:
		DEBUG3("%s %d: random read: block size %d", fctx->file, worker->tid, wl->blocksize);
		io = do_rand_read;
		break;
	}

	return io(worker);
}

/**********************************************************************************************************************
 * Validation features
 **********************************************************************************************************************/

/**
 * Initialize the shared context part of the file context 'fctx'.
 * 
 * Opens/Creates the verification md file for this file or open /dev/zero to be used for the mmap
 * @see init_validation_md()
 * 
 * This function must be called only once per file, before any other references to the verification md /md file.
 */
static void init_shared_file_ctx(file_ctx *fctx)
{
        shared_file_ctx *shared = &fctx->shared;
        char md_file[512] = "";
        char *devname, *s;

        if (!conf.verify || !use_stamps)
                return;

        DEBUG2("verification requested - for filename %s base %s", fctx->file, conf.block_md_base);
        if (!conf.block_md_base)
                sprintf(md_file, "/dev/zero");
        else if (conf.nfiles == 1) {
                strncpy(md_file, conf.block_md_base, sizeof md_file -1 );
        } else {

                devname = strdupa(fctx->file);

                for (s = devname; *s; s++)
                        if (*s == '/')
                                *s = '_';

                snprintf(md_file, sizeof md_file, "%s-%s", conf.block_md_base, devname);
                md_file[sizeof md_file -1 ] = 0;
        }

        shared->md_file = strdup(md_file);
        DEBUG2("open/create md file %s\n", md_file);
        if ((shared->fd = open(shared->md_file, O_RDWR | O_CREAT, 0744)) < 0)
                PANIC("can't open md file '%s'", shared->md_file);
}

/**
 * Initialize a new verification md header
 */
static void init_md_hdr(file_ctx *ctx, md_file_hdr *hdr, size_t hdrsize, size_t mdsize)
{
        printf("Initializing new md file %s for device %s\n", ctx->shared.md_file, ctx->file);
        hdr->stampblock = conf.stampblock;
        strncpy(hdr->devname, ctx->file, sizeof hdr->devname - 1);
        hdr->max_mds = sizeof hdr->workers_map / sizeof (uint);
        hdr->md_start = hdrsize;
        hdr->version = MD_VERSION;
        hdr->magic = MD_MAGIC;
        hdr->initialized = 1;

        hdr->hdrsize = hdrsize;
        hdr->mdsize = mdsize;

}

/**
 * Validates that an opend md file size is sane.
 * 
 * This function is required because it may happen that we attempt to use an existing md file.
 */
static void validate_md_file_size(shared_file_ctx *shared, off_t size)
{
        struct stat f_stat;

        if (fstat(shared->fd, &f_stat) < 0)
                PANIC("can't fstat %s", shared->md_file);

        if (f_stat.st_size < size) {
                DEBUG("resize %s to %ld bytes", shared->md_file, size);
                ftruncate(shared->fd, size);
        }
}

/**
 * initialize validation md structures
 *
 * Create a new mmap region or attach to an existing one. In the later case check that our critical verification
 * parameters match the existing file.
 * 
 * In any case (short of panic) ref the file.
 * 
 * return true if I am the first to init.
 */
static int init_validation_md(file_ctx *fctx, uint64 start, uint64 end)
{
        shared_file_ctx *file_shared = &fctx->shared;
        int pagesize = sysconf(_SC_PAGE_SIZE);
        size_t size, hdrsize;
        int initializer = 0;
        ulong blocks;
        int flags, ref;

        if (!conf.verify || conf.stampblock <= 0 || !use_stamps)
                return 1;         /* no verification is enabled, or no stamps, so I am always "initializer" */
        
        if (file_shared->md)         /* already initialized */
                return atomic_fetch_and_inc32(&file_shared->hdr->ref) == 0;

        blocks = (end - start + conf.stampblock - 1) / conf.stampblock;
        size = blocks * sizeof (block_md);
        size = (size + pagesize -1) / pagesize * pagesize;
        hdrsize = ((sizeof(*file_shared->hdr) + pagesize -1 )/ pagesize) * pagesize;
        DEBUG("allocating %lu bytes (+ %lu bytes for hdr) for file %s md (%lu blocks of %u size) using mmap file %s fd %d",
                size, hdrsize, fctx->file, blocks, conf.stampblock, file_shared->md_file, file_shared->fd);

        if (conf.block_md_base) {
                /* md file case - mmap the file to allow shared memory */
                flags = MAP_SHARED /*| MAP_HUGETBL*/ | MAP_NORESERVE;
                
                validate_md_file_size(file_shared, hdrsize + size);
                
                if ((file_shared->hdr = mmap(NULL, hdrsize, PROT_WRITE | PROT_READ, flags, file_shared->fd, 0)) == (void *)-1)
                        PANIC("mmap failed: '%s' arg md calloc: size %lu", file_shared->md_file, hdrsize);
                
                if (file_shared->hdr->magic != MD_MAGIC || conf.force_md_init) {
                        if (file_shared->hdr->magic != MD_MAGIC)
                                DEBUG("initializing %s: bad md hdr (magic bad %x != %x)",
                                        file_shared->md_file, file_shared->hdr->magic, MD_MAGIC);
                        else if (conf.force_md_init)
                                DEBUG("initializing %s: bad md hdr (force md init)", file_shared->md_file);
                        
                        memset(file_shared->hdr, 0, hdrsize);
                        file_shared->hdr->magic = MD_MAGIC;
                        
                        do_format(file_shared->md_file, hdrsize, size, IO_MODEL_SYNC);
                }
                
                if (!(ref = atomic_fetch_and_inc32(&file_shared->hdr->ref)) && !file_shared->hdr->initialized) {
                        /* non initialized file and first to ref it */
                        initializer = 1;
                        init_md_hdr(fctx, file_shared->hdr, hdrsize, size);
                } else {
                        /* We may be non first thread to join a not yet initialized file... */
                        while (!file_shared->hdr->initialized) {
                                if (file_shared->hdr->ref < 2)
                                        PANIC("I am not initializer but there is no one except me?!");
                                printf("wait until md %s will be initialized...", file_shared->md_file);
                                th_busywait();
                        }
                        
                        /* Check that our critical verification parameters match the file parameters */
                        if (ref)
                                printf("Joining to already reffed md file %s for device %s\n",
                                        file_shared->md_file, fctx->file);
                        else
                                printf("Opening md file %s for device %s\n", file_shared->md_file, fctx->file);
                                
                        if (file_shared->hdr->version/100 != MD_VERSION/100)     /* only major version matters */
                                PANIC("md version mismatch (md file %d mine is %d)",
                                        file_shared->hdr->version, MD_VERSION);
                        if (file_shared->hdr->stampblock != conf.stampblock) {
                                atomic_fetch_and_inc32(&file_shared->hdr->ref);
                                PANIC("can't join to %s - stampblock don't match %d (my stampblock %d)",
                                        file_shared->md_file, file_shared->hdr->stampblock, conf.stampblock);
                        }
                        if (size > file_shared->hdr->mdsize)
                                PANIC("MD file %s md size %lu is smaller than my calculated one %lu - "
                                        "did file/dev get larger?",
                                        file_shared->md_file, file_shared->hdr->mdsize, size);
                        if (hdrsize > file_shared->hdr->hdrsize)
                                PANIC("MD file %s hdr size is smaller than my calculated one %lu - ???",
                                        file_shared->md_file, file_shared->hdr->hdrsize, hdrsize);
                }
        } else {
                /* non md file case - use an anonymous mmap region */
                flags = MAP_PRIVATE /*| MAP_HUGETBL*/ | MAP_NORESERVE;
                file_shared->hdr = calloc(1, sizeof(*file_shared->hdr));
                initializer = 1;
                init_md_hdr(fctx, file_shared->hdr, hdrsize, size);
        }

        if ((file_shared->md = mmap(NULL, size, PROT_WRITE | PROT_READ, flags,
                                    file_shared->fd, file_shared->hdr->md_start)) == (void *)-1)
                PANIC("mmap failed: '%s' arg md calloc: size %lu", file_shared->md_file, size);
        
        return initializer;
}

/**
 * Force all verification md files to flush (msync).
 * 
 * @note this function may take a while if data range is large.
 * @todo: enable concurrent flush using several threads (one per file?)
 */
static void md_flush()
{
	file_ctx *ctx, *e;

	for (ctx = files, e = ctx + total_nfiles; ctx < e; ctx++) {
                if (!ctx->shared.md_file)
                        continue;

                if (atomic_fetch_and_dec32(&ctx->shared.hdr->ref) != 1) {
                        DEBUG("md file %s still refed. Not syncing", ctx->shared.md_file);
                        continue;
                }

                printf("Please wait while flushing block md to %s\n", ctx->shared.md_file);
                msync(ctx->shared.hdr, ctx->shared.hdr->md_start, MS_SYNC);
                msync(ctx->shared.md, ctx->shared.hdr->mdsize, MS_SYNC);
                printf("Done md flush to %s\n", ctx->shared.md_file);
                close(ctx->shared.fd);
                ctx->shared.md_file = NULL;
	}
}


/**********************************************************************************************************************
 * Sync + Async IO init 
 **********************************************************************************************************************/

/**
 * Initialized the requested file range - optionally by formating and/or trimming it.
 * 
 * Note that each of the format/trim options forces verification md reset. This means that formating
 * a shared verification md may not be what you want.
 */
void init_file_range(file_ctx *ctx, uint64  start, uint64 end)
{
        if (conf.pretrim) {
                /* TODO: make do trimformat use stamp block - verify that stamp is zero */
                do_trimformat(ctx->atafd, start, end - start);

                reset_block_md(ctx, start, end);
        }

        if (conf.preformat) {
                /* TODO: make do format use stamp block */
                do_format(ctx->file, start, end - start, conf.iomodel);

                reset_block_md(ctx, start, end);
        }
}

/**
 * Initialize workload context.
 * 
 * Should be called only once per file.
 */
void init_workload_context(file_ctx *ctx, workload_ctx *wlctx, workload *wl)
{
        wlctx->wl = wl;
        
        if (wl->len == 0 && ctx->size >= wl->startoffset + wl->blocksize)
                wlctx->len = ctx->size - wl->startoffset;
        if (wl->len && ctx->size >= wl->startoffset + wl->len)
                wlctx->len = wl->len;

        /* make sure len is alignd on alignsize */
        if (wlctx->len % wl->alignsize)
                wlctx->len -= wlctx->len % wl->blocksize;
        
        if (wlctx->len < wl->blocksize)
                PANIC("file/dev %s size %lu doesn't match workload %d start %lu len %lu (wlctx len %ld wl blocksize %d)",
                        ctx->file, ctx->size, wl->num, wl->startoffset, wl->len, wlctx->len, wl->blocksize);

        wlctx->dedup_stamp_modulo = calc_dedup_stamp_modulo(wlctx->len, wl->dedup_likehood);
        wlctx->start = wl->startoffset;
        wlctx->end = wlctx->start + wlctx->len;

        DEBUG("workload %d file '%s' size is %" PRId64 " using blocksize %d aligned to %d",
                wl->num, ctx->file, ctx->size, wl->blocksize, wl->alignsize);
}

/**
 * Return file type FILE/BLOCK/SG/INVALID
 */
FileType file_get_type(char *filename)
{
        struct stat st;
        int is_sg = sg_is_sg(filename);

        if (is_sg)
                return F_SG;

        if (stat(filename, &st) < 0) {
                if (errno == ENOENT)
                        return F_FILE;  /* normal file can be created upon open */
                PANIC("can't stat %s", filename);
        }

        if (S_ISREG(st.st_mode))
                return F_FILE;

        if (S_ISBLK(st.st_mode))
                return F_BLOCK;

        PANIC("unsupported file type for '%s'", filename);
        return F_INVALID;
}

/**
 * Allocate and initialize new file context using the next non initialized file name.
 *
 * Open/Create the file/block device, check that we can do IO on it, and init its size and IDE ata fd (if applicable).
 */
file_ctx *new_file_ctx(void)
{
	int fd = 0;
	int is_sg;
        int openflags;
        size_t iosize = 4096, size;
        file_ctx *ctx;

        shared.lock_func();
        if (total_nfiles >= max_nfiles)
                PANIC("number limit of files is reached %d now %d", max_nfiles, total_nfiles);
        ctx = files + total_nfiles++;     
        ctx->num = ctx - files;
        ctx->file = filenames[ctx->num];
        shared.unlock_func();
        

        ctx->type = file_get_type(ctx->file);
        is_sg = ctx->type == F_SG;

        if (is_sg) {    /* automatically switch to SGIO model if SG device is discovered */
                if (conf.iomodel != IO_MODEL_SGIO && (conf.iomodel != IO_MODEL_SYNC && ctx->num > 0))
                        PANIC("can't mix SG devices and non SG devices (found %s sg %d)", ctx->file, is_sg);
                if (conf.iomodel != IO_MODEL_SGIO && conf.iomodel != IO_MODEL_SGIO_DIRECT) {
                        conf.iomodel = IO_MODEL_SGIO;
                        shared.read = sg_read;
                        shared.write = sg_write;
                        printf("Switch to SGIO mode\n");
                }
        } else if (ctx->type == F_FILE && (conf.iomodel == IO_MODEL_SGIO || conf.iomodel == IO_MODEL_SGIO_DIRECT))
                PANIC("can't use SGIO on file '%s'", ctx->file);

        openflags = openflags_iomodel[conf.iomodel];
        if (conf.iomodel != IO_MODEL_SGIO)
                openflags |= (readonly) ? O_RDONLY : O_RDWR;
        
        DEBUG("file '%s' IOModel: %s open flags: (octal) %o", ctx->file, iomodel_str[conf.iomodel], openflags);
	fd = open(ctx->file, openflags, 0600);

        /* If open was successful, do one READ op to make sure we device is active */
        /* file type files should not be checked now, they can be zero sized */
        if (fd >= 0 && ctx->type != F_FILE) {
                char* buf = valloc(iosize);
                ssize_t (*readfn)(worker_ctx *worker, int fd, void *buf, size_t count, off_t offset) = shared.read;
                
                /* we don't have worker struct here, so use sync io for this check */
                if (conf.iomodel == IO_MODEL_ASYNC)
                        readfn = sync_read;

                if (readfn(NULL, fd, buf, iosize, startoffset) < 0) {
                        close(fd);
                        fd = -1; 
                }
                free(buf);                        
        }

        /* if open failed, let extentions try to recover */
        if (fd < 0 && shared.ext.open_failure)
                fd = shared.ext.open_failure(ctx->file, openflags, openflags);

        if (fd < 0)
		PANIC("open '%s' failed", ctx->file);

        ctx->fd = fd;

        /* ata fd must be initialized for format or real time trim */
        ctx->atafd = -1;
        if (conf.pretrim || conf.pretrim)
                ctx->atafd = ata_init(ctx->file);

        /*
         * If the file/device size is 0 and we are doing only writes or format is requested
         * we assume that the size can be resize to requested size, if the device supports it.
         */
        size = endoffset;
        if (size < startoffset + maxblocksize)
                size = startoffset + maxblocksize;
        if ((ctx->size = getsize(is_sg, fd, size, conf.preformat || !readonly)) < size)
                PANIC("can't get size of '%s' sz %"PRId64", or size < end offset %"PRId64,
                        ctx->file, ctx->size, size);

        return ctx;
}

/**
 * Handle IO operation end.
 * 
 * updates statistics and/or errors.
 */
int io_ended(worker_ctx *worker, int ioret, int update_stats)
{
	IOStats *stats = &worker->stats;
        file_ctx *fctx = worker->fctx;
        uint64 duration, duration_milli;

        if (ioret < 0) {
                if (!conf.ignore_errors)
                        PANIC("%d: IO error on '%s'", worker->tid, fctx->file);
                WARN("%d: IO error on '%s': %m", worker->tid, fctx->file);
                stats->errors++;
                return 1;       /* ended with errors */
        }
        if (ioret == 1 || worker->offset == ~0ul)
                return -1; /* end of test reached */
        if (!update_stats || !state_reached(RUNNING))
                return 0;       /* OK */

        clock_gettime(CLOCK_REALTIME, &(worker->end_time));

        duration = (worker->end_time.tv_sec - worker->start_time.tv_sec) * 1000000llu +
                   (worker->end_time.tv_nsec - worker->start_time.tv_nsec) / 1000;
        if (conf.timeout_ms && duration/1000 > conf.timeout_ms)
                PANIC("IO (worker %d) on '%s' offset %ld block size %d didn't complete after %ld micro seconds",
                        worker->num, worker->fctx->file, worker->offset, worker->wlctx->wl->blocksize,
                        duration);

        if (duration > stats->max_duration)
                stats->max_duration = duration;
        if (duration > stats->last_max_duration)
                stats->last_max_duration = duration;
        duration_milli = duration / 1000;
        if (!duration_milli)
                stats->hickup_histogram[HICKUP_LEVEL_0_MILLI]++;
        else if (duration_milli == 1)
                stats->hickup_histogram[HICKUP_LEVEL_1_MILLI]++;
        else if ((duration_milli >= 2) && (duration_milli <= 10))
                stats->hickup_histogram[HICKUP_LEVEL_2TO10_MILLI]++;
        else if ((duration_milli >= 11) && (duration_milli <= 100))
                stats->hickup_histogram[HICKUP_LEVEL_11TO100_MILLI]++;
        else if (duration_milli > 100)
                stats->hickup_histogram[HICKUP_LEVEL_101ANDUP_MILLI]++;

        stats->duration += duration;
        stats->ops++;
        stats->bytes += worker->wlctx->wl->blocksize;

        return 0;       /* ended normaly */
}

/**
 * Perform the common init work for all workers/threads that share a given file
 */
void thread_init_file(file_ctx *ctx)
{
        ssize_t size;
        int w;

        DEBUG("file ctx %d '%s' is being initialized", ctx->num, ctx->file);

        if (use_stamps)
                init_shared_file_ctx(ctx);

        /*
         * If file size is smaller than endoffset, it means that it is a regular file that should
         * be expended to endoffset.
         * If endoffset is 0, it means that we want to use the device/file size.
         */
        if (endoffset == 0)
                size = ctx->size;
        else
                size = endoffset;
                
        /* if no md is used or we are the initializer of this md, format it */
        if (!use_stamps || init_validation_md(ctx, startoffset, size)) {

                /* TODO: init each workload range instead of the containing range */
                init_file_range(ctx, startoffset, size);

                /* we recalc the size because it may have changed due to our file init (format) */
                size = endoffset;
                if (size < startoffset + maxblocksize)
                        size = startoffset + maxblocksize;
                if ((ctx->size = getsize(ctx->type == F_SG, ctx->fd, size, 0)) < size)
                        PANIC("can't get size of '%s' sz %"PRId64", or size < end offset %"PRId64 " - did "
                                "you format the file (try -F)?",
                                ctx->file, ctx->size, size);
        }
        /* now that all sizes are known, build the workload ctx for this file */
        for (w = 0; w < total_nworkloads; w++)
                init_workload_context(ctx, ctx->wlctxs + w, workloads + w);
        
        DEBUG("seq offset is set to %ld", startoffset);
        ctx->seq_offset = startoffset;
}

/**
 * Fill data buf with the correct data pattern. Data pattern is generated once and copied to all data buffers.
 */
static void init_data_buf(void *buf, size_t size)
{
        struct drand48_data rbuf;
        static void *savebuf;
        static int initialized;
        uint32 *u, *e;
        int r;
  
        shared.lock_func();
        if (initialized++)
                goto saved;
        
        if (!(savebuf = malloc(maxblocksize)))
                PANIC("can't alloc memory for data buf %d bytes", maxblocksize);
        
        if (conf.compression < 0) {
                memset(savebuf, 0, maxblocksize);
                goto saved;
        }
        
        srand48_r(conf.rseed, &rbuf);
        
        if (conf.compression == 0) {
                DEBUG2("fill data buf (%ld byte) with full random data", maxblocksize);
                /* no compression - fill will random data */
                for (u = savebuf, e = u + (maxblocksize/sizeof *u); u < e; u++)
                        *u = saferandom(&rbuf);
                goto saved;
        }
        
        DEBUG2("fill data buf (%ld byte) with random data compression rate %d", maxblocksize, conf.compression);
        /* compression rate is given, fill buf with random stamps with repetitions */
        for (u = savebuf, e = u + (maxblocksize/sizeof *u); u < e; ) {
                uint32 v = saferandom(&rbuf);
                for (r = 0; r < conf.compression && u < e; r++, u++)
                        *u = v;
        }
        
saved:
        DEBUG2("used saved buf to fill buf (%ld bytes)", size);
        memcpy(buf, savebuf, size);
        shared.unlock_func();
}

/**
 * Allocates and initializes new worker structure
 */
worker_ctx *new_worker(file_ctx *fctx)
{
        worker_ctx *worker;

        shared.lock_func();
        if (total_nworkers >= max_nworkers)
                PANIC("too many workers %s limit is reached...", total_nworkers);
        worker = workers + total_nworkers;
        worker->num = total_nworkers++;
        shared.unlock_func();

        worker->fctx = fctx;
        
        if (!(worker->buf = valloc(maxblocksize)))
                PANIC("can't alloc buf sized %d bytes", maxblocksize);
        
        init_data_buf(worker->buf, maxblocksize);

        srand48_r(conf.rseed + worker->num * 10000, &worker->rbuf);

        worker->tid = gettid();
        worker->offset = startoffset;

        return worker;
}

/**********************************************************************************************************************
 * Worker main and init - AsyncIO
 **********************************************************************************************************************/
#define io_event_is_valid(event) ((event)->res2 == 0 && ((signed long)(event)->res) >= 0)

/**
 * Initializes aio specific worker fields.
 */
void init_async_worker(worker_ctx *worker, aio_thread_ctx *athread)
{
        worker->io_context = athread->io_context;
        worker->aio_cb = calloc(1, sizeof *worker->aio_cb);
}

/**
 * Main AIO Thread logic function.
 * 
 * This function does the following:
 * - allocates and initialized conf.aio_window_size workers per file
 * - initializes files (in fact race on initialization - the first thread to reach the file init it
 * - calls start barrier
 * - for each file sends the initial io window
 * - during the test itself: maintain the window on all files
 * - for each file summerizes the stats from all relevant workers
 * - updates the global shared stats
 */
void *aio_thread(aio_thread_ctx *athread)
{
        int nworkers = total_nfiles * conf.aio_window_size;
        struct io_event *events = calloc(nworkers, sizeof(struct io_event));
        struct io_event *event;
        struct iocb *completed_iocb;
        worker_ctx *myworkers[total_nfiles][conf.aio_window_size];
        worker_ctx *worker;
        int aiores, initializer = 0;
        int inflight_ios_count = 0;
        int r, f, i;

        DEBUG("initializing...");
        if (conf.iomodel != IO_MODEL_ASYNC || conf.aio_window_size == 0)
                PANIC("AsyncIO completion thread started but model is wrong or window size is 0");

        for (f = 0; f < total_nfiles; f++) {
                for (i = 0; i < conf.aio_window_size; i++) {
                        myworkers[f][i] = new_worker(files + f);
                        init_async_worker(myworkers[f][i], athread);
                }
        }

        /* let all aio thread to race on file initialization - the first to get a file will init it */
        for (f = 0; f < total_nfiles; f++) {
                shared.lock_func();
                if (!files[f].initialized) {
                        files[f].initialized = 1;
                        initializer = 1;
                }
                shared.unlock_func();

                if (initializer)
                        thread_init_file(files + f);
        }

        DEBUG("sync with other threads");
        shared.lock_func();
	shared.started++;
	shared.cond_wait_func();
        shared.unlock_func();

        DEBUG("starting - sending first window");
        /* bootstrap - send window size IOs on all file */
        for (f = 0; f < total_nfiles; f++) {
                for (i = 0; i < conf.aio_window_size; i++) {
                        worker = myworkers[f][i];

                        worker->wlctx = next_workload_ctx(worker);
                        worker->offset = next_seq_offset(worker);

                        r = do_io(worker);

                        if (io_ended(worker, r, 0) < 0)
                                break;

                        inflight_ios_count++;
                }
        }

        DEBUG("maintain window");
        /* start completion loop, and trade each completed IO with a new IO */
        while (inflight_ios_count > 0) {
                aiores = io_getevents(athread->io_context,
                                      1 /* min events */,
                                      conf.aio_window_size * total_nfiles /* max events */,
                                      events,
                                      NULL /* timeout */);
                if (aiores <= 0)
                        PANIC("AsyncIO io_getevents failed with error: %d (%s)", aiores, strerror(-aiores));

                inflight_ios_count -= aiores;
                DEBUG3("got %d events, inflight %d", aiores, inflight_ios_count);
                /* process all events */
                for (i = 0, event = events; i < aiores; i++, event++) {
                        completed_iocb = (struct iocb *)event->obj;
                        worker = (worker_ctx*)event->data;
                        file_ctx *fctx = worker->fctx;
                        workload *wl = worker->wlctx->wl;

                        if ((completed_iocb == NULL) || (worker == NULL)) {
                                PANIC("AyncIO completion no data - event %d out of %d.", i, aiores);
                                continue;
                        }

                        r = 0;

                        if (conf.verify) {
                                if (completed_iocb->aio_lio_opcode == 1/*LIO_WRITE*/)
                                        shared.write_completed(worker, completed_iocb->u.c.buf,
                                                                completed_iocb->u.c.offset, completed_iocb->u.c.nbytes);
                                else if (completed_iocb->aio_lio_opcode == 0/*LIO_READ*/)
                                        shared.read_completed(worker, completed_iocb->u.c.buf,
                                                                completed_iocb->u.c.offset, completed_iocb->u.c.nbytes);
                                else
                                        WARN("unknown aio code: %u", (uint)completed_iocb->aio_lio_opcode);
                        }
                        
                        /* verify the IO result code and size */
                        if (!io_event_is_valid(event) || event->res != completed_iocb->u.c.nbytes) {
                                r = -1;

                                WARN("%d: IO error on '%s (event %d out of %d). return code %d. number of bytes "
                                        "processed is %d out of %d.",
                                        worker->tid, fctx->file, i, aiores,
                                        event->res2, event->res, completed_iocb->u.c.nbytes);
                        }

                        if ((fctx->fd != completed_iocb->aio_fildes) || (wl->blocksize != completed_iocb->u.c.nbytes)) {
                                WARN("AsyncIO completion mismatch (event %d out of %d): fd is %d, expected %d. "
                                        "blocksize is %d expected %d",
                                        i, aiores,
                                        completed_iocb->aio_fildes, fctx->fd,
                                        completed_iocb->u.c.nbytes, wl->blocksize);
                        }

                        /*printf("-- AsyncIO completion details: fd=%d buf=%p nbytes=%d offset=%d. rc=%d nbytes=%d. \n",
                                completed_iocb->aio_fildes, completed_iocb->u.c.buf, completed_iocb->u.c.nbytes,
                                completed_iocb->u.c.offset,
                                event->res2, event->res);*/

                        if (io_ended(worker, r, 1) < 0 || state_reached(FINISHED))
                                continue;       /* of end of the keep looping to close the window */

                        /* send another io */
                        worker->wlctx = next_workload_ctx(worker);

                        r = do_io(worker);

                        if (io_ended(worker, r, 0) < 0)
                                goto end;

                        inflight_ios_count++;
                }
        }

end:
        thread_finished();

	return 0;
}

/**********************************************************************************************************************
 * Worker main and init - sync IO
 **********************************************************************************************************************/

/**
 * Main synchronous IO thread logic
 * 
 * This function does the following:
 * - initializes a new worker
 * - initializes the to be used file (if not already initialized)
 * - calls the start barrier
 * - during the test: select a workload and perform the IO
 * - sums up the stats
 * - updates the shared global stats
 */
void* sync_thread(io_thread_ctx *io_thread)
{
        worker_ctx *worker = new_worker(io_thread->fctx);
        int initializer = 0;
        int r;
        
	DEBUG("%d: starting worker thread on '%s' using conf.rseed %d",
                      worker->tid, worker->fctx->file, conf.rseed + worker->num * 10);

        shared.lock_func();
        if (!io_thread->fctx->initialized) {
                io_thread->fctx->initialized = 1;
                initializer = 1;
        }
        shared.unlock_func();

        if (initializer)
                thread_init_file(worker->fctx);
        
	DEBUG2("%d: starting worker: waiting for test start", worker->tid);

        shared.lock_func(); 
	shared.started++;
	shared.cond_wait_func(); 
        shared.unlock_func(); 

        /*
         * In verification mode, make thread # on this file to start from # block. 
         * Note that we use the fact that there is only one workload.
         */
        worker->wlctx = next_workload_ctx(worker);
        worker->offset = next_seq_offset(worker);
        if (conf.verification_mode) {
                DEBUG("io thread %d file %s set offset to %lu", io_thread->num, worker->fctx->file, worker->offset);
        }
        
	DEBUG("%d: worker on thread ['%s']: Start", worker->tid, worker->fctx->file);

        while (!state_reached(FINISHED)) {
                worker->wlctx = next_workload_ctx(worker);
                
                r = do_io(worker);

                if (io_ended(worker, r, 1) < 0)
                        break;
        }

        DEBUG("worker done");
        
        thread_finished();
        return 0;
}

/**********************************************************************************************************************
 * Main
 **********************************************************************************************************************/
static struct option btest_long_options[] = {
        /* Operation Modes */
        /* Main options */
        {"workload_file", 1, 0, 'f'},
        {"block_size", 1, 0, 'b'},
        {"alignment_size", 1, 0, 'a'},
        {"duration", 1, 0, 't'},
        {"num_ops", 1, 0, 'n'},
        {"exit_eof", 0, 0, 'e'},
        {"threads", 1, 0, 'T'},
        {"offset", 1, 0, 'o'},
        {"length", 1, 0, 'l'},
        {"seed", 1, 0, 'S'},
        {"async_io", 1, 0, 'w'},
        {"sgio", 0, 0, 'G'},
        {"stampblock", 1, 0, 'P'},
        {"dedup", 1, 0, 'p'},
        {"compression", 1, 0, 'Z'},
        {"progressive", 0, 0, 'g'},
        {"offset_stamp", 0, 0, 'O'},
        {"block_md", 1, 0, 'm'},
        {"check_scan", 1, 0, 'C'},
        {"verify", 0, 0, 'v'},
        {"check", 0, 0, 'c'},
	{"ignore_errors", 0, 0, 'i'},

        {"write_behind", 0, 0, 'W'},
        {"direct", 0, 0, 'D'},
        {"activity_check", 0, 0, 'A'},
        {"timeout", 1, 0, 'B'},
        {"warmup", 1, 0, 'u'},

        {"diff_report_interval", 1, 0, 'r'},
        {"subtotal_report_internal", 1, 0, 'R'},
        {"report_workers", 0, 0, 'z'},

        {"format", 0, 0, 'F'},
        {"trim", 0, 0, 'X'},
        {"trim_replace", 1, 0, 'x'},

        {"help", 0, 0, 'h'},
        {"version", 0, 0, 'V'},
        {"debug", 0, 0, 'd'},
        {"debuglines", 0, 0, 'L'},
        
        {"iomode", 1, 0, 0},
        {"csv", 1, 0, 0},
        
        {"sync", 0, 0, 0},
        {"direct_sync", 0, 0, 0},
        {"sgio_direct", 0, 0, 0},
        
        {"force_md_init", 0, 0, 0},
        
        {0, 0, 0, 0}
};

void usage(void)
{
	printf("Usage: %s [-hdV -W -D -G -b <blksz> -a <alignsize> -t <sec> "
             "-T <threads> -o <start> -l <length> -S <seed> -w <window-size> -p <dedup_likelihood> "
                "-Z <comression_rate> -B <timeout_ms> -u <warmup_sec> -P <stampsz> -O -m <md_file_base> -v -c "
                "-n <num_ops_limit> -r <sec> -R <sec>] <S|R|rand-ratio> <R|W|read-ratio> <dev/file> ...\n", prog);
	printf("\nWorkload file mode:\n       %s [-hdV -W -D -G -f <workloads filename> -t <sec> "
             "-T <threads> -S <seed> -w <window-size> -m <md_file_base> -v -c  -B <timeout_ms> -u <warmup_sec> "
                "-n <num_ops_limit> -r <sec> -R <sec>] <dev/file> ...\n", prog);
	printf("\nVerification mode:\n       %s [-hdV -D -C <md_base> -b <blksz> -a <alignsize> "
                "-o <start> -l <length> -S <seed> "
                "-p <dedup_ratio> -P <stampsz> -O -v -r <sec> -R <sec>] <dev/file> ...\n", prog);
        printf("\n\tOperation Modes:\n");
        printf("\t\t: Sync/Async - If -w/--write_behind is specified async is enabled, if not sync is used.\n");
        printf("\t\t: Direct IO - forced by a single -D flag. the second -D flag force SYNC+DIRECT IO.\n");
        printf("\t\t: SCSI Genetic mode - used if device starts with /dev/sg or if -G/--sgio option is used. "
                "Second -G will force direct SG IO\n");
        printf("\t\t: Verification mode: -C/--check_scan  - sequentially scan the file and verify its data stamps "
                "according to specified md file. The default behavior is to stop on first error. "
                "This can be changed using "
                "the -v option. See also -m (--block_md) and -v (--verify)/-c (--check) options."
                "This mode is read only and most flags are irrelevant for it.\n");
        printf("\n\tMain options:\n");
        printf("\t\t-f/--workload_file <filename> - Accept multiple workloads per thread from file See "
                "'Mutiple Workloads From File' below. \n");
	printf("\t\t Size options support prefixes b (block) K (KB) M (MB) G (GB) T (TB), all in 2 base\n");
	printf("\t\t-b/--block_size <IO Block size> [%d]\n", conf.def_blocksize);
	printf("\t\t-a/--alignment_size <IO alignment size> [by default same as block size]\n");
	printf("\t\t-t/--duration <sec> - limit test duration in seconds, 0 for infinity [%d]\n", conf.secs);
        printf("\t\t-u/--warmup <sec> - run workload for the specified seconds period before starting test "
                "[default %d msec]\n", conf.warmup_sec);
	printf("\t\t-n/--num_ops <ops number>  - limit the test's total number of IO operations 0 for infinity "
                "[%d]\n", DEFAULT_TIME_LIMIT);
	printf("\t\t-e/--exit_eof  - exit on EOF (make sense for sequential IO) [%d]\n", conf.exit_eof);
	printf("\t\t-T/--threads <For sync IO: number of threads per file. For AsyncIO: total number of "
                "working threads> [%d]\n", conf.nthreads);
	printf("\t\t-o/--offset <start offset> [0]\n");
	printf("\t\t-l/--length <size of area in file/device to use for IO> [full]\n");
	printf("\t\t-S/--seed <random seed>  [current time]\n");
        printf("\t\t-w/--async_io <window size> - AsyncIO set window size in blocks per file per "
                "worker thread. The total number of "
                "inflight IOs is #threads*#files*window_size. > [0]\n");
        printf("\t\t--iomode=<sync,direct,direct_sync,async,write_behind,sgio,sgio_direct> select IO mode [sync]\n");
        printf("\t\t-P/--stampblock <size > - size of block to use when stamping writes. "
                "Stamp is the dedup/write stamp (see -p) and/or offset stamp (see -O). Size 0 disables data stamping"
                " [the default size is smallest of block size or 4k (see -b)]\n");
        printf("\t\t-p/--dedup <expected dedup> control the expected dedup rate per device. "
                "E.g. 12 should result dedup factor of 12 after the target data set is filled at least once. "
                "Use -1 to disable the dedup stamp patterns, -2 for fixed stamp, 0 for no dedup.> [0 == no dedup]\n");
        printf("\t\t-Z/--compression <expected compression> control the expected compression rate. "
                "E.g. 12 should result compression factor of 12 for any written blocks. Contradicts offset stamping."
                "Use -1 to disable the compression patterns, 0 for no compression.> [0 == no compression]\n");
        printf("\t\t-g/--progressive  - if dedup pattern is requested, use a progressive fill instead of the default "
                "random one. This may be important if the target object is not being completely filled "
                "(e.g. due its large size).\n");
        printf("\t\t-O/--offset_stamp  - use offset stamp, one per stamp block [No]\n");
        printf("\t\t-m/--block_md <base-filename>  - use specified string + dev name as file to load/save"
                "verification md. If only a single file is given, the base will be used as the md file name."
                "Used by -v/-y options [%s]\n", conf.block_md_base);
	printf("\tReal Time checks:\n");
        printf("\t\t-A/--activity_check  - exit if there were no successful I/Os in the last interval \n");
        printf("\t\t-B/--timeout_ms  -  break if an IO duration exceeds that specified msec value. "
                "Set to 0 to disable check [default %d msec]\n", conf.timeout_ms);
        printf("\t\t-v/--verify  - verify stamps after each read (see options -p, -P and -O [False]\n");
        printf("\t\t-c/--check  - like verify, but stop on verification errors [False]\n");
        printf("\t\t--force_md_init  -  force initialization of verification md. Useful when md backend is a block device\n");
        printf("\t\t-i/--ignore_errors  - do not stop on errors, just count them [False]\n");
	printf("\tOpen flags options:\n");
	printf("\t\t(Default -  O_CREAT | O_LARGEFILE | O_NOATIME | O_SYNC)\n");
	printf("\t\t-W/--write_behind : Write behind mode : O_CREAT | O_LARGEFILE | O_NOATIME \n");
	printf("\t\t-D/--direct  - use direct IO mode : O_CREAT | O_LARGEFILE | O_NOATIME | O_DIRECT \n");
	printf("\t\t-DD/--direct_sync  - use direct IO mode : O_CREAT | O_LARGEFILE | O_NOATIME | O_DIRECT | O_SYNC \n");
        printf("\t\t-G/--sgio  -  force SCSI generic mode. Will not work for files. This is the default for /dev/sgX devices.\n");
        printf("\t\t-GG/--sgio_sirect  -  force SCSI generic mode with direct IO mode. Will not work for files.\n");
	printf("\tReal Time Reports:\n");
	printf("\t\tsignal SIGUSR1 prints reports until now\n");
	printf("\t\tsignal SIGUSR2 prints reports from last report\n");
	printf("\t\t-r/--diff_report_interval <seconds> - report of activitly from last report [%d], "
                "set to 0 to disable\n", conf.diff_interval);
	printf("\t\t-R/--subtotal_report_internal <seconds> - report activity from test start [%d], "
                "set to 0 to disable\n", conf.subtotal_interval);
	printf("\t\t-z/--report_workers  - report stats for each worker [%d] (note: using this flag for"
                "very large amount of threads/workers may affect the test and make the "
                "measurements inaccurate)\n", conf.report_workers);
	printf("\tFormat/Trim options:\n");
	printf("\t\t-F/--format : preformat test area (using writes)\n");
	printf("\t\t-X/--trim : Pre-Trim test area (SSD)\n");
	printf("\t\t-x/--trim_replace <trim block size> : After each write, trim blocks of "
                "\"trim block size\" at random \n"
		"\t\t\tlocations such that write block size data is trimmed\n");
	printf("\tSG support:\n");
	printf("\t\ttarget files that are formated as /dev/sgX are accessed using raw generic scsi calls\n");
	printf("\tMisc:\n");
	printf("\t\t-h/--help : show this help and exit\n");
	printf("\t\t-V/--verbose : show the program version and exit\n");
	printf("\t\t-d/--debug : increase the debugging level\n");
	printf("\t\t-L/--debuglines <lines>  - set debug lines (binary trace lines). 0 to disable [%u]\n", ndebuglines);
        printf("\n\tMutiple Workloads From File:\n");
        printf("\t\tIf -f option for workloads configuration from file is set, the "
                "following parameters must not be \n");
        printf("\t\tconfigured in the commands line: -b -p -P -a -o -l <S|R|rand-ratio> <R|W|read-ratio>\n");
        printf("\t\tIn the configuration file, each line represents a workload. \n");
        printf("\t\tEach line begins with a weight of this workload, must be a number betwee 1 and 100. \n");
        printf("\t\tThe weight is followed by -b <blksz> -p <dedup_likehood> -P "
                "<stamp_block> -a <align_size> -o <start> -l <length> "
                "<S|R|rand-ratio> <R|W|read-ratio> \n");
        printf("\t\tMaximal number of workloads is %d.\n", MAX_WORKLOADS);
        printf("\t\tExample of a configuration file content:\n");
        printf("\t\t10 -b 4k -p -1 -l 100m R W\n");
        printf("\t\t50 -b 32k -P 4k -p 10 -l 100m R R\n");
        printf("\t\t20 -b 8k -a 4k -p 3 -P 4k -l 100m R 50\n");
        btest_ext_usage();
	exit(1);
}

/**
 * Real time report thread entry function
 */
void *stats_main(void* arg)
{
        int warmup = conf.warmup_sec;
        struct timespec duration = {0}, remaining;
        
        while (!state_reached(WARMINGUP)) {
                usleep(100 * 1000);
        }

	enable_signals();

        if (warmup) {
                DEBUG("warming up starting");
                while (warmup-- > 0) {
                        duration.tv_sec = 1;
                        duration.tv_nsec = 0;
                        DEBUG2("warming up %d seconds left", warmup+1);
                        while (nanosleep(&duration, &remaining) < 0)
                                duration = remaining;
                }
                DEBUG("warming up done");
                state_set(RUNNING, 0);
        }
        
	realtime_reports(conf.secs);

	disable_signals();

        state_set(FINISHED, 0);

        return NULL; 
}

/**
 * Real time report thread entry function
 */
void *timeout_check_main(void* arg)
{
        while (!state_reached(WARMINGUP)) {
                usleep(100 * 1000);
        }

	timeout_check((conf.timeout_ms + 999)/1000);

        return NULL; 
}

/**
 * Async IO thread entry function
 * 
 * This function does the following:
 * - calls shared init function
 * - creates a file context per test file
 * - optionally initializes file shared verification context
 * - for each requested aio thread, setup an aio context and pass it to a newly created thread
 * - starts the start barrier
 * - busy wait for threads to finish
 * - call exit code
 */
void *async_main(void* unused)
{
        int i, t;
        
        DEBUG("using random seed %d", conf.rseed);

        if (conf.iomodel != IO_MODEL_ASYNC || conf.aio_window_size == 0)
                PANIC("AsyncIO completion thread started but model is wrong or window size is 0");

        shared.init_func();

        /* init file ctxs */
	for (i = 0; i < conf.nfiles; i++) {
                file_ctx *ctx = new_file_ctx();
                if (use_stamps)
                        init_shared_file_ctx(ctx);
        }

        /* init aio working threads, aio_thread context is per thread */
        for (t = 0; t < conf.nthreads; t++) {
                aio_thread_ctx *athread = aio_ctx + t;
                pthread_t thid = 0;
                int aiores;

                if (total_nthreads >= max_nthreads)
                        PANIC("Thread limit %d now %d has been reached!", max_nthreads, total_nthreads);
                athread->num = total_nthreads++;

                /* initialize AsyncIO kernel global context */
                memset(&athread->io_context, 0, sizeof athread->io_context);
                DEBUG("total_nfiles %d conf.aio_window_size %d", conf.nfiles, conf.aio_window_size);
                if ((aiores = io_setup(total_nfiles * conf.aio_window_size * 2, &athread->io_context)) < 0)
                        PANIC("AsyncIO io_setup failed with error: %d (%s)\n", aiores, strerror(-aiores));

                if (pthread_create(&thid, NULL, (void *(*)(void *))aio_thread, athread))
                        PANIC("async thread creation failed [num %d]", athread->num);

                DEBUG("async working thread %d thid %d created", athread->num, thid);
        }

	start(total_nthreads);

        while (!state_reached(FINISHED)) {
                th_busywait();
        }

	doexit();

	return NULL;
}

/**
 * @brief main (thread) entry function for Synchronous IO flows.
 * 
 * This function does the following:
 * - calls shared init function
 * - creates a file context per test file
 * - for each file, creates the requested number of threads
 * - starts the start barrier
 * - busy wait for threads to finish
 * - call exit code
 */
void *sync_main(void * unused)
{
        int i, t;

        DEBUG("using random seed %d", conf.rseed);

        shared.init_func();
        
	for (i = 0; i < conf.nfiles; i++) {
                file_ctx *fctx = new_file_ctx();

                /* init sync worker threads (threads per file), io_thread_ctx is per file */
                for (t = 0; t < conf.nthreads; t++) {
                        io_thread_ctx *io_thread = io_ctx + total_nthreads;
                        pthread_t thid = 0;

                        io_thread->fctx = fctx;
                        io_thread->num = total_nthreads;

                        if (total_nthreads >= max_nthreads)
                                PANIC("Thread limit %d now %d has been reached!", max_nthreads, total_nthreads);

                        if (pthread_create(&thid, NULL, (void *(*)(void *))sync_thread, io_thread))
                                PANIC("thread creation failed [file %s thread %d]", files[i], t);

                        total_nthreads++;
                        DEBUG("sync worker thread %d created", thid);
		}
        }

        start(total_nthreads);

        while (!state_reached(FINISHED))
                th_busywait();

	doexit();

	return NULL;
}

/**
 * Parse and check the align size parameter
 */
static void parse_alignsize(workload *wl, char* optarg)
{
        wl->alignsize = parse_storage_size(optarg);
        if (!wl->alignsize)
                PANIC("invalid align size parameter: -a %s", optarg);
        printf("IO alignment size is %d\n", wl->alignsize);
}

/**
 * Parse and check the block size parameter
 */
static void parse_blocksize(workload *wl, char* optarg)
{
        wl->blocksize = parse_storage_size(optarg);
        if (!wl->blocksize)
                PANIC("invalid blocksize parameter: -b %s", optarg);
        printf("IO Block size is %d\n", wl->blocksize);
}

/**
 * Parse and check the start offset parameter
 */
static void parse_startoffset(workload *wl, char* optarg)
{
        wl->startoffset = parse_storage_size(optarg);
        printf("File start offset is %" PRId64 "\n", wl->startoffset);
}

/**
 * Parse and check the parse length parameter
 */
static void parse_len(workload *wl, char* optarg)
{
        wl->len = parse_storage_size(optarg);
        if (!wl->len)
                PANIC("invalid length size parameter: -l %s", optarg);
        printf("Limit IO space to %s (%" PRId64 " bytes) per file\n", optarg, wl->len);
}

/**
 * Parse and check the workload weight parameter (within a workloads definition file)
 */
static void parse_weight(workload *wl, char* optarg)
{
        wl->weight = atoi(optarg);
        if ((wl->weight < 0) || (wl->weight > 100))
                PANIC("invalid workload weight, should be number larger than 0, smaller than 100: %s", optarg);
        printf("Workload weight is %d\n", wl->weight);
}

/**
 * Parse and check the dedup likelihood parameter
 */
static void parse_dedup_likelihood(workload *wl, char* optarg)
{
        wl->dedup_likehood = (uint64)atoi(optarg);
        if ((wl->dedup_likehood < -2) || (wl->dedup_likehood > 1000000))
                PANIC("invalid dedup likelihood, should be number between 0 and 1000000 "
                        "(== expected dedup factor of 1000000): %s", optarg);
        if (wl->dedup_likehood == -1)
                printf("Dedup stamps are disabled\n");
        else if (wl->dedup_likehood == -2)
                printf("Dedup stamp is fixed\n");
        else printf("Dedup rate is %d (expected dedup factor %d)\n",
                wl->dedup_likehood, wl->dedup_likehood);
}

/**
 * Parse and check the dedup likelihood parameter
 */
static void parse_compression(char* optarg)
{
        conf.compression = (uint64)atoi(optarg);
        if ((conf.compression < -2) || (conf.compression > 1000))
                PANIC("invalid compression, should be number between 0 and 1000: %s", optarg);
        if (conf.compression == -1)
                printf("Compression stamps are disabled\n");
        else
                printf("Compression rate is %d\n", conf.compression);
}

/**
 * Parse and check the stamp block size parameter
 */
static void parse_stampblock(char* optarg)
{
        conf.stampblock = parse_storage_size(optarg);
        if (conf.stampblock && conf.stampblock < 16)
                PANIC("can't use stampblock < 16 (%d). Use 0 to disable all data patterns\n", conf.stampblock);
        printf("Use stamps each %d bytes\n", conf.stampblock);
}

/**
 * Parse and check the random ratio parameter
 */
static void parse_dorandom(workload *wl, char* optarg)
{
        switch (optarg[0]) {
        case 'R':
        case 'r':
                wl->randomratio = 100;
                printf("Use pure random IO\n");
                break;
        case 'S':
        case 's':
                wl->randomratio = 0;
                printf("Use pure sequential IO\n");
                break;
        default:
                wl->randomratio = atoi(optarg);

                if (wl->randomratio < 0 || wl->randomratio > 100)
                        PANIC("bad random/sequential parameter: should be R|S|0-100");
                printf("Use %d%% random IO\n", wl->randomratio);

        }
}

/**
 * Parse and check the random read parameter
 */
static void parse_doread(workload *wl, char* optarg)
{
        switch (optarg[0]) {
        case 'R':
        case 'r':
                wl->readratio = 100;
                printf("Generate only reads\n");
                break;
        case 'W':
        case 'w':
                wl->readratio = 0;
                printf("Generate only writes\n");
                break;
        default:
                wl->readratio = atoi(optarg);
                if (wl->readratio < 0 || wl->readratio > 100)
                        PANIC("bad read/write parameter: should be R|W|0-100");
                printf("Generate %d%% reads, the rest will be writes\n", wl->readratio);
        }
}

/**
 * Verify that the user defined sizes are sane. Panic if not.
 */
static void verify_sizes(workload *wl)
{
        if (!wl->alignsize)
                wl->alignsize = wl->blocksize;

        if (conf.stampblock > wl->blocksize) {
                PANIC("stamp block size %d must be <= workload block size %d", conf.stampblock, wl->blocksize);
        }
        if (conf.verify && conf.stampblock && (wl->alignsize % conf.stampblock))
                PANIC("stampblock size %d must be aligned with alignsize %d", conf.stampblock, wl->alignsize);

        DEBUG2("start offset %ld align %d", wl->startoffset, wl->alignsize);
        
        if (wl->startoffset % wl->alignsize) {
                uint64 fix = wl->alignsize - (wl->startoffset % wl->alignsize);
                wl->startoffset += fix;
                if (wl->len)
                        wl->len -= fix;
                printf("startoffset is changed to %"PRId64" and len to %"PRId64" to match alignment size %d\n",
                        wl->startoffset, wl->len, wl->alignsize);
        }
        if (wl->len % wl->alignsize) {
                wl->len = (wl->len / wl->alignsize) * wl->alignsize;
                printf("len is changed to %"PRId64" to match alignment size %d\n",
                        wl->len, wl->alignsize);
        }

        if (wl->trimsize > wl->blocksize) {
                wl->trimsize = wl->blocksize;
                printf("trim size is changed to %d to match block size\n", wl->blocksize);
        }

        if (wl->blocksize < conf.stampblock)
                PANIC("invalid stampblock %d > block size %d", conf.stampblock, wl->blocksize);
}

/**
 * Process user defined workloads and calculated some shared global variables out of them.
 */
void init_workloads(void)
{
        uint64 start = ~0lu, end = 0, use_dev_size = 0;
        uint maxbsz = 0, minbsz = ~0u;
        int rdonly = 1;
        int w;

        if (total_nworkloads == 0)
                PANIC("no workload is defined");
        if (total_nworkloads >= MAX_WORKLOADS)
                PANIC("number limit of workloads is reached %d", MAX_WORKLOADS);
        
        DEBUG("total workloads %d", total_nworkloads);
        /* compute max data range, check for writers */
        for (w = 0; w < total_nworkloads; w++) {
                workload *wl = workloads + w;

                if (wl->dedup_likehood != -1)
                        use_stamps = 1;
                if (wl->dedup_likehood > 0 && wl->progressive_dedup)
                        use_stamps = 2;
                if (wl->startoffset < start)
                        start = wl->startoffset;
                if (wl->readratio < 100)
                        rdonly = 0;
                if (wl->blocksize > maxbsz)
                        maxbsz = wl->blocksize;
                if (wl->blocksize < minbsz)
                        minbsz = wl->blocksize;
                if (use_dev_size || !wl->len) {
                        use_dev_size = 1;
                        continue;
                }
                if (wl->startoffset + wl->len > end)
                        end = wl->startoffset + wl->len;
        }

        startoffset = start;
        if (use_dev_size)
                endoffset = 0;
        else
                endoffset = end;
        readonly = rdonly;
        maxblocksize = maxbsz;
        minblocksize = minbsz;
        DEBUG("startoffset %lu readonly %d block size (%d-%d)", startoffset, readonly, minblocksize, maxblocksize);
        
        /* if stamp block is not set by now, use the min block size */
        if (conf.stampblock == -1) {
                if (minblocksize < DEF_STAMPBLOCK)
                        conf.stampblock = minblocksize;
                else
                        conf.stampblock = DEF_STAMPBLOCK;
        }
        
        /* verify all workloads */
        for (w = 0; w < total_nworkloads; w++)
                verify_sizes(workloads + w);
}

/**
 * Initialize an empty workload structure to its defaults.
 */
static void init_workload(workload *wl)
{
        bzero(wl, sizeof(*wl));
        wl->blocksize = conf.def_blocksize;
        wl->dedup_likehood = 0;         /* inf modul -> 0 dedup */
}

/**
 * Read and parse an workload definitions file
 */
static int parse_workload(char const *workload_filename)
{
        char *parseline, *parseopt, *parseoptarg;
        char readline[MAX_LINE_SIZE];
        FILE *workload_file;
        uint wlnum = 0;
        workload *wl;
        int c;

        workload_file = fopen(workload_filename, "r");
        if (workload_file == NULL)
                PANIC("Workload file cannot be opened: %s", optarg);

        bzero(readline, MAX_LINE_SIZE);

        while (fgets(readline, MAX_LINE_SIZE, workload_file) != NULL) {

                parseline = readline;
                parseopt = strtok(parseline, " ");

                if ((parseopt == NULL) || (parseopt[0] == '\n'))
                        continue;

                if (wlnum >= MAX_WORKLOADS)
                        PANIC("Too many workloads. Maximum is %d", MAX_WORKLOADS);

                wl = workloads + wlnum++;
                init_workload(wl);

                parse_weight(wl, parseopt);

                parseopt = strtok(NULL, " ");
                while ((parseopt != NULL) && (parseopt[0] == '-')) {
                        parseoptarg = strtok(NULL, " ");
                        c = btest_ext_workload_get_opt(parseopt[1], parseoptarg, &shared.ext);
                        switch (c) {
                        case '\0':
                                break;  /* handled by the extension */
                        case 'a':
                                parse_alignsize(wl, parseoptarg);
                                break;
                        case 'b':
                                parse_blocksize(wl, parseoptarg);
                                break;
                        case 'o':
                                parse_startoffset(wl, parseoptarg);
                                break;
                        case 'l':
                                parse_len(wl, parseoptarg);
                                break;
                        case 'p':
                                parse_dedup_likelihood(wl, parseoptarg);
                                break;
                        case 'P':
                                if (conf.verify) {
                                        WARN("workload %d: on verify mode per workload stampblocks "
                                             "are not supported - ignore. Use cmdline -P option instead", wlnum);
                                        break;
                                }
                                parse_stampblock(parseoptarg);
                                break;
                        }
                        parseopt = strtok(NULL, " ");
                }

                verify_sizes(wl);

                parse_dorandom(wl, parseopt);

                parseopt = strtok(NULL, " ");
                parse_doread(wl, parseopt);
        }

        return wlnum;
}

char *workload_filename = NULL;
int workload_defined = 0;

/**
 * Check that the to be used option is allowed in this mode
 */
void check_mode(char *option, int cmdline, int verification)
{
        if (verification == 0 && conf.verification_mode)
                PANIC("option %s can't be used if verification (check) mode is requested", option);
        if (cmdline == -1 && workload_filename)
                PANIC("option %s can't be used if workload file is defined", option);
        if (cmdline == 0 && workload_defined)
                PANIC("option %s can't be used if command line work load is defined (options -a -b -o -l -p -P)",
                        option);
}

int main(int argc, char **argv)
{
        struct option *unified_long_options;
        struct drand48_data rbuf;
        pthread_t thid = 0;
        workload *wl;
        char *optstr;
	int i, j, opt, option_index;
        
        for (wl = workloads; wl < workloads + MAX_WORKLOADS; wl++)
                init_workload(wl);

        wl = workloads; /* by default use the first workload */
        
        setlinebuf(stdout);

        /* find the base name of the exec name */
	prog = strchr(argv[0], '/');
	if (!prog)
		prog = argv[0];
	else
		prog++;

	conf.rseed = time(0);

        optind = 0;
        /* allow extensions to add options */
        optstr = btest_ext_opt_str("+hVdf:t:T:b:s:o:l:H:S:w:DAWP:p:r:R:FXx:a:m:vcn:OL:C:ziegZ:B:u:G",
                                   btest_long_options, &unified_long_options);

	while ((opt = getopt_long(argc, argv, optstr, unified_long_options, &option_index)) != -1) {

                /* let extensions to control their options (or take control over default options) */
                opt = btest_ext_get_opt(opt, optarg, &shared.ext);
                
		switch (opt) {
		default:
                case '\1': /* handled by extension */
                        break;
                case '\0':
                        /* long option only */
                        if (strncmp(unified_long_options[option_index].name, "csv", 4) == 0) {
                                conf.csv_report = optarg;
                                printf("Produce CSV report to file %s\n", optarg);
                                if (!strncmp(optarg, "-", 2))
                                        csv_file = stdout;
                                else if ((csv_file = fopen(optarg, "w")) == NULL)
                                        PANIC("Can't open/create csv file %s: %m", optarg);
                                /* make csv file line buffered */
                                setlinebuf(csv_file);
                        } else if (strncmp(unified_long_options[option_index].name, "sync", 5) == 0) {
                                conf.iomodel = IO_MODEL_SYNC;
                        } else if (strncmp(unified_long_options[option_index].name, "sgio", 5) == 0) {
                                conf.iomodel = IO_MODEL_SGIO;
                        } else if (strncmp(unified_long_options[option_index].name, "sgio_direct", 12) == 0) {
                                conf.iomodel = IO_MODEL_SGIO_DIRECT;
                        } else if (strncmp(unified_long_options[option_index].name, "direct_sync", 12) == 0) {
                                conf.iomodel = IO_MODEL_DIRECT_SYNC;
                        } else if (strncmp(unified_long_options[option_index].name, "force_md_init", 14) == 0) {
                                conf.force_md_init = 1;
                                printf("forcing initialization of verification md data\n");
                        } else if (strncmp(unified_long_options[option_index].name, "iomode", 7) == 0) {
                                char **s;
                                for (s = iomodel_str; s < iomodel_str + IO_MODEL_LAST; s++) {
                                        if (strncmp(*s, optarg, strlen(*s)+1) == 0)
                                                break;
                                }
                                if (s - iomodel_str >= IO_MODEL_LAST)
                                        PANIC("unknown io model '%s'", optarg);
                                conf.iomodel = s - iomodel_str;
                                printf("IOModel is %s\n", optarg);
                        } else {
                                fprintf(stderr, "Error: unknown option %s", unified_long_options[option_index].name);
                                if (optarg)
                                        fprintf(stderr, " with arg %s", optarg);
                                fprintf(stderr, "\n");
                                usage();
                        }
                        break;
		case 'h':
			usage();
			break;
		case 'V':
			printf("%s version %d commit %s\n", prog, BTEST_VERSION, BTEST_COMMIT);
			exit(0);
                case 'f':
                        check_mode("workload file (-f)", 0, 0);
                        if (workload_filename != NULL)
                                PANIC("only one workload file can be specified");

                        if (argc - optind < 1)
                                usage();
                        workload_filename = optarg;
                        break; 
		case 'd':
			conf.debug++;
			break;
		case 'a': 
                        check_mode("alignsize (-a)", 1, -1);
			parse_alignsize(wl, optarg);
                        workload_defined = 1; 
			break;
                case 'A':
                        conf.activity_check = 1;
                        printf("Turn on activity check\n");
                        break;
                case 'B':
                        conf.timeout_ms = atoi(optarg);
			printf("Set timeout check to %d msec\n", conf.timeout_ms);
                        break;
		case 'b': 
                        check_mode("blocksize (-b)", 1, -1);
                        parse_blocksize(wl, optarg);
                        workload_defined = 1; 
			break;
		case 'o': 
                        check_mode("startoffset (-o)", 1, -1);
                        parse_startoffset(wl, optarg);
                        workload_defined = 1; 
			break;
		case 'l': 
                        check_mode("file length (-l)", 1, -1);
                        parse_len(wl, optarg);
                        workload_defined = 1; 
			break;
		case 'S':
			conf.rseed = atoi(optarg);
			printf("Use random seed %d\n", conf.rseed);
			break;
		case 'w':
                        if (conf.iomodel != IO_MODEL_INVALID && conf.iomodel != IO_MODEL_DIRECT)
                                PANIC("Async IO conflicts previous selected IO model %s", iomodel_str[conf.iomodel]);
                        check_mode("conf.aio_window_size (-w)", -1, 0);
			conf.aio_window_size = atoi(optarg);
                        if (!conf.aio_window_size)
                                PANIC("conf.aio_window_size (-w) must be > 0");
			printf("AIO implies direct IO\n");
                        conf.iomodel = IO_MODEL_ASYNC;
			printf("Use AsyncIO with window size of %d requests per thread\n", conf.aio_window_size);
			break;
		case 't':
                        check_mode("time limit (-s)", -1, 0);
                        conf.secs = atoi(optarg);
			if (!conf.secs) {
                                conf.secs = 2000000; 
				printf("Infinity time requested. time set to %d seconds\n", conf.secs);
                        }
			break;
                case 'n':
                        check_mode("ops limit (-n)", -1, 0);
                        conf.num_op_limit = strtol(optarg, 0, 0);
                        if (conf.secs < 0)      /* if time limit is not specified - use infinity */
                                conf.secs = 2000000;
                        printf("Test is limited to %lu IO operations\n", conf.num_op_limit);
			break;
                case 'e':
                        check_mode("exit on eof (-e)", -1, 0);
                        conf.exit_eof = 1;
                        if (conf.secs < 0)      /* if time limit is not specified - use infinity */
                                conf.secs = 2000000;                        
                        printf("Test will exit on EOF\n");
                        break;
		case 'T':
                        check_mode("threads number (-T)", -1, 1);
			conf.nthreads = atoi(optarg);
			if (!conf.nthreads)
				PANIC("invalid threads parameter: -T %s", optarg);
			break;
                case 'G':
                        if (conf.iomodel == IO_MODEL_SGIO) {
                                conf.iomodel = IO_MODEL_SGIO_DIRECT;
                                break;
                        }
                        if (conf.iomodel != IO_MODEL_INVALID)
                                PANIC("SG IO conflicts previous selected IO model %s", iomodel_str[conf.iomodel]);
                        check_mode("SCSI Generic IO mode", -1, 0);
                        conf.iomodel = IO_MODEL_SGIO;
                        break;
		case 'W':
                        if (conf.iomodel != IO_MODEL_INVALID)
                                PANIC("SG IO conflicts previous selected IO model %s", iomodel_str[conf.iomodel]);
                        check_mode("Allow write behind (-W)", -1, 0);
                        conf.iomodel = IO_MODEL_WRITE_BEHIND;
			break;
		case 'D':
                        if (conf.iomodel == IO_MODEL_DIRECT) {
                                conf.iomodel = IO_MODEL_DIRECT_SYNC;
                                break;
                        }
                        if (conf.iomodel != IO_MODEL_INVALID && conf.iomodel != IO_MODEL_ASYNC)
                                PANIC("SG IO conflicts previous selected IO model %s", iomodel_str[conf.iomodel]);
                        if (conf.iomodel == IO_MODEL_INVALID)
                                conf.iomodel = IO_MODEL_DIRECT;
			break;
		case 'P':
                        parse_stampblock(optarg);
			break;
		case 'p':
                        check_mode("dedup likelihood (-p)", 1, -1);
                        parse_dedup_likelihood(wl, optarg);
                        workload_defined = 1;
			break;
		case 'Z':
                        check_mode("compression factor (-Z)", 1, -1);
                        parse_compression(optarg);
                        workload_defined = 1;
			break;
		case 'g':
                        check_mode("dedup generation progressive (-g)", 1, -1);
                        wl->progressive_dedup = 1;
                        printf("Use progressive dedup fill\n");
                        workload_defined = 1;
			break;
                case 'O':
                        check_mode("Use offset based stamps (-O)", 1, -1);
                        wl->use_offset_stamps = 1;
                        printf("Use offset based stamps\n");
			break;
		case 'r':
			conf.diff_interval = atoi(optarg);
			printf("Diff report interval %d sec\n", conf.diff_interval);
			break;
		case 'R':
			conf.subtotal_interval = atoi(optarg);
			printf("Subtotal report interval %d sec\n", conf.subtotal_interval);
			break;
		case 'z':
			conf.report_workers = 1;
			printf("Report stats for each thread\n");
			break;
		case 'F':
			conf.preformat = 1;
			printf("Format the disk before the test\n");
			break;
		case 'X':
			conf.pretrim = 1;
			printf("Format the disk using trim before the test\n");
			break;
		case 'x':
                        check_mode("Trim mode (-x)", -1, 0);
			wl->trimsize = parse_storage_size(optarg);
			printf("Time mode: for each write trim same data using random blocks of %d bytes\n",
			     wl->trimsize);
			break;
                case 'm':
                        check_mode("block md file (-m)", -1, 0);
                        conf.block_md_base = optarg;
                        if (!conf.verify)
                                conf.verify = 1;
                        printf("Verification md file base: '%s'\n", conf.block_md_base);
                        break;
                case 'v':
                        conf.verify = 1;
                        printf("Verify data on read\n");
                        break;
                case 'c':
                        conf.verify = -1;
                        printf("Verify data on read and stop on verification errors\n");
                        break;
		case 'i':
			conf.ignore_errors = 1;
			printf("Ignore IO errors - do not panic, just count the errors\n");
			break;
                case 'C':
                        conf.verification_mode = 1;
                        conf.block_md_base = optarg;
                        if (!conf.verify)                    /* default is stop (panic) on errors */
                                conf.verify = -1;
                        workload_defined = 1;
                        printf("block md file base: '%s', scan files and verify data using md\n", conf.block_md_base);
                        break;
                case 'L':
                        ndebuglines = strtoul(optarg, 0, 0);
                        printf("Use %u debug lines\n", ndebuglines);
                        break;
                case 'u':
                        check_mode("warmup (-u)", -1, 0);
                        conf.warmup_sec = atoi(optarg);
                        if (conf.warmup_sec > 0)
                                printf("Warmup for %d seconds\n", conf.warmup_sec);
                        break;
		}
	}

        if (conf.iomodel == IO_MODEL_INVALID)
                conf.iomodel = IO_MODEL_SYNC; /* default */
        if (conf.iomodel == IO_MODEL_ASYNC && conf.aio_window_size <= 0)
                conf.aio_window_size = 1;
        
        printf("Use %s IO mode\n", iomodel_str[conf.iomodel]);
        
        if (conf.secs < 0) {
                printf("Using the default %d seconds time limit\n", DEFAULT_TIME_LIMIT);
                conf.secs = DEFAULT_TIME_LIMIT;
        }
        
        init_debug_lines();

        btest_ext_init(&(shared.ext));
        
        if (wl->dedup_likehood == -2) {
                srand48_r(conf.rseed, &rbuf);
                fixstamp = saferandom64(&rbuf);
                printf("use fixed stamp %"PRIx64"\n", fixstamp); 
        }
        
        if (conf.verification_mode) {
                conf.preformat = 0;
                conf.pretrim = 0;
                conf.exit_eof = 1;
                wl->trimsize = 0;
                wl->randomratio = 0;
                wl->readratio = 100;
                conf.iomodel = IO_MODEL_SYNC;
                conf.subtotal_interval = 0;
                conf.warmup_sec = 0;
                total_nworkloads = 1;

                verify_sizes(wl);
                
        } else if (workload_filename == NULL) { /* standard command line workload mode */
                total_nworkloads = 1;
                
                if (argc - optind < 3)
                        usage();        	

                verify_sizes(wl);
                
                parse_dorandom(wl, argv[optind]);
                optind++;

                parse_doread(wl, argv[optind]);
                optind++;
        } else                                  /* workload file mode */
                total_nworkloads = parse_workload(workload_filename);

        init_workloads();
        check_interval_ratio();

        DEBUG("total_nworkloads %d", total_nworkloads);
        
        conf.nfiles = argc - optind;
        if (conf.nfiles > MAX_FILES)
                PANIC("too much files %d > %d", conf.nfiles, MAX_FILES);
        for (i = 0; i < conf.nfiles; i++)
                filenames[i] = strdup(argv[optind + i]);

        state_set(STARTING, 0);

        if (pthread_create(&thid, NULL, (void *(*)(void *))stats_main, NULL))
                PANIC("Stats main thread creation failed");

        if (conf.timeout_ms && pthread_create(&thid, NULL, (void *(*)(void *))timeout_check_main, NULL))
                PANIC("timeout main thread creation failed");
                
        if (workload_filename) {
                int workload_weight_ix = 0;
                
                /**
                 * Duplicate the fields that were taken from command line,
                 * and init the weights. 
                 */
                for (i = 0; i < total_nworkloads; i++) {
                        total_workload_weights += workloads[i].weight;
                        
                        for (j = 0; j < workloads[i].weight; j++)
                                workload_weights[workload_weight_ix++] = i;
                }
        }

        /* init files and file shared ctx */
        max_nfiles = conf.nfiles;
        if (!(files = calloc(max_nfiles, sizeof *files)))
                PANIC("can't alloc %d file ctx", max_nfiles);
        if (conf.verify && !(shared_file_ctx_arr = calloc(max_nfiles, sizeof *shared_file_ctx_arr)))
                PANIC("can't alloc %d shared file ctx", max_nfiles);

        switch (conf.iomodel) {
        case IO_MODEL_SYNC:
        case IO_MODEL_WRITE_BEHIND:
        case IO_MODEL_SGIO:
        case IO_MODEL_SGIO_DIRECT:
        case IO_MODEL_DIRECT:
        case IO_MODEL_DIRECT_SYNC:
                /* nthreads per file, one worker per IO thread */
                max_nthreads = conf.nfiles * conf.nthreads;
                max_nworkers = max_nthreads;
                devs_per_thread = 1;
                
                if (!(workers = calloc(max_nworkers, sizeof *workers)))
                        PANIC("can't alloc %d workers", max_nworkers);
                if (!(io_ctx = calloc(max_nthreads, sizeof *io_ctx)))
                        PANIC("can't alloc %d io threads", max_nthreads);
                
                th_busywait = sync_th_busywait;

                shared.init_func = sync_shared_init;
                shared.destroy_func = sync_shared_destroy;
                shared.lock_func = sync_lock;
                shared.unlock_func = sync_unlock;
                shared.cond_wait_func = sync_cond_wait_func;
                shared.cond_broadcast_func = sync_cond_broadcast_func;                

                if (conf.iomodel == IO_MODEL_SGIO) {
                        shared.read = sg_read;
                        shared.write = sg_write;
                } else {
                        shared.write = sync_write;
                        shared.read = sync_read;
                }
                shared.prepare_buf = sync_prepare_buf;
                shared.write_completed = io_write_completed;
                shared.read_completed = io_read_completed;
                
                /* Load main thread */
                if (pthread_create(&thid, NULL, (void *(*)(void *))sync_main, NULL))
                        PANIC("Stats main thread creation failed");

                while (1) {
                        th_busywait();
                }
                break;

        case IO_MODEL_ASYNC:
                /* aio threads == nthreads, for each thread there are conf.aio_window_size * files * workloads workers */
                max_nthreads = conf.nthreads;
                max_nworkers = max_nthreads * (conf.aio_window_size * total_nworkloads * conf.nfiles);
                devs_per_thread = conf.nfiles;
                
                if (!(workers = calloc(max_nworkers, sizeof *workers)))
                        PANIC("can't alloc %d workers", max_nworkers);
                if (!(aio_ctx = calloc(max_nthreads, sizeof *aio_ctx)))
                        PANIC("can't alloc %d aio threads ctx", max_nthreads);

                th_busywait = sync_th_busywait;

                shared.init_func = sync_shared_init;
                shared.destroy_func = sync_shared_destroy;
                shared.lock_func = sync_lock;
                shared.unlock_func = sync_unlock;
                shared.cond_wait_func = sync_cond_wait_func;
                shared.cond_broadcast_func = sync_cond_broadcast_func;

                shared.write = aio_write;
                shared.read = aio_read;
                shared.prepare_buf = aio_prepare_buf;
                shared.write_completed = io_write_completed;
                shared.read_completed = io_read_completed;

                /* Load main thread */
                if (pthread_create(&thid, NULL, (void *(*)(void *))async_main, NULL))
                        PANIC("Stats main thread creation failed");

                while (1) {
                        th_busywait();
                }
                break;

        default:
                PANIC("btest unknown IO model %d", conf.iomodel);
        }
        
        return 0;
}

