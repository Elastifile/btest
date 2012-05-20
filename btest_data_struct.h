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

#ifndef BTEST_DATA_STRUCT_H
#define	BTEST_DATA_STRUCT_H

#include <libaio.h>
#include "btest_ext.h"
#include "ata.h"

#ifdef	__cplusplus
extern "C" {
#endif


/**
 * Data types
 */
#define MAX_WORKLOADS   10
#define MAX_FILES       1024
#define DEF_STAMPBLOCK  4096
        
typedef struct workload workload;
typedef struct block_worker_md block_worker_md;
typedef struct shared_file_ctx shared_file_ctx;
typedef struct worker_ctx worker_ctx;
typedef struct aio_thread_ctx aio_thread_ctx;
typedef struct io_thread_ctx io_thread_ctx;
typedef struct file_ctx file_ctx;
typedef struct workload_ctx workload_ctx;

typedef enum HiccupLevel {
        HICKUP_LEVEL_0_MILLI,   /* up to next level */
        HICKUP_LEVEL_1_MILLI,
        HICKUP_LEVEL_2TO10_MILLI,
        HICKUP_LEVEL_11TO100_MILLI,
        HICKUP_LEVEL_101ANDUP_MILLI,
        HICCUP_LEVEL_NUM_OF
} HiccupLevel;

typedef struct IOStats {
	char *title;
	uint64 duration;
	uint64 sduration;	/* sync duration */
	uint64 lat;
	uint64 ops;
	uint64 bytes;
	uint64 errors;
        uint64 verify_errors;
        uint32 hickup_histogram[HICCUP_LEVEL_NUM_OF];
        uint32 max_duration;
        uint32 last_max_duration;
} IOStats;

//// Need workload(pattern), worker(thread), io_ctx(stats, buffers, etc), file_ctx (name, fd, md, etc)

struct workload {
        int num;                /**< workload number */
	int blocksize;		/**< IO block size */
	int alignsize;		/**< IO block size */
	int randomratio;	/**< random IO ratio: 0 is pure sequential, 100 is pure random */
	int readratio;		/**< Read IO ratio: 0 is pure write, 100 pure read */
	loff_t startoffset;	/**< Offset of first byte in the IO region within the file/dev */
	uint64 len;		/**< Length of IO region (starting at 'startoffset'. 0 -> up to end of file */
        int dedup_likehood;     /**< Modulu stamp in this value to enlarge dedup likelihood */
        int progressive_dedup;  /**< Keep dedup factor at requested factor right from the start */
        int weight;             /**< Weight of this workload in case of multiple ones */
        int use_offset_stamps;  /**< fill block data with offset stamps */

	int trimsize;		/**< Trim block size in bytes */
};

#define BLOCK_STAMP_REFED(id, version)  ((1llu << 63) | ((uint64)(id) << 32) | ((version) & 0xfffffffflu))
#define BLOCK_STAMP_IS_REFED(stamp)     ((uint)((stamp) >> 63))
#define BLOCK_STAMP_ID(stamp)           (((stamp) >> 32) & 0x7fffffff)
#define BLOCK_STAMP_VERSION(stamp)      ((stamp) & 0xffffffffllu)
#define BLOCK_STAMP(stamp)              ((stamp) & ~(1llu << 63))

typedef struct block_md {
        uint64 stamp;           /** if ref > 0 -> new stamp, ref == 0 -> current stamp */
} block_md;

#define BLOCK_MD_VERREF(version, ref)   ((((uint64)(version)) & 0xfffffffflu) | (((uint64)(ref)) << 32))
#define BLOCK_MD_VERSION(verref)   ((verref) & 0xfffffffflu)
#define BLOCK_MD_REF(verref)   ((verref) >> 32)

struct block_worker_md {
        uint32 id;
        uint32 dowrite;         /**< flag - if set stamp will be next md stamp, otherwise old is restored */
        uint64 verref;          /**< 16 msb bits are ref, then 48 bit version */
        uint64 old;             /**< previous stamp */
        uint64 stamp;           /**< new stamp to be writen */
        uint64 blockid;         /**< block id (debug) */
};

#define MD_MAX_WORKERS  255     /**< MAX workers acting on a signle md */
#define MD_MAX_BLOCK_SIZE  (1 << 20)
#define MD_MAX_MD_MAPS     (MD_MAX_WORKERS*(MD_MAX_BLOCK_SIZE/512)*2)
#define MD_VERSION         100          /* major 1, minor 0 - btest binary major must >= file md */

#define MD_MAGIC        0x7131f1f1

typedef struct md_file_hdr {
        uint32 magic;
        char devname[256];
        uint version;
        uint initialized;
        uint md_start;
        uint stampblock;
        size_t hdrsize;
        size_t mdsize;
        uint32 ref;
        uint max_mds;
        uint workers_map[MD_MAX_MD_MAPS];
        block_worker_md workers_mds[MD_MAX_MD_MAPS];
} md_file_hdr;

struct workload_ctx {
        uint64 len;                 /**< length of data range for this workload */
        uint64 start;               /**< convenience: start offset of workload */
        uint64 end;                 /**< convenience: end offset of workload */
        
        int64 dedup_stamp_modulo;   /**< Modulul stamp in this value to enlarge dedup likelihood */
        int dedup_likehood;      /**< fixed ratio */
        uint64 last_stamp;          /**< state used for progrssive dedup generation see generate_dedup_stamp() */
        uint32 dedup_fill_counter;  /**< for progressive dedup fills */

        workload *wl;               /**< used workload */
};

/**
 * Context of IO worker (sync thread or aio request)
 */
struct worker_ctx {
        int num;
        int initializer;            /**< Am I an initialize worker? */
        
	/* Internal - Common */
	void *buf;
        uint64 offset;		    /**< Offset of next IO in bytes */
        
        struct drand48_data rbuf;

        struct timespec start_time; /**< Start time of last IO */
        struct timespec end_time;   /**< End time of last IO */

        IOStats stats;              /**< Accumulative statistics from the start */
	IOStats last;               /**< Accumulative statistics from the last diff report */

        pid_t tid;

        file_ctx *fctx;             /**< file context */
        workload_ctx *wlctx;        /**< current workload context */

        io_context_t io_context;   /**< AsyncIO context, copied from its aio_thread */
        struct iocb *aio_cb;

        block_worker_md *worker_md;
};

struct aio_thread_ctx {
        int num;

        io_context_t io_context;   /**< AsyncIO context */
        pid_t tid;
};

struct io_thread_ctx {
        int num;

        file_ctx *fctx;
        int initialized;
};

/**
 * Context that is shared among workers of the same file
 */
struct shared_file_ctx {
        md_file_hdr *hdr;
        block_md *md;               /**< optinal md per block to implement various validation options */
        char *md_file;              /**< name of md backstore file */
        int fd;                     /**< opend md_file */
};

typedef enum FileType {
        F_INVALID,
        F_FILE,
        F_BLOCK,
        F_SG,
} FileType;

/**
 * Per file/dev context
 */
struct file_ctx {
        char *file;		/**< File name */

	int num;		/**< id number of file context */
        int initialized;
        int usestamps;
        int fd;                 /**< File descriptor */
        FileType type;          /**< type */
	int64 size;		/**< Total size of device/file in bytes */
        int atafd;		/**< fd for ATA specific opertaions, e.g. trim */

        IOStats stats;          /**< Accumulative statistics from the start */
        
        workload_ctx wlctxs[MAX_WORKLOADS];     /* all workload contexts for this file */
        shared_file_ctx shared;
        
        uint64 seq_offset;          /**< for seq workloads - shared among workloads */
};

#ifdef	__cplusplus
}
#endif

#endif	/* BTEST_DATA_STRUCT_H */

