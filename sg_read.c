#define _XOPEN_SOURCE 500
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <linux/major.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_io_linux.h"

/*
 * Based on sg_read.c from sg_utils, follows original copyright:
 */
 
/* A utility program for the Linux OS SCSI generic ("sg") device driver.
*  Copyright (C) 2001 - 2007 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program reads data from the given SCSI device (typically a disk
   or cdrom) and discards that data. Its primary goal is to time
   multiple reads all starting from the same logical address. Its interface
   is a subset of another member of this package: sg_dd which is a
   "dd" variant. The input file can be a scsi generic device, a block device,
   a raw device or a seekable file. Streams such as stdin are not acceptable.
   The block size ('bs') is assumed to be 512 if not given.

   This version should compile with Linux sg drivers with version numbers
   >= 30000 . For mmap-ed IO the sg version number >= 30122 .

*/

#define DEF_BLOCK_SIZE 512
#define DEF_BLOCKS_PER_TRANSFER 128
#define DEF_SCSI_CDBSZ 10
#define MAX_SCSI_CDBSZ 16

#define ME "sg_read: "

#ifndef SG_FLAG_MMAP_IO
#define SG_FLAG_MMAP_IO 4
#endif

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 40000       /* 40,000 millisecs == 40 seconds */

#ifndef RAW_MAJOR
#define RAW_MAJOR 255   /*unlikey value */
#endif

#define FT_OTHER 1              /* filetype other than sg or raw device */
#define FT_SG 2                 /* filetype is sg char device */
#define FT_RAW 4                /* filetype is raw char device */
#define FT_BLOCK 8              /* filetype is block device */
#define FT_ERROR 64             /* couldn't "stat" file */

#define MIN_RESERVED_SIZE 8192

static int pack_id_count = 0;
static int verbose = 0;

int sg_is_sg(const char * filename)
{
    struct stat st;

    if (stat(filename, &st) < 0)
        return 0;
    if (S_ISCHR(st.st_mode) && (SCSI_GENERIC_MAJOR == major(st.st_rdev)))
            return 1;
    return 0;
}

static int sg_build_rw_scsi_cdb(unsigned char * cdbp, int cdb_sz,
                             unsigned int blocks, int64_t start_block,
                             int write_true, int fua, int dpo)
{
    int rd_opcode[] = {0x8, 0x28, 0xa8, 0x88};
    int wr_opcode[] = {0xa, 0x2a, 0xaa, 0x8a};
    int sz_ind;

    memset(cdbp, 0, cdb_sz);
    if (dpo)
        cdbp[1] |= 0x10;
    if (fua)
        cdbp[1] |= 0x8;
    switch (cdb_sz) {
    case 6:
        sz_ind = 0;
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        cdbp[1] = (unsigned char)((start_block >> 16) & 0x1f);
        cdbp[2] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[3] = (unsigned char)(start_block & 0xff);
        cdbp[4] = (256 == blocks) ? 0 : (unsigned char)blocks;
        if (blocks > 256) {
            fprintf(stderr, ME "for 6 byte commands, maximum number of "
                            "blocks is 256\n");
            return 1;
        }
        if ((start_block + blocks - 1) & (~0x1fffff)) {
            fprintf(stderr, ME "for 6 byte commands, can't address blocks"
                            " beyond %d\n", 0x1fffff);
            return 1;
        }
        if (dpo || fua) {
            fprintf(stderr, ME "for 6 byte commands, neither dpo nor fua"
                            " bits supported\n");
            return 1;
        }
        break;
    case 10:
        sz_ind = 1;
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        cdbp[2] = (unsigned char)((start_block >> 24) & 0xff);
        cdbp[3] = (unsigned char)((start_block >> 16) & 0xff);
        cdbp[4] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[5] = (unsigned char)(start_block & 0xff);
        cdbp[7] = (unsigned char)((blocks >> 8) & 0xff);
        cdbp[8] = (unsigned char)(blocks & 0xff);
        if (blocks & (~0xffff)) {
            fprintf(stderr, ME "for 10 byte commands, maximum number of "
                            "blocks is %d\n", 0xffff);
            return 1;
        }
        break;
    case 12:
        sz_ind = 2;
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        cdbp[2] = (unsigned char)((start_block >> 24) & 0xff);
        cdbp[3] = (unsigned char)((start_block >> 16) & 0xff);
        cdbp[4] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[5] = (unsigned char)(start_block & 0xff);
        cdbp[6] = (unsigned char)((blocks >> 24) & 0xff);
        cdbp[7] = (unsigned char)((blocks >> 16) & 0xff);
        cdbp[8] = (unsigned char)((blocks >> 8) & 0xff);
        cdbp[9] = (unsigned char)(blocks & 0xff);
        break;
    case 16:
        sz_ind = 3;
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        cdbp[2] = (unsigned char)((start_block >> 56) & 0xff);
        cdbp[3] = (unsigned char)((start_block >> 48) & 0xff);
        cdbp[4] = (unsigned char)((start_block >> 40) & 0xff);
        cdbp[5] = (unsigned char)((start_block >> 32) & 0xff);
        cdbp[6] = (unsigned char)((start_block >> 24) & 0xff);
        cdbp[7] = (unsigned char)((start_block >> 16) & 0xff);
        cdbp[8] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[9] = (unsigned char)(start_block & 0xff);
        cdbp[10] = (unsigned char)((blocks >> 24) & 0xff);
        cdbp[11] = (unsigned char)((blocks >> 16) & 0xff);
        cdbp[12] = (unsigned char)((blocks >> 8) & 0xff);
        cdbp[13] = (unsigned char)(blocks & 0xff);
        break;
    default:
        fprintf(stderr, ME "expected cdb size of 6, 10, 12, or 16 but got"
                        " %d\n", cdb_sz);
        return 1;
    }
    return 0;
}

// simplified from sg_io_linux.c
int
sg_err_category_new(int scsi_status, int host_status, int driver_status,
                    const unsigned char * sense_buffer, int sb_len)
{
    int masked_driver_status = (SG_LIB_DRIVER_MASK & driver_status);

    scsi_status &= 0x7e;
    if ((0 == scsi_status) && (0 == host_status) &&
        (0 == masked_driver_status))
        return SG_LIB_CAT_CLEAN;
    return SG_LIB_CAT_OTHER;
}

int
sg_err_category3(struct sg_io_hdr * hp)
{
    return sg_err_category_new(hp->status, hp->host_status,
                               hp->driver_status, hp->sbp, hp->sb_len_wr);
}

static int sg_send_scsi_cmd(int sg_fd, unsigned char *rdCmd, int cdbsz, int rw, unsigned char *buff, int len, int * diop, int do_mmap, int no_dxfer)
{
    int k;
    unsigned char senseBuff[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = cdbsz;
    io_hdr.cmdp = rdCmd;
    if (len > 0) {
        io_hdr.dxfer_direction = rw ? SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV;
        io_hdr.dxfer_len = len;
        if (! do_mmap) /* not required: shows dxferp unused during mmap-ed IO */
            io_hdr.dxferp = buff;
        if (diop && *diop)
            io_hdr.flags |= SG_FLAG_DIRECT_IO;
        else if (do_mmap)
            io_hdr.flags |= SG_FLAG_MMAP_IO;
        else if (no_dxfer)
            io_hdr.flags |= SG_FLAG_NO_DXFER;
    } else
        io_hdr.dxfer_direction = SG_DXFER_NONE;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.pack_id = pack_id_count++;
    if (verbose > 1) {
        fprintf(stderr, "    read cdb: ");
        for (k = 0; k < cdbsz; ++k)
            fprintf(stderr, "%02x ", rdCmd[k]);
        fprintf(stderr, "\n");
    }

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        if (ENOMEM == errno)
            return 1;
        perror("reading (SG_IO) on sg device, error");
        return -1;
    }

    if (verbose > 2)
        fprintf(stderr, "      duration=%u ms\n", io_hdr.duration);
        
    if (sg_err_category3(&io_hdr) != SG_LIB_CAT_CLEAN) {
      fprintf(stderr, "SG error\n");
      return -1;
    }

    return 0;
}

/* -3 medium/hardware error, -2 -> not ready, 0 -> successful,
   1 -> recoverable (ENOMEM), 2 -> try again (e.g. unit attention),
   3 -> try again (e.g. aborted command), -1 -> other unrecoverable error */
int sg_rw(int sg_fd, int rw, unsigned char * buff, int blocks,
                    int64_t from_block, int bs, int cdbsz,
                    int fua, int dpo, int * diop, int do_mmap,
                    int no_dxfer)
{
    unsigned char rdCmd[MAX_SCSI_CDBSZ];

    if (sg_build_rw_scsi_cdb(rdCmd, cdbsz, blocks, from_block, rw, fua, dpo)) {
        fprintf(stderr, ME "bad cdb build, from_block=%"PRId64", blocks=%d\n",
                from_block, blocks);
        return -1;
    }
    return sg_send_scsi_cmd(sg_fd, rdCmd, cdbsz, rw, buff, bs * blocks, diop, do_mmap, no_dxfer);
}

int64_t sg_getsize(int sg_fd)
{
  unsigned char rdCmd[MAX_SCSI_CDBSZ];
  unsigned char resp_buff[512];
  long long capacity;
  int rc, block_size;

  memset(rdCmd, 0, MAX_SCSI_CDBSZ);
  memset(resp_buff, 0, 512);
  rdCmd[0] = 0x25;

  rc = sg_send_scsi_cmd(sg_fd, rdCmd, 10, 0, resp_buff, 8, NULL, 0, 0);
  if (rc == -1) {
    printf("READ_CAPACITY failed\n");
    return -1;
  }
  block_size = (resp_buff[4] << 24) | (resp_buff[5] << 16) | (resp_buff[6] << 8) | resp_buff[7];
  if (block_size != 512) {
    printf("error: physical block size %d not supported\n", block_size);
    return -1;
  }
  capacity = 512 * (((long long) resp_buff[0] << 24) | (resp_buff[1] << 16) | (resp_buff[2] << 8) | resp_buff[3]);
//  printf("capacity %lld (%lld GB)\n", capacity, capacity / 1024 / 1024 / 1024);
  return capacity;
}
