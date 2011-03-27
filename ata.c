/* based on hdparm.c - Command line interface to get/set hard disk parameters */
/*          - by Mark Lord (C) 1994-2008 -- freely distributable */
/*	    - Shahar Frank (C) - 2010 */

#ifndef __GLIBC_HAVE_LONG_LONG
#define __GLIBC_HAVE_LONG_LONG
#endif
#ifndef __USE_MISC		/* for strtoll() */
#define __USE_MISC		/* for strtoll() */
#endif
#include <unistd.h>
#include <stdio.h>
#define __USE_GNU		/* for O_DIRECT */
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <endian.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/major.h>
#include <asm/byteorder.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "btest.h"
#include "hdparm.h"
#include "sgio.h"
#include "ata.h"

#define MAX_SECTORS 1024
#define THREAD_DATA_SZ 4096

static void *sector_data[MAX_SECTORS];

static int get_sector_count(int fd, uint64_t * nsectors)
{
	int err;
	unsigned int nsects32 = 0;
	uint64_t nbytes64 = 0;

#ifdef BLKGETSIZE64
	if (0 == ioctl(fd, BLKGETSIZE64, &nbytes64)) {	// returns bytes
		*nsectors = nbytes64 / 512;
		return 0;
	}
#endif
	err = ioctl(fd, BLKGETSIZE, &nsects32);	// returns sectors
	if (err == 0) {
		*nsectors = nsects32;
	} else {
		err = errno;
		perror(" BLKGETSIZE failed");
	}
	return err;
}

int get_dev_geometry(int fd, __u32 * cyls, __u32 * heads, __u32 * sects,
		     uint64_t * start_lba, uint64_t * nsectors)
{
	static struct local_hd_geometry g;
	static struct local_hd_big_geometry bg;
	int err = 0;

	if (nsectors) {
		err = get_sector_count(fd, nsectors);
		if (err)
			return err;
	}

	if (cyls || heads || sects || start_lba) {
		if (!ioctl(fd, HDIO_GETGEO_BIG, &bg)) {
			if (cyls)
				*cyls = bg.cylinders;
			if (heads)
				*heads = bg.heads;
			if (sects)
				*sects = bg.sectors;
			if (start_lba)
				*start_lba = bg.start;
		} else if (!ioctl(fd, HDIO_GETGEO, &g)) {
			if (cyls)
				*cyls = g.cylinders;
			if (heads)
				*heads = g.heads;
			if (sects)
				*sects = g.sectors;
			if (start_lba)
				*start_lba = g.start;
		} else {
			err = errno;
			perror(" HDIO_GETGEO failed");
			return err;
		}
		/*
		 * On all (32 and 64 bit) systems, the cyls value is bit-limited.
		 * So try and correct it using other info we have at hand.
		 */
		if (nsectors && cyls && heads && sects) {
			uint64_t hs = (*heads) * (*sects);
			uint64_t cyl = (*cyls);
			uint64_t chs = cyl * hs;
			if (chs < (*nsectors))
				*cyls = (*nsectors) / hs;
		}
	}

	return 0;
}

static int abort_if_not_full_device(int fd, const char *devname)
{
	uint64_t start_lba = ~0;
	int i, err, shortened = 0;
	char *fdevname = strdup(devname);

	err = get_dev_geometry(fd, NULL, NULL, NULL, &start_lba, NULL);
	if (err)
		PANIC("can't get dev geometry of %s", devname);

	for (i = strlen(fdevname); --i > 2 && (fdevname[i] >= '0' && fdevname[i] <= '9');) {
		fdevname[i] = '\0';
		shortened = 1;
	}

	if (!shortened)
		fdevname = strdup("the full disk");

	if (start_lba == 0ULL)
		return 0;

	fprintf(stderr,
		"Device %s has non-zero LBA starting offset of %" PRId64 ".\n", devname, start_lba);
	fprintf(stderr,
		"Please use an absolute LBA with the /dev/ entry for the full device, rather than a partition name.\n");
	fprintf(stderr, "%s is probably a partition of %s (?)\n", devname, fdevname);

	return -1;
}


static int trim_sectors(int fd, int nranges, void *data)
{
	struct ata_tf tf;
	int err = 0;
	unsigned int data_bytes = nranges * sizeof(uint64_t);
	unsigned int data_sects = (data_bytes + 511) / 512;

	data_bytes = data_sects * 512;

	DEBUG3("fd %d trimming %d ranges", fd, nranges);

	// Try and ensure that the system doesn't have the to-be-trimmed sectors in cache:
	/*flush_buffer_cache(fd); */

	tf_init(&tf, ATA_OP_DSM, 0, data_sects);
	tf.lob.feat = 0x01;	/* DSM/TRIM */

	if (sg16(fd, SG_WRITE, SG_DMA, &tf, data, data_bytes, 300 /* seconds */ )) {
		err = -errno;
		WARN("FAILED: fd %d nrange %d data %p", fd, nranges, data);
	} else {
		DEBUG3("fd %d: succeeded", fd);
	}
	return err;
}

int ata_trim_sectors(int fd, uint64_t lba, uint64_t nsectors)
{
	uint64_t range, *data;

	DEBUG("fd %d lba 0x%"PRIx64" nsectors %"PRId64, fd, lba, nsectors);
	/* use the fd specific buffer */
	if (fd < 0 || fd >= MAX_SECTORS)
		return -1;

	data = (uint64_t *) (sector_data[fd]);
	range = (nsectors << 48) | lba;
	*data = __cpu_to_le64(range);

	return trim_sectors(fd, 1, data);
}

int ata_trim_sector_ranges(int fd, struct sector_range_s *ranges, int nranges)
{
	uint64_t range, *data;
	int r;

	/* use the fd specific buffer */
	if (fd < 0 || fd >= MAX_SECTORS)
		return -1;
	if (nranges > SECTOR_RANGES_MAX) {
		WARN("bad nranges %d > %d", nranges, SECTOR_RANGES_MAX);
		return -1;
	}

	data = (uint64_t *) (sector_data[fd]);
	for (r = 0; r < nranges; r++) {
		DEBUG("fd %d lba 0x%"PRIx64" nsectors %"PRId64, fd, ranges[r].lba, ranges[r].nsectors);
		range = (ranges[r].nsectors << 48) | ranges[r].lba;
		*data++ = __cpu_to_le64(range);
	}

	return trim_sectors(fd, nranges, sector_data[fd]);
}

/* init a full device - return a fd to be used by future ata ops */
int ata_init(char *devname)
{
	int fd;

	if ((fd = open(devname, O_RDWR | O_DIRECT)) < 0)
		PANIC("can't open ata device %s\n", devname);
	if (abort_if_not_full_device(fd, devname))
		PANIC("ata opertaions (TRIM, etc.) can be used on full devices only");
	if (fd >= MAX_SECTORS)
		PANIC("too many fds (%d >= %d)", fd, MAX_SECTORS);

	sector_data[fd] =
	    mmap(NULL, THREAD_DATA_SZ, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (sector_data[fd] == MAP_FAILED)
		PANIC("mmap(MAP_ANONYMOUS) on fd %d", fd);

	DEBUG("devname %s fd %d data %p", devname, fd, sector_data[fd]);
	return fd;
}
