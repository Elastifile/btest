#ifndef _HDPARAM_H_
/* Some prototypes for extern functions. */

#define lba28_limit ((uint64_t)(1<<28) - 1)

int sysfs_get_attr(int fd, const char *attr, const char *fmt, void *val1, void *val2, int verbose);
int sysfs_set_attr(int fd, const char *attr, const char *fmt, void *val_p, int verbose);
int get_dev_geometry(int fd, uint32_t * cyls, uint32_t * heads,
		     uint32_t * sects, uint64_t * start_lba, uint64_t * nsectors);

extern const char *BuffType[4];

struct local_hd_big_geometry {
	unsigned char heads;
	unsigned char sectors;
	unsigned int cylinders;
	unsigned long start;
};

struct local_hd_geometry {
	unsigned char heads;
	unsigned char sectors;
	unsigned short cylinders;
	unsigned long start;	/* mmm.. on 32-bit, this limits us to LBA32, 2TB max offset */
};

enum {				/* ioctl() numbers */
	HDIO_DRIVE_CMD = 0x031f,
	HDIO_DRIVE_RESET = 0x031c,
	HDIO_DRIVE_TASK = 0x031e,
	HDIO_DRIVE_TASKFILE = 0x031d,
	HDIO_GETGEO = 0x0301,
	HDIO_GETGEO_BIG = 0x0330,
	HDIO_GET_32BIT = 0x0309,
	HDIO_GET_ACOUSTIC = 0x030f,
	HDIO_GET_BUSSTATE = 0x031a,
	HDIO_GET_DMA = 0x030b,
	HDIO_GET_IDENTITY = 0x030d,
	HDIO_GET_KEEPSETTINGS = 0x0308,
	HDIO_GET_MULTCOUNT = 0x0304,
	HDIO_GET_NOWERR = 0x030a,
	HDIO_GET_QDMA = 0x0305,
	HDIO_GET_UNMASKINTR = 0x0302,
	HDIO_OBSOLETE_IDENTITY = 0x0307,
	HDIO_SCAN_HWIF = 0x0328,
	HDIO_SET_32BIT = 0x0324,
	HDIO_SET_ACOUSTIC = 0x032c,
	HDIO_SET_BUSSTATE = 0x032d,
	HDIO_SET_DMA = 0x0326,
	HDIO_SET_KEEPSETTINGS = 0x0323,
	HDIO_SET_MULTCOUNT = 0x0321,
	HDIO_SET_NOWERR = 0x0325,
	HDIO_SET_PIO_MODE = 0x0327,
	HDIO_SET_QDMA = 0x032e,
	HDIO_SET_UNMASKINTR = 0x0322,
	HDIO_SET_WCACHE = 0x032b,
	HDIO_TRISTATE_HWIF = 0x031b,
	HDIO_UNREGISTER_HWIF = 0x032a,
	CDROM__SPEED = 0x5322,
};
#endif
