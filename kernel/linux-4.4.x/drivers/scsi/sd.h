#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifndef _SCSI_DISK_H
#define _SCSI_DISK_H

#define SD_MAJORS	16

#ifdef MY_DEF_HERE
#define SD_TIMEOUT		(1024 * HZ)
#elif defined(MY_ABC_HERE)
#define SD_TIMEOUT		(60 * HZ)
#else  
#define SD_TIMEOUT		(30 * HZ)
#endif  
#define SD_MOD_TIMEOUT		(75 * HZ)
 
#define SD_FLUSH_TIMEOUT_MULTIPLIER	2
#define SD_WRITE_SAME_TIMEOUT	(120 * HZ)

#define SD_MAX_RETRIES		5
#define SD_PASSTHROUGH_RETRIES	1
#ifdef MY_DEF_HERE
#define SD_MAX_MEDIUM_TIMEOUTS 1024
#else
#define SD_MAX_MEDIUM_TIMEOUTS	2
#endif  

#define SD_BUF_SIZE		512

#define SD_LAST_BUGGY_SECTORS	8

enum {
	SD_EXT_CDB_SIZE = 32,	 
	SD_MEMPOOL_SIZE = 2,	 
};

enum {
	SD_DEF_XFER_BLOCKS = 0xffff,
	SD_MAX_XFER_BLOCKS = 0xffffffff,
	SD_MAX_WS10_BLOCKS = 0xffff,
	SD_MAX_WS16_BLOCKS = 0x7fffff,
};

enum {
	SD_LBP_FULL = 0,	 
	SD_LBP_UNMAP,		 
	SD_LBP_WS16,		 
	SD_LBP_WS10,		 
	SD_LBP_ZERO,		 
	SD_LBP_DISABLE,		 
};

#ifdef MY_ABC_HERE
typedef enum __syno_disk_type {
	SYNO_DISK_UNKNOWN = 0,
	SYNO_DISK_SATA,
	SYNO_DISK_USB,
	SYNO_DISK_SYNOBOOT,
	SYNO_DISK_ISCSI,
	SYNO_DISK_SAS,
#ifdef MY_DEF_HERE
	SYNO_DISK_CACHE,  
#endif  
	SYNO_DISK_END,  
} SYNO_DISK_TYPE;
#endif  

struct scsi_disk {
	struct scsi_driver *driver;	 
	struct scsi_device *device;
	struct device	dev;
	struct gendisk	*disk;
	atomic_t	openers;
	sector_t	capacity;	 
	u32		max_xfer_blocks;
	u32		opt_xfer_blocks;
	u32		max_ws_blocks;
	u32		max_unmap_blocks;
	u32		unmap_granularity;
	u32		unmap_alignment;
	u32		index;
#ifdef MY_ABC_HERE
	SYNO_DISK_TYPE	synodisktype;
#endif  
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	u32		synoindex;
#endif  
	unsigned int	physical_block_size;
	unsigned int	max_medium_access_timeouts;
	unsigned int	medium_access_timed_out;
	u8		media_present;
	u8		write_prot;
	u8		protection_type; 
	u8		provisioning_mode;
	unsigned	ATO : 1;	 
	unsigned	cache_override : 1;  
	unsigned	WCE : 1;	 
	unsigned	RCD : 1;	 
	unsigned	DPOFUA : 1;	 
	unsigned	first_scan : 1;
	unsigned	lbpme : 1;
	unsigned	lbprz : 1;
	unsigned	lbpu : 1;
	unsigned	lbpws : 1;
	unsigned	lbpws10 : 1;
	unsigned	lbpvpd : 1;
	unsigned	ws10 : 1;
	unsigned	ws16 : 1;
};
#define to_scsi_disk(obj) container_of(obj,struct scsi_disk,dev)

static inline struct scsi_disk *scsi_disk(struct gendisk *disk)
{
	return container_of(disk->private_data, struct scsi_disk, driver);
}

#define sd_printk(prefix, sdsk, fmt, a...)				\
        (sdsk)->disk ?							\
	      sdev_prefix_printk(prefix, (sdsk)->device,		\
				 (sdsk)->disk->disk_name, fmt, ##a) :	\
	      sdev_printk(prefix, (sdsk)->device, fmt, ##a)

#define sd_first_printk(prefix, sdsk, fmt, a...)			\
	do {								\
		if ((sdkp)->first_scan)					\
			sd_printk(prefix, sdsk, fmt, ##a);		\
	} while (0)

static inline int scsi_medium_access_command(struct scsi_cmnd *scmd)
{
	switch (scmd->cmnd[0]) {
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
	case SYNCHRONIZE_CACHE:
	case VERIFY:
	case VERIFY_12:
	case VERIFY_16:
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	case WRITE_SAME:
	case WRITE_SAME_16:
	case UNMAP:
		return 1;
	case VARIABLE_LENGTH_CMD:
		switch (scmd->cmnd[9]) {
		case READ_32:
		case VERIFY_32:
		case WRITE_32:
		case WRITE_SAME_32:
			return 1;
		}
	}

	return 0;
}

static inline sector_t logical_to_sectors(struct scsi_device *sdev, sector_t blocks)
{
	return blocks << (ilog2(sdev->sector_size) - 9);
}

static inline unsigned int logical_to_bytes(struct scsi_device *sdev, sector_t blocks)
{
	return blocks * sdev->sector_size;
}

enum sd_dif_target_protection_types {
	SD_DIF_TYPE0_PROTECTION = 0x0,
	SD_DIF_TYPE1_PROTECTION = 0x1,
	SD_DIF_TYPE2_PROTECTION = 0x2,
	SD_DIF_TYPE3_PROTECTION = 0x3,
};

static inline unsigned int sd_prot_op(bool write, bool dix, bool dif)
{
	 
	const unsigned int ops[] = {	 
		SCSI_PROT_NORMAL,	 
		SCSI_PROT_READ_STRIP,	 
		SCSI_PROT_READ_INSERT,	 
		SCSI_PROT_READ_PASS,	 
		SCSI_PROT_NORMAL,	 
		SCSI_PROT_WRITE_INSERT,  
		SCSI_PROT_WRITE_STRIP,	 
		SCSI_PROT_WRITE_PASS,	 
	};

	return ops[write << 2 | dix << 1 | dif];
}

static inline unsigned int sd_prot_flag_mask(unsigned int prot_op)
{
	const unsigned int flag_mask[] = {
		[SCSI_PROT_NORMAL]		= 0,

		[SCSI_PROT_READ_STRIP]		= SCSI_PROT_TRANSFER_PI |
						  SCSI_PROT_GUARD_CHECK |
						  SCSI_PROT_REF_CHECK |
						  SCSI_PROT_REF_INCREMENT,

		[SCSI_PROT_READ_INSERT]		= SCSI_PROT_REF_INCREMENT |
						  SCSI_PROT_IP_CHECKSUM,

		[SCSI_PROT_READ_PASS]		= SCSI_PROT_TRANSFER_PI |
						  SCSI_PROT_GUARD_CHECK |
						  SCSI_PROT_REF_CHECK |
						  SCSI_PROT_REF_INCREMENT |
						  SCSI_PROT_IP_CHECKSUM,

		[SCSI_PROT_WRITE_INSERT]	= SCSI_PROT_TRANSFER_PI |
						  SCSI_PROT_REF_INCREMENT,

		[SCSI_PROT_WRITE_STRIP]		= SCSI_PROT_GUARD_CHECK |
						  SCSI_PROT_REF_CHECK |
						  SCSI_PROT_REF_INCREMENT |
						  SCSI_PROT_IP_CHECKSUM,

		[SCSI_PROT_WRITE_PASS]		= SCSI_PROT_TRANSFER_PI |
						  SCSI_PROT_GUARD_CHECK |
						  SCSI_PROT_REF_CHECK |
						  SCSI_PROT_REF_INCREMENT |
						  SCSI_PROT_IP_CHECKSUM,
	};

	return flag_mask[prot_op];
}

struct sd_dif_tuple {
       __be16 guard_tag;	 
       __be16 app_tag;		 
       __be32 ref_tag;		 
};

#ifdef CONFIG_BLK_DEV_INTEGRITY

extern void sd_dif_config_host(struct scsi_disk *);
extern void sd_dif_prepare(struct scsi_cmnd *scmd);
extern void sd_dif_complete(struct scsi_cmnd *, unsigned int);

#else  

static inline void sd_dif_config_host(struct scsi_disk *disk)
{
}
static inline int sd_dif_prepare(struct scsi_cmnd *scmd)
{
	return 0;
}
static inline void sd_dif_complete(struct scsi_cmnd *cmd, unsigned int a)
{
}

#endif  

#endif  
