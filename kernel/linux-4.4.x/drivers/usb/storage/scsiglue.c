#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/module.h>
#include <linux/mutex.h>

#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_devinfo.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_eh.h>

#include "usb.h"
#include "scsiglue.h"
#include "debug.h"
#include "transport.h"
#include "protocol.h"

#define VENDOR_ID_NOKIA		0x0421
#define VENDOR_ID_NIKON		0x04b0
#define VENDOR_ID_PENTAX	0x0a17
#define VENDOR_ID_MOTOROLA	0x22b8

static const char* host_info(struct Scsi_Host *host)
{
	struct us_data *us = host_to_us(host);
	return us->scsi_name;
}

static int slave_alloc (struct scsi_device *sdev)
{
	struct us_data *us = host_to_us(sdev->host);

	sdev->inquiry_len = 36;

	blk_queue_update_dma_alignment(sdev->request_queue, (512 - 1));

	if (us->protocol == USB_PR_BULK && us->max_lun > 0)
		sdev->sdev_bflags |= BLIST_FORCELUN;

	return 0;
}

static int slave_configure(struct scsi_device *sdev)
{
	struct us_data *us = host_to_us(sdev->host);

	if (us->fflags & (US_FL_MAX_SECTORS_64 | US_FL_MAX_SECTORS_MIN)) {
		unsigned int max_sectors = 64;

		if (us->fflags & US_FL_MAX_SECTORS_MIN)
			max_sectors = PAGE_CACHE_SIZE >> 9;
		if (queue_max_hw_sectors(sdev->request_queue) > max_sectors)
			blk_queue_max_hw_sectors(sdev->request_queue,
					      max_sectors);
	} else if (sdev->type == TYPE_TAPE) {
		 
		blk_queue_max_hw_sectors(sdev->request_queue, 0x7FFFFF);
	}

	if (!us->pusb_dev->bus->controller->dma_mask)
		blk_queue_bounce_limit(sdev->request_queue, BLK_BOUNCE_HIGH);

	if (sdev->type == TYPE_DISK) {

		switch (le16_to_cpu(us->pusb_dev->descriptor.idVendor)) {
		case VENDOR_ID_NOKIA:
		case VENDOR_ID_NIKON:
		case VENDOR_ID_PENTAX:
		case VENDOR_ID_MOTOROLA:
			if (!(us->fflags & (US_FL_FIX_CAPACITY |
					US_FL_CAPACITY_OK)))
				us->fflags |= US_FL_CAPACITY_HEURISTICS;
			break;
		}

		if (us->subclass != USB_SC_SCSI && us->subclass != USB_SC_CYP_ATACB)
			sdev->use_10_for_ms = 1;

		sdev->use_192_bytes_for_3f = 1;

		if (us->fflags & US_FL_NO_WP_DETECT)
			sdev->skip_ms_page_3f = 1;

		sdev->skip_ms_page_8 = 1;

		sdev->skip_vpd_pages = 1;

		sdev->no_report_opcodes = 1;

		sdev->no_write_same = 1;

		if (us->fflags & US_FL_FIX_CAPACITY)
			sdev->fix_capacity = 1;

		if (us->fflags & US_FL_CAPACITY_HEURISTICS)
			sdev->guess_capacity = 1;

		if (us->fflags & US_FL_NO_READ_CAPACITY_16)
			sdev->no_read_capacity_16 = 1;

		if (!(us->fflags & US_FL_NEEDS_CAP16))
			sdev->try_rc_10_first = 1;

		if (sdev->scsi_level > SCSI_SPC_2)
			us->fflags |= US_FL_SANE_SENSE;

		sdev->retry_hwerror = 1;

		sdev->allow_restart = 1;

		sdev->last_sector_bug = 1;

		if (!(us->fflags & (US_FL_FIX_CAPACITY | US_FL_CAPACITY_OK |
					US_FL_SCM_MULT_TARG)) &&
				us->protocol == USB_PR_BULK)
			us->use_last_sector_hacks = 1;

		if (us->fflags & US_FL_WRITE_CACHE)
			sdev->wce_default_on = 1;

		if (us->fflags & US_FL_BROKEN_FUA)
			sdev->broken_fua = 1;

	} else {

		sdev->use_10_for_ms = 1;

		if (us->fflags & US_FL_NO_READ_DISC_INFO)
			sdev->no_read_disc_info = 1;
	}

	if ((us->protocol == USB_PR_CB || us->protocol == USB_PR_CBI) &&
			sdev->scsi_level == SCSI_UNKNOWN)
		us->max_lun = 0;

	if (us->fflags & US_FL_NOT_LOCKABLE)
		sdev->lockable = 0;

	return 0;
}

static int target_alloc(struct scsi_target *starget)
{
	struct us_data *us = host_to_us(dev_to_shost(starget->dev.parent));

	starget->no_report_luns = 1;

	if (us->subclass == USB_SC_UFI)
		starget->pdt_1f_for_no_lun = 1;

	return 0;
}

static int queuecommand_lck(struct scsi_cmnd *srb,
			void (*done)(struct scsi_cmnd *))
{
	struct us_data *us = host_to_us(srb->device->host);

	if (us->srb != NULL) {
		printk(KERN_ERR USB_STORAGE "Error in %s: us->srb = %p\n",
			__func__, us->srb);
		return SCSI_MLQUEUE_HOST_BUSY;
	}

	if (test_bit(US_FLIDX_DISCONNECTING, &us->dflags)) {
		usb_stor_dbg(us, "Fail command during disconnect\n");
		srb->result = DID_NO_CONNECT << 16;
		done(srb);
		return 0;
	}

	srb->scsi_done = done;
	us->srb = srb;
	complete(&us->cmnd_ready);

	return 0;
}

static DEF_SCSI_QCMD(queuecommand)

static int command_abort(struct scsi_cmnd *srb)
{
	struct us_data *us = host_to_us(srb->device->host);

	usb_stor_dbg(us, "%s called\n", __func__);

	scsi_lock(us_to_host(us));

	if (us->srb != srb) {
		scsi_unlock(us_to_host(us));
		usb_stor_dbg(us, "-- nothing to abort\n");
		return FAILED;
	}

	set_bit(US_FLIDX_TIMED_OUT, &us->dflags);
	if (!test_bit(US_FLIDX_RESETTING, &us->dflags)) {
		set_bit(US_FLIDX_ABORTING, &us->dflags);
		usb_stor_stop_transport(us);
	}
	scsi_unlock(us_to_host(us));

	wait_for_completion(&us->notify);
	return SUCCESS;
}

static int device_reset(struct scsi_cmnd *srb)
{
	struct us_data *us = host_to_us(srb->device->host);
	int result;

	usb_stor_dbg(us, "%s called\n", __func__);

	mutex_lock(&(us->dev_mutex));
	result = us->transport_reset(us);
	mutex_unlock(&us->dev_mutex);

	return result < 0 ? FAILED : SUCCESS;
}

static int bus_reset(struct scsi_cmnd *srb)
{
	struct us_data *us = host_to_us(srb->device->host);
	int result;

	usb_stor_dbg(us, "%s called\n", __func__);

	result = usb_stor_port_reset(us);
	return result < 0 ? FAILED : SUCCESS;
}

void usb_stor_report_device_reset(struct us_data *us)
{
	int i;
	struct Scsi_Host *host = us_to_host(us);

	scsi_report_device_reset(host, 0, 0);
	if (us->fflags & US_FL_SCM_MULT_TARG) {
		for (i = 1; i < host->max_id; ++i)
			scsi_report_device_reset(host, 0, i);
	}
}

void usb_stor_report_bus_reset(struct us_data *us)
{
	struct Scsi_Host *host = us_to_host(us);

	scsi_lock(host);
	scsi_report_bus_reset(host, 0);
	scsi_unlock(host);
}

static int write_info(struct Scsi_Host *host, char *buffer, int length)
{
	 
	return length;
}

static int show_info (struct seq_file *m, struct Scsi_Host *host)
{
	struct us_data *us = host_to_us(host);
	const char *string;

	seq_printf(m, "   Host scsi%d: usb-storage\n", host->host_no);

	if (us->pusb_dev->manufacturer)
		string = us->pusb_dev->manufacturer;
	else if (us->unusual_dev->vendorName)
		string = us->unusual_dev->vendorName;
	else
		string = "Unknown";
	seq_printf(m, "       Vendor: %s\n", string);
	if (us->pusb_dev->product)
		string = us->pusb_dev->product;
	else if (us->unusual_dev->productName)
		string = us->unusual_dev->productName;
	else
		string = "Unknown";
	seq_printf(m, "      Product: %s\n", string);
	if (us->pusb_dev->serial)
		string = us->pusb_dev->serial;
	else
		string = "None";
	seq_printf(m, "Serial Number: %s\n", string);

	seq_printf(m, "     Protocol: %s\n", us->protocol_name);
	seq_printf(m, "    Transport: %s\n", us->transport_name);

	seq_printf(m, "       Quirks:");

#define US_FLAG(name, value) \
	if (us->fflags & value) seq_printf(m, " " #name);
US_DO_ALL_FLAGS
#undef US_FLAG
	seq_putc(m, '\n');
	return 0;
}

static ssize_t max_sectors_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);

	return sprintf(buf, "%u\n", queue_max_hw_sectors(sdev->request_queue));
}

static ssize_t max_sectors_store(struct device *dev, struct device_attribute *attr, const char *buf,
		size_t count)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	unsigned short ms;

	if (sscanf(buf, "%hu", &ms) > 0) {
		blk_queue_max_hw_sectors(sdev->request_queue, ms);
		return count;
	}
	return -EINVAL;
}

#ifdef MY_ABC_HERE
extern int blIsCardReader(struct usb_device *usbdev);
static ssize_t show_syno_cardreader(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdp = to_scsi_device(dev);
	struct us_data *us = host_to_us(sdp->host);
	struct usb_device *usbdev = us->pusb_dev;

	if (blIsCardReader(usbdev)) {
		return sprintf(buf, "1");
	} else {
		return sprintf(buf, "0");
	}
}
static DEVICE_ATTR(syno_cardreader, S_IRUGO, show_syno_cardreader, NULL);
#endif  
static DEVICE_ATTR_RW(max_sectors);

static struct device_attribute *sysfs_device_attr_list[] = {
	&dev_attr_max_sectors,
#ifdef MY_ABC_HERE
	&dev_attr_syno_cardreader,
#endif  
	NULL,
};

static const struct scsi_host_template usb_stor_host_template = {
	 
	.name =				"usb-storage",
	.proc_name =			"usb-storage",
	.show_info =			show_info,
	.write_info =			write_info,
	.info =				host_info,

	.queuecommand =			queuecommand,

	.eh_abort_handler =		command_abort,
	.eh_device_reset_handler =	device_reset,
	.eh_bus_reset_handler =		bus_reset,

	.can_queue =			1,

	.this_id =			-1,

	.slave_alloc =			slave_alloc,
	.slave_configure =		slave_configure,
	.target_alloc =			target_alloc,

	.sg_tablesize =			SCSI_MAX_SG_CHAIN_SEGMENTS,

	.max_sectors =                  240,

	.use_clustering =		1,

	.emulated =			1,

	.skip_settle_delay =		1,

	.sdev_attrs =			sysfs_device_attr_list,

#ifdef MY_ABC_HERE
	.syno_port_type         = SYNO_PORT_TYPE_USB,
#endif  

	.module =			THIS_MODULE
};

void usb_stor_host_template_init(struct scsi_host_template *sht,
				 const char *name, struct module *owner)
{
	*sht = usb_stor_host_template;
	sht->name = name;
	sht->proc_name = name;
	sht->module = owner;
}
EXPORT_SYMBOL_GPL(usb_stor_host_template_init);

unsigned char usb_stor_sense_invalidCDB[18] = {
	[0]	= 0x70,			     
	[2]	= ILLEGAL_REQUEST,	     
	[7]	= 0x0a,			     
	[12]	= 0x24			     
};
EXPORT_SYMBOL_GPL(usb_stor_sense_invalidCDB);
