#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/bio.h>
#include <linux/bitops.h>
#include <linux/blkdev.h>
#include <linux/completion.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/mempool.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/hardirq.h>
#include <linux/scatterlist.h>
#include <linux/blk-mq.h>
#include <linux/ratelimit.h>
#ifdef MY_ABC_HERE
#include <linux/ata.h>
#ifdef MY_ABC_HERE
#include <linux/synolib.h>
#endif  
#endif  

#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_dbg.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_driver.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_dh.h>

#include <trace/events/scsi.h>

#include "scsi_priv.h"
#include "scsi_logging.h"

#define SG_MEMPOOL_NR		ARRAY_SIZE(scsi_sg_pools)
#define SG_MEMPOOL_SIZE		2

#ifdef MY_DEF_HERE
extern int gSynoSASWriteConflictPanic;
#endif  

struct scsi_host_sg_pool {
	size_t		size;
	char		*name;
	struct kmem_cache	*slab;
	mempool_t	*pool;
};

#define SP(x) { .size = x, "sgpool-" __stringify(x) }
#if (SCSI_MAX_SG_SEGMENTS < 32)
#error SCSI_MAX_SG_SEGMENTS is too small (must be 32 or greater)
#endif
static struct scsi_host_sg_pool scsi_sg_pools[] = {
	SP(8),
	SP(16),
#if (SCSI_MAX_SG_SEGMENTS > 32)
	SP(32),
#if (SCSI_MAX_SG_SEGMENTS > 64)
	SP(64),
#if (SCSI_MAX_SG_SEGMENTS > 128)
	SP(128),
#if (SCSI_MAX_SG_SEGMENTS > 256)
#error SCSI_MAX_SG_SEGMENTS is too large (256 MAX)
#endif
#endif
#endif
#endif
	SP(SCSI_MAX_SG_SEGMENTS)
};
#undef SP

#ifdef MY_ABC_HERE
SDBADSECTORS grgSdBadSectors[CONFIG_SYNO_MAX_INTERNAL_DISK];
int gBadSectorTest = 0;
#endif  

struct kmem_cache *scsi_sdb_cache;

#define SCSI_QUEUE_DELAY	3

static void
scsi_set_blocked(struct scsi_cmnd *cmd, int reason)
{
	struct Scsi_Host *host = cmd->device->host;
	struct scsi_device *device = cmd->device;
	struct scsi_target *starget = scsi_target(device);

	switch (reason) {
	case SCSI_MLQUEUE_HOST_BUSY:
		atomic_set(&host->host_blocked, host->max_host_blocked);
		break;
	case SCSI_MLQUEUE_DEVICE_BUSY:
	case SCSI_MLQUEUE_EH_RETRY:
		atomic_set(&device->device_blocked,
			   device->max_device_blocked);
		break;
	case SCSI_MLQUEUE_TARGET_BUSY:
		atomic_set(&starget->target_blocked,
			   starget->max_target_blocked);
		break;
	}
}

static void scsi_mq_requeue_cmd(struct scsi_cmnd *cmd)
{
	struct scsi_device *sdev = cmd->device;
	struct request_queue *q = cmd->request->q;

	blk_mq_requeue_request(cmd->request);
	blk_mq_kick_requeue_list(q);
	put_device(&sdev->sdev_gendev);
}

static void __scsi_queue_insert(struct scsi_cmnd *cmd, int reason, int unbusy)
{
	struct scsi_device *device = cmd->device;
	struct request_queue *q = device->request_queue;
	unsigned long flags;

	SCSI_LOG_MLQUEUE(1, scmd_printk(KERN_INFO, cmd,
		"Inserting command %p into mlqueue\n", cmd));

	scsi_set_blocked(cmd, reason);

	if (unbusy)
		scsi_device_unbusy(device);

	cmd->result = 0;
	if (q->mq_ops) {
		scsi_mq_requeue_cmd(cmd);
		return;
	}
	spin_lock_irqsave(q->queue_lock, flags);
	blk_requeue_request(q, cmd->request);
	kblockd_schedule_work(&device->requeue_work);
	spin_unlock_irqrestore(q->queue_lock, flags);
}

void scsi_queue_insert(struct scsi_cmnd *cmd, int reason)
{
	__scsi_queue_insert(cmd, reason, 1);
}
 
int scsi_execute(struct scsi_device *sdev, const unsigned char *cmd,
		 int data_direction, void *buffer, unsigned bufflen,
		 unsigned char *sense, int timeout, int retries, u64 flags,
		 int *resid)
{
	struct request *req;
	int write = (data_direction == DMA_TO_DEVICE);
	int ret = DRIVER_ERROR << 24;

	req = blk_get_request(sdev->request_queue, write, __GFP_RECLAIM);
	if (IS_ERR(req))
		return ret;
	blk_rq_set_block_pc(req);

	if (bufflen &&	blk_rq_map_kern(sdev->request_queue, req,
					buffer, bufflen, __GFP_RECLAIM))
		goto out;

	req->cmd_len = COMMAND_SIZE(cmd[0]);
	memcpy(req->cmd, cmd, req->cmd_len);
	req->sense = sense;
	req->sense_len = 0;
	req->retries = retries;
#ifdef MY_ABC_HERE
	req->timeout = ((sdev->scmd_timeout_sec*HZ) > timeout ? (sdev->scmd_timeout_sec*HZ) : timeout);
#else  
	req->timeout = timeout;
#endif  
	req->cmd_flags |= flags | REQ_QUIET | REQ_PREEMPT;

	blk_execute_rq(req->q, NULL, req, 1);

	if (unlikely(req->resid_len > 0 && req->resid_len <= bufflen))
		memset(buffer + (bufflen - req->resid_len), 0, req->resid_len);

	if (resid)
		*resid = req->resid_len;
	ret = req->errors;
 out:
	blk_put_request(req);

	return ret;
}
EXPORT_SYMBOL(scsi_execute);

int scsi_execute_req_flags(struct scsi_device *sdev, const unsigned char *cmd,
		     int data_direction, void *buffer, unsigned bufflen,
		     struct scsi_sense_hdr *sshdr, int timeout, int retries,
		     int *resid, u64 flags)
{
	char *sense = NULL;
	int result;
	
	if (sshdr) {
		sense = kzalloc(SCSI_SENSE_BUFFERSIZE, GFP_NOIO);
		if (!sense)
			return DRIVER_ERROR << 24;
	}
	result = scsi_execute(sdev, cmd, data_direction, buffer, bufflen,
			      sense, timeout, retries, flags, resid);
	if (sshdr)
		scsi_normalize_sense(sense, SCSI_SENSE_BUFFERSIZE, sshdr);

	kfree(sense);
	return result;
}
EXPORT_SYMBOL(scsi_execute_req_flags);

static void scsi_init_cmd_errh(struct scsi_cmnd *cmd)
{
	cmd->serial_number = 0;
	scsi_set_resid(cmd, 0);
	memset(cmd->sense_buffer, 0, SCSI_SENSE_BUFFERSIZE);
	if (cmd->cmd_len == 0)
		cmd->cmd_len = scsi_command_size(cmd->cmnd);
}

#ifdef MY_ABC_HERE
 
static void __scsi_eh_wakeup(struct Scsi_Host *shost)
{
	unsigned long flags;

	spin_lock_irqsave(shost->host_lock, flags);
	if (unlikely(scsi_host_in_recovery(shost) &&
		     (shost->host_failed || shost->host_eh_scheduled)))
		scsi_eh_wakeup(shost);
	spin_unlock_irqrestore(shost->host_lock, flags);
}
#endif  

void scsi_device_unbusy(struct scsi_device *sdev)
{
	struct Scsi_Host *shost = sdev->host;
	struct scsi_target *starget = scsi_target(sdev);
#ifdef MY_ABC_HERE
#else
	unsigned long flags;
#endif  

	atomic_dec(&shost->host_busy);
	if (starget->can_queue > 0)
		atomic_dec(&starget->target_busy);

#ifdef MY_ABC_HERE
	__scsi_eh_wakeup(shost);
#else
	if (unlikely(scsi_host_in_recovery(shost) &&
		     (shost->host_failed || shost->host_eh_scheduled))) {
		spin_lock_irqsave(shost->host_lock, flags);
		scsi_eh_wakeup(shost);
		spin_unlock_irqrestore(shost->host_lock, flags);
	}

#endif  
	atomic_dec(&sdev->device_busy);
}

static void scsi_kick_queue(struct request_queue *q)
{
	if (q->mq_ops)
		blk_mq_start_hw_queues(q);
	else
		blk_run_queue(q);
}

static void scsi_single_lun_run(struct scsi_device *current_sdev)
{
	struct Scsi_Host *shost = current_sdev->host;
	struct scsi_device *sdev, *tmp;
	struct scsi_target *starget = scsi_target(current_sdev);
	unsigned long flags;

	spin_lock_irqsave(shost->host_lock, flags);
	starget->starget_sdev_user = NULL;
	spin_unlock_irqrestore(shost->host_lock, flags);

	scsi_kick_queue(current_sdev->request_queue);

	spin_lock_irqsave(shost->host_lock, flags);
	if (starget->starget_sdev_user)
		goto out;
	list_for_each_entry_safe(sdev, tmp, &starget->devices,
			same_target_siblings) {
		if (sdev == current_sdev)
			continue;
		if (scsi_device_get(sdev))
			continue;

		spin_unlock_irqrestore(shost->host_lock, flags);
		scsi_kick_queue(sdev->request_queue);
		spin_lock_irqsave(shost->host_lock, flags);
	
		scsi_device_put(sdev);
	}
 out:
	spin_unlock_irqrestore(shost->host_lock, flags);
}

static inline bool scsi_device_is_busy(struct scsi_device *sdev)
{
	if (atomic_read(&sdev->device_busy) >= sdev->queue_depth)
		return true;
	if (atomic_read(&sdev->device_blocked) > 0)
		return true;
	return false;
}

static inline bool scsi_target_is_busy(struct scsi_target *starget)
{
	if (starget->can_queue > 0) {
		if (atomic_read(&starget->target_busy) >= starget->can_queue)
			return true;
		if (atomic_read(&starget->target_blocked) > 0)
			return true;
	}
	return false;
}

static inline bool scsi_host_is_busy(struct Scsi_Host *shost)
{
	if (shost->can_queue > 0 &&
	    atomic_read(&shost->host_busy) >= shost->can_queue)
		return true;
	if (atomic_read(&shost->host_blocked) > 0)
		return true;
	if (shost->host_self_blocked)
		return true;
	return false;
}

static void scsi_starved_list_run(struct Scsi_Host *shost)
{
	LIST_HEAD(starved_list);
	struct scsi_device *sdev;
	unsigned long flags;

	spin_lock_irqsave(shost->host_lock, flags);
	list_splice_init(&shost->starved_list, &starved_list);

	while (!list_empty(&starved_list)) {
		struct request_queue *slq;

		if (scsi_host_is_busy(shost))
			break;

		sdev = list_entry(starved_list.next,
				  struct scsi_device, starved_entry);
		list_del_init(&sdev->starved_entry);
		if (scsi_target_is_busy(scsi_target(sdev))) {
			list_move_tail(&sdev->starved_entry,
				       &shost->starved_list);
			continue;
		}

		slq = sdev->request_queue;
		if (!blk_get_queue(slq))
			continue;
		spin_unlock_irqrestore(shost->host_lock, flags);

		scsi_kick_queue(slq);
		blk_put_queue(slq);

		spin_lock_irqsave(shost->host_lock, flags);
	}
	 
	list_splice(&starved_list, &shost->starved_list);
	spin_unlock_irqrestore(shost->host_lock, flags);
}

static void scsi_run_queue(struct request_queue *q)
{
	struct scsi_device *sdev = q->queuedata;

	if (scsi_target(sdev)->single_lun)
		scsi_single_lun_run(sdev);
	if (!list_empty(&sdev->host->starved_list))
		scsi_starved_list_run(sdev->host);

	if (q->mq_ops)
		blk_mq_start_stopped_hw_queues(q, false);
	else
		blk_run_queue(q);
}

void scsi_requeue_run_queue(struct work_struct *work)
{
	struct scsi_device *sdev;
	struct request_queue *q;

	sdev = container_of(work, struct scsi_device, requeue_work);
	q = sdev->request_queue;
	scsi_run_queue(q);
}

static void scsi_requeue_command(struct request_queue *q, struct scsi_cmnd *cmd)
{
	struct scsi_device *sdev = cmd->device;
	struct request *req = cmd->request;
	unsigned long flags;

	spin_lock_irqsave(q->queue_lock, flags);
	blk_unprep_request(req);
	req->special = NULL;
	scsi_put_command(cmd);
	blk_requeue_request(q, req);
	spin_unlock_irqrestore(q->queue_lock, flags);

	scsi_run_queue(q);

	put_device(&sdev->sdev_gendev);
}

void scsi_run_host_queues(struct Scsi_Host *shost)
{
	struct scsi_device *sdev;

	shost_for_each_device(sdev, shost)
		scsi_run_queue(sdev->request_queue);
}

static inline unsigned int scsi_sgtable_index(unsigned short nents)
{
	unsigned int index;

	BUG_ON(nents > SCSI_MAX_SG_SEGMENTS);

	if (nents <= 8)
		index = 0;
	else
		index = get_count_order(nents) - 3;

	return index;
}

static void scsi_sg_free(struct scatterlist *sgl, unsigned int nents)
{
	struct scsi_host_sg_pool *sgp;

	sgp = scsi_sg_pools + scsi_sgtable_index(nents);
	mempool_free(sgl, sgp->pool);
}

static struct scatterlist *scsi_sg_alloc(unsigned int nents, gfp_t gfp_mask)
{
	struct scsi_host_sg_pool *sgp;

	sgp = scsi_sg_pools + scsi_sgtable_index(nents);
	return mempool_alloc(sgp->pool, gfp_mask);
}

static void scsi_free_sgtable(struct scsi_data_buffer *sdb, bool mq)
{
	if (mq && sdb->table.orig_nents <= SCSI_MAX_SG_SEGMENTS)
		return;
	__sg_free_table(&sdb->table, SCSI_MAX_SG_SEGMENTS, mq, scsi_sg_free);
}

static int scsi_alloc_sgtable(struct scsi_data_buffer *sdb, int nents, bool mq)
{
	struct scatterlist *first_chunk = NULL;
	int ret;

	BUG_ON(!nents);

	if (mq) {
		if (nents <= SCSI_MAX_SG_SEGMENTS) {
			sdb->table.nents = sdb->table.orig_nents = nents;
			sg_init_table(sdb->table.sgl, nents);
			return 0;
		}
		first_chunk = sdb->table.sgl;
	}

	ret = __sg_alloc_table(&sdb->table, nents, SCSI_MAX_SG_SEGMENTS,
			       first_chunk, GFP_ATOMIC, scsi_sg_alloc);
	if (unlikely(ret))
		scsi_free_sgtable(sdb, mq);
	return ret;
}

static void scsi_uninit_cmd(struct scsi_cmnd *cmd)
{
	if (cmd->request->cmd_type == REQ_TYPE_FS) {
		struct scsi_driver *drv = scsi_cmd_to_driver(cmd);

		if (drv->uninit_command)
			drv->uninit_command(cmd);
	}
}

static void scsi_mq_free_sgtables(struct scsi_cmnd *cmd)
{
	if (cmd->sdb.table.nents)
		scsi_free_sgtable(&cmd->sdb, true);
	if (cmd->request->next_rq && cmd->request->next_rq->special)
		scsi_free_sgtable(cmd->request->next_rq->special, true);
	if (scsi_prot_sg_count(cmd))
		scsi_free_sgtable(cmd->prot_sdb, true);
}

static void scsi_mq_uninit_cmd(struct scsi_cmnd *cmd)
{
	struct scsi_device *sdev = cmd->device;
	struct Scsi_Host *shost = sdev->host;
	unsigned long flags;

	scsi_mq_free_sgtables(cmd);
	scsi_uninit_cmd(cmd);

	if (shost->use_cmd_list) {
		BUG_ON(list_empty(&cmd->list));
		spin_lock_irqsave(&sdev->list_lock, flags);
		list_del_init(&cmd->list);
		spin_unlock_irqrestore(&sdev->list_lock, flags);
	}
}

static void scsi_release_buffers(struct scsi_cmnd *cmd)
{
	if (cmd->sdb.table.nents)
		scsi_free_sgtable(&cmd->sdb, false);

	memset(&cmd->sdb, 0, sizeof(cmd->sdb));

	if (scsi_prot_sg_count(cmd))
		scsi_free_sgtable(cmd->prot_sdb, false);
}

#ifdef MY_DEF_HERE
static void SynoSpinupDone(struct request *req, int uptodate)
{
	struct scsi_device *sdev = req->q->queuedata;

	__blk_put_request(req->q, req);

	SynoSpinupEnd(sdev);
}

static void SynoSubmitSpinupReq(struct scsi_device *device)
{
	struct request *req;
	static int is_print = 0;

	while (1) {
		req = blk_get_request(device->request_queue, READ, GFP_ATOMIC);
		if (!req) {
			if (!is_print) {
				printk(KERN_ERR, "%s: Can't get request, retry it", __func__);
				is_print = 1;
			}
		} else {
			break;
		}
	}

	req->cmd[0] = START_STOP;
	req->cmd[1] = 0;
	req->cmd[2] = 0;
	req->cmd[3] = 0;
	req->cmd[4] = 1;  
	req->cmd[5] = 0;

	req->cmd_len = COMMAND_SIZE(req->cmd[0]);

	req->cmd_type = REQ_TYPE_BLOCK_PC;
	req->cmd_flags |= REQ_QUIET;
	req->timeout = 60 * HZ;
	req->retries = 5;

	blk_execute_rq_nowait(req->q, NULL, req, 1, SynoSpinupDone);
}

static void SynoSpinupDisk(struct scsi_device *device)
{
	if (SynoSpinupBegin(device)) {
		SynoSubmitSpinupReq(device);
	}
}
#endif  

static void scsi_release_bidi_buffers(struct scsi_cmnd *cmd)
{
	struct scsi_data_buffer *bidi_sdb = cmd->request->next_rq->special;

	scsi_free_sgtable(bidi_sdb, false);
	kmem_cache_free(scsi_sdb_cache, bidi_sdb);
	cmd->request->next_rq->special = NULL;
}

static bool scsi_end_request(struct request *req, int error,
		unsigned int bytes, unsigned int bidi_bytes)
{
	struct scsi_cmnd *cmd = req->special;
	struct scsi_device *sdev = cmd->device;
	struct request_queue *q = sdev->request_queue;

	if (blk_update_request(req, error, bytes))
		return true;

	if (unlikely(bidi_bytes) &&
	    blk_update_request(req->next_rq, error, bidi_bytes))
		return true;

	if (blk_queue_add_random(q))
		add_disk_randomness(req->rq_disk);

	if (req->mq_ctx) {
		 
		scsi_mq_uninit_cmd(cmd);

		__blk_mq_end_request(req, error);

		if (scsi_target(sdev)->single_lun ||
		    !list_empty(&sdev->host->starved_list))
			kblockd_schedule_work(&sdev->requeue_work);
		else
			blk_mq_start_stopped_hw_queues(q, true);
	} else {
		unsigned long flags;

		if (bidi_bytes)
			scsi_release_bidi_buffers(cmd);

		spin_lock_irqsave(q->queue_lock, flags);
		blk_finish_request(req, error);
		spin_unlock_irqrestore(q->queue_lock, flags);

		scsi_release_buffers(cmd);

		scsi_put_command(cmd);
		scsi_run_queue(q);
	}

	put_device(&sdev->sdev_gendev);
	return false;
}

static int __scsi_error_from_host_byte(struct scsi_cmnd *cmd, int result)
{
	int error = 0;

	switch(host_byte(result)) {
	case DID_TRANSPORT_FAILFAST:
		error = -ENOLINK;
		break;
	case DID_TARGET_FAILURE:
		set_host_byte(cmd, DID_OK);
		error = -EREMOTEIO;
		break;
	case DID_NEXUS_FAILURE:
		set_host_byte(cmd, DID_OK);
		error = -EBADE;
		break;
	case DID_ALLOC_FAILURE:
		set_host_byte(cmd, DID_OK);
		error = -ENOSPC;
		break;
	case DID_MEDIUM_ERROR:
		set_host_byte(cmd, DID_OK);
		error = -ENODATA;
		break;
	default:
		error = -EIO;
		break;
	}

	return error;
}

#ifdef MY_ABC_HERE
extern unsigned char
blSectorNeedAutoRemap(struct scsi_cmnd *scsi_cmd, sector_t lba);

static void
syno_scsi_do_remap_done(struct request *req, int uptodate)
{
	__blk_put_request(req->q, req);
}

static unsigned int
syno_scsi_do_remap(struct scsi_cmnd *scsi_cmd, sector_t badLba)
{
	unsigned int iRet = -1, iCheck = 0, i = 0;
	unsigned int uSectors = 0;
	struct request_queue *q = NULL;
	u8 lbal = 0;
	size_t size = 0;
	struct scsi_device *device = NULL;
	struct request *req = NULL;

	if (NULL == scsi_cmd) {
		printk("%s:%s(%d) Failed to get scsi_cmd", __FILE__, __FUNCTION__,  __LINE__);
		goto ERR;
	}

	device = scsi_cmd->device;
	if (NULL == device) {
		printk("%s:%s(%d) Failed to get device", __FILE__, __FUNCTION__,  __LINE__);
		goto ERR;
	}

	q = device->request_queue;
	if (NULL == q) {
		printk("%s:%s(%d) Failed to get request_queue\n", __FILE__, __FUNCTION__,  __LINE__);
		goto ERR;
	}

	uSectors = queue_physical_block_size(q) / queue_logical_block_size(q);
	lbal = (u8)(badLba & 0xff);
	lbal = (lbal & (~(uSectors - 1)));  
	size = SYNO_SCSI_SECT_SIZE * uSectors;

	req = blk_get_request(q, WRITE, GFP_ATOMIC);
	if (NULL == req) {
		printk("%s:%s(%d) Failed to get request\n", __FILE__, __FUNCTION__,  __LINE__);
		goto ERR;
	}

	req->cmd[0] = WRITE_16;
	req->cmd[1] = 0;
	 
	req->cmd[2] = (u8)((badLba & 0xff00000000000000) >> 56);
	req->cmd[3] = (u8)((badLba & 0xff000000000000) >> 48);
	req->cmd[4] = (u8)((badLba & 0xff0000000000) >> 40);
	req->cmd[5] = (u8)((badLba & 0xff00000000) >> 32);
	req->cmd[6] = (u8)((badLba & 0xff000000) >> 24);
	req->cmd[7] = (u8)((badLba & 0xff0000) >> 16);
	req->cmd[8] = (u8)((badLba & 0xff00) >> 8);
	req->cmd[9] = lbal;
	 
	req->cmd[10] = (u8)((uSectors & 0xff000000) >> 24);
	req->cmd[11] = (u8)((uSectors & 0xff0000) >> 16);
	req->cmd[12] = (u8)((uSectors & 0xff00) >> 8);
	req->cmd[13] = (u8)(uSectors & 0xff);

	req->cmd_len = COMMAND_SIZE(req->cmd[0]);

	req->cmd_type = REQ_TYPE_BLOCK_PC;
	req->cmd_flags |= REQ_QUIET;
	req->timeout = 60 * HZ;
	req->retries = 0;

	iCheck = blk_rq_map_kern(q, req, page_address(ZERO_PAGE(0)), size, GFP_DMA | GFP_KERNEL);
	if (0 != iCheck) {
		printk("%s:%s(%d) blk_rq_map_kern return != 0\n", __FILE__, __FUNCTION__,  __LINE__);
		goto ERR;
	}

	sdev_printk(KERN_INFO, device, "Insert write command :");
	for (i = 0; i < req->cmd_len; ++i) {
		printk("%02x ", req->cmd[i]);
	}
	printk("\n");

	blk_execute_rq_nowait(q, NULL, req, 1, syno_scsi_do_remap_done);

	iRet = 0;
	goto OUT;
ERR:
	if (NULL != req) {
		blk_put_request(req);
	}
OUT:
	return iRet;
}

static int
syno_scsi_check_ncq_fake_unc(const u8 * sense_buffer, int iSbLen)
{
	int iRet = 0;
	const u8 * desc = NULL;
	u8 format = 0;

	if (7 > iSbLen) {
		goto OUT;
	}

	format = 0x7f & sense_buffer[0];
	if (0x72 == format || 0x73 == format) {
		desc = scsi_sense_desc_find(sense_buffer, iSbLen, 0  );
		if (desc && (0xa == desc[1])) {
			iRet = SYNO_NCQ_FAKE_UNC & desc[SYNO_DESCRIPTOR_RESERVED_INDEX];
		}
	}
OUT:
	return iRet;
}

static unsigned int
syno_scsi_writes_sector(struct scsi_cmnd *scsi_cmd)
{
	unsigned int iRet = -1, iCheck = 0;
	sector_t badLba = 0;
	u8 blIsWrite = 0;
#ifdef MY_ABC_HERE
	struct bio* b = NULL;
	unsigned int len = 0;
	int i = 0;
#endif  

	if (NULL == scsi_cmd) {
		printk("%s:%s(%d) Failed to get scsi_cmd", __FILE__, __FUNCTION__,  __LINE__);
		goto ERR;
	}

	if (NULL == scsi_cmd->request) {
		printk("%s:%s(%d) Failed to get scsi_cmd request\n", __FILE__, __FUNCTION__,  __LINE__);
		goto ERR;
	}

	if (NULL == scsi_cmd->sense_buffer) {
		printk("%s:%s(%d) Failed to get scsi_cmd sense_buffer\n", __FILE__, __FUNCTION__,  __LINE__);
		goto ERR;
	}

	if (NULL == scsi_cmd->cmnd) {
		printk("%s:%s(%d) Failed to get scsi_cmd cmnd\n", __FILE__, __FUNCTION__,  __LINE__);
		goto ERR;
	}

	iCheck = scsi_get_sense_info_fld(scsi_cmd->sense_buffer,
			SCSI_SENSE_BUFFERSIZE,
			(u64*) &badLba);
	if (0 == iCheck) {
		printk("%s:%s(%d) sense info in sense data invalid\n", __FILE__, __FUNCTION__,  __LINE__);
		goto ERR;
	}

	if (syno_scsi_check_ncq_fake_unc(scsi_cmd->sense_buffer, SCSI_SENSE_BUFFERSIZE)) {
		scmd_printk(KERN_INFO, scsi_cmd, "UNC ERROR code but NCQ abort, do NOT remap");
		goto ERR;
	}

	switch (scsi_cmd->cmnd[0]) {
		case WRITE_6:
		case WRITE_10:
		case WRITE_12:
		case WRITE_16:
		case WRITE_32:
			blIsWrite = 1;
			break;
		default:
			if (DMA_TO_DEVICE == scsi_cmd->sc_data_direction) {
				blIsWrite = 1;
			}
	}

	scmd_printk(KERN_INFO, scsi_cmd, "%s unc at %llu\n",
		(blIsWrite) ? "write" : "read",
		(unsigned long long)badLba);

	if (!blIsWrite && !blSectorNeedAutoRemap(scsi_cmd, badLba)) {
		goto ERR;
	}

#ifdef MY_ABC_HERE
	 
	if (!blIsWrite) {
		for (b = scsi_cmd->request->bio; b; b = b->bi_next) {
			len = 0;
			for (i = 0; i < b->bi_vcnt; i++) {
				len += b->bi_io_vec[i].bv_len;
			}
			if (b->bi_iter.bi_sector <= badLba && badLba < b->bi_iter.bi_sector + (len >> 9)) {
				bio_set_flag(b, BIO_AUTO_REMAP);
				printk("%s:%s(%d) set bio BIO_AUTO_REMAP bit on\n",
					__FILE__, __FUNCTION__, __LINE__);
			}
		}
	}
#endif  

	syno_scsi_do_remap(scsi_cmd, badLba);
	iRet = 0;
ERR:
	return iRet;
}
#endif  

void scsi_io_completion(struct scsi_cmnd *cmd, unsigned int good_bytes)
{
	int result = cmd->result;
	struct request_queue *q = cmd->device->request_queue;
	struct request *req = cmd->request;
	int error = 0;
	struct scsi_sense_hdr sshdr;
	bool sense_valid = false;
	int sense_deferred = 0, level = 0;
	enum {ACTION_FAIL, ACTION_REPREP, ACTION_RETRY,
	      ACTION_DELAYED_RETRY} action;
	unsigned long wait_for = (cmd->allowed + 1) * req->timeout;

	if (result) {
		sense_valid = scsi_command_normalize_sense(cmd, &sshdr);
		if (sense_valid)
			sense_deferred = scsi_sense_is_deferred(&sshdr);
	}

#ifdef MY_DEF_HERE
	 
	if (1 == gSynoSASWriteConflictPanic) {
		if (unlikely(RESERVATION_CONFLICT == status_byte(cmd->result) && COMMAND_COMPLETE == msg_byte(cmd->result) &&
			(WRITE_6 == cmd->cmnd[0] ||
			 WRITE_10 == cmd->cmnd[0] ||
			 WRITE_12 == cmd->cmnd[0] ||
			 WRITE_16 == cmd->cmnd[0] ||
			 WRITE_32 == cmd->cmnd[0] ||
			 WRITE_SAME == cmd->cmnd[0] ||
			 WRITE_SAME_16 == cmd->cmnd[0] ||
			 WRITE_SAME_32 == cmd->cmnd[0] ||
			 WRITE_VERIFY == cmd->cmnd[0] ||
			 WRITE_VERIFY_12 == cmd->cmnd[0] ||
			 WRITE_LONG == cmd->cmnd[0] ||
			 WRITE_LONG_2 == cmd->cmnd[0]))) {
			scmd_printk(KERN_INFO, cmd, "Unhandled error code\n");
			scsi_print_result(cmd, NULL, FAILED);
			scsi_print_sense(cmd);
			scsi_print_command(cmd);
			panic("Reservation conflict!, try to reboot\n");
		}
	}
#endif  

#ifdef MY_DEF_HERE
	 
	if ((cmd->device->spinup_queue) &&
		(status_byte(result) == CHECK_CONDITION) &&
		(sshdr.sense_key == NOT_READY) &&
		(sshdr.asc == 0x04)) {
		switch (cmd->cmnd[0]) {
			 
			case TEST_UNIT_READY:
			case REQUEST_SENSE:
				 
				break;
			default:
				switch (sshdr.ascq) {
					case 0x02:  
						SynoSpinupDisk(cmd->device);
						 
					case 0x01:  
					case 0x11:  
						action = ACTION_DELAYED_RETRY;
						goto handle_cmd;
						break;
					default:
						 
						break;
				}
				break;
		}
	}
#endif  

	if (req->cmd_type == REQ_TYPE_BLOCK_PC) {  
		if (result) {
			if (sense_valid && req->sense) {
				 
				int len = 8 + cmd->sense_buffer[7];

				if (len > SCSI_SENSE_BUFFERSIZE)
					len = SCSI_SENSE_BUFFERSIZE;
				memcpy(req->sense, cmd->sense_buffer,  len);
				req->sense_len = len;
			}
			if (!sense_deferred)
				error = __scsi_error_from_host_byte(cmd, result);
		}
		 
		req->errors = cmd->result;

		req->resid_len = scsi_get_resid(cmd);

		if (scsi_bidi_cmnd(cmd)) {
			 
			req->next_rq->resid_len = scsi_in(cmd)->resid;
			if (scsi_end_request(req, 0, blk_rq_bytes(req),
					blk_rq_bytes(req->next_rq)))
				BUG();
			return;
		}
	} else if (blk_rq_bytes(req) == 0 && result && !sense_deferred) {
		 
		error = __scsi_error_from_host_byte(cmd, result);
	}

	BUG_ON(blk_bidi_rq(req));

	SCSI_LOG_HLCOMPLETE(1, scmd_printk(KERN_INFO, cmd,
		"%u sectors total, %d bytes done.\n",
		blk_rq_sectors(req), good_bytes));

	if (sense_valid && (sshdr.sense_key == RECOVERED_ERROR)) {
		 
		if ((sshdr.asc == 0x0) && (sshdr.ascq == 0x1d))
			;
		else if (!(req->cmd_flags & REQ_QUIET))
			scsi_print_sense(cmd);
		result = 0;
		 
		error = 0;
	}

	if (!(blk_rq_bytes(req) == 0 && error) &&
	    !scsi_end_request(req, error, good_bytes, 0))
		return;

	if (error && scsi_noretry_cmd(cmd)) {
		if (scsi_end_request(req, error, blk_rq_bytes(req), 0))
			BUG();
		return;
	}

	if (result == 0)
		goto requeue;

	error = __scsi_error_from_host_byte(cmd, result);

	if (host_byte(result) == DID_RESET) {
		 
		action = ACTION_RETRY;
	} else if (sense_valid && !sense_deferred) {
		switch (sshdr.sense_key) {
		case UNIT_ATTENTION:
			if (cmd->device->removable) {
				 
				cmd->device->changed = 1;
				action = ACTION_FAIL;
			} else {
				 
				action = ACTION_RETRY;
			}
			break;
		case ILLEGAL_REQUEST:
			 
			if ((cmd->device->use_10_for_rw &&
			    sshdr.asc == 0x20 && sshdr.ascq == 0x00) &&
			    (cmd->cmnd[0] == READ_10 ||
			     cmd->cmnd[0] == WRITE_10)) {
				 
				cmd->device->use_10_for_rw = 0;
				action = ACTION_REPREP;
			} else if (sshdr.asc == 0x10)   {
				action = ACTION_FAIL;
				error = -EILSEQ;
			 
			} else if (sshdr.asc == 0x20 || sshdr.asc == 0x24) {
				action = ACTION_FAIL;
				error = -EREMOTEIO;
			} else
				action = ACTION_FAIL;
			break;
		case ABORTED_COMMAND:
			action = ACTION_FAIL;
			if (sshdr.asc == 0x10)  
				error = -EILSEQ;
			break;
		case NOT_READY:
			 
			if (sshdr.asc == 0x04) {
				switch (sshdr.ascq) {
				case 0x01:  
				case 0x04:  
				case 0x05:  
				case 0x06:  
				case 0x07:  
				case 0x08:  
				case 0x09:  
				case 0x14:  
					action = ACTION_DELAYED_RETRY;
					break;
				default:
					action = ACTION_FAIL;
					break;
				}
			} else
				action = ACTION_FAIL;
			break;
		case VOLUME_OVERFLOW:
			 
			action = ACTION_FAIL;
			break;
#ifdef MY_ABC_HERE
		case MEDIUM_ERROR:
			switch (sshdr.asc) {
				case 0x11:
					switch (sshdr.ascq) {
						case 0x00:
						case 0x04:
						case 0x14:
							syno_scsi_writes_sector(cmd);
							action = ACTION_FAIL;
							break;
						default:
							action = ACTION_FAIL;
							break;
					}
					break;
				default:
					action = ACTION_FAIL;
					break;
			}
			break;
#endif  
		default:
			action = ACTION_FAIL;
			break;
		}
	} else
		action = ACTION_FAIL;

	if (action != ACTION_FAIL &&
	    time_before(cmd->jiffies_at_alloc + wait_for, jiffies))
		action = ACTION_FAIL;

#ifdef MY_DEF_HERE
handle_cmd:
#endif  
	switch (action) {
	case ACTION_FAIL:
		 
		if (!(req->cmd_flags & REQ_QUIET)) {
			static DEFINE_RATELIMIT_STATE(_rs,
					DEFAULT_RATELIMIT_INTERVAL,
					DEFAULT_RATELIMIT_BURST);

			if (unlikely(scsi_logging_level))
				level = SCSI_LOG_LEVEL(SCSI_LOG_MLCOMPLETE_SHIFT,
						       SCSI_LOG_MLCOMPLETE_BITS);

			if (!level && __ratelimit(&_rs)) {
				scsi_print_result(cmd, NULL, FAILED);
				if (driver_byte(result) & DRIVER_SENSE)
					scsi_print_sense(cmd);
				scsi_print_command(cmd);
			}
		}
		if (!scsi_end_request(req, error, blk_rq_err_bytes(req), 0))
			return;
		 
	case ACTION_REPREP:
	requeue:
		 
		if (q->mq_ops) {
			cmd->request->cmd_flags &= ~REQ_DONTPREP;
			scsi_mq_uninit_cmd(cmd);
			scsi_mq_requeue_cmd(cmd);
		} else {
			scsi_release_buffers(cmd);
			scsi_requeue_command(q, cmd);
		}
		break;
	case ACTION_RETRY:
		 
		__scsi_queue_insert(cmd, SCSI_MLQUEUE_EH_RETRY, 0);
		break;
	case ACTION_DELAYED_RETRY:
		 
		__scsi_queue_insert(cmd, SCSI_MLQUEUE_DEVICE_BUSY, 0);
		break;
	}
}

static int scsi_init_sgtable(struct request *req, struct scsi_data_buffer *sdb)
{
	int count;

	if (unlikely(scsi_alloc_sgtable(sdb, req->nr_phys_segments,
					req->mq_ctx != NULL)))
		return BLKPREP_DEFER;

	count = blk_rq_map_sg(req->q, req, sdb->table.sgl);
	BUG_ON(count > sdb->table.nents);
	sdb->table.nents = count;
	sdb->length = blk_rq_bytes(req);
	return BLKPREP_OK;
}

int scsi_init_io(struct scsi_cmnd *cmd)
{
	struct scsi_device *sdev = cmd->device;
	struct request *rq = cmd->request;
	bool is_mq = (rq->mq_ctx != NULL);
	int error;

	if (WARN_ON_ONCE(!rq->nr_phys_segments))
		return -EINVAL;

	error = scsi_init_sgtable(rq, &cmd->sdb);
	if (error)
		goto err_exit;

#ifdef MY_ABC_HERE
	if (0 < gBadSectorTest) {
		sector_t badSector, curSector;
		int i;
		struct gendisk *disk = cmd->request->rq_disk;
		char *diskname = NULL;
		int max_support_disk = sizeof(grgSdBadSectors) / sizeof(SDBADSECTORS);

		if (disk) {
			diskname = disk->disk_name;
			i = SynoGetInternalDiskSeq(diskname);
			curSector = blk_rq_pos(cmd->request);
			if (i < max_support_disk && grgSdBadSectors[i].uiEnable) {
				int j;
				for (j = 0; j < 100; j++) {
					badSector = grgSdBadSectors[i].rgSectors[j];
					if (curSector <= badSector && (curSector + blk_rq_sectors(cmd->request)) >= badSector) {
						if (grgSdBadSectors[i].rgEnableSector[j] & EN_BAD_SECTOR_READ) {
							if (READ == rq_data_dir(cmd->request)) {
								printk("%s[%d]:%s [%s], found badsector at %llu of %s curSector %llu\n",
									   __FILE__, __LINE__, __FUNCTION__,
									   "read",
									   (unsigned long long)badSector,
									   diskname,
									   (unsigned long long)curSector);
								return BLKPREP_KILL;
							} else {
								grgSdBadSectors[i].rgEnableSector[j] &= ~EN_BAD_SECTOR_READ;
							}
						}
						if (grgSdBadSectors[i].rgEnableSector[j] & EN_BAD_SECTOR_WRITE) {
							if (WRITE == rq_data_dir(cmd->request)) {
								printk("%s[%d]:%s [%s], found badsector at %llu of %s curSector %llu\n",
									   __FILE__, __LINE__, __FUNCTION__,
									   "write",
									   (unsigned long long)badSector,
									   diskname,
									   (unsigned long long)curSector);
								return BLKPREP_KILL;
							}
						}
					} else if ( 0xFFFFFFFF == badSector) {
						break;
					}
				}
			}
		}
	}
#endif  

	if (blk_bidi_rq(rq)) {
		if (!rq->q->mq_ops) {
			struct scsi_data_buffer *bidi_sdb =
				kmem_cache_zalloc(scsi_sdb_cache, GFP_ATOMIC);
			if (!bidi_sdb) {
				error = BLKPREP_DEFER;
				goto err_exit;
			}

			rq->next_rq->special = bidi_sdb;
		}

		error = scsi_init_sgtable(rq->next_rq, rq->next_rq->special);
		if (error)
			goto err_exit;
	}

	if (blk_integrity_rq(rq)) {
		struct scsi_data_buffer *prot_sdb = cmd->prot_sdb;
		int ivecs, count;

		if (prot_sdb == NULL) {
			 
			WARN_ON_ONCE(1);
			error = BLKPREP_KILL;
			goto err_exit;
		}

		ivecs = blk_rq_count_integrity_sg(rq->q, rq->bio);

		if (scsi_alloc_sgtable(prot_sdb, ivecs, is_mq)) {
			error = BLKPREP_DEFER;
			goto err_exit;
		}

		count = blk_rq_map_integrity_sg(rq->q, rq->bio,
						prot_sdb->table.sgl);
		BUG_ON(unlikely(count > ivecs));
		BUG_ON(unlikely(count > queue_max_integrity_segments(rq->q)));

		cmd->prot_sdb = prot_sdb;
		cmd->prot_sdb->table.nents = count;
	}

	return BLKPREP_OK;
err_exit:
	if (is_mq) {
		scsi_mq_free_sgtables(cmd);
	} else {
		scsi_release_buffers(cmd);
		cmd->request->special = NULL;
		scsi_put_command(cmd);
		put_device(&sdev->sdev_gendev);
	}
	return error;
}
EXPORT_SYMBOL(scsi_init_io);

static struct scsi_cmnd *scsi_get_cmd_from_req(struct scsi_device *sdev,
		struct request *req)
{
	struct scsi_cmnd *cmd;

	if (!req->special) {
		 
		if (!get_device(&sdev->sdev_gendev))
			return NULL;

		cmd = scsi_get_command(sdev, GFP_ATOMIC);
		if (unlikely(!cmd)) {
			put_device(&sdev->sdev_gendev);
			return NULL;
		}
		req->special = cmd;
	} else {
		cmd = req->special;
	}

	cmd->tag = req->tag;
	cmd->request = req;

	cmd->cmnd = req->cmd;
	cmd->prot_op = SCSI_PROT_NORMAL;

	return cmd;
}

static int scsi_setup_blk_pc_cmnd(struct scsi_device *sdev, struct request *req)
{
	struct scsi_cmnd *cmd = req->special;

	if (req->bio) {
		int ret = scsi_init_io(cmd);
		if (unlikely(ret))
			return ret;
	} else {
		BUG_ON(blk_rq_bytes(req));

		memset(&cmd->sdb, 0, sizeof(cmd->sdb));
	}

	cmd->cmd_len = req->cmd_len;
	cmd->transfersize = blk_rq_bytes(req);
	cmd->allowed = req->retries;
	return BLKPREP_OK;
}

static int scsi_setup_fs_cmnd(struct scsi_device *sdev, struct request *req)
{
	struct scsi_cmnd *cmd = req->special;

	if (unlikely(sdev->handler && sdev->handler->prep_fn)) {
		int ret = sdev->handler->prep_fn(sdev, req);
		if (ret != BLKPREP_OK)
			return ret;
	}

	memset(cmd->cmnd, 0, BLK_MAX_CDB);
	return scsi_cmd_to_driver(cmd)->init_command(cmd);
}

static int scsi_setup_cmnd(struct scsi_device *sdev, struct request *req)
{
	struct scsi_cmnd *cmd = req->special;

	if (!blk_rq_bytes(req))
		cmd->sc_data_direction = DMA_NONE;
	else if (rq_data_dir(req) == WRITE)
		cmd->sc_data_direction = DMA_TO_DEVICE;
	else
		cmd->sc_data_direction = DMA_FROM_DEVICE;

	switch (req->cmd_type) {
	case REQ_TYPE_FS:
		return scsi_setup_fs_cmnd(sdev, req);
	case REQ_TYPE_BLOCK_PC:
		return scsi_setup_blk_pc_cmnd(sdev, req);
	default:
		return BLKPREP_KILL;
	}
}

static int
scsi_prep_state_check(struct scsi_device *sdev, struct request *req)
{
	int ret = BLKPREP_OK;

	if (unlikely(sdev->sdev_state != SDEV_RUNNING)) {
		switch (sdev->sdev_state) {
		case SDEV_OFFLINE:
		case SDEV_TRANSPORT_OFFLINE:
			 
#ifdef MY_ABC_HERE
			if (printk_ratelimit()) {
#endif  
			sdev_printk(KERN_ERR, sdev,
				    "rejecting I/O to offline device\n");
#ifdef MY_ABC_HERE
			}
#endif  
			ret = BLKPREP_KILL;
			break;
		case SDEV_DEL:
			 
			sdev_printk(KERN_ERR, sdev,
				    "rejecting I/O to dead device\n");
			ret = BLKPREP_KILL;
			break;
		case SDEV_BLOCK:
		case SDEV_CREATED_BLOCK:
			ret = BLKPREP_DEFER;
			break;
		case SDEV_QUIESCE:
			 
			if (!(req->cmd_flags & REQ_PREEMPT))
				ret = BLKPREP_DEFER;
			break;
		default:
			 
			if (!(req->cmd_flags & REQ_PREEMPT))
				ret = BLKPREP_KILL;
			break;
		}
	}
	return ret;
}

static int
scsi_prep_return(struct request_queue *q, struct request *req, int ret)
{
	struct scsi_device *sdev = q->queuedata;

	switch (ret) {
	case BLKPREP_KILL:
		req->errors = DID_NO_CONNECT << 16;
		 
		if (req->special) {
			struct scsi_cmnd *cmd = req->special;
			scsi_release_buffers(cmd);
			scsi_put_command(cmd);
			put_device(&sdev->sdev_gendev);
			req->special = NULL;
		}
		break;
	case BLKPREP_DEFER:
		 
		if (atomic_read(&sdev->device_busy) == 0)
			blk_delay_queue(q, SCSI_QUEUE_DELAY);
		break;
	default:
		req->cmd_flags |= REQ_DONTPREP;
	}

	return ret;
}

static int scsi_prep_fn(struct request_queue *q, struct request *req)
{
	struct scsi_device *sdev = q->queuedata;
	struct scsi_cmnd *cmd;
	int ret;

	ret = scsi_prep_state_check(sdev, req);
	if (ret != BLKPREP_OK)
		goto out;

	cmd = scsi_get_cmd_from_req(sdev, req);
	if (unlikely(!cmd)) {
		ret = BLKPREP_DEFER;
		goto out;
	}

	ret = scsi_setup_cmnd(sdev, req);
out:
	return scsi_prep_return(q, req, ret);
}

static void scsi_unprep_fn(struct request_queue *q, struct request *req)
{
	scsi_uninit_cmd(req->special);
}

static inline int scsi_dev_queue_ready(struct request_queue *q,
				  struct scsi_device *sdev)
{
	unsigned int busy;

	busy = atomic_inc_return(&sdev->device_busy) - 1;
	if (atomic_read(&sdev->device_blocked)) {
		if (busy)
			goto out_dec;

		if (atomic_dec_return(&sdev->device_blocked) > 0) {
			 
			if (!q->mq_ops)
				blk_delay_queue(q, SCSI_QUEUE_DELAY);
			goto out_dec;
		}
		SCSI_LOG_MLQUEUE(3, sdev_printk(KERN_INFO, sdev,
				   "unblocking device at zero depth\n"));
	}

	if (busy >= sdev->queue_depth)
		goto out_dec;

	return 1;
out_dec:
	atomic_dec(&sdev->device_busy);
	return 0;
}

static inline int scsi_target_queue_ready(struct Scsi_Host *shost,
					   struct scsi_device *sdev)
{
	struct scsi_target *starget = scsi_target(sdev);
	unsigned int busy;

	if (starget->single_lun) {
		spin_lock_irq(shost->host_lock);
		if (starget->starget_sdev_user &&
		    starget->starget_sdev_user != sdev) {
			spin_unlock_irq(shost->host_lock);
			return 0;
		}
		starget->starget_sdev_user = sdev;
		spin_unlock_irq(shost->host_lock);
	}

	if (starget->can_queue <= 0)
		return 1;

	busy = atomic_inc_return(&starget->target_busy) - 1;
	if (atomic_read(&starget->target_blocked) > 0) {
		if (busy)
			goto starved;

		if (atomic_dec_return(&starget->target_blocked) > 0)
			goto out_dec;

		SCSI_LOG_MLQUEUE(3, starget_printk(KERN_INFO, starget,
				 "unblocking target at zero depth\n"));
	}

	if (busy >= starget->can_queue)
		goto starved;

	return 1;

starved:
	spin_lock_irq(shost->host_lock);
	list_move_tail(&sdev->starved_entry, &shost->starved_list);
	spin_unlock_irq(shost->host_lock);
out_dec:
	if (starget->can_queue > 0)
		atomic_dec(&starget->target_busy);
	return 0;
}

static inline int scsi_host_queue_ready(struct request_queue *q,
				   struct Scsi_Host *shost,
				   struct scsi_device *sdev)
{
	unsigned int busy;

	if (scsi_host_in_recovery(shost))
		return 0;

	busy = atomic_inc_return(&shost->host_busy) - 1;
	if (atomic_read(&shost->host_blocked) > 0) {
		if (busy)
			goto starved;

		if (atomic_dec_return(&shost->host_blocked) > 0)
			goto out_dec;

		SCSI_LOG_MLQUEUE(3,
			shost_printk(KERN_INFO, shost,
				     "unblocking host at zero depth\n"));
	}

	if (shost->can_queue > 0 && busy >= shost->can_queue)
		goto starved;
	if (shost->host_self_blocked)
		goto starved;

	if (!list_empty(&sdev->starved_entry)) {
		spin_lock_irq(shost->host_lock);
		if (!list_empty(&sdev->starved_entry))
			list_del_init(&sdev->starved_entry);
		spin_unlock_irq(shost->host_lock);
	}

	return 1;

starved:
	spin_lock_irq(shost->host_lock);
	if (list_empty(&sdev->starved_entry))
		list_add_tail(&sdev->starved_entry, &shost->starved_list);
	spin_unlock_irq(shost->host_lock);
out_dec:
	atomic_dec(&shost->host_busy);
#ifdef MY_ABC_HERE
	__scsi_eh_wakeup(shost);
#endif  
	return 0;
}

static int scsi_lld_busy(struct request_queue *q)
{
	struct scsi_device *sdev = q->queuedata;
	struct Scsi_Host *shost;

	if (blk_queue_dying(q))
		return 0;

	shost = sdev->host;

	if (scsi_host_in_recovery(shost) || scsi_device_is_busy(sdev))
		return 1;

	return 0;
}

static void scsi_kill_request(struct request *req, struct request_queue *q)
{
	struct scsi_cmnd *cmd = req->special;
	struct scsi_device *sdev;
	struct scsi_target *starget;
	struct Scsi_Host *shost;

	blk_start_request(req);

	scmd_printk(KERN_INFO, cmd, "killing request\n");

	sdev = cmd->device;
	starget = scsi_target(sdev);
	shost = sdev->host;
	scsi_init_cmd_errh(cmd);
	cmd->result = DID_NO_CONNECT << 16;
	atomic_inc(&cmd->device->iorequest_cnt);

	atomic_inc(&sdev->device_busy);
	atomic_inc(&shost->host_busy);
	if (starget->can_queue > 0)
		atomic_inc(&starget->target_busy);

	blk_complete_request(req);
}

static void scsi_softirq_done(struct request *rq)
{
	struct scsi_cmnd *cmd = rq->special;
	unsigned long wait_for = (cmd->allowed + 1) * rq->timeout;
	int disposition;

	INIT_LIST_HEAD(&cmd->eh_entry);

	atomic_inc(&cmd->device->iodone_cnt);
	if (cmd->result)
		atomic_inc(&cmd->device->ioerr_cnt);

	disposition = scsi_decide_disposition(cmd);
	if (disposition != SUCCESS &&
	    time_before(cmd->jiffies_at_alloc + wait_for, jiffies)) {
		sdev_printk(KERN_ERR, cmd->device,
			    "timing out command, waited %lus\n",
			    wait_for/HZ);
		disposition = SUCCESS;
	}

	scsi_log_completion(cmd, disposition);

	switch (disposition) {
		case SUCCESS:
			scsi_finish_command(cmd);
			break;
		case NEEDS_RETRY:
			scsi_queue_insert(cmd, SCSI_MLQUEUE_EH_RETRY);
			break;
		case ADD_TO_MLQUEUE:
			scsi_queue_insert(cmd, SCSI_MLQUEUE_DEVICE_BUSY);
			break;
		default:
			if (!scsi_eh_scmd_add(cmd, 0))
				scsi_finish_command(cmd);
	}
}

#if defined(MY_ABC_HERE) && defined(MY_ABC_HERE)
 
static void syno_disk_hiternation_cmd_printk(struct scsi_device *sdp, struct scsi_cmnd *cmd)
{
	 
	if (SYNO_PORT_TYPE_SATA == sdp->host->hostt->syno_port_type ||
		SYNO_PORT_TYPE_SAS  == sdp->host->hostt->syno_port_type) {
		 
		syno_do_hibernation_scsi_log(sdp->syno_disk_name);
	} else if (SYNO_PORT_TYPE_USB == sdp->host->hostt->syno_port_type) {
		char szBuf[128];
		struct mm_struct *mm;
		int len;
		if (current) {
			mm = current->mm;
			if (mm) {
				len = mm->arg_end - mm->arg_start;
				memset(szBuf, 0, sizeof(szBuf));
				memcpy(szBuf, (unsigned char *)mm->arg_start, len);
				printk(KERN_WARNING"%s[%d]:%s(), %s: spin up by pid=%d, name=%s\n",
					   __FILE__, __LINE__, __FUNCTION__,
					   sdp->syno_disk_name, current->pid, szBuf);
			} else {
				printk(KERN_WARNING"%s[%d]:%s(), %s: spin up by pid = %d, current->mm = NULL\n",
					   __FILE__, __LINE__, __FUNCTION__,
					   sdp->syno_disk_name, current->pid);
			}
		} else {
			printk(KERN_WARNING"%s[%d]:%s(), current = NULL\n",
				   __FILE__, __LINE__, __FUNCTION__);
		}
	}
}
#endif  

static int scsi_dispatch_cmd(struct scsi_cmnd *cmd)
{
	struct Scsi_Host *host = cmd->device->host;
	int rtn = 0;

	atomic_inc(&cmd->device->iorequest_cnt);

	if (unlikely(cmd->device->sdev_state == SDEV_DEL)) {
		 
		cmd->result = DID_NO_CONNECT << 16;
		goto done;
	}

	if (unlikely(scsi_device_blocked(cmd->device))) {
		 
		SCSI_LOG_MLQUEUE(3, scmd_printk(KERN_INFO, cmd,
			"queuecommand : device blocked\n"));
		return SCSI_MLQUEUE_DEVICE_BUSY;
	}

	if (cmd->device->lun_in_cdb)
		cmd->cmnd[1] = (cmd->cmnd[1] & 0x1f) |
			       (cmd->device->lun << 5 & 0xe0);

	scsi_log_send(cmd);

	if (cmd->cmd_len > cmd->device->host->max_cmd_len) {
		SCSI_LOG_MLQUEUE(3, scmd_printk(KERN_INFO, cmd,
			       "queuecommand : command too long. "
			       "cdb_size=%d host->max_cmd_len=%d\n",
			       cmd->cmd_len, cmd->device->host->max_cmd_len));
		cmd->result = (DID_ABORT << 16);
		goto done;
	}

#ifdef MY_ABC_HERE
	 
	if (cmd->device->spindown &&
	 
		!(ATA_16 == cmd->cmnd[0] && (ATA_CMD_PMP_WRITE == cmd->cmnd[14] || ATA_CMD_PMP_READ == cmd->cmnd[14])) &&
		TEST_UNIT_READY != cmd->cmnd[0]) {
#ifdef MY_ABC_HERE
		if (0 < gSynoHibernationLogLevel) {
			syno_disk_hiternation_cmd_printk(cmd->device, cmd);
		}
#endif  
		if (0 == cmd->device->do_standby_syncing) {
			cmd->device->idle = jiffies;
		}
		cmd->device->spindown = 0;
	}

	if (0x0C == cmd->cmnd[0]) {
		struct scatterlist *sg;
		unsigned char* pBuffer;

		if (cmd->sdb.table.nents) {
			sg = (struct scatterlist *)cmd->sdb.table.sgl;
			pBuffer = kmap_atomic(sg_page(sg)) + sg->offset;
		} else {
			pBuffer = (char *)cmd->sdb.table.sgl;
		}

		if (0xE0 == pBuffer[0]) {
			cmd->device->spindown = 1;
		}

		if (cmd->sdb.table.nents) {
			kunmap_atomic(pBuffer - sg->offset);
		}
	} else if (ATA_16 == cmd->cmnd[0]) {
		 
		if (0xE0 == cmd->cmnd[14]) {
			cmd->device->spindown = 1;
		}
	} else if (START_STOP == cmd->cmnd[0]) {
		if (0x01 == cmd->cmnd[4]) {
			 
#ifdef MY_ABC_HERE
			if (0 < gSynoHibernationLogLevel) {
				syno_disk_hiternation_cmd_printk(cmd->device, cmd);
			}
#endif  
			if (0 == cmd->device->do_standby_syncing) {
				cmd->device->idle = jiffies;
			}
		}
	} else if (LOG_SENSE != cmd->cmnd[0] &&
			TEST_UNIT_READY != cmd->cmnd[0] &&
			SYNCHRONIZE_CACHE != cmd->cmnd[0]) {

#ifdef MY_ABC_HERE
			if (1 < gSynoHibernationLogLevel) {  
				syno_disk_hiternation_cmd_printk(cmd->device, cmd);
			}
#endif  

		if (0 == cmd->device->do_standby_syncing) {
			cmd->device->idle = jiffies;
		}
	}
#endif  

	if (unlikely(host->shost_state == SHOST_DEL)) {
		cmd->result = (DID_NO_CONNECT << 16);
		goto done;

	}

	trace_scsi_dispatch_cmd_start(cmd);
	rtn = host->hostt->queuecommand(host, cmd);
	if (rtn) {
		trace_scsi_dispatch_cmd_error(cmd, rtn);
		if (rtn != SCSI_MLQUEUE_DEVICE_BUSY &&
		    rtn != SCSI_MLQUEUE_TARGET_BUSY)
			rtn = SCSI_MLQUEUE_HOST_BUSY;

		SCSI_LOG_MLQUEUE(3, scmd_printk(KERN_INFO, cmd,
			"queuecommand : request rejected\n"));
	}

	return rtn;
 done:
	cmd->scsi_done(cmd);
	return 0;
}

static void scsi_done(struct scsi_cmnd *cmd)
{
	trace_scsi_dispatch_cmd_done(cmd);
	blk_complete_request(cmd->request);
}

static void scsi_request_fn(struct request_queue *q)
	__releases(q->queue_lock)
	__acquires(q->queue_lock)
{
	struct scsi_device *sdev = q->queuedata;
	struct Scsi_Host *shost;
	struct scsi_cmnd *cmd;
	struct request *req;

	shost = sdev->host;
	for (;;) {
		int rtn;
		 
		req = blk_peek_request(q);
		if (!req)
			break;

		if (unlikely(!scsi_device_online(sdev))) {
#ifdef MY_ABC_HERE
			if (printk_ratelimit()) {
#endif  
			sdev_printk(KERN_ERR, sdev,
				    "rejecting I/O to offline device\n");
#ifdef MY_ABC_HERE
			}
#endif  
			scsi_kill_request(req, q);
			continue;
		}

		if (!scsi_dev_queue_ready(q, sdev))
			break;

		if (!(blk_queue_tagged(q) && !blk_queue_start_tag(q, req)))
			blk_start_request(req);

		spin_unlock_irq(q->queue_lock);
		cmd = req->special;
		if (unlikely(cmd == NULL)) {
			printk(KERN_CRIT "impossible request in %s.\n"
					 "please mail a stack trace to "
					 "linux-scsi@vger.kernel.org\n",
					 __func__);
			blk_dump_rq_flags(req, "foo");
			BUG();
		}

		if (blk_queue_tagged(q) && !(req->cmd_flags & REQ_QUEUED)) {
			spin_lock_irq(shost->host_lock);
			if (list_empty(&sdev->starved_entry))
				list_add_tail(&sdev->starved_entry,
					      &shost->starved_list);
			spin_unlock_irq(shost->host_lock);
			goto not_ready;
		}

		if (!scsi_target_queue_ready(shost, sdev))
			goto not_ready;

		if (!scsi_host_queue_ready(q, shost, sdev))
			goto host_not_ready;
	
		if (sdev->simple_tags)
			cmd->flags |= SCMD_TAGGED;
		else
			cmd->flags &= ~SCMD_TAGGED;

		scsi_init_cmd_errh(cmd);

		cmd->scsi_done = scsi_done;
		rtn = scsi_dispatch_cmd(cmd);
		if (rtn) {
			scsi_queue_insert(cmd, rtn);
			spin_lock_irq(q->queue_lock);
			goto out_delay;
		}
		spin_lock_irq(q->queue_lock);
	}

	return;

 host_not_ready:
	if (scsi_target(sdev)->can_queue > 0)
		atomic_dec(&scsi_target(sdev)->target_busy);
 not_ready:
	 
	spin_lock_irq(q->queue_lock);
	blk_requeue_request(q, req);
	atomic_dec(&sdev->device_busy);
out_delay:
	if (!atomic_read(&sdev->device_busy) && !scsi_device_blocked(sdev))
		blk_delay_queue(q, SCSI_QUEUE_DELAY);
}

static inline int prep_to_mq(int ret)
{
	switch (ret) {
	case BLKPREP_OK:
		return 0;
	case BLKPREP_DEFER:
		return BLK_MQ_RQ_QUEUE_BUSY;
	default:
		return BLK_MQ_RQ_QUEUE_ERROR;
	}
}

static int scsi_mq_prep_fn(struct request *req)
{
	struct scsi_cmnd *cmd = blk_mq_rq_to_pdu(req);
	struct scsi_device *sdev = req->q->queuedata;
	struct Scsi_Host *shost = sdev->host;
	unsigned char *sense_buf = cmd->sense_buffer;
	struct scatterlist *sg;

	memset(cmd, 0, sizeof(struct scsi_cmnd));

	req->special = cmd;

	cmd->request = req;
	cmd->device = sdev;
	cmd->sense_buffer = sense_buf;

	cmd->tag = req->tag;

	cmd->cmnd = req->cmd;
	cmd->prot_op = SCSI_PROT_NORMAL;

	INIT_LIST_HEAD(&cmd->list);
	INIT_DELAYED_WORK(&cmd->abort_work, scmd_eh_abort_handler);
	cmd->jiffies_at_alloc = jiffies;

	if (shost->use_cmd_list) {
		spin_lock_irq(&sdev->list_lock);
		list_add_tail(&cmd->list, &sdev->cmd_list);
		spin_unlock_irq(&sdev->list_lock);
	}

	sg = (void *)cmd + sizeof(struct scsi_cmnd) + shost->hostt->cmd_size;
	cmd->sdb.table.sgl = sg;

	if (scsi_host_get_prot(shost)) {
		cmd->prot_sdb = (void *)sg +
			min_t(unsigned int,
			      shost->sg_tablesize, SCSI_MAX_SG_SEGMENTS) *
			sizeof(struct scatterlist);
		memset(cmd->prot_sdb, 0, sizeof(struct scsi_data_buffer));

		cmd->prot_sdb->table.sgl =
			(struct scatterlist *)(cmd->prot_sdb + 1);
	}

	if (blk_bidi_rq(req)) {
		struct request *next_rq = req->next_rq;
		struct scsi_data_buffer *bidi_sdb = blk_mq_rq_to_pdu(next_rq);

		memset(bidi_sdb, 0, sizeof(struct scsi_data_buffer));
		bidi_sdb->table.sgl =
			(struct scatterlist *)(bidi_sdb + 1);

		next_rq->special = bidi_sdb;
	}

	blk_mq_start_request(req);

	return scsi_setup_cmnd(sdev, req);
}

static void scsi_mq_done(struct scsi_cmnd *cmd)
{
	trace_scsi_dispatch_cmd_done(cmd);
	blk_mq_complete_request(cmd->request, cmd->request->errors);
}

static int scsi_queue_rq(struct blk_mq_hw_ctx *hctx,
			 const struct blk_mq_queue_data *bd)
{
	struct request *req = bd->rq;
	struct request_queue *q = req->q;
	struct scsi_device *sdev = q->queuedata;
	struct Scsi_Host *shost = sdev->host;
	struct scsi_cmnd *cmd = blk_mq_rq_to_pdu(req);
	int ret;
	int reason;

	ret = prep_to_mq(scsi_prep_state_check(sdev, req));
	if (ret)
		goto out;

	ret = BLK_MQ_RQ_QUEUE_BUSY;
	if (!get_device(&sdev->sdev_gendev))
		goto out;

	if (!scsi_dev_queue_ready(q, sdev))
		goto out_put_device;
	if (!scsi_target_queue_ready(shost, sdev))
		goto out_dec_device_busy;
	if (!scsi_host_queue_ready(q, shost, sdev))
		goto out_dec_target_busy;

	if (!(req->cmd_flags & REQ_DONTPREP)) {
		ret = prep_to_mq(scsi_mq_prep_fn(req));
		if (ret)
			goto out_dec_host_busy;
		req->cmd_flags |= REQ_DONTPREP;
	} else {
		blk_mq_start_request(req);
	}

	if (sdev->simple_tags)
		cmd->flags |= SCMD_TAGGED;
	else
		cmd->flags &= ~SCMD_TAGGED;

	scsi_init_cmd_errh(cmd);
	cmd->scsi_done = scsi_mq_done;

	reason = scsi_dispatch_cmd(cmd);
	if (reason) {
		scsi_set_blocked(cmd, reason);
		ret = BLK_MQ_RQ_QUEUE_BUSY;
		goto out_dec_host_busy;
	}

	return BLK_MQ_RQ_QUEUE_OK;

out_dec_host_busy:
	atomic_dec(&shost->host_busy);
#ifdef MY_ABC_HERE
	__scsi_eh_wakeup(shost);
#endif  
out_dec_target_busy:
	if (scsi_target(sdev)->can_queue > 0)
		atomic_dec(&scsi_target(sdev)->target_busy);
out_dec_device_busy:
	atomic_dec(&sdev->device_busy);
out_put_device:
	put_device(&sdev->sdev_gendev);
out:
	switch (ret) {
	case BLK_MQ_RQ_QUEUE_BUSY:
		blk_mq_stop_hw_queue(hctx);
		if (atomic_read(&sdev->device_busy) == 0 &&
		    !scsi_device_blocked(sdev))
			blk_mq_delay_queue(hctx, SCSI_QUEUE_DELAY);
		break;
	case BLK_MQ_RQ_QUEUE_ERROR:
		 
		if (req->cmd_flags & REQ_DONTPREP)
			scsi_mq_uninit_cmd(cmd);
		break;
	default:
		break;
	}
	return ret;
}

static enum blk_eh_timer_return scsi_timeout(struct request *req,
		bool reserved)
{
	if (reserved)
		return BLK_EH_RESET_TIMER;
	return scsi_times_out(req);
}

static int scsi_init_request(void *data, struct request *rq,
		unsigned int hctx_idx, unsigned int request_idx,
		unsigned int numa_node)
{
	struct scsi_cmnd *cmd = blk_mq_rq_to_pdu(rq);

	cmd->sense_buffer = kzalloc_node(SCSI_SENSE_BUFFERSIZE, GFP_KERNEL,
			numa_node);
	if (!cmd->sense_buffer)
		return -ENOMEM;
	return 0;
}

static void scsi_exit_request(void *data, struct request *rq,
		unsigned int hctx_idx, unsigned int request_idx)
{
	struct scsi_cmnd *cmd = blk_mq_rq_to_pdu(rq);

	kfree(cmd->sense_buffer);
}

static u64 scsi_calculate_bounce_limit(struct Scsi_Host *shost)
{
	struct device *host_dev;
	u64 bounce_limit = 0xffffffff;

	if (shost->unchecked_isa_dma)
		return BLK_BOUNCE_ISA;
	 
	if (!PCI_DMA_BUS_IS_PHYS)
		return BLK_BOUNCE_ANY;

	host_dev = scsi_get_device(shost);
	if (host_dev && host_dev->dma_mask)
		bounce_limit = (u64)dma_max_pfn(host_dev) << PAGE_SHIFT;

	return bounce_limit;
}

static void __scsi_init_queue(struct Scsi_Host *shost, struct request_queue *q)
{
	struct device *dev = shost->dma_dev;

	blk_queue_max_segments(q, min_t(unsigned short, shost->sg_tablesize,
					SCSI_MAX_SG_CHAIN_SEGMENTS));

	if (scsi_host_prot_dma(shost)) {
		shost->sg_prot_tablesize =
			min_not_zero(shost->sg_prot_tablesize,
				     (unsigned short)SCSI_MAX_PROT_SG_SEGMENTS);
		BUG_ON(shost->sg_prot_tablesize < shost->sg_tablesize);
		blk_queue_max_integrity_segments(q, shost->sg_prot_tablesize);
	}

	blk_queue_max_hw_sectors(q, shost->max_sectors);
	blk_queue_bounce_limit(q, scsi_calculate_bounce_limit(shost));
	blk_queue_segment_boundary(q, shost->dma_boundary);
	dma_set_seg_boundary(dev, shost->dma_boundary);

	blk_queue_max_segment_size(q, dma_get_max_seg_size(dev));

	if (!shost->use_clustering)
		q->limits.cluster = 0;

	blk_queue_dma_alignment(q, 0x03);
}

struct request_queue *__scsi_alloc_queue(struct Scsi_Host *shost,
					 request_fn_proc *request_fn)
{
	struct request_queue *q;

	q = blk_init_queue(request_fn, NULL);
	if (!q)
		return NULL;
	__scsi_init_queue(shost, q);
	return q;
}
EXPORT_SYMBOL(__scsi_alloc_queue);

struct request_queue *scsi_alloc_queue(struct scsi_device *sdev)
{
	struct request_queue *q;

	q = __scsi_alloc_queue(sdev->host, scsi_request_fn);
	if (!q)
		return NULL;

	blk_queue_prep_rq(q, scsi_prep_fn);
	blk_queue_unprep_rq(q, scsi_unprep_fn);
	blk_queue_softirq_done(q, scsi_softirq_done);
	blk_queue_rq_timed_out(q, scsi_times_out);
	blk_queue_lld_busy(q, scsi_lld_busy);
	return q;
}

static struct blk_mq_ops scsi_mq_ops = {
	.map_queue	= blk_mq_map_queue,
	.queue_rq	= scsi_queue_rq,
	.complete	= scsi_softirq_done,
	.timeout	= scsi_timeout,
	.init_request	= scsi_init_request,
	.exit_request	= scsi_exit_request,
};

struct request_queue *scsi_mq_alloc_queue(struct scsi_device *sdev)
{
	sdev->request_queue = blk_mq_init_queue(&sdev->host->tag_set);
	if (IS_ERR(sdev->request_queue))
		return NULL;

	sdev->request_queue->queuedata = sdev;
	__scsi_init_queue(sdev->host, sdev->request_queue);
	return sdev->request_queue;
}

int scsi_mq_setup_tags(struct Scsi_Host *shost)
{
	unsigned int cmd_size, sgl_size, tbl_size;

	tbl_size = shost->sg_tablesize;
	if (tbl_size > SCSI_MAX_SG_SEGMENTS)
		tbl_size = SCSI_MAX_SG_SEGMENTS;
	sgl_size = tbl_size * sizeof(struct scatterlist);
	cmd_size = sizeof(struct scsi_cmnd) + shost->hostt->cmd_size + sgl_size;
	if (scsi_host_get_prot(shost))
		cmd_size += sizeof(struct scsi_data_buffer) + sgl_size;

	memset(&shost->tag_set, 0, sizeof(shost->tag_set));
	shost->tag_set.ops = &scsi_mq_ops;
	shost->tag_set.nr_hw_queues = shost->nr_hw_queues ? : 1;
	shost->tag_set.queue_depth = shost->can_queue;
	shost->tag_set.cmd_size = cmd_size;
	shost->tag_set.numa_node = NUMA_NO_NODE;
	shost->tag_set.flags = BLK_MQ_F_SHOULD_MERGE | BLK_MQ_F_SG_MERGE;
	shost->tag_set.flags |=
		BLK_ALLOC_POLICY_TO_MQ_FLAG(shost->hostt->tag_alloc_policy);
	shost->tag_set.driver_data = shost;

	return blk_mq_alloc_tag_set(&shost->tag_set);
}

void scsi_mq_destroy_tags(struct Scsi_Host *shost)
{
	blk_mq_free_tag_set(&shost->tag_set);
}

struct scsi_device *scsi_device_from_queue(struct request_queue *q)
{
	struct scsi_device *sdev = NULL;

	if (q->mq_ops) {
		if (q->mq_ops == &scsi_mq_ops)
			sdev = q->queuedata;
	} else if (q->request_fn == scsi_request_fn)
		sdev = q->queuedata;
	if (!sdev || !get_device(&sdev->sdev_gendev))
		sdev = NULL;

	return sdev;
}
EXPORT_SYMBOL_GPL(scsi_device_from_queue);

void scsi_block_requests(struct Scsi_Host *shost)
{
	shost->host_self_blocked = 1;
}
EXPORT_SYMBOL(scsi_block_requests);

void scsi_unblock_requests(struct Scsi_Host *shost)
{
	shost->host_self_blocked = 0;
	scsi_run_host_queues(shost);
}
EXPORT_SYMBOL(scsi_unblock_requests);

int __init scsi_init_queue(void)
{
	int i;

	scsi_sdb_cache = kmem_cache_create("scsi_data_buffer",
					   sizeof(struct scsi_data_buffer),
					   0, 0, NULL);
	if (!scsi_sdb_cache) {
		printk(KERN_ERR "SCSI: can't init scsi sdb cache\n");
		return -ENOMEM;
	}

	for (i = 0; i < SG_MEMPOOL_NR; i++) {
		struct scsi_host_sg_pool *sgp = scsi_sg_pools + i;
		int size = sgp->size * sizeof(struct scatterlist);

		sgp->slab = kmem_cache_create(sgp->name, size, 0,
				SLAB_HWCACHE_ALIGN, NULL);
		if (!sgp->slab) {
			printk(KERN_ERR "SCSI: can't init sg slab %s\n",
					sgp->name);
			goto cleanup_sdb;
		}

		sgp->pool = mempool_create_slab_pool(SG_MEMPOOL_SIZE,
						     sgp->slab);
		if (!sgp->pool) {
			printk(KERN_ERR "SCSI: can't init sg mempool %s\n",
					sgp->name);
			goto cleanup_sdb;
		}
	}

	return 0;

cleanup_sdb:
	for (i = 0; i < SG_MEMPOOL_NR; i++) {
		struct scsi_host_sg_pool *sgp = scsi_sg_pools + i;
		if (sgp->pool)
			mempool_destroy(sgp->pool);
		if (sgp->slab)
			kmem_cache_destroy(sgp->slab);
	}
	kmem_cache_destroy(scsi_sdb_cache);

	return -ENOMEM;
}

void scsi_exit_queue(void)
{
	int i;

	kmem_cache_destroy(scsi_sdb_cache);

	for (i = 0; i < SG_MEMPOOL_NR; i++) {
		struct scsi_host_sg_pool *sgp = scsi_sg_pools + i;
		mempool_destroy(sgp->pool);
		kmem_cache_destroy(sgp->slab);
	}
}

int
scsi_mode_select(struct scsi_device *sdev, int pf, int sp, int modepage,
		 unsigned char *buffer, int len, int timeout, int retries,
		 struct scsi_mode_data *data, struct scsi_sense_hdr *sshdr)
{
	unsigned char cmd[10];
	unsigned char *real_buffer;
	int ret;

	memset(cmd, 0, sizeof(cmd));
	cmd[1] = (pf ? 0x10 : 0) | (sp ? 0x01 : 0);

	if (sdev->use_10_for_ms) {
		if (len > 65535)
			return -EINVAL;
		real_buffer = kmalloc(8 + len, GFP_KERNEL);
		if (!real_buffer)
			return -ENOMEM;
		memcpy(real_buffer + 8, buffer, len);
		len += 8;
		real_buffer[0] = 0;
		real_buffer[1] = 0;
		real_buffer[2] = data->medium_type;
		real_buffer[3] = data->device_specific;
		real_buffer[4] = data->longlba ? 0x01 : 0;
		real_buffer[5] = 0;
		real_buffer[6] = data->block_descriptor_length >> 8;
		real_buffer[7] = data->block_descriptor_length;

		cmd[0] = MODE_SELECT_10;
		cmd[7] = len >> 8;
		cmd[8] = len;
	} else {
		if (len > 255 || data->block_descriptor_length > 255 ||
		    data->longlba)
			return -EINVAL;

		real_buffer = kmalloc(4 + len, GFP_KERNEL);
		if (!real_buffer)
			return -ENOMEM;
		memcpy(real_buffer + 4, buffer, len);
		len += 4;
		real_buffer[0] = 0;
		real_buffer[1] = data->medium_type;
		real_buffer[2] = data->device_specific;
		real_buffer[3] = data->block_descriptor_length;
		
		cmd[0] = MODE_SELECT;
		cmd[4] = len;
	}

	ret = scsi_execute_req(sdev, cmd, DMA_TO_DEVICE, real_buffer, len,
			       sshdr, timeout, retries, NULL);
	kfree(real_buffer);
	return ret;
}
EXPORT_SYMBOL_GPL(scsi_mode_select);

int
scsi_mode_sense(struct scsi_device *sdev, int dbd, int modepage,
		  unsigned char *buffer, int len, int timeout, int retries,
		  struct scsi_mode_data *data, struct scsi_sense_hdr *sshdr)
{
	unsigned char cmd[12];
	int use_10_for_ms;
	int header_length;
	int result, retry_count = retries;
	struct scsi_sense_hdr my_sshdr;

	memset(data, 0, sizeof(*data));
	memset(&cmd[0], 0, 12);
	cmd[1] = dbd & 0x18;	 
	cmd[2] = modepage;

	if (!sshdr)
		sshdr = &my_sshdr;

 retry:
	use_10_for_ms = sdev->use_10_for_ms;

	if (use_10_for_ms) {
		if (len < 8)
			len = 8;

		cmd[0] = MODE_SENSE_10;
		cmd[8] = len;
		header_length = 8;
	} else {
		if (len < 4)
			len = 4;

		cmd[0] = MODE_SENSE;
		cmd[4] = len;
		header_length = 4;
	}

	memset(buffer, 0, len);

	result = scsi_execute_req(sdev, cmd, DMA_FROM_DEVICE, buffer, len,
				  sshdr, timeout, retries, NULL);

	if (use_10_for_ms && !scsi_status_is_good(result) &&
	    (driver_byte(result) & DRIVER_SENSE)) {
		if (scsi_sense_valid(sshdr)) {
			if ((sshdr->sense_key == ILLEGAL_REQUEST) &&
			    (sshdr->asc == 0x20) && (sshdr->ascq == 0)) {
				 
				sdev->use_10_for_ms = 0;
				goto retry;
			}
		}
	}

	if(scsi_status_is_good(result)) {
		if (unlikely(buffer[0] == 0x86 && buffer[1] == 0x0b &&
			     (modepage == 6 || modepage == 8))) {
			 
			header_length = 0;
			data->length = 13;
			data->medium_type = 0;
			data->device_specific = 0;
			data->longlba = 0;
			data->block_descriptor_length = 0;
		} else if(use_10_for_ms) {
			data->length = buffer[0]*256 + buffer[1] + 2;
			data->medium_type = buffer[2];
			data->device_specific = buffer[3];
			data->longlba = buffer[4] & 0x01;
			data->block_descriptor_length = buffer[6]*256
				+ buffer[7];
		} else {
			data->length = buffer[0] + 1;
			data->medium_type = buffer[1];
			data->device_specific = buffer[2];
			data->block_descriptor_length = buffer[3];
		}
		data->header_length = header_length;
	} else if ((status_byte(result) == CHECK_CONDITION) &&
		   scsi_sense_valid(sshdr) &&
		   sshdr->sense_key == UNIT_ATTENTION && retry_count) {
		retry_count--;
		goto retry;
	}

	return result;
}
EXPORT_SYMBOL(scsi_mode_sense);

int
scsi_test_unit_ready(struct scsi_device *sdev, int timeout, int retries,
		     struct scsi_sense_hdr *sshdr_external)
{
	char cmd[] = {
		TEST_UNIT_READY, 0, 0, 0, 0, 0,
	};
	struct scsi_sense_hdr *sshdr;
	int result;

	if (!sshdr_external)
		sshdr = kzalloc(sizeof(*sshdr), GFP_KERNEL);
	else
		sshdr = sshdr_external;

	do {
		result = scsi_execute_req(sdev, cmd, DMA_NONE, NULL, 0, sshdr,
					  timeout, retries, NULL);
		if (sdev->removable && scsi_sense_valid(sshdr) &&
		    sshdr->sense_key == UNIT_ATTENTION)
			sdev->changed = 1;
	} while (scsi_sense_valid(sshdr) &&
		 sshdr->sense_key == UNIT_ATTENTION && --retries);

	if (!sshdr_external)
		kfree(sshdr);
	return result;
}
EXPORT_SYMBOL(scsi_test_unit_ready);

int
scsi_device_set_state(struct scsi_device *sdev, enum scsi_device_state state)
{
	enum scsi_device_state oldstate = sdev->sdev_state;

	if (state == oldstate)
		return 0;

	switch (state) {
	case SDEV_CREATED:
		switch (oldstate) {
		case SDEV_CREATED_BLOCK:
			break;
		default:
			goto illegal;
		}
		break;
			
	case SDEV_RUNNING:
		switch (oldstate) {
		case SDEV_CREATED:
		case SDEV_OFFLINE:
		case SDEV_TRANSPORT_OFFLINE:
		case SDEV_QUIESCE:
		case SDEV_BLOCK:
			break;
		default:
			goto illegal;
		}
		break;

	case SDEV_QUIESCE:
		switch (oldstate) {
		case SDEV_RUNNING:
		case SDEV_OFFLINE:
		case SDEV_TRANSPORT_OFFLINE:
			break;
		default:
			goto illegal;
		}
		break;

	case SDEV_OFFLINE:
	case SDEV_TRANSPORT_OFFLINE:
		switch (oldstate) {
		case SDEV_CREATED:
		case SDEV_RUNNING:
		case SDEV_QUIESCE:
		case SDEV_BLOCK:
			break;
		default:
			goto illegal;
		}
		break;

	case SDEV_BLOCK:
		switch (oldstate) {
		case SDEV_RUNNING:
		case SDEV_CREATED_BLOCK:
			break;
		default:
			goto illegal;
		}
		break;

	case SDEV_CREATED_BLOCK:
		switch (oldstate) {
		case SDEV_CREATED:
			break;
		default:
			goto illegal;
		}
		break;

	case SDEV_CANCEL:
		switch (oldstate) {
		case SDEV_CREATED:
		case SDEV_RUNNING:
		case SDEV_QUIESCE:
		case SDEV_OFFLINE:
		case SDEV_TRANSPORT_OFFLINE:
		case SDEV_BLOCK:
			break;
		default:
			goto illegal;
		}
		break;

	case SDEV_DEL:
		switch (oldstate) {
		case SDEV_CREATED:
		case SDEV_RUNNING:
		case SDEV_OFFLINE:
		case SDEV_TRANSPORT_OFFLINE:
		case SDEV_CANCEL:
		case SDEV_CREATED_BLOCK:
			break;
		default:
			goto illegal;
		}
		break;

	}
	sdev->sdev_state = state;
	return 0;

 illegal:
	SCSI_LOG_ERROR_RECOVERY(1,
				sdev_printk(KERN_ERR, sdev,
					    "Illegal state transition %s->%s",
					    scsi_device_state_name(oldstate),
					    scsi_device_state_name(state))
				);
	return -EINVAL;
}
EXPORT_SYMBOL(scsi_device_set_state);

static void scsi_evt_emit(struct scsi_device *sdev, struct scsi_event *evt)
{
	int idx = 0;
	char *envp[3];

	switch (evt->evt_type) {
	case SDEV_EVT_MEDIA_CHANGE:
		envp[idx++] = "SDEV_MEDIA_CHANGE=1";
		break;
	case SDEV_EVT_INQUIRY_CHANGE_REPORTED:
		envp[idx++] = "SDEV_UA=INQUIRY_DATA_HAS_CHANGED";
		break;
	case SDEV_EVT_CAPACITY_CHANGE_REPORTED:
		envp[idx++] = "SDEV_UA=CAPACITY_DATA_HAS_CHANGED";
		break;
	case SDEV_EVT_SOFT_THRESHOLD_REACHED_REPORTED:
	       envp[idx++] = "SDEV_UA=THIN_PROVISIONING_SOFT_THRESHOLD_REACHED";
		break;
	case SDEV_EVT_MODE_PARAMETER_CHANGE_REPORTED:
		envp[idx++] = "SDEV_UA=MODE_PARAMETERS_CHANGED";
		break;
	case SDEV_EVT_LUN_CHANGE_REPORTED:
		envp[idx++] = "SDEV_UA=REPORTED_LUNS_DATA_HAS_CHANGED";
		break;
	case SDEV_EVT_ALUA_STATE_CHANGE_REPORTED:
		envp[idx++] = "SDEV_UA=ASYMMETRIC_ACCESS_STATE_CHANGED";
		break;
	default:
		 
		break;
	}

	envp[idx++] = NULL;

	kobject_uevent_env(&sdev->sdev_gendev.kobj, KOBJ_CHANGE, envp);
}

void scsi_evt_thread(struct work_struct *work)
{
	struct scsi_device *sdev;
	enum scsi_device_event evt_type;
	LIST_HEAD(event_list);

	sdev = container_of(work, struct scsi_device, event_work);

	for (evt_type = SDEV_EVT_FIRST; evt_type <= SDEV_EVT_LAST; evt_type++)
		if (test_and_clear_bit(evt_type, sdev->pending_events))
			sdev_evt_send_simple(sdev, evt_type, GFP_KERNEL);

	while (1) {
		struct scsi_event *evt;
		struct list_head *this, *tmp;
		unsigned long flags;

		spin_lock_irqsave(&sdev->list_lock, flags);
		list_splice_init(&sdev->event_list, &event_list);
		spin_unlock_irqrestore(&sdev->list_lock, flags);

		if (list_empty(&event_list))
			break;

		list_for_each_safe(this, tmp, &event_list) {
			evt = list_entry(this, struct scsi_event, node);
			list_del(&evt->node);
			scsi_evt_emit(sdev, evt);
			kfree(evt);
		}
	}
}

void sdev_evt_send(struct scsi_device *sdev, struct scsi_event *evt)
{
	unsigned long flags;

#if 0
	 
	if (!test_bit(evt->evt_type, sdev->supported_events)) {
		kfree(evt);
		return;
	}
#endif

	spin_lock_irqsave(&sdev->list_lock, flags);
	list_add_tail(&evt->node, &sdev->event_list);
	schedule_work(&sdev->event_work);
	spin_unlock_irqrestore(&sdev->list_lock, flags);
}
EXPORT_SYMBOL_GPL(sdev_evt_send);

struct scsi_event *sdev_evt_alloc(enum scsi_device_event evt_type,
				  gfp_t gfpflags)
{
	struct scsi_event *evt = kzalloc(sizeof(struct scsi_event), gfpflags);
	if (!evt)
		return NULL;

	evt->evt_type = evt_type;
	INIT_LIST_HEAD(&evt->node);

	switch (evt_type) {
	case SDEV_EVT_MEDIA_CHANGE:
	case SDEV_EVT_INQUIRY_CHANGE_REPORTED:
	case SDEV_EVT_CAPACITY_CHANGE_REPORTED:
	case SDEV_EVT_SOFT_THRESHOLD_REACHED_REPORTED:
	case SDEV_EVT_MODE_PARAMETER_CHANGE_REPORTED:
	case SDEV_EVT_LUN_CHANGE_REPORTED:
	case SDEV_EVT_ALUA_STATE_CHANGE_REPORTED:
	default:
		 
		break;
	}

	return evt;
}
EXPORT_SYMBOL_GPL(sdev_evt_alloc);

void sdev_evt_send_simple(struct scsi_device *sdev,
			  enum scsi_device_event evt_type, gfp_t gfpflags)
{
	struct scsi_event *evt = sdev_evt_alloc(evt_type, gfpflags);
	if (!evt) {
		sdev_printk(KERN_ERR, sdev, "event %d eaten due to OOM\n",
			    evt_type);
		return;
	}

	sdev_evt_send(sdev, evt);
}
EXPORT_SYMBOL_GPL(sdev_evt_send_simple);

int
scsi_device_quiesce(struct scsi_device *sdev)
{
	int err = scsi_device_set_state(sdev, SDEV_QUIESCE);
	if (err)
		return err;

	scsi_run_queue(sdev->request_queue);
	while (atomic_read(&sdev->device_busy)) {
		msleep_interruptible(200);
		scsi_run_queue(sdev->request_queue);
	}
	return 0;
}
EXPORT_SYMBOL(scsi_device_quiesce);

void scsi_device_resume(struct scsi_device *sdev)
{
	 
	if (sdev->sdev_state != SDEV_QUIESCE ||
	    scsi_device_set_state(sdev, SDEV_RUNNING))
		return;
	scsi_run_queue(sdev->request_queue);
}
EXPORT_SYMBOL(scsi_device_resume);

static void
device_quiesce_fn(struct scsi_device *sdev, void *data)
{
	scsi_device_quiesce(sdev);
}

void
scsi_target_quiesce(struct scsi_target *starget)
{
	starget_for_each_device(starget, NULL, device_quiesce_fn);
}
EXPORT_SYMBOL(scsi_target_quiesce);

static void
device_resume_fn(struct scsi_device *sdev, void *data)
{
	scsi_device_resume(sdev);
}

void
scsi_target_resume(struct scsi_target *starget)
{
	starget_for_each_device(starget, NULL, device_resume_fn);
}
EXPORT_SYMBOL(scsi_target_resume);

int
scsi_internal_device_block(struct scsi_device *sdev)
{
	struct request_queue *q = sdev->request_queue;
	unsigned long flags;
	int err = 0;

	err = scsi_device_set_state(sdev, SDEV_BLOCK);
	if (err) {
		err = scsi_device_set_state(sdev, SDEV_CREATED_BLOCK);

		if (err)
			return err;
	}

	if (q->mq_ops) {
		blk_mq_stop_hw_queues(q);
	} else {
		spin_lock_irqsave(q->queue_lock, flags);
		blk_stop_queue(q);
		spin_unlock_irqrestore(q->queue_lock, flags);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(scsi_internal_device_block);
 
int
scsi_internal_device_unblock(struct scsi_device *sdev,
			     enum scsi_device_state new_state)
{
	struct request_queue *q = sdev->request_queue; 
	unsigned long flags;

	if ((sdev->sdev_state == SDEV_BLOCK) ||
	    (sdev->sdev_state == SDEV_TRANSPORT_OFFLINE))
		sdev->sdev_state = new_state;
	else if (sdev->sdev_state == SDEV_CREATED_BLOCK) {
		if (new_state == SDEV_TRANSPORT_OFFLINE ||
		    new_state == SDEV_OFFLINE)
			sdev->sdev_state = new_state;
		else
			sdev->sdev_state = SDEV_CREATED;
	} else if (sdev->sdev_state != SDEV_CANCEL &&
		 sdev->sdev_state != SDEV_OFFLINE)
		return -EINVAL;

	if (q->mq_ops) {
		blk_mq_start_stopped_hw_queues(q, false);
	} else {
		spin_lock_irqsave(q->queue_lock, flags);
		blk_start_queue(q);
		spin_unlock_irqrestore(q->queue_lock, flags);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(scsi_internal_device_unblock);

static void
device_block(struct scsi_device *sdev, void *data)
{
	scsi_internal_device_block(sdev);
}

static int
target_block(struct device *dev, void *data)
{
	if (scsi_is_target_device(dev))
		starget_for_each_device(to_scsi_target(dev), NULL,
					device_block);
	return 0;
}

void
scsi_target_block(struct device *dev)
{
	if (scsi_is_target_device(dev))
		starget_for_each_device(to_scsi_target(dev), NULL,
					device_block);
	else
		device_for_each_child(dev, NULL, target_block);
}
EXPORT_SYMBOL_GPL(scsi_target_block);

static void
device_unblock(struct scsi_device *sdev, void *data)
{
	scsi_internal_device_unblock(sdev, *(enum scsi_device_state *)data);
}

static int
target_unblock(struct device *dev, void *data)
{
	if (scsi_is_target_device(dev))
		starget_for_each_device(to_scsi_target(dev), data,
					device_unblock);
	return 0;
}

void
scsi_target_unblock(struct device *dev, enum scsi_device_state new_state)
{
	if (scsi_is_target_device(dev))
		starget_for_each_device(to_scsi_target(dev), &new_state,
					device_unblock);
	else
		device_for_each_child(dev, &new_state, target_unblock);
}
EXPORT_SYMBOL_GPL(scsi_target_unblock);

void *scsi_kmap_atomic_sg(struct scatterlist *sgl, int sg_count,
			  size_t *offset, size_t *len)
{
	int i;
	size_t sg_len = 0, len_complete = 0;
	struct scatterlist *sg;
	struct page *page;

	WARN_ON(!irqs_disabled());

	for_each_sg(sgl, sg, sg_count, i) {
		len_complete = sg_len;  
		sg_len += sg->length;
		if (sg_len > *offset)
			break;
	}

	if (unlikely(i == sg_count)) {
		printk(KERN_ERR "%s: Bytes in sg: %zu, requested offset %zu, "
			"elements %d\n",
		       __func__, sg_len, *offset, sg_count);
		WARN_ON(1);
		return NULL;
	}

	*offset = *offset - len_complete + sg->offset;

	page = nth_page(sg_page(sg), (*offset >> PAGE_SHIFT));
	*offset &= ~PAGE_MASK;

	sg_len = PAGE_SIZE - *offset;
	if (*len > sg_len)
		*len = sg_len;

	return kmap_atomic(page);
}
EXPORT_SYMBOL(scsi_kmap_atomic_sg);

void scsi_kunmap_atomic_sg(void *virt)
{
	kunmap_atomic(virt);
}
EXPORT_SYMBOL(scsi_kunmap_atomic_sg);

void sdev_disable_disk_events(struct scsi_device *sdev)
{
	atomic_inc(&sdev->disk_events_disable_depth);
}
EXPORT_SYMBOL(sdev_disable_disk_events);

void sdev_enable_disk_events(struct scsi_device *sdev)
{
	if (WARN_ON_ONCE(atomic_read(&sdev->disk_events_disable_depth) <= 0))
		return;
	atomic_dec(&sdev->disk_events_disable_depth);
}
EXPORT_SYMBOL(sdev_enable_disk_events);
