#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/fault-inject.h>

#include "blk.h"
#include "blk-mq.h"

#ifdef CONFIG_FAIL_IO_TIMEOUT

static DECLARE_FAULT_ATTR(fail_io_timeout);

static int __init setup_fail_io_timeout(char *str)
{
	return setup_fault_attr(&fail_io_timeout, str);
}
__setup("fail_io_timeout=", setup_fail_io_timeout);

int blk_should_fake_timeout(struct request_queue *q)
{
	if (!test_bit(QUEUE_FLAG_FAIL_IO, &q->queue_flags))
		return 0;

	return should_fail(&fail_io_timeout, 1);
}

static int __init fail_io_timeout_debugfs(void)
{
	struct dentry *dir = fault_create_debugfs_attr("fail_io_timeout",
						NULL, &fail_io_timeout);

	return PTR_ERR_OR_ZERO(dir);
}

late_initcall(fail_io_timeout_debugfs);

ssize_t part_timeout_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	struct gendisk *disk = dev_to_disk(dev);
	int set = test_bit(QUEUE_FLAG_FAIL_IO, &disk->queue->queue_flags);

	return sprintf(buf, "%d\n", set != 0);
}

ssize_t part_timeout_store(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct gendisk *disk = dev_to_disk(dev);
	int val;

	if (count) {
		struct request_queue *q = disk->queue;
		char *p = (char *) buf;

		val = simple_strtoul(p, &p, 10);
		spin_lock_irq(q->queue_lock);
		if (val)
			queue_flag_set(QUEUE_FLAG_FAIL_IO, q);
		else
			queue_flag_clear(QUEUE_FLAG_FAIL_IO, q);
		spin_unlock_irq(q->queue_lock);
	}

	return count;
}

#endif  

void blk_delete_timer(struct request *req)
{
	list_del_init(&req->timeout_list);
}

static void blk_rq_timed_out(struct request *req)
{
	struct request_queue *q = req->q;
	enum blk_eh_timer_return ret = BLK_EH_RESET_TIMER;

	if (q->rq_timed_out_fn)
		ret = q->rq_timed_out_fn(req);
	switch (ret) {
	case BLK_EH_HANDLED:
		 
		__blk_complete_request(req);
		break;
	case BLK_EH_RESET_TIMER:
		blk_add_timer(req);
		blk_clear_rq_complete(req);
		break;
	case BLK_EH_NOT_HANDLED:
		 
		break;
	default:
		printk(KERN_ERR "block: bad eh return: %d\n", ret);
		break;
	}
}

static void blk_rq_check_expired(struct request *rq, unsigned long *next_timeout,
			  unsigned int *next_set)
{
	if (time_after_eq(jiffies, rq->deadline)) {
		list_del_init(&rq->timeout_list);

		if (!blk_mark_rq_complete(rq))
			blk_rq_timed_out(rq);
	} else if (!*next_set || time_after(*next_timeout, rq->deadline)) {
		*next_timeout = rq->deadline;
		*next_set = 1;
	}
}

void blk_rq_timed_out_timer(unsigned long data)
{
	struct request_queue *q = (struct request_queue *) data;
	unsigned long flags, next = 0;
	struct request *rq, *tmp;
	int next_set = 0;

	spin_lock_irqsave(q->queue_lock, flags);

	list_for_each_entry_safe(rq, tmp, &q->timeout_list, timeout_list)
		blk_rq_check_expired(rq, &next, &next_set);

	if (next_set)
		mod_timer(&q->timeout, round_jiffies_up(next));

	spin_unlock_irqrestore(q->queue_lock, flags);
}

void blk_abort_request(struct request *req)
{
	if (blk_mark_rq_complete(req))
		return;

	if (req->q->mq_ops) {
		blk_mq_rq_timed_out(req, false);
	} else {
		blk_delete_timer(req);
		blk_rq_timed_out(req);
	}
}
EXPORT_SYMBOL_GPL(blk_abort_request);

unsigned long blk_rq_timeout(unsigned long timeout)
{
	unsigned long maxt;

	maxt = round_jiffies_up(jiffies + BLK_MAX_TIMEOUT);
	if (time_after(timeout, maxt))
		timeout = maxt;

	return timeout;
}

#ifdef MY_ABC_HERE
unsigned int blk_timeout_factory = 0;
EXPORT_SYMBOL(blk_timeout_factory);
#endif  

void blk_add_timer(struct request *req)
{
	struct request_queue *q = req->q;
	unsigned long expiry;

	if (req->cmd_flags & REQ_NO_TIMEOUT)
		return;

	if (!q->mq_ops && !q->rq_timed_out_fn)
		return;

	BUG_ON(!list_empty(&req->timeout_list));

	if (!req->timeout)
		req->timeout = q->rq_timeout;

#ifdef MY_ABC_HERE
	if (blk_timeout_factory) {
		req->timeout = 3 * HZ;
	}
#endif  

	req->deadline = jiffies + req->timeout;
	if (!q->mq_ops)
		list_add_tail(&req->timeout_list, &req->q->timeout_list);

	expiry = blk_rq_timeout(round_jiffies_up(req->deadline));

	if (!timer_pending(&q->timeout) ||
	    time_before(expiry, q->timeout.expires)) {
		unsigned long diff = q->timeout.expires - expiry;

		if (!timer_pending(&q->timeout) || (diff >= HZ / 2))
			mod_timer(&q->timeout, expiry);
	}

}
