#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/kthread.h>
#include <linux/export.h>

#include "usbip_common.h"

static int event_handler(struct usbip_device *ud)
{
	usbip_dbg_eh("enter\n");

	while (usbip_event_happened(ud)) {
		usbip_dbg_eh("pending event %lx\n", ud->event);

		if (ud->event & USBIP_EH_SHUTDOWN) {
			ud->eh_ops.shutdown(ud);
			ud->event &= ~USBIP_EH_SHUTDOWN;
		}

		if (ud->event & USBIP_EH_RESET) {
			ud->eh_ops.reset(ud);
			ud->event &= ~USBIP_EH_RESET;
		}

		if (ud->event & USBIP_EH_UNUSABLE) {
			ud->eh_ops.unusable(ud);
			ud->event &= ~USBIP_EH_UNUSABLE;
		}

		if (ud->event & USBIP_EH_BYE)
			return -1;
	}

	return 0;
}

static int event_handler_loop(void *data)
{
	struct usbip_device *ud = data;

	while (!kthread_should_stop()) {
		wait_event_interruptible(ud->eh_waitq,
					 usbip_event_happened(ud) ||
					 kthread_should_stop());
		usbip_dbg_eh("wakeup\n");

		if (event_handler(ud) < 0)
			break;
	}

	return 0;
}

int usbip_start_eh(struct usbip_device *ud)
{
	init_waitqueue_head(&ud->eh_waitq);
	ud->event = 0;

	ud->eh = kthread_run(event_handler_loop, ud, "usbip_eh");
	if (IS_ERR(ud->eh)) {
		pr_warning("Unable to start control thread\n");
		return PTR_ERR(ud->eh);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(usbip_start_eh);

void usbip_stop_eh(struct usbip_device *ud)
{
	if (ud->eh == current)
		return;  

	kthread_stop(ud->eh);
	usbip_dbg_eh("usbip_eh has finished\n");
}
EXPORT_SYMBOL_GPL(usbip_stop_eh);

void usbip_event_add(struct usbip_device *ud, unsigned long event)
{
	unsigned long flags;

	spin_lock_irqsave(&ud->lock, flags);
	ud->event |= event;
	wake_up(&ud->eh_waitq);
	spin_unlock_irqrestore(&ud->lock, flags);
}
EXPORT_SYMBOL_GPL(usbip_event_add);

int usbip_event_happened(struct usbip_device *ud)
{
	int happened = 0;

	spin_lock(&ud->lock);
#ifdef MY_ABC_HERE
	if (0 != ud->event && USBIP_EH_RESET != ud->event) {
		happened = 1;
	}
#else
	if (ud->event != 0)
		happened = 1;
#endif
	spin_unlock(&ud->lock);

	return happened;
}
EXPORT_SYMBOL_GPL(usbip_event_happened);
