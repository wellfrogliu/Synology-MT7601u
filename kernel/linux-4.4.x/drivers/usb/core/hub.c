#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/completion.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/ioctl.h>
#include <linux/usb.h>
#include <linux/usbdevice_fs.h>
#include <linux/usb/hcd.h>
#include <linux/usb/otg.h>
#include <linux/usb/quirks.h>
#ifdef MY_ABC_HERE
#include <linux/usb/syno_quirks.h>
#endif  
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/pm_qos.h>
#if defined (MY_ABC_HERE)
#include <linux/gpio.h>
#endif  

#include <asm/uaccess.h>
#include <asm/byteorder.h>

#include "hub.h"
#include "otg_whitelist.h"

#define USB_VENDOR_GENESYS_LOGIC		0x05e3
#define HUB_QUIRK_CHECK_PORT_AUTOSUSPEND	0x01

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
#define SYNO_SERIAL_EXT_HUB "syno.ext.hub"
#endif  

static DEFINE_SPINLOCK(device_state_lock);

static struct workqueue_struct *hub_wq;
static void hub_event(struct work_struct *work);

DEFINE_MUTEX(usb_port_peer_mutex);

static bool blinkenlights = 0;
module_param(blinkenlights, bool, S_IRUGO);
MODULE_PARM_DESC(blinkenlights, "true to cycle leds on hubs");

static int initial_descriptor_timeout = USB_CTRL_GET_TIMEOUT;
module_param(initial_descriptor_timeout, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(initial_descriptor_timeout,
		"initial 64-byte descriptor request timeout in milliseconds "
		"(default 5000 - 5.0 seconds)");

static bool old_scheme_first = 0;
module_param(old_scheme_first, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(old_scheme_first,
		 "start with the old device initialization scheme");

static bool use_both_schemes = 1;
module_param(use_both_schemes, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(use_both_schemes,
		"try the other device initialization scheme if the "
		"first one fails");

DECLARE_RWSEM(ehci_cf_port_reset_rwsem);
EXPORT_SYMBOL_GPL(ehci_cf_port_reset_rwsem);

#ifdef MY_ABC_HERE
DEFINE_MUTEX(hub_init_mutex);
#endif  

#define HUB_DEBOUNCE_TIMEOUT	2000
#define HUB_DEBOUNCE_STEP	  25
#define HUB_DEBOUNCE_STABLE	 100

static void hub_release(struct kref *kref);
static int usb_reset_and_verify_device(struct usb_device *udev);
static int hub_port_disable(struct usb_hub *hub, int port1, int set_state);
#if defined (MY_DEF_HERE) || defined (MY_DEF_HERE)
static int is_syno_ext_hub(struct usb_device *udev);
#endif  

static inline char *portspeed(struct usb_hub *hub, int portstatus)
{
	if (hub_is_superspeed(hub->hdev))
		return "5.0 Gb/s";
	if (portstatus & USB_PORT_STAT_HIGH_SPEED)
		return "480 Mb/s";
	else if (portstatus & USB_PORT_STAT_LOW_SPEED)
		return "1.5 Mb/s";
	else
		return "12 Mb/s";
}

struct usb_hub *usb_hub_to_struct_hub(struct usb_device *hdev)
{
	if (!hdev || !hdev->actconfig || !hdev->maxchild)
		return NULL;
	return usb_get_intfdata(hdev->actconfig->interface[0]);
}

int usb_device_supports_lpm(struct usb_device *udev)
{
	 
	if (udev->quirks & USB_QUIRK_NO_LPM)
		return 0;

	if (udev->speed == USB_SPEED_HIGH || udev->speed == USB_SPEED_FULL) {
		if (udev->bos->ext_cap &&
			(USB_LPM_SUPPORT &
			 le32_to_cpu(udev->bos->ext_cap->bmAttributes)))
			return 1;
		return 0;
	}

	if (!udev->bos->ss_cap) {
		dev_info(&udev->dev, "No LPM exit latency info found, disabling LPM.\n");
		return 0;
	}

	if (udev->bos->ss_cap->bU1devExitLat == 0 &&
			udev->bos->ss_cap->bU2DevExitLat == 0) {
		if (udev->parent)
			dev_info(&udev->dev, "LPM exit latency is zeroed, disabling LPM.\n");
		else
			dev_info(&udev->dev, "We don't know the algorithms for LPM for this host, disabling LPM.\n");
		return 0;
	}

	if (!udev->parent || udev->parent->lpm_capable)
		return 1;
	return 0;
}

static void usb_set_lpm_mel(struct usb_device *udev,
		struct usb3_lpm_parameters *udev_lpm_params,
		unsigned int udev_exit_latency,
		struct usb_hub *hub,
		struct usb3_lpm_parameters *hub_lpm_params,
		unsigned int hub_exit_latency)
{
	unsigned int total_mel;
	unsigned int device_mel;
	unsigned int hub_mel;

	total_mel = hub_lpm_params->mel +
		(hub->descriptor->u.ss.bHubHdrDecLat * 100);

	device_mel = udev_exit_latency * 1000;
	hub_mel = hub_exit_latency * 1000;
	if (device_mel > hub_mel)
		total_mel += device_mel;
	else
		total_mel += hub_mel;

	udev_lpm_params->mel = total_mel;
}

static void usb_set_lpm_pel(struct usb_device *udev,
		struct usb3_lpm_parameters *udev_lpm_params,
		unsigned int udev_exit_latency,
		struct usb_hub *hub,
		struct usb3_lpm_parameters *hub_lpm_params,
		unsigned int hub_exit_latency,
		unsigned int port_to_port_exit_latency)
{
	unsigned int first_link_pel;
	unsigned int hub_pel;

	if (udev_exit_latency > hub_exit_latency)
		first_link_pel = udev_exit_latency * 1000;
	else
		first_link_pel = hub_exit_latency * 1000;

	hub_pel = port_to_port_exit_latency * 1000 + hub_lpm_params->pel;

	if (first_link_pel > hub_pel)
		udev_lpm_params->pel = first_link_pel;
	else
		udev_lpm_params->pel = hub_pel;
}

static void usb_set_lpm_sel(struct usb_device *udev,
		struct usb3_lpm_parameters *udev_lpm_params)
{
	struct usb_device *parent;
	unsigned int num_hubs;
	unsigned int total_sel;

	total_sel = udev_lpm_params->pel;
	 
	for (parent = udev->parent, num_hubs = 0; parent->parent;
			parent = parent->parent)
		num_hubs++;
	 
	if (num_hubs > 0)
		total_sel += 2100 + 250 * (num_hubs - 1);

	total_sel += 250 * num_hubs;

	udev_lpm_params->sel = total_sel;
}

static void usb_set_lpm_parameters(struct usb_device *udev)
{
	struct usb_hub *hub;
	unsigned int port_to_port_delay;
	unsigned int udev_u1_del;
	unsigned int udev_u2_del;
	unsigned int hub_u1_del;
	unsigned int hub_u2_del;

	if (!udev->lpm_capable || udev->speed < USB_SPEED_SUPER)
		return;

	hub = usb_hub_to_struct_hub(udev->parent);
	 
	if (!hub)
		return;

	udev_u1_del = udev->bos->ss_cap->bU1devExitLat;
	udev_u2_del = le16_to_cpu(udev->bos->ss_cap->bU2DevExitLat);
	hub_u1_del = udev->parent->bos->ss_cap->bU1devExitLat;
	hub_u2_del = le16_to_cpu(udev->parent->bos->ss_cap->bU2DevExitLat);

	usb_set_lpm_mel(udev, &udev->u1_params, udev_u1_del,
			hub, &udev->parent->u1_params, hub_u1_del);

	usb_set_lpm_mel(udev, &udev->u2_params, udev_u2_del,
			hub, &udev->parent->u2_params, hub_u2_del);

	port_to_port_delay = 1;

	usb_set_lpm_pel(udev, &udev->u1_params, udev_u1_del,
			hub, &udev->parent->u1_params, hub_u1_del,
			port_to_port_delay);

	if (hub_u2_del > hub_u1_del)
		port_to_port_delay = 1 + hub_u2_del - hub_u1_del;
	else
		port_to_port_delay = 1 + hub_u1_del;

	usb_set_lpm_pel(udev, &udev->u2_params, udev_u2_del,
			hub, &udev->parent->u2_params, hub_u2_del,
			port_to_port_delay);

	usb_set_lpm_sel(udev, &udev->u1_params);
	usb_set_lpm_sel(udev, &udev->u2_params);
}

static int get_hub_descriptor(struct usb_device *hdev, void *data)
{
	int i, ret, size;
	unsigned dtype;

	if (hub_is_superspeed(hdev)) {
		dtype = USB_DT_SS_HUB;
		size = USB_DT_SS_HUB_SIZE;
	} else {
		dtype = USB_DT_HUB;
		size = sizeof(struct usb_hub_descriptor);
	}

	for (i = 0; i < 3; i++) {
		ret = usb_control_msg(hdev, usb_rcvctrlpipe(hdev, 0),
			USB_REQ_GET_DESCRIPTOR, USB_DIR_IN | USB_RT_HUB,
			dtype << 8, 0, data, size,
			USB_CTRL_GET_TIMEOUT);
		if (ret >= (USB_DT_HUB_NONVAR_SIZE + 2))
			return ret;
	}
	return -EINVAL;
}

static int clear_hub_feature(struct usb_device *hdev, int feature)
{
	return usb_control_msg(hdev, usb_sndctrlpipe(hdev, 0),
		USB_REQ_CLEAR_FEATURE, USB_RT_HUB, feature, 0, NULL, 0, 1000);
}

int usb_clear_port_feature(struct usb_device *hdev, int port1, int feature)
{
	return usb_control_msg(hdev, usb_sndctrlpipe(hdev, 0),
		USB_REQ_CLEAR_FEATURE, USB_RT_PORT, feature, port1,
		NULL, 0, 1000);
}

static int set_port_feature(struct usb_device *hdev, int port1, int feature)
{
	return usb_control_msg(hdev, usb_sndctrlpipe(hdev, 0),
		USB_REQ_SET_FEATURE, USB_RT_PORT, feature, port1,
		NULL, 0, 1000);
}

static char *to_led_name(int selector)
{
	switch (selector) {
	case HUB_LED_AMBER:
		return "amber";
	case HUB_LED_GREEN:
		return "green";
	case HUB_LED_OFF:
		return "off";
	case HUB_LED_AUTO:
		return "auto";
	default:
		return "??";
	}
}

static void set_port_led(struct usb_hub *hub, int port1, int selector)
{
	struct usb_port *port_dev = hub->ports[port1 - 1];
	int status;

	status = set_port_feature(hub->hdev, (selector << 8) | port1,
			USB_PORT_FEAT_INDICATOR);
	dev_dbg(&port_dev->dev, "indicator %s status %d\n",
		to_led_name(selector), status);
}

#define	LED_CYCLE_PERIOD	((2*HZ)/3)

static void led_work(struct work_struct *work)
{
	struct usb_hub		*hub =
		container_of(work, struct usb_hub, leds.work);
	struct usb_device	*hdev = hub->hdev;
	unsigned		i;
	unsigned		changed = 0;
	int			cursor = -1;

	if (hdev->state != USB_STATE_CONFIGURED || hub->quiescing)
		return;

	for (i = 0; i < hdev->maxchild; i++) {
		unsigned	selector, mode;

		switch (hub->indicator[i]) {
		 
		case INDICATOR_CYCLE:
			cursor = i;
			selector = HUB_LED_AUTO;
			mode = INDICATOR_AUTO;
			break;
		 
		case INDICATOR_GREEN_BLINK:
			selector = HUB_LED_GREEN;
			mode = INDICATOR_GREEN_BLINK_OFF;
			break;
		case INDICATOR_GREEN_BLINK_OFF:
			selector = HUB_LED_OFF;
			mode = INDICATOR_GREEN_BLINK;
			break;
		 
		case INDICATOR_AMBER_BLINK:
			selector = HUB_LED_AMBER;
			mode = INDICATOR_AMBER_BLINK_OFF;
			break;
		case INDICATOR_AMBER_BLINK_OFF:
			selector = HUB_LED_OFF;
			mode = INDICATOR_AMBER_BLINK;
			break;
		 
		case INDICATOR_ALT_BLINK:
			selector = HUB_LED_GREEN;
			mode = INDICATOR_ALT_BLINK_OFF;
			break;
		case INDICATOR_ALT_BLINK_OFF:
			selector = HUB_LED_AMBER;
			mode = INDICATOR_ALT_BLINK;
			break;
		default:
			continue;
		}
		if (selector != HUB_LED_AUTO)
			changed = 1;
		set_port_led(hub, i + 1, selector);
		hub->indicator[i] = mode;
	}
	if (!changed && blinkenlights) {
		cursor++;
		cursor %= hdev->maxchild;
		set_port_led(hub, cursor + 1, HUB_LED_GREEN);
		hub->indicator[cursor] = INDICATOR_CYCLE;
		changed++;
	}
	if (changed)
		queue_delayed_work(system_power_efficient_wq,
				&hub->leds, LED_CYCLE_PERIOD);
}

#define	USB_STS_TIMEOUT		1000
#define	USB_STS_RETRIES		5

static int get_hub_status(struct usb_device *hdev,
		struct usb_hub_status *data)
{
	int i, status = -ETIMEDOUT;

	for (i = 0; i < USB_STS_RETRIES &&
			(status == -ETIMEDOUT || status == -EPIPE); i++) {
		status = usb_control_msg(hdev, usb_rcvctrlpipe(hdev, 0),
			USB_REQ_GET_STATUS, USB_DIR_IN | USB_RT_HUB, 0, 0,
			data, sizeof(*data), USB_STS_TIMEOUT);
	}
	return status;
}

static int get_port_status(struct usb_device *hdev, int port1,
		struct usb_port_status *data)
{
	int i, status = -ETIMEDOUT;

	for (i = 0; i < USB_STS_RETRIES &&
			(status == -ETIMEDOUT || status == -EPIPE); i++) {
		status = usb_control_msg(hdev, usb_rcvctrlpipe(hdev, 0),
			USB_REQ_GET_STATUS, USB_DIR_IN | USB_RT_PORT, 0, port1,
			data, sizeof(*data), USB_STS_TIMEOUT);
	}
	return status;
}

static int hub_port_status(struct usb_hub *hub, int port1,
		u16 *status, u16 *change)
{
	int ret;

	mutex_lock(&hub->status_mutex);
	ret = get_port_status(hub->hdev, port1, &hub->status->port);
	if (ret < 4) {
		if (ret != -ENODEV)
			dev_err(hub->intfdev,
				"%s failed (err = %d)\n", __func__, ret);
		if (ret >= 0)
			ret = -EIO;
	} else {
		*status = le16_to_cpu(hub->status->port.wPortStatus);
		*change = le16_to_cpu(hub->status->port.wPortChange);

		ret = 0;
	}
	mutex_unlock(&hub->status_mutex);
	return ret;
}

static void kick_hub_wq(struct usb_hub *hub)
{
	struct usb_interface *intf;

	if (hub->disconnected || work_pending(&hub->events))
		return;

	intf = to_usb_interface(hub->intfdev);
	usb_autopm_get_interface_no_resume(intf);
	kref_get(&hub->kref);

	if (queue_work(hub_wq, &hub->events))
		return;

	usb_autopm_put_interface_async(intf);
	kref_put(&hub->kref, hub_release);
}

void usb_kick_hub_wq(struct usb_device *hdev)
{
	struct usb_hub *hub = usb_hub_to_struct_hub(hdev);

#if defined(CONFIG_USB_ETRON_HUB)
	if (usb_is_etron_hcd(hdev))
		return ethub_usb_kick_hub_wq(hdev);
#endif  

	if (hub)
		kick_hub_wq(hub);
}

void usb_wakeup_notification(struct usb_device *hdev,
		unsigned int portnum)
{
	struct usb_hub *hub;

#if defined(CONFIG_USB_ETRON_HUB)
	if (usb_is_etron_hcd(hdev))
		return ethub_usb_wakeup_notification(hdev, portnum);
#endif  

	if (!hdev)
		return;

	hub = usb_hub_to_struct_hub(hdev);
	if (hub) {
		set_bit(portnum, hub->wakeup_bits);
		kick_hub_wq(hub);
	}
}
EXPORT_SYMBOL_GPL(usb_wakeup_notification);

static void hub_irq(struct urb *urb)
{
	struct usb_hub *hub = urb->context;
	int status = urb->status;
	unsigned i;
	unsigned long bits;

	switch (status) {
	case -ENOENT:		 
	case -ECONNRESET:	 
	case -ESHUTDOWN:	 
		return;

	default:		 
		 
		dev_dbg(hub->intfdev, "transfer --> %d\n", status);
		if ((++hub->nerrors < 10) || hub->error)
			goto resubmit;
		hub->error = status;
		 
	case 0:			 
		bits = 0;
		for (i = 0; i < urb->actual_length; ++i)
			bits |= ((unsigned long) ((*hub->buffer)[i]))
					<< (i*8);
		hub->event_bits[0] = bits;
		break;
	}

	hub->nerrors = 0;

	kick_hub_wq(hub);

resubmit:
	if (hub->quiescing)
		return;

	status = usb_submit_urb(hub->urb, GFP_ATOMIC);
	if (status != 0 && status != -ENODEV && status != -EPERM)
		dev_err(hub->intfdev, "resubmit --> %d\n", status);
}

static inline int
hub_clear_tt_buffer(struct usb_device *hdev, u16 devinfo, u16 tt)
{
	 
	if (((devinfo >> 11) & USB_ENDPOINT_XFERTYPE_MASK) ==
			USB_ENDPOINT_XFER_CONTROL) {
		int status = usb_control_msg(hdev, usb_sndctrlpipe(hdev, 0),
				HUB_CLEAR_TT_BUFFER, USB_RT_PORT,
				devinfo ^ 0x8000, tt, NULL, 0, 1000);
		if (status)
			return status;
	}
	return usb_control_msg(hdev, usb_sndctrlpipe(hdev, 0),
			       HUB_CLEAR_TT_BUFFER, USB_RT_PORT, devinfo,
			       tt, NULL, 0, 1000);
}

static void hub_tt_work(struct work_struct *work)
{
	struct usb_hub		*hub =
		container_of(work, struct usb_hub, tt.clear_work);
	unsigned long		flags;

	spin_lock_irqsave(&hub->tt.lock, flags);
	while (!list_empty(&hub->tt.clear_list)) {
		struct list_head	*next;
		struct usb_tt_clear	*clear;
		struct usb_device	*hdev = hub->hdev;
		const struct hc_driver	*drv;
		int			status;

		next = hub->tt.clear_list.next;
		clear = list_entry(next, struct usb_tt_clear, clear_list);
		list_del(&clear->clear_list);

		spin_unlock_irqrestore(&hub->tt.lock, flags);
		status = hub_clear_tt_buffer(hdev, clear->devinfo, clear->tt);
		if (status && status != -ENODEV)
			dev_err(&hdev->dev,
				"clear tt %d (%04x) error %d\n",
				clear->tt, clear->devinfo, status);

		drv = clear->hcd->driver;
		if (drv->clear_tt_buffer_complete)
			(drv->clear_tt_buffer_complete)(clear->hcd, clear->ep);

		kfree(clear);
		spin_lock_irqsave(&hub->tt.lock, flags);
	}
	spin_unlock_irqrestore(&hub->tt.lock, flags);
}

int usb_hub_set_port_power(struct usb_device *hdev, struct usb_hub *hub,
			   int port1, bool set)
{
	int ret;

	if (set)
		ret = set_port_feature(hdev, port1, USB_PORT_FEAT_POWER);
	else
		ret = usb_clear_port_feature(hdev, port1, USB_PORT_FEAT_POWER);

	if (ret)
		return ret;

	if (set)
		set_bit(port1, hub->power_bits);
	else
		clear_bit(port1, hub->power_bits);
	return 0;
}

int usb_hub_clear_tt_buffer(struct urb *urb)
{
	struct usb_device	*udev = urb->dev;
	int			pipe = urb->pipe;
	struct usb_tt		*tt = udev->tt;
	unsigned long		flags;
	struct usb_tt_clear	*clear;

	clear = kmalloc(sizeof *clear, GFP_ATOMIC);
	if (clear == NULL) {
		dev_err(&udev->dev, "can't save CLEAR_TT_BUFFER state\n");
		 
		return -ENOMEM;
	}

	clear->tt = tt->multi ? udev->ttport : 1;
	clear->devinfo = usb_pipeendpoint (pipe);
	clear->devinfo |= udev->devnum << 4;
	clear->devinfo |= usb_pipecontrol(pipe)
			? (USB_ENDPOINT_XFER_CONTROL << 11)
			: (USB_ENDPOINT_XFER_BULK << 11);
	if (usb_pipein(pipe))
		clear->devinfo |= 1 << 15;

	clear->hcd = bus_to_hcd(udev->bus);
	clear->ep = urb->ep;

	spin_lock_irqsave(&tt->lock, flags);
	list_add_tail(&clear->clear_list, &tt->clear_list);
	schedule_work(&tt->clear_work);
	spin_unlock_irqrestore(&tt->lock, flags);
	return 0;
}
EXPORT_SYMBOL_GPL(usb_hub_clear_tt_buffer);

static void hub_power_on(struct usb_hub *hub, bool do_delay)
{
	int port1;

	if (hub_is_port_power_switchable(hub))
		dev_dbg(hub->intfdev, "enabling power on all ports\n");
	else
		dev_dbg(hub->intfdev, "trying to enable port power on "
				"non-switchable hub\n");
	for (port1 = 1; port1 <= hub->hdev->maxchild; port1++)
		if (test_bit(port1, hub->power_bits))
			set_port_feature(hub->hdev, port1, USB_PORT_FEAT_POWER);
		else
			usb_clear_port_feature(hub->hdev, port1,
						USB_PORT_FEAT_POWER);
	if (do_delay)
		msleep(hub_power_on_good_delay(hub));
}

static int hub_hub_status(struct usb_hub *hub,
		u16 *status, u16 *change)
{
	int ret;

	mutex_lock(&hub->status_mutex);
	ret = get_hub_status(hub->hdev, &hub->status->hub);
	if (ret < 0) {
		if (ret != -ENODEV)
			dev_err(hub->intfdev,
				"%s failed (err = %d)\n", __func__, ret);
	} else {
		*status = le16_to_cpu(hub->status->hub.wHubStatus);
		*change = le16_to_cpu(hub->status->hub.wHubChange);
		ret = 0;
	}
	mutex_unlock(&hub->status_mutex);
	return ret;
}

static int hub_set_port_link_state(struct usb_hub *hub, int port1,
			unsigned int link_status)
{
	return set_port_feature(hub->hdev,
			port1 | (link_status << 3),
			USB_PORT_FEAT_LINK_STATE);
}

#if defined (MY_ABC_HERE)	\
	 || defined (MY_ABC_HERE)
#define IS_XHCI(hcd) (hcd->driver->flags & HCD_USB3)
#endif  

#if defined (MY_ABC_HERE)
static inline int get_vbus_gpio(struct usb_hub *hub, int port) {
#ifdef MY_ABC_HERE
	struct usb_port *port_dev = hub->ports[port - 1];

	if (0 <= port_dev->syno_vbus_gpp) {  
		return port_dev->syno_vbus_gpp;
	}
#else  
	struct usb_device *hdev = hub->hdev;
	struct usb_hcd *hcd = bus_to_hcd(hdev->bus);

	if (0 <= hcd->vbus_gpio_pin) {
		return hcd->vbus_gpio_pin;
	}

#endif  
	return -EINVAL;
}

static inline int
syno_usb_set_power(struct usb_hub *hub, int enable, int port) {
	int usb_vbus_gpio = get_vbus_gpio(hub, port);
	int ret = -EINVAL;
	if (0 > usb_vbus_gpio) {
		dev_err(hub->intfdev,
			"cannot find VBUS gpio for port %d\n", port);
		goto END;
	}
	 
	enable = !(enable ^ hub->ports[port-1]->syno_vbus_gpp_pol);

#ifdef MY_DEF_HERE
	syno_pch_lpc_gpio_pin(usb_vbus_gpio, &enable, 1);
#else  
	SYNO_GPIO_WRITE(usb_vbus_gpio, enable);
#endif  
	ret = 0;
END:
	return ret;
}

static inline unsigned int
syno_get_power_off_time_ms(void) {
	unsigned int power_off_time = CONFIG_SYNO_USB_POWER_OFF_TIME;
	unsigned int power_off_extra_delay = CONFIG_SYNO_HUB_POWER_CYCLE_EXTRA_DELAY_TIME;
	return power_off_time + power_off_extra_delay;
}

static inline unsigned int
syno_get_power_on_time_ms(void) {
	return CONFIG_SYNO_USB_POWER_ON_TIME;
}

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
 
static int syno_usb_power_set_children(struct usb_hub *hub, int port, int enable)
{
	int i;
	struct usb_device *hdev = hub->hdev;
	extern char gSynoUsbVbusHostAddr[CONFIG_SYNO_USB_VBUS_NUM_GPIO][20];
	extern unsigned gSynoUsbVbusGpp[CONFIG_SYNO_USB_VBUS_NUM_GPIO];
	extern unsigned gSynoUsbVbusGppPol[CONFIG_SYNO_USB_VBUS_NUM_GPIO];
	int ret = -EINVAL;
	if (strncmp(hdev->serial, CONFIG_SYNO_USB_EXT_HUB_PARENT_SERIAL, strlen(hdev->serial))) {
		printk(KERN_INFO "This host %s has no children hub(%s).\n",hdev->serial,
			CONFIG_SYNO_USB_EXT_HUB_PARENT_SERIAL);
		goto END;
	}
	for (i = 0; i < CONFIG_SYNO_USB_VBUS_NUM_GPIO; i++) {
		if (!strncmp(SYNO_SERIAL_EXT_HUB, gSynoUsbVbusHostAddr[i],
				strlen(SYNO_SERIAL_EXT_HUB))) {
			printk(KERN_INFO "Turn %s children hub %s vbus gpio %d(%s)\n",
				enable ? "ON" : "OFF", gSynoUsbVbusHostAddr[i], gSynoUsbVbusGpp[i],
				gSynoUsbVbusGppPol[i] ? "ACTIVE_HIGH" : "ACTIVE_LOW");
			SYNO_GPIO_WRITE(gSynoUsbVbusGpp[i], !(enable ^ gSynoUsbVbusGppPol[i]));
		}
	}
	ret = 0;
END:
	return ret;
}
#endif  

static int
__syno_usb_power_cycle(struct usb_hub *hub, int port) {
	unsigned int power_cycle_delay_time;
	int ret;
	if (0 >= hub->ports[port - 1]->power_cycle_counter) {
		dev_info(hub->intfdev,
			"Stop power cycle handling for port %d\n", port);
		 
		hub->ports[port - 1]->power_cycle_counter = SYNO_POWER_CYCLE_TRIES;
		return -EINVAL;
	}
	 
	power_cycle_delay_time = syno_get_power_off_time_ms();

	dev_info(hub->intfdev,
		"[%u/%u] Disabling USB power and waiting %u ms for port %d\n",
		hub->ports[port - 1]->power_cycle_counter,
		SYNO_POWER_CYCLE_TRIES,
		power_cycle_delay_time, port);
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	syno_usb_power_set_children(hub, port, 0);
#endif  
	ret = syno_usb_set_power(hub, 0, port);
	if (0 > ret)
		return -EINVAL;
	msleep(power_cycle_delay_time);

	power_cycle_delay_time = syno_get_power_on_time_ms();
	dev_info(hub->intfdev,
		"[%u/%u] Enabling USB power and waiting %u ms for port %d\n",
		hub->ports[port - 1]->power_cycle_counter,
		SYNO_POWER_CYCLE_TRIES,
		power_cycle_delay_time, port);
	ret = syno_usb_set_power(hub, 1, port);
	if (0 > ret)
		return -EINVAL;
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	 
	msleep(power_cycle_delay_time);
	syno_usb_power_set_children(hub, port, 1);
#endif  
	msleep(power_cycle_delay_time);
	hub->ports[port - 1]->power_cycle_counter--;
	return 0;
}

static int
syno_usb_power_cycle(struct usb_hub *hub, int port, int status) {
	struct usb_device *hdev = hub->hdev;
	struct usb_hcd *hcd = bus_to_hcd(hdev->bus);
	 
	if (hub->hdev->parent)
		return -EINVAL;

	if ((status == -ENODEV) || (status == -ENOTCONN))
		return -EINVAL;

	if (hcd->power_control_support) {
		return __syno_usb_power_cycle(hub, port);
	} else {
		printk("This model does not support power control\n");
		return -ENOSYS;	 
	}
}
#endif  

static void hub_port_logical_disconnect(struct usb_hub *hub, int port1)
{
#if defined (MY_ABC_HERE)
	dev_info(&hub->ports[port1 - 1]->dev, "logical disconnect on port"
		" %d [%s]\n", port1, current->comm);
#else  
	dev_dbg(&hub->ports[port1 - 1]->dev, "logical disconnect\n");
#endif  
	hub_port_disable(hub, port1, 1);

	set_bit(port1, hub->change_bits);
	kick_hub_wq(hub);
}

int usb_remove_device(struct usb_device *udev)
{
	struct usb_hub *hub;
	struct usb_interface *intf;

#if defined(CONFIG_USB_ETRON_HUB)
	if (usb_is_etron_hcd(udev))
		return ethub_usb_remove_device(udev);
#endif  

	if (!udev->parent)	 
		return -EINVAL;
	hub = usb_hub_to_struct_hub(udev->parent);
	intf = to_usb_interface(hub->intfdev);

	usb_autopm_get_interface(intf);
	set_bit(udev->portnum, hub->removed_bits);
	hub_port_logical_disconnect(hub, udev->portnum);
	usb_autopm_put_interface(intf);
	return 0;
}

enum hub_activation_type {
	HUB_INIT, HUB_INIT2, HUB_INIT3,		 
	HUB_POST_RESET, HUB_RESUME, HUB_RESET_RESUME,
};

static void hub_init_func2(struct work_struct *ws);
static void hub_init_func3(struct work_struct *ws);

static void hub_activate(struct usb_hub *hub, enum hub_activation_type type)
{
	struct usb_device *hdev = hub->hdev;
	struct usb_hcd *hcd;
	int ret;
	int port1;
	int status;
	bool need_debounce_delay = false;
	unsigned delay;

	if (type == HUB_INIT2 || type == HUB_INIT3) {
		device_lock(&hdev->dev);

		if (hub->disconnected)
			goto disconnected;
		if (type == HUB_INIT2)
			goto init2;
		goto init3;
	}
	kref_get(&hub->kref);

	if (type != HUB_RESUME) {
		if (hdev->parent && hub_is_superspeed(hdev)) {
			ret = usb_control_msg(hdev, usb_sndctrlpipe(hdev, 0),
					HUB_SET_DEPTH, USB_RT_HUB,
					hdev->level - 1, 0, NULL, 0,
					USB_CTRL_SET_TIMEOUT);
			if (ret < 0)
				dev_err(hub->intfdev,
						"set hub depth failed\n");
		}

		if (type == HUB_INIT) {
			delay = hub_power_on_good_delay(hub);

			hub_power_on(hub, false);
			INIT_DELAYED_WORK(&hub->init_work, hub_init_func2);
			queue_delayed_work(system_power_efficient_wq,
					&hub->init_work,
					msecs_to_jiffies(delay));

			usb_autopm_get_interface_no_resume(
					to_usb_interface(hub->intfdev));
			return;		 
		} else if (type == HUB_RESET_RESUME) {
			 
			hcd = bus_to_hcd(hdev->bus);
			if (hcd->driver->update_hub_device) {
				ret = hcd->driver->update_hub_device(hcd, hdev,
						&hub->tt, GFP_NOIO);
				if (ret < 0) {
					dev_err(hub->intfdev, "Host not "
							"accepting hub info "
							"update.\n");
					dev_err(hub->intfdev, "LS/FS devices "
							"and hubs may not work "
							"under this hub\n.");
				}
			}
			hub_power_on(hub, true);
		} else {
			hub_power_on(hub, true);
		}
	}
 init2:

	for (port1 = 1; port1 <= hdev->maxchild; ++port1) {
		struct usb_port *port_dev = hub->ports[port1 - 1];
		struct usb_device *udev = port_dev->child;
		u16 portstatus, portchange;

		portstatus = portchange = 0;
		status = hub_port_status(hub, port1, &portstatus, &portchange);
		if (udev || (portstatus & USB_PORT_STAT_CONNECTION))
			dev_dbg(&port_dev->dev, "status %04x change %04x\n",
					portstatus, portchange);

		if ((portstatus & USB_PORT_STAT_ENABLE) && (
				type != HUB_RESUME ||
				!(portstatus & USB_PORT_STAT_CONNECTION) ||
				!udev ||
				udev->state == USB_STATE_NOTATTACHED)) {
			 
			portstatus &= ~USB_PORT_STAT_ENABLE;
			if (!hub_is_superspeed(hdev))
				usb_clear_port_feature(hdev, port1,
						   USB_PORT_FEAT_ENABLE);
		}

		if (portchange & USB_PORT_STAT_C_CONNECTION) {
			need_debounce_delay = true;
			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_CONNECTION);
		}
		if (portchange & USB_PORT_STAT_C_ENABLE) {
			need_debounce_delay = true;
			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_ENABLE);
		}
		if (portchange & USB_PORT_STAT_C_RESET) {
			need_debounce_delay = true;
			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_RESET);
		}
		if ((portchange & USB_PORT_STAT_C_BH_RESET) &&
				hub_is_superspeed(hub->hdev)) {
			need_debounce_delay = true;
			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_BH_PORT_RESET);
		}
		 
		if (!(portstatus & USB_PORT_STAT_CONNECTION) ||
				(portchange & USB_PORT_STAT_C_CONNECTION))
			clear_bit(port1, hub->removed_bits);

		if (!udev || udev->state == USB_STATE_NOTATTACHED) {
			 
			if (udev || (portstatus & USB_PORT_STAT_CONNECTION) ||
			    (portstatus & USB_PORT_STAT_OVERCURRENT))
				set_bit(port1, hub->change_bits);

		} else if (portstatus & USB_PORT_STAT_ENABLE) {
			bool port_resumed = (portstatus &
					USB_PORT_STAT_LINK_STATE) ==
				USB_SS_PORT_LS_U0;
			 
			if (portchange || (hub_is_superspeed(hub->hdev) &&
						port_resumed))
				set_bit(port1, hub->change_bits);

		} else if (udev->persist_enabled) {
#ifdef CONFIG_PM
			udev->reset_resume = 1;
#endif
			 
			if (test_bit(port1, hub->power_bits))
				set_bit(port1, hub->change_bits);

		} else {
			 
			usb_set_device_state(udev, USB_STATE_NOTATTACHED);
			set_bit(port1, hub->change_bits);
		}
	}

	if (need_debounce_delay) {
		delay = HUB_DEBOUNCE_STABLE;

		if (type == HUB_INIT2) {
			INIT_DELAYED_WORK(&hub->init_work, hub_init_func3);
			queue_delayed_work(system_power_efficient_wq,
					&hub->init_work,
					msecs_to_jiffies(delay));
			device_unlock(&hdev->dev);
			return;		 
		} else {
			msleep(delay);
		}
	}
 init3:
	hub->quiescing = 0;

	status = usb_submit_urb(hub->urb, GFP_NOIO);
	if (status < 0)
		dev_err(hub->intfdev, "activate --> %d\n", status);
	if (hub->has_indicators && blinkenlights)
		queue_delayed_work(system_power_efficient_wq,
				&hub->leds, LED_CYCLE_PERIOD);

	kick_hub_wq(hub);

	if (type == HUB_INIT2 || type == HUB_INIT3) {
		 
 disconnected:
		usb_autopm_put_interface_async(to_usb_interface(hub->intfdev));
		device_unlock(&hdev->dev);
	}

	kref_put(&hub->kref, hub_release);
}

static void hub_init_func2(struct work_struct *ws)
{
	struct usb_hub *hub = container_of(ws, struct usb_hub, init_work.work);

	hub_activate(hub, HUB_INIT2);
}

static void hub_init_func3(struct work_struct *ws)
{
	struct usb_hub *hub = container_of(ws, struct usb_hub, init_work.work);

	hub_activate(hub, HUB_INIT3);
}

enum hub_quiescing_type {
	HUB_DISCONNECT, HUB_PRE_RESET, HUB_SUSPEND
};

static void hub_quiesce(struct usb_hub *hub, enum hub_quiescing_type type)
{
	struct usb_device *hdev = hub->hdev;
	int i;

	hub->quiescing = 1;

	if (type != HUB_SUSPEND) {
		 
		for (i = 0; i < hdev->maxchild; ++i) {
			if (hub->ports[i]->child)
				usb_disconnect(&hub->ports[i]->child);
		}
	}

	usb_kill_urb(hub->urb);
	if (hub->has_indicators)
		cancel_delayed_work_sync(&hub->leds);
	if (hub->tt.hub)
		flush_work(&hub->tt.clear_work);
}

static void hub_pm_barrier_for_all_ports(struct usb_hub *hub)
{
	int i;

	for (i = 0; i < hub->hdev->maxchild; ++i)
		pm_runtime_barrier(&hub->ports[i]->dev);
}

static int hub_pre_reset(struct usb_interface *intf)
{
	struct usb_hub *hub = usb_get_intfdata(intf);

	hub_quiesce(hub, HUB_PRE_RESET);
	hub->in_reset = 1;
	hub_pm_barrier_for_all_ports(hub);
	return 0;
}

static int hub_post_reset(struct usb_interface *intf)
{
	struct usb_hub *hub = usb_get_intfdata(intf);

	hub->in_reset = 0;
	hub_pm_barrier_for_all_ports(hub);
	hub_activate(hub, HUB_POST_RESET);
	return 0;
}

static int hub_configure(struct usb_hub *hub,
	struct usb_endpoint_descriptor *endpoint)
{
	struct usb_hcd *hcd;
	struct usb_device *hdev = hub->hdev;
	struct device *hub_dev = hub->intfdev;
	u16 hubstatus, hubchange;
	u16 wHubCharacteristics;
	unsigned int pipe;
	int maxp, ret, i;
	char *message = "out of memory";
	unsigned unit_load;
	unsigned full_load;
	unsigned maxchild;

#ifdef MY_ABC_HERE
	mutex_lock(&hub_init_mutex);
#endif  

	hub->buffer = kmalloc(sizeof(*hub->buffer), GFP_KERNEL);
	if (!hub->buffer) {
		ret = -ENOMEM;
		goto fail;
	}

	hub->status = kmalloc(sizeof(*hub->status), GFP_KERNEL);
	if (!hub->status) {
		ret = -ENOMEM;
		goto fail;
	}
	mutex_init(&hub->status_mutex);

	hub->descriptor = kmalloc(sizeof(*hub->descriptor), GFP_KERNEL);
	if (!hub->descriptor) {
		ret = -ENOMEM;
		goto fail;
	}

	ret = get_hub_descriptor(hdev, hub->descriptor);
	if (ret < 0) {
		message = "can't read hub descriptor";
		goto fail;
	} else if (hub->descriptor->bNbrPorts > USB_MAXCHILDREN) {
		message = "hub has too many ports!";
		ret = -ENODEV;
		goto fail;
	} else if (hub->descriptor->bNbrPorts == 0) {
		message = "hub doesn't have any ports!";
		ret = -ENODEV;
		goto fail;
	}

	maxchild = hub->descriptor->bNbrPorts;
	dev_info(hub_dev, "%d port%s detected\n", maxchild,
			(maxchild == 1) ? "" : "s");

	hub->ports = kzalloc(maxchild * sizeof(struct usb_port *), GFP_KERNEL);
	if (!hub->ports) {
		ret = -ENOMEM;
		goto fail;
	}

	wHubCharacteristics = le16_to_cpu(hub->descriptor->wHubCharacteristics);
	if (hub_is_superspeed(hdev)) {
		unit_load = 150;
		full_load = 900;
	} else {
		unit_load = 100;
		full_load = 500;
	}

	if ((wHubCharacteristics & HUB_CHAR_COMPOUND) &&
			!(hub_is_superspeed(hdev))) {
		char	portstr[USB_MAXCHILDREN + 1];

		for (i = 0; i < maxchild; i++)
			portstr[i] = hub->descriptor->u.hs.DeviceRemovable
				    [((i + 1) / 8)] & (1 << ((i + 1) % 8))
				? 'F' : 'R';
		portstr[maxchild] = 0;
		dev_dbg(hub_dev, "compound device; port removable status: %s\n", portstr);
	} else
		dev_dbg(hub_dev, "standalone hub\n");

	switch (wHubCharacteristics & HUB_CHAR_LPSM) {
	case HUB_CHAR_COMMON_LPSM:
		dev_dbg(hub_dev, "ganged power switching\n");
		break;
	case HUB_CHAR_INDV_PORT_LPSM:
		dev_dbg(hub_dev, "individual port power switching\n");
		break;
	case HUB_CHAR_NO_LPSM:
	case HUB_CHAR_LPSM:
		dev_dbg(hub_dev, "no power switching (usb 1.0)\n");
		break;
	}

	switch (wHubCharacteristics & HUB_CHAR_OCPM) {
	case HUB_CHAR_COMMON_OCPM:
		dev_dbg(hub_dev, "global over-current protection\n");
		break;
	case HUB_CHAR_INDV_PORT_OCPM:
		dev_dbg(hub_dev, "individual port over-current protection\n");
		break;
	case HUB_CHAR_NO_OCPM:
	case HUB_CHAR_OCPM:
		dev_dbg(hub_dev, "no over-current protection\n");
		break;
	}

	spin_lock_init(&hub->tt.lock);
	INIT_LIST_HEAD(&hub->tt.clear_list);
	INIT_WORK(&hub->tt.clear_work, hub_tt_work);
	switch (hdev->descriptor.bDeviceProtocol) {
	case USB_HUB_PR_FS:
		break;
	case USB_HUB_PR_HS_SINGLE_TT:
		dev_dbg(hub_dev, "Single TT\n");
		hub->tt.hub = hdev;
		break;
	case USB_HUB_PR_HS_MULTI_TT:
		ret = usb_set_interface(hdev, 0, 1);
		if (ret == 0) {
			dev_dbg(hub_dev, "TT per port\n");
			hub->tt.multi = 1;
		} else
			dev_err(hub_dev, "Using single TT (err %d)\n",
				ret);
		hub->tt.hub = hdev;
		break;
	case USB_HUB_PR_SS:
		 
		break;
	default:
		dev_dbg(hub_dev, "Unrecognized hub protocol %d\n",
			hdev->descriptor.bDeviceProtocol);
		break;
	}

	switch (wHubCharacteristics & HUB_CHAR_TTTT) {
	case HUB_TTTT_8_BITS:
		if (hdev->descriptor.bDeviceProtocol != 0) {
			hub->tt.think_time = 666;
			dev_dbg(hub_dev, "TT requires at most %d "
					"FS bit times (%d ns)\n",
				8, hub->tt.think_time);
		}
		break;
	case HUB_TTTT_16_BITS:
		hub->tt.think_time = 666 * 2;
		dev_dbg(hub_dev, "TT requires at most %d "
				"FS bit times (%d ns)\n",
			16, hub->tt.think_time);
		break;
	case HUB_TTTT_24_BITS:
		hub->tt.think_time = 666 * 3;
		dev_dbg(hub_dev, "TT requires at most %d "
				"FS bit times (%d ns)\n",
			24, hub->tt.think_time);
		break;
	case HUB_TTTT_32_BITS:
		hub->tt.think_time = 666 * 4;
		dev_dbg(hub_dev, "TT requires at most %d "
				"FS bit times (%d ns)\n",
			32, hub->tt.think_time);
		break;
	}

	if (wHubCharacteristics & HUB_CHAR_PORTIND) {
		hub->has_indicators = 1;
		dev_dbg(hub_dev, "Port indicators are supported\n");
	}

	dev_dbg(hub_dev, "power on to power good time: %dms\n",
		hub->descriptor->bPwrOn2PwrGood * 2);

	ret = usb_get_status(hdev, USB_RECIP_DEVICE, 0, &hubstatus);
	if (ret) {
		message = "can't get hub status";
		goto fail;
	}
	hcd = bus_to_hcd(hdev->bus);
	if (hdev == hdev->bus->root_hub) {
		if (hcd->power_budget > 0)
			hdev->bus_mA = hcd->power_budget;
		else
			hdev->bus_mA = full_load * maxchild;
		if (hdev->bus_mA >= full_load)
			hub->mA_per_port = full_load;
		else {
			hub->mA_per_port = hdev->bus_mA;
			hub->limited_power = 1;
		}
	} else if ((hubstatus & (1 << USB_DEVICE_SELF_POWERED)) == 0) {
		int remaining = hdev->bus_mA -
			hub->descriptor->bHubContrCurrent;

		dev_dbg(hub_dev, "hub controller current requirement: %dmA\n",
			hub->descriptor->bHubContrCurrent);
		hub->limited_power = 1;

		if (remaining < maxchild * unit_load)
			dev_warn(hub_dev,
					"insufficient power available "
					"to use all downstream ports\n");
		hub->mA_per_port = unit_load;	 

	} else {	 
		 
		hub->mA_per_port = full_load;
	}
	if (hub->mA_per_port < full_load)
		dev_dbg(hub_dev, "%umA bus power budget for each child\n",
				hub->mA_per_port);

	ret = hub_hub_status(hub, &hubstatus, &hubchange);
	if (ret < 0) {
		message = "can't get hub status";
		goto fail;
	}

	if (hdev->actconfig->desc.bmAttributes & USB_CONFIG_ATT_SELFPOWER)
		dev_dbg(hub_dev, "local power source is %s\n",
			(hubstatus & HUB_STATUS_LOCAL_POWER)
			? "lost (inactive)" : "good");

	if ((wHubCharacteristics & HUB_CHAR_OCPM) == 0)
		dev_dbg(hub_dev, "%sover-current condition exists\n",
			(hubstatus & HUB_STATUS_OVERCURRENT) ? "" : "no ");

	pipe = usb_rcvintpipe(hdev, endpoint->bEndpointAddress);
	maxp = usb_maxpacket(hdev, pipe, usb_pipeout(pipe));

	if (maxp > sizeof(*hub->buffer))
		maxp = sizeof(*hub->buffer);

	hub->urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!hub->urb) {
		ret = -ENOMEM;
		goto fail;
	}

	usb_fill_int_urb(hub->urb, hdev, pipe, *hub->buffer, maxp, hub_irq,
		hub, endpoint->bInterval);

	if (hub->has_indicators && blinkenlights)
		hub->indicator[0] = INDICATOR_CYCLE;

	mutex_lock(&usb_port_peer_mutex);
	for (i = 0; i < maxchild; i++) {
		ret = usb_hub_create_port_device(hub, i + 1);
		if (ret < 0) {
			dev_err(hub->intfdev,
				"couldn't create port%d device.\n", i + 1);
			break;
		}
	}
	hdev->maxchild = i;
	for (i = 0; i < hdev->maxchild; i++) {
		struct usb_port *port_dev = hub->ports[i];

		pm_runtime_put(&port_dev->dev);
	}

	mutex_unlock(&usb_port_peer_mutex);
	if (ret < 0)
		goto fail;

	if (hcd->driver->update_hub_device) {
		ret = hcd->driver->update_hub_device(hcd, hdev,
				&hub->tt, GFP_KERNEL);
		if (ret < 0) {
			message = "can't update HCD hub info";
			goto fail;
		}
	}
#ifdef MY_ABC_HERE
	mutex_unlock(&hub_init_mutex);
#endif  

	usb_hub_adjust_deviceremovable(hdev, hub->descriptor);

	hub_activate(hub, HUB_INIT);
	return 0;

fail:
	dev_err(hub_dev, "config failed, %s (err %d)\n",
			message, ret);
	 
#ifdef MY_ABC_HERE
	mutex_unlock(&hub_init_mutex);
#endif  
	return ret;
}

static void hub_release(struct kref *kref)
{
	struct usb_hub *hub = container_of(kref, struct usb_hub, kref);

	usb_put_dev(hub->hdev);
	usb_put_intf(to_usb_interface(hub->intfdev));
	kfree(hub);
}

static unsigned highspeed_hubs;

static void hub_disconnect(struct usb_interface *intf)
{
	struct usb_hub *hub = usb_get_intfdata(intf);
	struct usb_device *hdev = interface_to_usbdev(intf);
	int port1;

	hub->disconnected = 1;
#ifdef MY_ABC_HERE
	del_timer_sync(&hub->ups_discon_flt_timer);
#endif  

	hub->error = 0;
	hub_quiesce(hub, HUB_DISCONNECT);

	mutex_lock(&usb_port_peer_mutex);

	spin_lock_irq(&device_state_lock);
	port1 = hdev->maxchild;
	hdev->maxchild = 0;
	usb_set_intfdata(intf, NULL);
	spin_unlock_irq(&device_state_lock);

	for (; port1 > 0; --port1)
		usb_hub_remove_port_device(hub, port1);

	mutex_unlock(&usb_port_peer_mutex);

	if (hub->hdev->speed == USB_SPEED_HIGH)
		highspeed_hubs--;

	usb_free_urb(hub->urb);
	kfree(hub->ports);
	kfree(hub->descriptor);
	kfree(hub->status);
	kfree(hub->buffer);

	pm_suspend_ignore_children(&intf->dev, false);
	kref_put(&hub->kref, hub_release);
}

#ifdef MY_ABC_HERE
static void ups_discon_flt_work(unsigned long arg)
{
	struct usb_hub *hub = (struct usb_hub *) arg;
	set_bit(hub->ups_discon_flt_port, hub->change_bits);
	hub->ups_discon_flt_status = SYNO_UPS_DISCON_FLT_STATUS_TIMEOUT;
	kick_hub_wq(hub);
}
#endif  

static int hub_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
	struct usb_host_interface *desc;
	struct usb_endpoint_descriptor *endpoint;
	struct usb_device *hdev;
	struct usb_hub *hub;

	desc = intf->cur_altsetting;
	hdev = interface_to_usbdev(intf);

#if defined(CONFIG_USB_ETRON_HUB)
	if (usb_is_etron_hcd(hdev))
		return -ENODEV;
#endif  

#ifdef CONFIG_PM
	if (hdev->dev.power.autosuspend_delay >= 0)
		pm_runtime_set_autosuspend_delay(&hdev->dev, 0);
#endif

	if (hdev->parent) {		 
		usb_enable_autosuspend(hdev);
	} else {			 
		const struct hc_driver *drv = bus_to_hcd(hdev->bus)->driver;

		if (drv->bus_suspend && drv->bus_resume)
			usb_enable_autosuspend(hdev);
	}

	if (hdev->level == MAX_TOPO_LEVEL) {
		dev_err(&intf->dev,
			"Unsupported bus topology: hub nested too deep\n");
		return -E2BIG;
	}

#ifdef	CONFIG_USB_OTG_BLACKLIST_HUB
	if (hdev->parent) {
		dev_warn(&intf->dev, "ignoring external hub\n");
		return -ENODEV;
	}
#endif

	if ((desc->desc.bInterfaceSubClass != 0) &&
	    (desc->desc.bInterfaceSubClass != 1)) {
descriptor_error:
		dev_err(&intf->dev, "bad descriptor, ignoring hub\n");
		return -EIO;
	}

	if (desc->desc.bNumEndpoints != 1)
		goto descriptor_error;

	endpoint = &desc->endpoint[0].desc;

	if (!usb_endpoint_is_int_in(endpoint))
		goto descriptor_error;

	dev_info(&intf->dev, "USB hub found\n");

	hub = kzalloc(sizeof(*hub), GFP_KERNEL);
	if (!hub) {
		dev_dbg(&intf->dev, "couldn't kmalloc hub struct\n");
		return -ENOMEM;
	}

	kref_init(&hub->kref);
	hub->intfdev = &intf->dev;
	hub->hdev = hdev;
	INIT_DELAYED_WORK(&hub->leds, led_work);
	INIT_DELAYED_WORK(&hub->init_work, NULL);
	INIT_WORK(&hub->events, hub_event);
	usb_get_intf(intf);
	usb_get_dev(hdev);

	usb_set_intfdata(intf, hub);
	intf->needs_remote_wakeup = 1;
	pm_suspend_ignore_children(&intf->dev, true);

	if (hdev->speed == USB_SPEED_HIGH)
		highspeed_hubs++;

	if (id->driver_info & HUB_QUIRK_CHECK_PORT_AUTOSUSPEND)
		hub->quirk_check_port_auto_suspend = 1;

#ifdef MY_ABC_HERE
	init_timer(&hub->ups_discon_flt_timer);
	hub->ups_discon_flt_timer.data = (unsigned long) hub;
	hub->ups_discon_flt_timer.function = ups_discon_flt_work;
	hub->ups_discon_flt_last = jiffies - 16 * HZ;
	hub->ups_discon_flt_status = SYNO_UPS_DISCON_FLT_STATUS_NONE;
#endif  

	if (hub_configure(hub, endpoint) >= 0)
		return 0;

	hub_disconnect(intf);
	return -ENODEV;
}

static int
hub_ioctl(struct usb_interface *intf, unsigned int code, void *user_data)
{
	struct usb_device *hdev = interface_to_usbdev(intf);
	struct usb_hub *hub = usb_hub_to_struct_hub(hdev);

	switch (code) {
	case USBDEVFS_HUB_PORTINFO: {
		struct usbdevfs_hub_portinfo *info = user_data;
		int i;

		spin_lock_irq(&device_state_lock);
		if (hdev->devnum <= 0)
			info->nports = 0;
		else {
			info->nports = hdev->maxchild;
			for (i = 0; i < info->nports; i++) {
				if (hub->ports[i]->child == NULL)
					info->port[i] = 0;
				else
					info->port[i] =
						hub->ports[i]->child->devnum;
			}
		}
		spin_unlock_irq(&device_state_lock);

		return info->nports + 1;
		}

	default:
		return -ENOSYS;
	}
}

static int find_port_owner(struct usb_device *hdev, unsigned port1,
		struct usb_dev_state ***ppowner)
{
	struct usb_hub *hub = usb_hub_to_struct_hub(hdev);

	if (hdev->state == USB_STATE_NOTATTACHED)
		return -ENODEV;
	if (port1 == 0 || port1 > hdev->maxchild)
		return -EINVAL;

	*ppowner = &(hub->ports[port1 - 1]->port_owner);
	return 0;
}

int usb_hub_claim_port(struct usb_device *hdev, unsigned port1,
		       struct usb_dev_state *owner)
{
	int rc;
	struct usb_dev_state **powner;

	rc = find_port_owner(hdev, port1, &powner);
	if (rc)
		return rc;
	if (*powner)
		return -EBUSY;
	*powner = owner;
	return rc;
}
EXPORT_SYMBOL_GPL(usb_hub_claim_port);

int usb_hub_release_port(struct usb_device *hdev, unsigned port1,
			 struct usb_dev_state *owner)
{
	int rc;
	struct usb_dev_state **powner;

	rc = find_port_owner(hdev, port1, &powner);
	if (rc)
		return rc;
	if (*powner != owner)
		return -ENOENT;
	*powner = NULL;
	return rc;
}
EXPORT_SYMBOL_GPL(usb_hub_release_port);

void usb_hub_release_all_ports(struct usb_device *hdev, struct usb_dev_state *owner)
{
	struct usb_hub *hub = usb_hub_to_struct_hub(hdev);
	int n;

	for (n = 0; n < hdev->maxchild; n++) {
		if (hub->ports[n]->port_owner == owner)
			hub->ports[n]->port_owner = NULL;
	}

}

bool usb_device_is_owned(struct usb_device *udev)
{
	struct usb_hub *hub;

	if (udev->state == USB_STATE_NOTATTACHED || !udev->parent)
		return false;
	hub = usb_hub_to_struct_hub(udev->parent);
	return !!hub->ports[udev->portnum - 1]->port_owner;
}

static void recursively_mark_NOTATTACHED(struct usb_device *udev)
{
	struct usb_hub *hub = usb_hub_to_struct_hub(udev);
	int i;

	for (i = 0; i < udev->maxchild; ++i) {
		if (hub->ports[i]->child)
			recursively_mark_NOTATTACHED(hub->ports[i]->child);
	}
	if (udev->state == USB_STATE_SUSPENDED)
		udev->active_duration -= jiffies;
	udev->state = USB_STATE_NOTATTACHED;
}

void usb_set_device_state(struct usb_device *udev,
		enum usb_device_state new_state)
{
	unsigned long flags;
	int wakeup = -1;

#if defined(CONFIG_USB_ETRON_HUB)
	if (usb_is_etron_hcd(udev))
		return ethub_usb_set_device_state(udev, new_state);
#endif  

	spin_lock_irqsave(&device_state_lock, flags);
	if (udev->state == USB_STATE_NOTATTACHED)
		;	 
	else if (new_state != USB_STATE_NOTATTACHED) {

		if (udev->parent) {
			if (udev->state == USB_STATE_SUSPENDED
					|| new_state == USB_STATE_SUSPENDED)
				;	 
			else if (new_state == USB_STATE_CONFIGURED)
				wakeup = (udev->quirks &
					USB_QUIRK_IGNORE_REMOTE_WAKEUP) ? 0 :
					udev->actconfig->desc.bmAttributes &
					USB_CONFIG_ATT_WAKEUP;
			else
				wakeup = 0;
		}
		if (udev->state == USB_STATE_SUSPENDED &&
			new_state != USB_STATE_SUSPENDED)
			udev->active_duration -= jiffies;
		else if (new_state == USB_STATE_SUSPENDED &&
				udev->state != USB_STATE_SUSPENDED)
			udev->active_duration += jiffies;
		udev->state = new_state;
	} else
		recursively_mark_NOTATTACHED(udev);
	spin_unlock_irqrestore(&device_state_lock, flags);
	if (wakeup >= 0)
		device_set_wakeup_capable(&udev->dev, wakeup);
}
EXPORT_SYMBOL_GPL(usb_set_device_state);

static void choose_devnum(struct usb_device *udev)
{
	int		devnum;
	struct usb_bus	*bus = udev->bus;

	mutex_lock(&bus->devnum_next_mutex);
	if (udev->wusb) {
		devnum = udev->portnum + 1;
		BUG_ON(test_bit(devnum, bus->devmap.devicemap));
	} else {
		 
		devnum = find_next_zero_bit(bus->devmap.devicemap, 128,
					    bus->devnum_next);
		if (devnum >= 128)
			devnum = find_next_zero_bit(bus->devmap.devicemap,
						    128, 1);
		bus->devnum_next = (devnum >= 127 ? 1 : devnum + 1);
	}
	if (devnum < 128) {
		set_bit(devnum, bus->devmap.devicemap);
		udev->devnum = devnum;
	}
	mutex_unlock(&bus->devnum_next_mutex);
}

static void release_devnum(struct usb_device *udev)
{
	if (udev->devnum > 0) {
		clear_bit(udev->devnum, udev->bus->devmap.devicemap);
		udev->devnum = -1;
	}
}

static void update_devnum(struct usb_device *udev, int devnum)
{
	 
	if (!udev->wusb)
		udev->devnum = devnum;
}

static void hub_free_dev(struct usb_device *udev)
{
	struct usb_hcd *hcd = bus_to_hcd(udev->bus);

	if (hcd->driver->free_dev && udev->parent)
		hcd->driver->free_dev(hcd, udev);
}

static void hub_disconnect_children(struct usb_device *udev)
{
	struct usb_hub *hub = usb_hub_to_struct_hub(udev);
	int i;

	for (i = 0; i < udev->maxchild; i++) {
		if (hub->ports[i]->child)
			usb_disconnect(&hub->ports[i]->child);
	}
}

void usb_disconnect(struct usb_device **pdev)
{
	struct usb_port *port_dev = NULL;
	struct usb_device *udev = *pdev;
	struct usb_hub *hub = NULL;
	int port1 = 1;

#if defined(CONFIG_USB_ETRON_HUB)
	if (usb_is_etron_hcd(*pdev))
		return ethub_usb_disconnect(pdev);
#endif  

	usb_set_device_state(udev, USB_STATE_NOTATTACHED);
	dev_info(&udev->dev, "USB disconnect, device number %d\n",
			udev->devnum);

	usb_lock_device(udev);

	hub_disconnect_children(udev);

	dev_dbg(&udev->dev, "unregistering device\n");
	usb_disable_device(udev, 0);
	usb_hcd_synchronize_unlinks(udev);

	if (udev->parent) {
		port1 = udev->portnum;
		hub = usb_hub_to_struct_hub(udev->parent);
		port_dev = hub->ports[port1 - 1];

		sysfs_remove_link(&udev->dev.kobj, "port");
		sysfs_remove_link(&port_dev->dev.kobj, "device");

		if (!test_and_set_bit(port1, hub->child_usage_bits))
			pm_runtime_get_sync(&port_dev->dev);
	}

	usb_remove_ep_devs(&udev->ep0);
	usb_unlock_device(udev);

	device_del(&udev->dev);

	release_devnum(udev);

	spin_lock_irq(&device_state_lock);
	*pdev = NULL;
	spin_unlock_irq(&device_state_lock);

	if (port_dev && test_and_clear_bit(port1, hub->child_usage_bits))
		pm_runtime_put(&port_dev->dev);

	hub_free_dev(udev);

	put_device(&udev->dev);
}

#ifdef CONFIG_USB_ANNOUNCE_NEW_DEVICES
static void show_string(struct usb_device *udev, char *id, char *string)
{
	if (!string)
		return;
	dev_info(&udev->dev, "%s: %s\n", id, string);
}

static void announce_device(struct usb_device *udev)
{
	dev_info(&udev->dev, "New USB device found, idVendor=%04x, idProduct=%04x\n",
		le16_to_cpu(udev->descriptor.idVendor),
		le16_to_cpu(udev->descriptor.idProduct));
	dev_info(&udev->dev,
		"New USB device strings: Mfr=%d, Product=%d, SerialNumber=%d\n",
		udev->descriptor.iManufacturer,
		udev->descriptor.iProduct,
		udev->descriptor.iSerialNumber);
	show_string(udev, "Product", udev->product);
	show_string(udev, "Manufacturer", udev->manufacturer);
	show_string(udev, "SerialNumber", udev->serial);
}
#else
static inline void announce_device(struct usb_device *udev) { }
#endif

static int usb_enumerate_device_otg(struct usb_device *udev)
{
	int err = 0;

#ifdef	CONFIG_USB_OTG
	 
	if (!udev->bus->is_b_host
			&& udev->config
			&& udev->parent == udev->bus->root_hub) {
		struct usb_otg_descriptor	*desc = NULL;
		struct usb_bus			*bus = udev->bus;
		unsigned			port1 = udev->portnum;

		err = __usb_get_extra_descriptor(udev->rawdescriptors[0],
				le16_to_cpu(udev->config[0].desc.wTotalLength),
				USB_DT_OTG, (void **) &desc);
		if (err || !(desc->bmAttributes & USB_OTG_HNP))
			return 0;

		dev_info(&udev->dev, "Dual-Role OTG device on %sHNP port\n",
					(port1 == bus->otg_port) ? "" : "non-");

		if (port1 == bus->otg_port) {
			bus->b_hnp_enable = 1;
			err = usb_control_msg(udev,
				usb_sndctrlpipe(udev, 0),
				USB_REQ_SET_FEATURE, 0,
				USB_DEVICE_B_HNP_ENABLE,
				0, NULL, 0,
				USB_CTRL_SET_TIMEOUT);
			if (err < 0) {
				 
				dev_err(&udev->dev, "can't set HNP mode: %d\n",
									err);
				bus->b_hnp_enable = 0;
			}
		} else if (desc->bLength == sizeof
				(struct usb_otg_descriptor)) {
			 
			err = usb_control_msg(udev,
				usb_sndctrlpipe(udev, 0),
				USB_REQ_SET_FEATURE, 0,
				USB_DEVICE_A_ALT_HNP_SUPPORT,
				0, NULL, 0,
				USB_CTRL_SET_TIMEOUT);
			if (err < 0)
				dev_err(&udev->dev,
					"set a_alt_hnp_support failed: %d\n",
					err);
		}
	}
#endif
	return err;
}

static int usb_enumerate_device(struct usb_device *udev)
{
	int err;
	struct usb_hcd *hcd = bus_to_hcd(udev->bus);

	if (udev->config == NULL) {
		err = usb_get_configuration(udev);
		if (err < 0) {
			if (err != -ENODEV)
				dev_err(&udev->dev, "can't read configurations, error %d\n",
						err);
			return err;
		}
	}

	udev->product = usb_cache_string(udev, udev->descriptor.iProduct);
	udev->manufacturer = usb_cache_string(udev,
					      udev->descriptor.iManufacturer);
	udev->serial = usb_cache_string(udev, udev->descriptor.iSerialNumber);
#ifdef MY_ABC_HERE
	 
	udev->syno_old_serial = udev->serial;
#endif  

	err = usb_enumerate_device_otg(udev);
	if (err < 0)
		return err;

	if (IS_ENABLED(CONFIG_USB_OTG_WHITELIST) && hcd->tpl_support &&
		!is_targeted(udev)) {
		 
		if (IS_ENABLED(CONFIG_USB_OTG) && (udev->bus->b_hnp_enable
			|| udev->bus->is_b_host)) {
			err = usb_port_suspend(udev, PMSG_AUTO_SUSPEND);
			if (err < 0)
				dev_dbg(&udev->dev, "HNP fail, %d\n", err);
		}
		return -ENOTSUPP;
	}

	usb_detect_interface_quirks(udev);

	return 0;
}

#ifdef MY_ABC_HERE
 
static int device_serial_match(struct usb_device *dev, struct usb_device *udev_search)
{
	int child, match = 0;
	struct usb_device *childdev;

	usb_hub_for_each_child(dev, child, childdev) {
		if (childdev && childdev != udev_search && childdev->serial) {

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
			if (0 == is_syno_ext_hub(childdev)) {
				continue;
			}
#endif  
			 
			if (childdev->serial[0] && strcmp(childdev->serial, udev_search->serial) == 0) {
				match++;
			} else {
				match = device_serial_match(childdev, udev_search);
			}

			if (match) {
				break;
			}
		}
	}
	return match;
}
#endif  

static void set_usb_port_removable(struct usb_device *udev)
{
	struct usb_device *hdev = udev->parent;
	struct usb_hub *hub;
	u8 port = udev->portnum;
	u16 wHubCharacteristics;
	bool removable = true;

	if (!hdev)
		return;

	hub = usb_hub_to_struct_hub(udev->parent);

	switch (hub->ports[udev->portnum - 1]->connect_type) {
	case USB_PORT_CONNECT_TYPE_HOT_PLUG:
		udev->removable = USB_DEVICE_REMOVABLE;
		return;
	case USB_PORT_CONNECT_TYPE_HARD_WIRED:
	case USB_PORT_NOT_USED:
		udev->removable = USB_DEVICE_FIXED;
		return;
	default:
		break;
	}

	wHubCharacteristics = le16_to_cpu(hub->descriptor->wHubCharacteristics);

	if (!(wHubCharacteristics & HUB_CHAR_COMPOUND))
		return;

	if (hub_is_superspeed(hdev)) {
		if (le16_to_cpu(hub->descriptor->u.ss.DeviceRemovable)
				& (1 << port))
			removable = false;
	} else {
		if (hub->descriptor->u.hs.DeviceRemovable[port / 8] & (1 << (port % 8)))
			removable = false;
	}

	if (removable)
		udev->removable = USB_DEVICE_REMOVABLE;
	else
		udev->removable = USB_DEVICE_FIXED;

}

int usb_new_device(struct usb_device *udev)
{
	int err;

#if defined(CONFIG_USB_ETRON_HUB)
	if (usb_is_etron_hcd(udev))
		return ethub_usb_new_device(udev);
#endif  

	if (udev->parent) {
		 
		device_init_wakeup(&udev->dev, 0);
	}

	pm_runtime_set_active(&udev->dev);
	pm_runtime_get_noresume(&udev->dev);
	pm_runtime_use_autosuspend(&udev->dev);
	pm_runtime_enable(&udev->dev);

	usb_disable_autosuspend(udev);

	err = usb_enumerate_device(udev);	 
	if (err < 0)
		goto fail;
	dev_dbg(&udev->dev, "udev %d, busnum %d, minor = %d\n",
			udev->devnum, udev->bus->busnum,
			(((udev->bus->busnum-1) * 128) + (udev->devnum-1)));
	 
	udev->dev.devt = MKDEV(USB_DEVICE_MAJOR,
			(((udev->bus->busnum-1) * 128) + (udev->devnum-1)));

#ifdef MY_ABC_HERE
#define SERIAL_LEN 33
	 
	if ( NULL == udev->product ) {
		udev->product = kmalloc(16, GFP_KERNEL);
		if (NULL != udev->product) {
			snprintf(udev->product, 16, "USBDevice");
		}
	}

	if (NULL == udev->serial && NULL != udev->product) {
		int i;
		char seed = 0xb4;  

		udev->serial = kmalloc(SERIAL_LEN, GFP_KERNEL);
		if (NULL != udev->serial) {
			const int cProductLen = strlen(udev->product);

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
			if (0 == is_syno_ext_hub(udev)) {
				snprintf(udev->serial, SERIAL_LEN, "%s", SYNO_SERIAL_EXT_HUB);
				printk("Set serial number \"%s\" for Synology External hub.\n",udev->serial);
			} else {
#endif  
			printk("Got empty serial number. "
					"Generate serial number from product.\n");
			udev->serial[0] = '\0';
			for(i = 0; (i < cProductLen) && (i < (SERIAL_LEN-1)/2); i++) {
				snprintf(udev->serial + strlen(udev->serial),
					   SERIAL_LEN - strlen(udev->serial),
					   "%02x", (seed ^= udev->product[cProductLen-i-1]));
			}
			udev->serial[SERIAL_LEN-1] = '\0';
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
			}
#endif  
		}
	}

	if (udev->parent && udev->serial) {
		int match, counter = 0;
		struct list_head *buslist;
		struct usb_bus *bus;

RETRY:
		match = 0;
		for (buslist = usb_bus_list.next;
			  buslist != &usb_bus_list;
			  buslist = buslist->next) {

			bus = container_of(buslist, struct usb_bus, bus_list);
			if (!bus->root_hub)
				continue;

			mutex_lock(&hub_init_mutex);
			match = device_serial_match(bus->root_hub, udev);
			mutex_unlock(&hub_init_mutex);

			if (match) {
				break;
			}
		}
		if (match) {
			int Len = strlen(udev->serial);

			if (Len == 0) {
				printk("USB serial length is 0!\n");
			} else if (counter > 9) {
				printk("There are to many same devices (%d)\n", counter);
			} else {
#if defined(MY_ABC_HERE)
				 
				udev->syno_old_serial = kmalloc(Len, GFP_KERNEL);
				memcpy(udev->syno_old_serial, udev->serial, Len);
#endif  
				udev->serial[Len - 1] = counter + '0';
				udev->serial[Len] = '\0';
				printk("%s (%d) Same device found. Change serial to %s \n",
						__FILE__, __LINE__, udev->serial);

				counter++;
				goto RETRY;
			}
		}
	}
#endif  

	announce_device(udev);

	if (udev->serial)
		add_device_randomness(udev->serial, strlen(udev->serial));
	if (udev->product)
		add_device_randomness(udev->product, strlen(udev->product));
	if (udev->manufacturer)
		add_device_randomness(udev->manufacturer,
				      strlen(udev->manufacturer));

	device_enable_async_suspend(&udev->dev);

	if (udev->parent)
		set_usb_port_removable(udev);

	err = device_add(&udev->dev);
	if (err) {
		dev_err(&udev->dev, "can't device_add, error %d\n", err);
		goto fail;
	}

	if (udev->parent) {
		struct usb_hub *hub = usb_hub_to_struct_hub(udev->parent);
		int port1 = udev->portnum;
		struct usb_port	*port_dev = hub->ports[port1 - 1];

		err = sysfs_create_link(&udev->dev.kobj,
				&port_dev->dev.kobj, "port");
		if (err)
			goto fail;

		err = sysfs_create_link(&port_dev->dev.kobj,
				&udev->dev.kobj, "device");
		if (err) {
			sysfs_remove_link(&udev->dev.kobj, "port");
			goto fail;
		}

		if (!test_and_set_bit(port1, hub->child_usage_bits))
			pm_runtime_get_sync(&port_dev->dev);
	}

	(void) usb_create_ep_devs(&udev->dev, &udev->ep0, udev);
	usb_mark_last_busy(udev);
	pm_runtime_put_sync_autosuspend(&udev->dev);
	return err;

fail:
	usb_set_device_state(udev, USB_STATE_NOTATTACHED);
	pm_runtime_disable(&udev->dev);
	pm_runtime_set_suspended(&udev->dev);
	return err;
}

int usb_deauthorize_device(struct usb_device *usb_dev)
{
	usb_lock_device(usb_dev);
	if (usb_dev->authorized == 0)
		goto out_unauthorized;

	usb_dev->authorized = 0;
	usb_set_configuration(usb_dev, -1);

out_unauthorized:
	usb_unlock_device(usb_dev);
	return 0;
}

int usb_authorize_device(struct usb_device *usb_dev)
{
	int result = 0, c;

	usb_lock_device(usb_dev);
	if (usb_dev->authorized == 1)
		goto out_authorized;

	result = usb_autoresume_device(usb_dev);
	if (result < 0) {
		dev_err(&usb_dev->dev,
			"can't autoresume for authorization: %d\n", result);
		goto error_autoresume;
	}

	if (usb_dev->wusb) {
		result = usb_get_device_descriptor(usb_dev, sizeof(usb_dev->descriptor));
		if (result < 0) {
			dev_err(&usb_dev->dev, "can't re-read device descriptor for "
				"authorization: %d\n", result);
			goto error_device_descriptor;
		}
	}

	usb_dev->authorized = 1;
	 
	c = usb_choose_configuration(usb_dev);
	if (c >= 0) {
		result = usb_set_configuration(usb_dev, c);
		if (result) {
			dev_err(&usb_dev->dev,
				"can't set config #%d, error %d\n", c, result);
			 
		}
	}
	dev_info(&usb_dev->dev, "authorized to connect\n");

error_device_descriptor:
	usb_autosuspend_device(usb_dev);
error_autoresume:
out_authorized:
	usb_unlock_device(usb_dev);	 
	return result;
}

static unsigned hub_is_wusb(struct usb_hub *hub)
{
	struct usb_hcd *hcd;
	if (hub->hdev->parent != NULL)   
		return 0;
	hcd = container_of(hub->hdev->bus, struct usb_hcd, self);
	return hcd->wireless;
}

#define PORT_RESET_TRIES	5
#define SET_ADDRESS_TRIES	2
#define GET_DESCRIPTOR_TRIES	2
#define SET_CONFIG_TRIES	(2 * (use_both_schemes + 1))
#define USE_NEW_SCHEME(i)	((i) / 2 == (int)old_scheme_first)

#define HUB_ROOT_RESET_TIME	50	 
#define HUB_SHORT_RESET_TIME	10
#define HUB_BH_RESET_TIME	50
#define HUB_LONG_RESET_TIME	200
#ifdef MY_ABC_HERE
#define HUB_SYNO_RESET_TIMEOUT   3000
#endif  
#define HUB_RESET_TIMEOUT	800

#if defined (MY_ABC_HERE)
#define SYNO_HUB_SPEED_MORPH_RESET_TRIES	(3)
#define SYNO_HUB_SPEED_MORPH_TRIES	(5)
#endif  

#ifdef MY_ABC_HERE
 
#define HUB_SYNO_ROOT_RESET_TIME	1000
#endif  

static bool use_new_scheme(struct usb_device *udev, int retry)
{
	if (udev->speed >= USB_SPEED_SUPER)
		return false;

	return USE_NEW_SCHEME(retry);
}

static bool hub_port_warm_reset_required(struct usb_hub *hub, int port1,
		u16 portstatus)
{
	u16 link_state;

	if (!hub_is_superspeed(hub->hdev))
		return false;

	if (test_bit(port1, hub->warm_reset_bits))
		return true;

	link_state = portstatus & USB_PORT_STAT_LINK_STATE;
	return link_state == USB_SS_PORT_LS_SS_INACTIVE
		|| link_state == USB_SS_PORT_LS_COMP_MOD;
}

static int hub_port_wait_reset(struct usb_hub *hub, int port1,
			struct usb_device *udev, unsigned int delay, bool warm)
{
	int delay_time, ret;
	u16 portstatus;
	u16 portchange;

#ifdef MY_ABC_HERE
	 
	msleep(20);
#endif  

	for (delay_time = 0;
#ifdef MY_ABC_HERE
			delay_time < HUB_SYNO_RESET_TIMEOUT;
#else
			delay_time < HUB_RESET_TIMEOUT;
#endif  
			delay_time += delay) {
		 
		msleep(delay);

		ret = hub_port_status(hub, port1, &portstatus, &portchange);
		if (ret < 0)
			return ret;

		if (!(portstatus & USB_PORT_STAT_RESET))
			break;

#ifdef MY_ABC_HERE
		 
		if (delay_time >= HUB_RESET_TIMEOUT)
			delay = HUB_SYNO_ROOT_RESET_TIME;
		else
#endif  
		 
		if (delay_time >= 2 * HUB_SHORT_RESET_TIME)
			delay = HUB_LONG_RESET_TIME;

		dev_dbg(&hub->ports[port1 - 1]->dev,
				"not %sreset yet, waiting %dms\n",
				warm ? "warm " : "", delay);
	}

#ifdef MY_ABC_HERE
	 
	if ((portstatus & USB_PORT_STAT_CONNECTION) &&
		(portstatus & USB_PORT_STAT_RESET))
		return -EBUSY;
#else  
	if ((portstatus & USB_PORT_STAT_RESET))
		return -EBUSY;
#endif  

	if (hub_port_warm_reset_required(hub, port1, portstatus))
		return -ENOTCONN;

	if (!(portstatus & USB_PORT_STAT_CONNECTION))
		return -ENOTCONN;

	if (!hub_is_superspeed(hub->hdev) &&
			(portchange & USB_PORT_STAT_C_CONNECTION))
#ifdef MY_ABC_HERE
	{
		usb_clear_port_feature(hub->hdev, port1,
				USB_PORT_FEAT_C_CONNECTION);
		if (portchange & USB_PORT_STAT_C_ENABLE)
			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_ENABLE);
		return -SYNO_CONNECT_BOUNCE;
	}
#else  
		return -ENOTCONN;
#endif  

	if (!(portstatus & USB_PORT_STAT_ENABLE))
		return -EBUSY;

	if (!udev)
		return 0;

	if (hub_is_wusb(hub))
		udev->speed = USB_SPEED_WIRELESS;
	else if (hub_is_superspeed(hub->hdev))
		udev->speed = USB_SPEED_SUPER;
	else if (portstatus & USB_PORT_STAT_HIGH_SPEED)
		udev->speed = USB_SPEED_HIGH;
	else if (portstatus & USB_PORT_STAT_LOW_SPEED)
		udev->speed = USB_SPEED_LOW;
	else
		udev->speed = USB_SPEED_FULL;
	return 0;
}

static int hub_port_reset(struct usb_hub *hub, int port1,
			struct usb_device *udev, unsigned int delay, bool warm)
{
	int i, status;
	u16 portchange, portstatus;
	struct usb_port *port_dev = hub->ports[port1 - 1];

	if (!hub_is_superspeed(hub->hdev)) {
		if (warm) {
			dev_err(hub->intfdev, "only USB3 hub support "
						"warm reset\n");
			return -EINVAL;
		}
		 
		down_read(&ehci_cf_port_reset_rwsem);
	} else if (!warm) {
		 
		if (hub_port_status(hub, port1, &portstatus, &portchange) == 0)
			if (hub_port_warm_reset_required(hub, port1,
							portstatus))
				warm = true;
	}
	clear_bit(port1, hub->warm_reset_bits);

	for (i = 0; i < PORT_RESET_TRIES; i++) {
		status = set_port_feature(hub->hdev, port1, (warm ?
					USB_PORT_FEAT_BH_PORT_RESET :
					USB_PORT_FEAT_RESET));
		if (status == -ENODEV) {
			;	 
		} else if (status) {
			dev_err(&port_dev->dev,
					"cannot %sreset (err = %d)\n",
					warm ? "warm " : "", status);
		} else {
			status = hub_port_wait_reset(hub, port1, udev, delay,
								warm);
			if (status && status != -ENOTCONN && status != -ENODEV)
				dev_dbg(hub->intfdev,
						"port_wait_reset: err = %d\n",
						status);
		}

		if ((status == 0 || status == -ENOTCONN || status == -ENODEV)
#ifdef MY_ABC_HERE
				&& -SYNO_CONNECT_BOUNCE != status
#endif  
			) {
			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_RESET);

			if (!hub_is_superspeed(hub->hdev))
				goto done;

			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_BH_PORT_RESET);
			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_PORT_LINK_STATE);
			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_CONNECTION);

			if (hub_port_status(hub, port1,
					&portstatus, &portchange) < 0)
				goto done;

			if (!hub_port_warm_reset_required(hub, port1,
					portstatus))
				goto done;

			if (!warm) {
				dev_dbg(&port_dev->dev,
						"hot reset failed, warm reset\n");
				warm = true;
			}
		}

		dev_dbg(&port_dev->dev,
				"not enabled, trying %sreset again...\n",
				warm ? "warm " : "");
		delay = HUB_LONG_RESET_TIME;
	}

	dev_err(&port_dev->dev, "Cannot enable. Maybe the USB cable is bad?\n");

done:
	if (status == 0) {
		 
		msleep(10 + 40);
		if (udev) {
			struct usb_hcd *hcd = bus_to_hcd(udev->bus);

			update_devnum(udev, 0);
			 
			if (hcd->driver->reset_device)
				hcd->driver->reset_device(hcd, udev);

			usb_set_device_state(udev, USB_STATE_DEFAULT);
		}
	} else {
		if (udev)
			usb_set_device_state(udev, USB_STATE_NOTATTACHED);
	}

	if (!hub_is_superspeed(hub->hdev))
		up_read(&ehci_cf_port_reset_rwsem);

	return status;
}

static int port_is_power_on(struct usb_hub *hub, unsigned portstatus)
{
	int ret = 0;

	if (hub_is_superspeed(hub->hdev)) {
		if (portstatus & USB_SS_PORT_STAT_POWER)
			ret = 1;
	} else {
		if (portstatus & USB_PORT_STAT_POWER)
			ret = 1;
	}

	return ret;
}

static void usb_lock_port(struct usb_port *port_dev)
		__acquires(&port_dev->status_lock)
{
	mutex_lock(&port_dev->status_lock);
	__acquire(&port_dev->status_lock);
}

static void usb_unlock_port(struct usb_port *port_dev)
		__releases(&port_dev->status_lock)
{
	mutex_unlock(&port_dev->status_lock);
	__release(&port_dev->status_lock);
}

#ifdef	CONFIG_PM

static int port_is_suspended(struct usb_hub *hub, unsigned portstatus)
{
	int ret = 0;

	if (hub_is_superspeed(hub->hdev)) {
		if ((portstatus & USB_PORT_STAT_LINK_STATE)
				== USB_SS_PORT_LS_U3)
			ret = 1;
	} else {
		if (portstatus & USB_PORT_STAT_SUSPEND)
			ret = 1;
	}

	return ret;
}

static int check_port_resume_type(struct usb_device *udev,
		struct usb_hub *hub, int port1,
		int status, u16 portchange, u16 portstatus)
{
	struct usb_port *port_dev = hub->ports[port1 - 1];
	int retries = 3;

 retry:
	 
	if (status == 0 && udev->reset_resume
		&& hub_port_warm_reset_required(hub, port1, portstatus)) {
		 ;
	}
	 
	else if (status || port_is_suspended(hub, portstatus) ||
			!port_is_power_on(hub, portstatus)) {
		if (status >= 0)
			status = -ENODEV;
	} else if (!(portstatus & USB_PORT_STAT_CONNECTION)) {
		if (retries--) {
			usleep_range(200, 300);
			status = hub_port_status(hub, port1, &portstatus,
							     &portchange);
			goto retry;
		}
		status = -ENODEV;
	}

	else if (!(portstatus & USB_PORT_STAT_ENABLE) && !udev->reset_resume) {
		if (udev->persist_enabled)
			udev->reset_resume = 1;
		else
			status = -ENODEV;
	}

	if (status) {
		dev_dbg(&port_dev->dev, "status %04x.%04x after resume, %d\n",
				portchange, portstatus, status);
	} else if (udev->reset_resume) {

		if (portchange & USB_PORT_STAT_C_CONNECTION)
			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_CONNECTION);
		if (portchange & USB_PORT_STAT_C_ENABLE)
			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_ENABLE);
	}

	return status;
}

int usb_disable_ltm(struct usb_device *udev)
{
	struct usb_hcd *hcd = bus_to_hcd(udev->bus);

	if (!usb_device_supports_ltm(hcd->self.root_hub) ||
			!usb_device_supports_ltm(udev))
		return 0;

	if (!udev->actconfig)
		return 0;

	return usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			USB_REQ_CLEAR_FEATURE, USB_RECIP_DEVICE,
			USB_DEVICE_LTM_ENABLE, 0, NULL, 0,
			USB_CTRL_SET_TIMEOUT);
}
EXPORT_SYMBOL_GPL(usb_disable_ltm);

void usb_enable_ltm(struct usb_device *udev)
{
	struct usb_hcd *hcd = bus_to_hcd(udev->bus);

	if (!usb_device_supports_ltm(hcd->self.root_hub) ||
			!usb_device_supports_ltm(udev))
		return;

	if (!udev->actconfig)
		return;

	usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			USB_REQ_SET_FEATURE, USB_RECIP_DEVICE,
			USB_DEVICE_LTM_ENABLE, 0, NULL, 0,
			USB_CTRL_SET_TIMEOUT);
}
EXPORT_SYMBOL_GPL(usb_enable_ltm);

static int usb_enable_remote_wakeup(struct usb_device *udev)
{
	if (udev->speed < USB_SPEED_SUPER)
		return usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
				USB_REQ_SET_FEATURE, USB_RECIP_DEVICE,
				USB_DEVICE_REMOTE_WAKEUP, 0, NULL, 0,
				USB_CTRL_SET_TIMEOUT);
	else
		return usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
				USB_REQ_SET_FEATURE, USB_RECIP_INTERFACE,
				USB_INTRF_FUNC_SUSPEND,
				USB_INTRF_FUNC_SUSPEND_RW |
					USB_INTRF_FUNC_SUSPEND_LP,
				NULL, 0, USB_CTRL_SET_TIMEOUT);
}

static int usb_disable_remote_wakeup(struct usb_device *udev)
{
	if (udev->speed < USB_SPEED_SUPER)
		return usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
				USB_REQ_CLEAR_FEATURE, USB_RECIP_DEVICE,
				USB_DEVICE_REMOTE_WAKEUP, 0, NULL, 0,
				USB_CTRL_SET_TIMEOUT);
	else
		return usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
				USB_REQ_CLEAR_FEATURE, USB_RECIP_INTERFACE,
				USB_INTRF_FUNC_SUSPEND,	0, NULL, 0,
				USB_CTRL_SET_TIMEOUT);
}

static unsigned wakeup_enabled_descendants(struct usb_device *udev)
{
	struct usb_hub *hub = usb_hub_to_struct_hub(udev);

	return udev->do_remote_wakeup +
			(hub ? hub->wakeup_enabled_descendants : 0);
}

int usb_port_suspend(struct usb_device *udev, pm_message_t msg)
{
	struct usb_hub	*hub = usb_hub_to_struct_hub(udev->parent);
	struct usb_port *port_dev = hub->ports[udev->portnum - 1];
	int		port1 = udev->portnum;
	int		status;
	bool		really_suspend = true;

#if defined(CONFIG_USB_ETRON_HUB)
	if (usb_is_etron_hcd(udev))
		return ethub_usb_port_suspend(udev, msg);
#endif  

	usb_lock_port(port_dev);

	if (udev->do_remote_wakeup) {
		status = usb_enable_remote_wakeup(udev);
		if (status) {
			dev_dbg(&udev->dev, "won't remote wakeup, status %d\n",
					status);
			 
			if (PMSG_IS_AUTO(msg))
				goto err_wakeup;
		}
	}

	if (udev->usb2_hw_lpm_enabled == 1)
		usb_set_usb2_hardware_lpm(udev, 0);

	if (usb_disable_ltm(udev)) {
		dev_err(&udev->dev, "Failed to disable LTM before suspend\n.");
		status = -ENOMEM;
		if (PMSG_IS_AUTO(msg))
			goto err_ltm;
	}
	if (usb_unlocked_disable_lpm(udev)) {
		dev_err(&udev->dev, "Failed to disable LPM before suspend\n.");
		status = -ENOMEM;
		if (PMSG_IS_AUTO(msg))
			goto err_lpm3;
	}

	if (hub_is_superspeed(hub->hdev))
		status = hub_set_port_link_state(hub, port1, USB_SS_PORT_LS_U3);

	else if (PMSG_IS_AUTO(msg) || wakeup_enabled_descendants(udev) > 0)
		status = set_port_feature(hub->hdev, port1,
				USB_PORT_FEAT_SUSPEND);
	else {
		really_suspend = false;
		status = 0;
	}
	if (status) {
		dev_dbg(&port_dev->dev, "can't suspend, status %d\n", status);

		usb_unlocked_enable_lpm(udev);
 err_lpm3:
		usb_enable_ltm(udev);
 err_ltm:
		 
		if (udev->usb2_hw_lpm_capable == 1)
			usb_set_usb2_hardware_lpm(udev, 1);

		if (udev->do_remote_wakeup)
			(void) usb_disable_remote_wakeup(udev);
 err_wakeup:

		if (!PMSG_IS_AUTO(msg))
			status = 0;
	} else {
		dev_dbg(&udev->dev, "usb %ssuspend, wakeup %d\n",
				(PMSG_IS_AUTO(msg) ? "auto-" : ""),
				udev->do_remote_wakeup);
		if (really_suspend) {
			udev->port_is_suspended = 1;

			msleep(10);
		}
		usb_set_device_state(udev, USB_STATE_SUSPENDED);
	}

	if (status == 0 && !udev->do_remote_wakeup && udev->persist_enabled
			&& test_and_clear_bit(port1, hub->child_usage_bits))
		pm_runtime_put_sync(&port_dev->dev);

	usb_mark_last_busy(hub->hdev);

	usb_unlock_port(port_dev);
	return status;
}

static int finish_port_resume(struct usb_device *udev)
{
	int	status = 0;
	u16	devstatus = 0;

	dev_dbg(&udev->dev, "%s\n",
		udev->reset_resume ? "finish reset-resume" : "finish resume");

	usb_set_device_state(udev, udev->actconfig
			? USB_STATE_CONFIGURED
			: USB_STATE_ADDRESS);

	if (udev->reset_resume) {
		 
 retry_reset_resume:
		if (udev->quirks & USB_QUIRK_RESET)
			status = -ENODEV;
		else
			status = usb_reset_and_verify_device(udev);
	}

	if (status == 0) {
		devstatus = 0;
		status = usb_get_status(udev, USB_RECIP_DEVICE, 0, &devstatus);

		if (status && !udev->reset_resume && udev->persist_enabled) {
			dev_dbg(&udev->dev, "retry with reset-resume\n");
			udev->reset_resume = 1;
			goto retry_reset_resume;
		}
	}

	if (status) {
		dev_dbg(&udev->dev, "gone after usb resume? status %d\n",
				status);
	 
	} else if (udev->actconfig && !udev->reset_resume) {
		if (udev->speed < USB_SPEED_SUPER) {
			if (devstatus & (1 << USB_DEVICE_REMOTE_WAKEUP))
				status = usb_disable_remote_wakeup(udev);
		} else {
			status = usb_get_status(udev, USB_RECIP_INTERFACE, 0,
					&devstatus);
			if (!status && devstatus & (USB_INTRF_STAT_FUNC_RW_CAP
					| USB_INTRF_STAT_FUNC_RW))
				status = usb_disable_remote_wakeup(udev);
		}

		if (status)
			dev_dbg(&udev->dev,
				"disable remote wakeup, status %d\n",
				status);
		status = 0;
	}
	return status;
}

static int wait_for_ss_port_enable(struct usb_device *udev,
		struct usb_hub *hub, int *port1,
		u16 *portchange, u16 *portstatus)
{
	int status = 0, delay_ms = 0;

	while (delay_ms < 2000) {
		if (status || *portstatus & USB_PORT_STAT_CONNECTION)
			break;
		msleep(20);
		delay_ms += 20;
		status = hub_port_status(hub, *port1, portstatus, portchange);
	}
	return status;
}

int usb_port_resume(struct usb_device *udev, pm_message_t msg)
{
	struct usb_hub	*hub = usb_hub_to_struct_hub(udev->parent);
	struct usb_port *port_dev = hub->ports[udev->portnum  - 1];
	int		port1 = udev->portnum;
	int		status;
	u16		portchange, portstatus;

#if defined(CONFIG_USB_ETRON_HUB)
	if (usb_is_etron_hcd(udev))
		return ethub_usb_port_resume(udev, msg);
#endif  

	if (!test_and_set_bit(port1, hub->child_usage_bits)) {
		status = pm_runtime_get_sync(&port_dev->dev);
		if (status < 0) {
			dev_dbg(&udev->dev, "can't resume usb port, status %d\n",
					status);
			return status;
		}
	}

	usb_lock_port(port_dev);

	status = hub_port_status(hub, port1, &portstatus, &portchange);
	if (status == 0 && !port_is_suspended(hub, portstatus))
		goto SuspendCleared;

	if (hub_is_superspeed(hub->hdev))
		status = hub_set_port_link_state(hub, port1, USB_SS_PORT_LS_U0);
	else
		status = usb_clear_port_feature(hub->hdev,
				port1, USB_PORT_FEAT_SUSPEND);
	if (status) {
		dev_dbg(&port_dev->dev, "can't resume, status %d\n", status);
	} else {
		 
		dev_dbg(&udev->dev, "usb %sresume\n",
				(PMSG_IS_AUTO(msg) ? "auto-" : ""));
		msleep(USB_RESUME_TIMEOUT);

		status = hub_port_status(hub, port1, &portstatus, &portchange);

		msleep(10);
	}

 SuspendCleared:
	if (status == 0) {
		udev->port_is_suspended = 0;
		if (hub_is_superspeed(hub->hdev)) {
			if (portchange & USB_PORT_STAT_C_LINK_STATE)
				usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_PORT_LINK_STATE);
		} else {
			if (portchange & USB_PORT_STAT_C_SUSPEND)
				usb_clear_port_feature(hub->hdev, port1,
						USB_PORT_FEAT_C_SUSPEND);
		}
	}

	if (udev->persist_enabled && hub_is_superspeed(hub->hdev))
		status = wait_for_ss_port_enable(udev, hub, &port1, &portchange,
				&portstatus);

	status = check_port_resume_type(udev,
			hub, port1, status, portchange, portstatus);
	if (status == 0)
		status = finish_port_resume(udev);
	if (status < 0) {
		dev_dbg(&udev->dev, "can't resume, status %d\n", status);
		hub_port_logical_disconnect(hub, port1);
	} else  {
		 
		if (udev->usb2_hw_lpm_capable == 1)
			usb_set_usb2_hardware_lpm(udev, 1);

		usb_enable_ltm(udev);
		usb_unlocked_enable_lpm(udev);
	}

	usb_unlock_port(port_dev);

	return status;
}

int usb_remote_wakeup(struct usb_device *udev)
{
	int	status = 0;

	usb_lock_device(udev);
	if (udev->state == USB_STATE_SUSPENDED) {
		dev_dbg(&udev->dev, "usb %sresume\n", "wakeup-");
		status = usb_autoresume_device(udev);
		if (status == 0) {
			 
			usb_autosuspend_device(udev);
		}
	}
	usb_unlock_device(udev);
	return status;
}

static int hub_handle_remote_wakeup(struct usb_hub *hub, unsigned int port,
		u16 portstatus, u16 portchange)
		__must_hold(&port_dev->status_lock)
{
	struct usb_port *port_dev = hub->ports[port - 1];
	struct usb_device *hdev;
	struct usb_device *udev;
	int connect_change = 0;
	int ret;

	hdev = hub->hdev;
	udev = port_dev->child;
	if (!hub_is_superspeed(hdev)) {
		if (!(portchange & USB_PORT_STAT_C_SUSPEND))
			return 0;
		usb_clear_port_feature(hdev, port, USB_PORT_FEAT_C_SUSPEND);
	} else {
		if (!udev || udev->state != USB_STATE_SUSPENDED ||
				 (portstatus & USB_PORT_STAT_LINK_STATE) !=
				 USB_SS_PORT_LS_U0)
			return 0;
	}

	if (udev) {
		 
		msleep(10);

		usb_unlock_port(port_dev);
		ret = usb_remote_wakeup(udev);
		usb_lock_port(port_dev);
		if (ret < 0)
			connect_change = 1;
	} else {
		ret = -ENODEV;
		hub_port_disable(hub, port, 1);
	}
	dev_dbg(&port_dev->dev, "resume, status %d\n", ret);
	return connect_change;
}

static int check_ports_changed(struct usb_hub *hub)
{
	int port1;

	for (port1 = 1; port1 <= hub->hdev->maxchild; ++port1) {
		u16 portstatus, portchange;
		int status;

		status = hub_port_status(hub, port1, &portstatus, &portchange);
		if (!status && portchange)
			return 1;
	}
	return 0;
}

static int hub_suspend(struct usb_interface *intf, pm_message_t msg)
{
	struct usb_hub		*hub = usb_get_intfdata(intf);
	struct usb_device	*hdev = hub->hdev;
	unsigned		port1;
	int			status;

	hub->wakeup_enabled_descendants = 0;
	for (port1 = 1; port1 <= hdev->maxchild; port1++) {
		struct usb_port *port_dev = hub->ports[port1 - 1];
		struct usb_device *udev = port_dev->child;

		if (udev && udev->can_submit) {
			dev_warn(&port_dev->dev, "device %s not suspended yet\n",
					dev_name(&udev->dev));
			if (PMSG_IS_AUTO(msg))
				return -EBUSY;
		}
		if (udev)
			hub->wakeup_enabled_descendants +=
					wakeup_enabled_descendants(udev);
	}

	if (hdev->do_remote_wakeup && hub->quirk_check_port_auto_suspend) {
		 
		if (check_ports_changed(hub)) {
			if (PMSG_IS_AUTO(msg))
				return -EBUSY;
			pm_wakeup_event(&hdev->dev, 2000);
		}
	}

	if (hub_is_superspeed(hdev) && hdev->do_remote_wakeup) {
		 
		for (port1 = 1; port1 <= hdev->maxchild; port1++) {
			status = set_port_feature(hdev,
					port1 |
					USB_PORT_FEAT_REMOTE_WAKE_CONNECT |
					USB_PORT_FEAT_REMOTE_WAKE_DISCONNECT |
					USB_PORT_FEAT_REMOTE_WAKE_OVER_CURRENT,
					USB_PORT_FEAT_REMOTE_WAKE_MASK);
		}
	}

	dev_dbg(&intf->dev, "%s\n", __func__);

	hub_quiesce(hub, HUB_SUSPEND);
	return 0;
}

static int hub_resume(struct usb_interface *intf)
{
	struct usb_hub *hub = usb_get_intfdata(intf);

	dev_dbg(&intf->dev, "%s\n", __func__);
	hub_activate(hub, HUB_RESUME);
	return 0;
}

static int hub_reset_resume(struct usb_interface *intf)
{
	struct usb_hub *hub = usb_get_intfdata(intf);

	dev_dbg(&intf->dev, "%s\n", __func__);
	hub_activate(hub, HUB_RESET_RESUME);
	return 0;
}

void usb_root_hub_lost_power(struct usb_device *rhdev)
{
	dev_warn(&rhdev->dev, "root hub lost power or was reset\n");
	rhdev->reset_resume = 1;
}
EXPORT_SYMBOL_GPL(usb_root_hub_lost_power);

static const char * const usb3_lpm_names[]  = {
	"U0",
	"U1",
	"U2",
	"U3",
};

static int usb_req_set_sel(struct usb_device *udev, enum usb3_link_state state)
{
	struct usb_set_sel_req *sel_values;
	unsigned long long u1_sel;
	unsigned long long u1_pel;
	unsigned long long u2_sel;
	unsigned long long u2_pel;
	int ret;

	if (udev->state != USB_STATE_CONFIGURED)
		return 0;

	u1_sel = DIV_ROUND_UP(udev->u1_params.sel, 1000);
	u1_pel = DIV_ROUND_UP(udev->u1_params.pel, 1000);
	u2_sel = DIV_ROUND_UP(udev->u2_params.sel, 1000);
	u2_pel = DIV_ROUND_UP(udev->u2_params.pel, 1000);

	if ((state == USB3_LPM_U1 &&
				(u1_sel > USB3_LPM_MAX_U1_SEL_PEL ||
				 u1_pel > USB3_LPM_MAX_U1_SEL_PEL)) ||
			(state == USB3_LPM_U2 &&
			 (u2_sel > USB3_LPM_MAX_U2_SEL_PEL ||
			  u2_pel > USB3_LPM_MAX_U2_SEL_PEL))) {
		dev_dbg(&udev->dev, "Device-initiated %s disabled due to long SEL %llu us or PEL %llu us\n",
				usb3_lpm_names[state], u1_sel, u1_pel);
		return -EINVAL;
	}

	if (u1_sel > USB3_LPM_MAX_U1_SEL_PEL)
		u1_sel = USB3_LPM_MAX_U1_SEL_PEL;

	if (u1_pel > USB3_LPM_MAX_U1_SEL_PEL)
		u1_pel = USB3_LPM_MAX_U1_SEL_PEL;

	if (u2_sel > USB3_LPM_MAX_U2_SEL_PEL)
		u2_sel = USB3_LPM_MAX_U2_SEL_PEL;

	if (u2_pel > USB3_LPM_MAX_U2_SEL_PEL)
		u2_pel = USB3_LPM_MAX_U2_SEL_PEL;

	sel_values = kmalloc(sizeof *(sel_values), GFP_NOIO);
	if (!sel_values)
		return -ENOMEM;

	sel_values->u1_sel = u1_sel;
	sel_values->u1_pel = u1_pel;
	sel_values->u2_sel = cpu_to_le16(u2_sel);
	sel_values->u2_pel = cpu_to_le16(u2_pel);

	ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			USB_REQ_SET_SEL,
			USB_RECIP_DEVICE,
			0, 0,
			sel_values, sizeof *(sel_values),
			USB_CTRL_SET_TIMEOUT);
	kfree(sel_values);
	return ret;
}

static int usb_set_device_initiated_lpm(struct usb_device *udev,
		enum usb3_link_state state, bool enable)
{
	int ret;
	int feature;

	switch (state) {
	case USB3_LPM_U1:
		feature = USB_DEVICE_U1_ENABLE;
		break;
	case USB3_LPM_U2:
		feature = USB_DEVICE_U2_ENABLE;
		break;
	default:
		dev_warn(&udev->dev, "%s: Can't %s non-U1 or U2 state.\n",
				__func__, enable ? "enable" : "disable");
		return -EINVAL;
	}

	if (udev->state != USB_STATE_CONFIGURED) {
		dev_dbg(&udev->dev, "%s: Can't %s %s state "
				"for unconfigured device.\n",
				__func__, enable ? "enable" : "disable",
				usb3_lpm_names[state]);
		return 0;
	}

	if (enable) {
		 
		ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
				USB_REQ_SET_FEATURE,
				USB_RECIP_DEVICE,
				feature,
				0, NULL, 0,
				USB_CTRL_SET_TIMEOUT);
	} else {
		ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
				USB_REQ_CLEAR_FEATURE,
				USB_RECIP_DEVICE,
				feature,
				0, NULL, 0,
				USB_CTRL_SET_TIMEOUT);
	}
	if (ret < 0) {
		dev_warn(&udev->dev, "%s of device-initiated %s failed.\n",
				enable ? "Enable" : "Disable",
				usb3_lpm_names[state]);
		return -EBUSY;
	}
	return 0;
}

static int usb_set_lpm_timeout(struct usb_device *udev,
		enum usb3_link_state state, int timeout)
{
	int ret;
	int feature;

	switch (state) {
	case USB3_LPM_U1:
		feature = USB_PORT_FEAT_U1_TIMEOUT;
		break;
	case USB3_LPM_U2:
		feature = USB_PORT_FEAT_U2_TIMEOUT;
		break;
	default:
		dev_warn(&udev->dev, "%s: Can't set timeout for non-U1 or U2 state.\n",
				__func__);
		return -EINVAL;
	}

	if (state == USB3_LPM_U1 && timeout > USB3_LPM_U1_MAX_TIMEOUT &&
			timeout != USB3_LPM_DEVICE_INITIATED) {
		dev_warn(&udev->dev, "Failed to set %s timeout to 0x%x, "
				"which is a reserved value.\n",
				usb3_lpm_names[state], timeout);
		return -EINVAL;
	}

	ret = set_port_feature(udev->parent,
			USB_PORT_LPM_TIMEOUT(timeout) | udev->portnum,
			feature);
	if (ret < 0) {
		dev_warn(&udev->dev, "Failed to set %s timeout to 0x%x,"
				"error code %i\n", usb3_lpm_names[state],
				timeout, ret);
		return -EBUSY;
	}
	if (state == USB3_LPM_U1)
		udev->u1_params.timeout = timeout;
	else
		udev->u2_params.timeout = timeout;
	return 0;
}

static void usb_enable_link_state(struct usb_hcd *hcd, struct usb_device *udev,
		enum usb3_link_state state)
{
	int timeout, ret;
	__u8 u1_mel = udev->bos->ss_cap->bU1devExitLat;
	__le16 u2_mel = udev->bos->ss_cap->bU2DevExitLat;

	if ((state == USB3_LPM_U1 && u1_mel == 0) ||
			(state == USB3_LPM_U2 && u2_mel == 0))
		return;

	ret = usb_req_set_sel(udev, state);
	if (ret < 0) {
		dev_warn(&udev->dev, "Set SEL for device-initiated %s failed.\n",
				usb3_lpm_names[state]);
		return;
	}

	timeout = hcd->driver->enable_usb3_lpm_timeout(hcd, udev, state);

	if (timeout == 0)
		return;

	if (timeout < 0) {
		dev_warn(&udev->dev, "Could not enable %s link state, "
				"xHCI error %i.\n", usb3_lpm_names[state],
				timeout);
		return;
	}

	if (usb_set_lpm_timeout(udev, state, timeout)) {
		 
		hcd->driver->disable_usb3_lpm_timeout(hcd, udev, state);
	} else {
		 
		if (udev->actconfig)
			usb_set_device_initiated_lpm(udev, state, true);

		if (state == USB3_LPM_U1)
			udev->usb3_lpm_u1_enabled = 1;
		else if (state == USB3_LPM_U2)
			udev->usb3_lpm_u2_enabled = 1;
	}
}

static int usb_disable_link_state(struct usb_hcd *hcd, struct usb_device *udev,
		enum usb3_link_state state)
{
	switch (state) {
	case USB3_LPM_U1:
	case USB3_LPM_U2:
		break;
	default:
		dev_warn(&udev->dev, "%s: Can't disable non-U1 or U2 state.\n",
				__func__);
		return -EINVAL;
	}

	if (usb_set_lpm_timeout(udev, state, 0))
		return -EBUSY;

	usb_set_device_initiated_lpm(udev, state, false);

	if (hcd->driver->disable_usb3_lpm_timeout(hcd, udev, state))
		dev_warn(&udev->dev, "Could not disable xHCI %s timeout, "
				"bus schedule bandwidth may be impacted.\n",
				usb3_lpm_names[state]);

	if (state == USB3_LPM_U1)
		udev->usb3_lpm_u1_enabled = 0;
	else if (state == USB3_LPM_U2)
		udev->usb3_lpm_u2_enabled = 0;

	return 0;
}

int usb_disable_lpm(struct usb_device *udev)
{
	struct usb_hcd *hcd;

	if (!udev || !udev->parent ||
			udev->speed < USB_SPEED_SUPER ||
			!udev->lpm_capable ||
			udev->state < USB_STATE_DEFAULT)
		return 0;

	hcd = bus_to_hcd(udev->bus);
	if (!hcd || !hcd->driver->disable_usb3_lpm_timeout)
		return 0;

	udev->lpm_disable_count++;
	if ((udev->u1_params.timeout == 0 && udev->u2_params.timeout == 0))
		return 0;

	if (usb_disable_link_state(hcd, udev, USB3_LPM_U1))
		goto enable_lpm;
	if (usb_disable_link_state(hcd, udev, USB3_LPM_U2))
		goto enable_lpm;

	return 0;

enable_lpm:
	usb_enable_lpm(udev);
	return -EBUSY;
}
EXPORT_SYMBOL_GPL(usb_disable_lpm);

int usb_unlocked_disable_lpm(struct usb_device *udev)
{
	struct usb_hcd *hcd = bus_to_hcd(udev->bus);
	int ret;

	if (!hcd)
		return -EINVAL;

	mutex_lock(hcd->bandwidth_mutex);
	ret = usb_disable_lpm(udev);
	mutex_unlock(hcd->bandwidth_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(usb_unlocked_disable_lpm);

void usb_enable_lpm(struct usb_device *udev)
{
	struct usb_hcd *hcd;

	if (!udev || !udev->parent ||
			udev->speed < USB_SPEED_SUPER ||
			!udev->lpm_capable ||
			udev->state < USB_STATE_DEFAULT)
		return;

	udev->lpm_disable_count--;
	hcd = bus_to_hcd(udev->bus);
	 
	if (!hcd || !hcd->driver->enable_usb3_lpm_timeout ||
			!hcd->driver->disable_usb3_lpm_timeout)
		return;

	if (udev->lpm_disable_count > 0)
		return;

	usb_enable_link_state(hcd, udev, USB3_LPM_U1);
	usb_enable_link_state(hcd, udev, USB3_LPM_U2);
}
EXPORT_SYMBOL_GPL(usb_enable_lpm);

void usb_unlocked_enable_lpm(struct usb_device *udev)
{
	struct usb_hcd *hcd = bus_to_hcd(udev->bus);

	if (!hcd)
		return;

	mutex_lock(hcd->bandwidth_mutex);
	usb_enable_lpm(udev);
	mutex_unlock(hcd->bandwidth_mutex);
}
EXPORT_SYMBOL_GPL(usb_unlocked_enable_lpm);

static void hub_usb3_port_prepare_disable(struct usb_hub *hub,
					  struct usb_port *port_dev)
{
	struct usb_device *udev = port_dev->child;
	int ret;

	if (udev && udev->port_is_suspended && udev->do_remote_wakeup) {
		ret = hub_set_port_link_state(hub, port_dev->portnum,
					      USB_SS_PORT_LS_U0);
		if (!ret) {
			msleep(USB_RESUME_TIMEOUT);
			ret = usb_disable_remote_wakeup(udev);
		}
		if (ret)
			dev_warn(&udev->dev,
				 "Port disable: can't disable remote wake\n");
		udev->do_remote_wakeup = 0;
	}
}

#else	 

#define hub_suspend		NULL
#define hub_resume		NULL
#define hub_reset_resume	NULL

static inline void hub_usb3_port_prepare_disable(struct usb_hub *hub,
						 struct usb_port *port_dev) { }

int usb_disable_lpm(struct usb_device *udev)
{
	return 0;
}
EXPORT_SYMBOL_GPL(usb_disable_lpm);

void usb_enable_lpm(struct usb_device *udev) { }
EXPORT_SYMBOL_GPL(usb_enable_lpm);

int usb_unlocked_disable_lpm(struct usb_device *udev)
{
	return 0;
}
EXPORT_SYMBOL_GPL(usb_unlocked_disable_lpm);

void usb_unlocked_enable_lpm(struct usb_device *udev) { }
EXPORT_SYMBOL_GPL(usb_unlocked_enable_lpm);

int usb_disable_ltm(struct usb_device *udev)
{
	return 0;
}
EXPORT_SYMBOL_GPL(usb_disable_ltm);

void usb_enable_ltm(struct usb_device *udev) { }
EXPORT_SYMBOL_GPL(usb_enable_ltm);

static int hub_handle_remote_wakeup(struct usb_hub *hub, unsigned int port,
		u16 portstatus, u16 portchange)
{
	return 0;
}

#endif	 

static int hub_port_disable(struct usb_hub *hub, int port1, int set_state)
{
	struct usb_port *port_dev = hub->ports[port1 - 1];
	struct usb_device *hdev = hub->hdev;
	int ret = 0;

	if (!hub->error) {
		if (hub_is_superspeed(hub->hdev)) {
			hub_usb3_port_prepare_disable(hub, port_dev);
			ret = hub_set_port_link_state(hub, port_dev->portnum,
						      USB_SS_PORT_LS_U3);
		} else {
			ret = usb_clear_port_feature(hdev, port1,
					USB_PORT_FEAT_ENABLE);
		}
	}
	if (port_dev->child && set_state)
		usb_set_device_state(port_dev->child, USB_STATE_NOTATTACHED);
	if (ret && ret != -ENODEV)
		dev_err(&port_dev->dev, "cannot disable (err = %d)\n", ret);
	return ret;
}

int hub_port_debounce(struct usb_hub *hub, int port1, bool must_be_connected)
{
	int ret;
	u16 portchange, portstatus;
	unsigned connection = 0xffff;
	int total_time, stable_time = 0;
	struct usb_port *port_dev = hub->ports[port1 - 1];

	for (total_time = 0; ; total_time += HUB_DEBOUNCE_STEP) {
		ret = hub_port_status(hub, port1, &portstatus, &portchange);
		if (ret < 0)
			return ret;

		if (!(portchange & USB_PORT_STAT_C_CONNECTION) &&
		     (portstatus & USB_PORT_STAT_CONNECTION) == connection) {
			if (!must_be_connected ||
			     (connection == USB_PORT_STAT_CONNECTION))
				stable_time += HUB_DEBOUNCE_STEP;
			if (stable_time >= HUB_DEBOUNCE_STABLE)
				break;
		} else {
			stable_time = 0;
			connection = portstatus & USB_PORT_STAT_CONNECTION;
		}

		if (portchange & USB_PORT_STAT_C_CONNECTION) {
			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_CONNECTION);
		}

		if (total_time >= HUB_DEBOUNCE_TIMEOUT)
			break;
		msleep(HUB_DEBOUNCE_STEP);
	}

	dev_dbg(&port_dev->dev, "debounce total %dms stable %dms status 0x%x\n",
			total_time, stable_time, portstatus);

	if (stable_time < HUB_DEBOUNCE_STABLE)
		return -ETIMEDOUT;
	return portstatus;
}

void usb_ep0_reinit(struct usb_device *udev)
{
	usb_disable_endpoint(udev, 0 + USB_DIR_IN, true);
	usb_disable_endpoint(udev, 0 + USB_DIR_OUT, true);
	usb_enable_endpoint(udev, &udev->ep0, true);
}
EXPORT_SYMBOL_GPL(usb_ep0_reinit);

#define usb_sndaddr0pipe()	(PIPE_CONTROL << 30)
#define usb_rcvaddr0pipe()	((PIPE_CONTROL << 30) | USB_DIR_IN)

static int hub_set_address(struct usb_device *udev, int devnum)
{
	int retval;
	struct usb_hcd *hcd = bus_to_hcd(udev->bus);

	if (!hcd->driver->address_device && devnum <= 1)
		return -EINVAL;
	if (udev->state == USB_STATE_ADDRESS)
		return 0;
	if (udev->state != USB_STATE_DEFAULT)
		return -EINVAL;
	if (hcd->driver->address_device)
		retval = hcd->driver->address_device(hcd, udev);
	else
		retval = usb_control_msg(udev, usb_sndaddr0pipe(),
				USB_REQ_SET_ADDRESS, 0, devnum, 0,
				NULL, 0, USB_CTRL_SET_TIMEOUT);
	if (retval == 0) {
		update_devnum(udev, devnum);
		 
		usb_set_device_state(udev, USB_STATE_ADDRESS);
		usb_ep0_reinit(udev);
	}
	return retval;
}

#if defined (MY_DEF_HERE) || defined (MY_DEF_HERE)
static int is_syno_ext_hub(struct usb_device *udev)
{
	int ret = -1;
	if (udev->level == 1) {
#if defined (MY_DEF_HERE)
		if (USB_SPEED_SUPER == udev->speed) {
			if ((CONFIG_SYNO_USB_EXTERNAL_USB3_HUB_VID ==
				udev->descriptor.idVendor) &&
			    (CONFIG_SYNO_USB_EXTERNAL_USB3_HUB_PID ==
				udev->descriptor.idProduct)) {
				ret = 0;
			}
		}
#endif  
#if defined (MY_DEF_HERE)
		if (USB_SPEED_HIGH == udev->speed) {
			if ((CONFIG_SYNO_USB_EXTERNAL_USB2_HUB_VID ==
				udev->descriptor.idVendor) &&
			    (CONFIG_SYNO_USB_EXTERNAL_USB2_HUB_PID ==
				udev->descriptor.idProduct)) {
				ret = 0;
			}
		}
#endif  
	}
	return ret;
}

#endif  
#if defined (MY_ABC_HERE)

static int check_superspeed(struct usb_hub *hub, struct usb_device *udev)
{
	struct usb_device *hdev = hub->hdev;
	int retval = -EINVAL;
#if defined (MY_DEF_HERE) || defined (MY_DEF_HERE)
	 
	if (0 == is_syno_ext_hub(udev)) {
		dev_info(&udev->dev, "This is Synology external hub. Skip %s\n", __func__);
		return retval;
	}

	if ((!hdev->parent || 0 == is_syno_ext_hub(hdev)) &&
#else  
	if (!hdev->parent &&
#endif  
		!hub_is_superspeed(hdev) &&
		0x0210 <= le16_to_cpu(udev->descriptor.bcdUSB)) {
		dev_info(&udev->dev, "not running at top speed\n");
		retval = 0;
	}

	return retval;
}
#endif  

static void hub_set_initial_usb2_lpm_policy(struct usb_device *udev)
{
	struct usb_hub *hub = usb_hub_to_struct_hub(udev->parent);
	int connect_type = USB_PORT_CONNECT_TYPE_UNKNOWN;

	if (!udev->usb2_hw_lpm_capable || !udev->bos)
		return;

	if (hub)
		connect_type = hub->ports[udev->portnum - 1]->connect_type;

	if ((udev->bos->ext_cap->bmAttributes & cpu_to_le32(USB_BESL_SUPPORT)) ||
			connect_type == USB_PORT_CONNECT_TYPE_HARD_WIRED) {
		udev->usb2_hw_lpm_allowed = 1;
		usb_set_usb2_hardware_lpm(udev, 1);
	}
}

static int hub_enable_device(struct usb_device *udev)
{
	struct usb_hcd *hcd = bus_to_hcd(udev->bus);

	if (!hcd->driver->enable_device)
		return 0;
	if (udev->state == USB_STATE_ADDRESS)
		return 0;
	if (udev->state != USB_STATE_DEFAULT)
		return -EINVAL;

	return hcd->driver->enable_device(hcd, udev);
}

static int
hub_port_init(struct usb_hub *hub, struct usb_device *udev, int port1,
		int retry_counter)
{
	struct usb_device	*hdev = hub->hdev;
	struct usb_hcd		*hcd = bus_to_hcd(hdev->bus);
	int			retries, operations, retval, i;
	unsigned		delay = HUB_SHORT_RESET_TIME;
	enum usb_device_speed	oldspeed = udev->speed;
	const char		*speed;
	int			devnum = udev->devnum;
#if defined (MY_ABC_HERE)
	int reset_retry = 1;
	int speed_morph_count = 0;
#endif  
#ifdef MY_ABC_HERE
	extern int gSynoFactoryUSB3Disable;
#endif  

	if (!hdev->parent) {
		delay = HUB_ROOT_RESET_TIME;
		if (port1 == hdev->bus->otg_port)
			hdev->bus->b_hnp_enable = 0;
	}

	if (oldspeed == USB_SPEED_LOW)
		delay = HUB_LONG_RESET_TIME;

	mutex_lock(hcd->address0_mutex);
#if defined (MY_ABC_HERE)
port_speed_morph:
	do {
		 
		retval = hub_port_reset(hub, port1, udev, delay, false);
		if (retval < 0)
			break;
	} while (--reset_retry);
#else  

	retval = hub_port_reset(hub, port1, udev, delay, false);
#endif  
	if (retval < 0)		 
		goto fail;
	 
	retval = -ENODEV;

	if (oldspeed != USB_SPEED_UNKNOWN && oldspeed != udev->speed &&
	    !(oldspeed == USB_SPEED_SUPER && udev->speed > oldspeed)) {
		dev_dbg(&udev->dev, "device reset changed speed!\n");
		goto fail;
	}
	oldspeed = udev->speed;

	switch (udev->speed) {
	case USB_SPEED_SUPER_PLUS:
	case USB_SPEED_SUPER:
	case USB_SPEED_WIRELESS:	 
		udev->ep0.desc.wMaxPacketSize = cpu_to_le16(512);
		break;
	case USB_SPEED_HIGH:		 
		udev->ep0.desc.wMaxPacketSize = cpu_to_le16(64);
		break;
	case USB_SPEED_FULL:		 
		 
		udev->ep0.desc.wMaxPacketSize = cpu_to_le16(64);
		break;
	case USB_SPEED_LOW:		 
		udev->ep0.desc.wMaxPacketSize = cpu_to_le16(8);
		break;
	default:
		goto fail;
	}

	if (udev->speed == USB_SPEED_WIRELESS)
		speed = "variable speed Wireless";
	else
		speed = usb_speed_string(udev->speed);

	if (udev->speed < USB_SPEED_SUPER)
		dev_info(&udev->dev,
				"%s %s USB device number %d using %s\n",
				(udev->config) ? "reset" : "new", speed,
				devnum, udev->bus->controller->driver->name);

	if (hdev->tt) {
		udev->tt = hdev->tt;
		udev->ttport = hdev->ttport;
	} else if (udev->speed != USB_SPEED_HIGH
			&& hdev->speed == USB_SPEED_HIGH) {
		if (!hub->tt.hub) {
			dev_err(&udev->dev, "parent hub has no TT\n");
			retval = -EINVAL;
			goto fail;
		}
		udev->tt = &hub->tt;
		udev->ttport = port1;
	}

	for (retries = 0; retries < GET_DESCRIPTOR_TRIES; (++retries, msleep(100))) {
		bool did_new_scheme = false;

		if (use_new_scheme(udev, retry_counter)) {
			struct usb_device_descriptor *buf;
			int r = 0;

			did_new_scheme = true;
			retval = hub_enable_device(udev);
			if (retval < 0) {
				dev_err(&udev->dev,
					"hub failed to enable device, error %d\n",
					retval);
				goto fail;
			}

#define GET_DESCRIPTOR_BUFSIZE	64
			buf = kmalloc(GET_DESCRIPTOR_BUFSIZE, GFP_NOIO);
			if (!buf) {
				retval = -ENOMEM;
				continue;
			}

			for (operations = 0; operations < 3; ++operations) {
				buf->bMaxPacketSize0 = 0;
				r = usb_control_msg(udev, usb_rcvaddr0pipe(),
					USB_REQ_GET_DESCRIPTOR, USB_DIR_IN,
					USB_DT_DEVICE << 8, 0,
					buf, GET_DESCRIPTOR_BUFSIZE,
					initial_descriptor_timeout);
				switch (buf->bMaxPacketSize0) {
				case 8: case 16: case 32: case 64: case 255:
					if (buf->bDescriptorType ==
							USB_DT_DEVICE) {
						r = 0;
						break;
					}
					 
				default:
					if (r == 0)
						r = -EPROTO;
					break;
				}
				 
				if (r == 0  || (r == -ETIMEDOUT && retries == 0))
					break;
			}
			udev->descriptor.bMaxPacketSize0 =
					buf->bMaxPacketSize0;
			kfree(buf);

			retval = hub_port_reset(hub, port1, udev, delay, false);
			if (retval < 0)		 
				goto fail;
			if (oldspeed != udev->speed) {
				dev_dbg(&udev->dev,
					"device reset changed speed!\n");
				retval = -ENODEV;
				goto fail;
			}
			if (r) {
				if (r != -ENODEV)
					dev_err(&udev->dev, "device descriptor read/64, error %d\n",
							r);
				retval = -EMSGSIZE;
				continue;
			}
#undef GET_DESCRIPTOR_BUFSIZE
		}

		if (udev->wusb == 0) {
			for (operations = 0; operations < SET_ADDRESS_TRIES; ++operations) {
				retval = hub_set_address(udev, devnum);
				if (retval >= 0)
					break;
				msleep(200);
			}
			if (retval < 0) {
				if (retval != -ENODEV)
					dev_err(&udev->dev, "device not accepting address %d, error %d\n",
							devnum, retval);
				goto fail;
			}
			if (udev->speed >= USB_SPEED_SUPER) {
				devnum = udev->devnum;
				dev_info(&udev->dev,
						"%s SuperSpeed%s USB device number %d using %s\n",
						(udev->config) ? "reset" : "new",
					 (udev->speed == USB_SPEED_SUPER_PLUS) ? "Plus" : "",
						devnum, udev->bus->controller->driver->name);
			}

			msleep(10);
			 
			if (did_new_scheme)
				break;
		}

		retval = usb_get_device_descriptor(udev, 8);
		if (retval < 8) {
			if (retval != -ENODEV)
				dev_err(&udev->dev,
					"device descriptor read/8, error %d\n",
					retval);
			if (retval >= 0)
				retval = -EMSGSIZE;
		} else {
			retval = 0;
			break;
		}
	}
	if (retval)
		goto fail;

	if ((udev->speed >= USB_SPEED_SUPER) &&
			(le16_to_cpu(udev->descriptor.bcdUSB) < 0x0300)) {
		dev_err(&udev->dev, "got a wrong device descriptor, "
				"warm reset device\n");
		hub_port_reset(hub, port1, udev,
				HUB_BH_RESET_TIME, true);
		retval = -EINVAL;
		goto fail;
	}

	if (udev->descriptor.bMaxPacketSize0 == 0xff ||
			udev->speed >= USB_SPEED_SUPER)
		i = 512;
	else
		i = udev->descriptor.bMaxPacketSize0;
	if (usb_endpoint_maxp(&udev->ep0.desc) != i) {
		if (udev->speed == USB_SPEED_LOW ||
				!(i == 8 || i == 16 || i == 32 || i == 64)) {
			dev_err(&udev->dev, "Invalid ep0 maxpacket: %d\n", i);
			retval = -EMSGSIZE;
			goto fail;
		}
		if (udev->speed == USB_SPEED_FULL)
			dev_dbg(&udev->dev, "ep0 maxpacket = %d\n", i);
		else
			dev_warn(&udev->dev, "Using ep0 maxpacket: %d\n", i);
		udev->ep0.desc.wMaxPacketSize = cpu_to_le16(i);
		usb_ep0_reinit(udev);
	}

	retval = usb_get_device_descriptor(udev, USB_DT_DEVICE_SIZE);
	if (retval < (signed)sizeof(udev->descriptor)) {
		if (retval != -ENODEV)
			dev_err(&udev->dev, "device descriptor read/all, error %d\n",
					retval);
		if (retval >= 0)
			retval = -ENOMSG;
		goto fail;
	}

	usb_detect_quirks(udev);

#if defined (MY_ABC_HERE)
	if (IS_XHCI(hcd)
#ifdef MY_ABC_HERE
		&& 0 == gSynoFactoryUSB3Disable
#endif  
#ifdef MY_ABC_HERE
		&& !(SYNO_USB_PORT_CASTRATED_XHC & hub->ports[port1 - 1]->flag)
#endif  
	) {
		retval = check_superspeed(hub, udev);
		if (!retval && speed_morph_count < SYNO_HUB_SPEED_MORPH_TRIES) {
			speed_morph_count++;
			reset_retry = SYNO_HUB_SPEED_MORPH_RESET_TRIES;
			hub_port_disable(hub, port1, 0);
			oldspeed = USB_SPEED_UNKNOWN;
			goto port_speed_morph;
		}
	}
#endif  
	if (udev->wusb == 0 && le16_to_cpu(udev->descriptor.bcdUSB) >= 0x0201) {
		retval = usb_get_bos_descriptor(udev);
		if (!retval) {
			udev->lpm_capable = usb_device_supports_lpm(udev);
			usb_set_lpm_parameters(udev);
		}
	}

	retval = 0;
#if defined (MY_ABC_HERE)
	hub->ports[port1 - 1]->power_cycle_counter = SYNO_POWER_CYCLE_TRIES;
#endif  
	 
	if (hcd->driver->update_device)
		hcd->driver->update_device(hcd, udev);
	hub_set_initial_usb2_lpm_policy(udev);
fail:
	if (retval) {
		hub_port_disable(hub, port1, 0);
		update_devnum(udev, devnum);	 
	}
	mutex_unlock(hcd->address0_mutex);
	return retval;
}

static void
check_highspeed(struct usb_hub *hub, struct usb_device *udev, int port1)
{
	struct usb_qualifier_descriptor	*qual;
	int				status;

	if (udev->quirks & USB_QUIRK_DEVICE_QUALIFIER)
		return;

	qual = kmalloc(sizeof *qual, GFP_KERNEL);
	if (qual == NULL)
		return;

	status = usb_get_descriptor(udev, USB_DT_DEVICE_QUALIFIER, 0,
			qual, sizeof *qual);
	if (status == sizeof *qual) {
		dev_info(&udev->dev, "not running at top speed; "
			"connect to a high speed hub\n");
		 
		if (hub->has_indicators) {
			hub->indicator[port1-1] = INDICATOR_GREEN_BLINK;
			queue_delayed_work(system_power_efficient_wq,
					&hub->leds, 0);
		}
	}
	kfree(qual);
}

static unsigned
hub_power_remaining(struct usb_hub *hub)
{
	struct usb_device *hdev = hub->hdev;
	int remaining;
	int port1;

	if (!hub->limited_power)
		return 0;

	remaining = hdev->bus_mA - hub->descriptor->bHubContrCurrent;
	for (port1 = 1; port1 <= hdev->maxchild; ++port1) {
		struct usb_port *port_dev = hub->ports[port1 - 1];
		struct usb_device *udev = port_dev->child;
		unsigned unit_load;
		int delta;

		if (!udev)
			continue;
		if (hub_is_superspeed(udev))
			unit_load = 150;
		else
			unit_load = 100;

		if (udev->actconfig)
			delta = usb_get_max_power(udev, udev->actconfig);
		else if (port1 != udev->bus->otg_port || hdev->parent)
			delta = unit_load;
		else
			delta = 8;
		if (delta > hub->mA_per_port)
			dev_warn(&port_dev->dev, "%dmA is over %umA budget!\n",
					delta, hub->mA_per_port);
		remaining -= delta;
	}
	if (remaining < 0) {
		dev_warn(hub->intfdev, "%dmA over power budget!\n",
			-remaining);
		remaining = 0;
	}
	return remaining;
}

static void hub_port_connect(struct usb_hub *hub, int port1, u16 portstatus,
		u16 portchange)
{
	int status, i;
	unsigned unit_load;
	struct usb_device *hdev = hub->hdev;
	struct usb_hcd *hcd = bus_to_hcd(hdev->bus);
	struct usb_port *port_dev = hub->ports[port1 - 1];
	struct usb_device *udev = port_dev->child;
	static int unreliable_port = -1;

	if (udev) {
#ifdef MY_ABC_HERE
		 
		if (unlikely(udev->syno_quirks &
					SYNO_USB_QUIRK_UPS_DISCONNECT_FILTER)) {
			if (portstatus & USB_PORT_STAT_CONNECTION) {
				 
				int ret;
				del_timer_sync(&hub->ups_discon_flt_timer);
				hub->ups_discon_flt_status =
					SYNO_UPS_DISCON_FLT_STATUS_NONE;
				hub->ups_discon_flt_last = jiffies;
				hub_port_debounce_be_stable(hub, port1);
				usb_lock_device(udev);
				ret = usb_reset_device(udev);
				usb_unlock_device(udev);
				if (0 > ret) {
					hub_port_status(hub, port1, &portstatus, &portchange);
					dev_err(&port_dev->dev, "deferred disconnect failed, "
							"on port %d reset (ret: %d), status: %04x, "
							"change: %04x\n", port1, ret, portstatus,
							portchange);
				} else
					return;
			} else if (portchange & USB_PORT_STAT_C_CONNECTION) {
				 
				if (unlikely((udev->syno_quirks &
								SYNO_USB_QUIRK_LIMITED_UPS_DISCONNECT_FILTERING)
							 && time_after(hub->ups_discon_flt_last + 15 * HZ,
								 jiffies)))
					 
					 ;
				else {
					if (!timer_pending(&hub->ups_discon_flt_timer)) {
						hub->ups_discon_flt_status =
							SYNO_UPS_DISCON_FLT_STATUS_DEFERRED;
						hub->ups_discon_flt_port = port1;
						hub->ups_discon_flt_timer.expires = jiffies + 3 * HZ;
						add_timer(&hub->ups_discon_flt_timer);
					}
					return;
				}
			} else {
				 
				del_timer_sync(&hub->ups_discon_flt_timer);
				hub->ups_discon_flt_status =
					SYNO_UPS_DISCON_FLT_STATUS_NONE;
			}
		}
#endif  
		if (hcd->usb_phy && !hdev->parent)
			usb_phy_notify_disconnect(hcd->usb_phy, udev->speed);
		usb_disconnect(&port_dev->child);
	}

	if (!(portstatus & USB_PORT_STAT_CONNECTION) ||
			(portchange & USB_PORT_STAT_C_CONNECTION))
		clear_bit(port1, hub->removed_bits);

	if (portchange & (USB_PORT_STAT_C_CONNECTION |
				USB_PORT_STAT_C_ENABLE)) {
		status = hub_port_debounce_be_stable(hub, port1);
		if (status < 0) {
#if defined (MY_ABC_HERE)
			syno_usb_power_cycle(hub, port1, status);
#endif	 
			if (status != -ENODEV &&
				port1 != unreliable_port &&
				printk_ratelimit())
				dev_err(&port_dev->dev, "connect-debounce failed\n");
			portstatus &= ~USB_PORT_STAT_CONNECTION;
			unreliable_port = port1;
		} else {
			portstatus = status;
		}
	}

	if (!(portstatus & USB_PORT_STAT_CONNECTION) ||
			test_bit(port1, hub->removed_bits)) {

		if (hub_is_port_power_switchable(hub)
				&& !port_is_power_on(hub, portstatus)
				&& !port_dev->port_owner)
			set_port_feature(hdev, port1, USB_PORT_FEAT_POWER);

		if (portstatus & USB_PORT_STAT_ENABLE)
			goto done;
		return;
	}
	if (hub_is_superspeed(hub->hdev))
		unit_load = 150;
	else
		unit_load = 100;

	status = 0;
	for (i = 0; i < SET_CONFIG_TRIES; i++) {

		udev = usb_alloc_dev(hdev, hdev->bus, port1);
		if (!udev) {
			dev_err(&port_dev->dev,
					"couldn't allocate usb_device\n");
			goto done;
		}

		usb_set_device_state(udev, USB_STATE_POWERED);
		udev->bus_mA = hub->mA_per_port;
		udev->level = hdev->level + 1;
		udev->wusb = hub_is_wusb(hub);

		if (hub_is_superspeed(hub->hdev))
			udev->speed = USB_SPEED_SUPER;
		else
			udev->speed = USB_SPEED_UNKNOWN;

		choose_devnum(udev);
		if (udev->devnum <= 0) {
			status = -ENOTCONN;	 
			goto loop;
		}

		usb_lock_port(port_dev);
		status = hub_port_init(hub, udev, port1, i);
		usb_unlock_port(port_dev);
		if (status < 0)
			goto loop;

		if (udev->quirks & USB_QUIRK_DELAY_INIT)
			msleep(1000);

		if (udev->descriptor.bDeviceClass == USB_CLASS_HUB
				&& udev->bus_mA <= unit_load) {
			u16	devstat;

			status = usb_get_status(udev, USB_RECIP_DEVICE, 0,
					&devstat);
			if (status) {
				dev_dbg(&udev->dev, "get status %d ?\n", status);
				goto loop_disable;
			}
			if ((devstat & (1 << USB_DEVICE_SELF_POWERED)) == 0) {
				dev_err(&udev->dev,
					"can't connect bus-powered hub "
					"to this port\n");
				if (hub->has_indicators) {
					hub->indicator[port1-1] =
						INDICATOR_AMBER_BLINK;
					queue_delayed_work(
						system_power_efficient_wq,
						&hub->leds, 0);
				}
				status = -ENOTCONN;	 
				goto loop_disable;
			}
		}

		if (le16_to_cpu(udev->descriptor.bcdUSB) >= 0x0200
				&& udev->speed == USB_SPEED_FULL
				&& highspeed_hubs != 0)
			check_highspeed(hub, udev, port1);

		status = 0;

		mutex_lock(&usb_port_peer_mutex);

		spin_lock_irq(&device_state_lock);
		if (hdev->state == USB_STATE_NOTATTACHED)
			status = -ENOTCONN;
		else
			port_dev->child = udev;
		spin_unlock_irq(&device_state_lock);
		mutex_unlock(&usb_port_peer_mutex);

		if (!status) {
			status = usb_new_device(udev);
			if (status) {
				mutex_lock(&usb_port_peer_mutex);
				spin_lock_irq(&device_state_lock);
				port_dev->child = NULL;
				spin_unlock_irq(&device_state_lock);
				mutex_unlock(&usb_port_peer_mutex);
			} else {
				if (hcd->usb_phy && !hdev->parent)
					usb_phy_notify_connect(hcd->usb_phy,
							udev->speed);
			}
		}

		if (status)
			goto loop_disable;

		status = hub_power_remaining(hub);
		if (status)
			dev_dbg(hub->intfdev, "%dmA power budget left\n", status);

		return;

loop_disable:
		hub_port_disable(hub, port1, 1);
loop:
		usb_ep0_reinit(udev);
		release_devnum(udev);
		hub_free_dev(udev);
		usb_put_dev(udev);
		if ((status == -ENOTCONN) || (status == -ENOTSUPP))
			break;
	}
	if (hub->hdev->parent ||
			!hcd->driver->port_handed_over ||
			!(hcd->driver->port_handed_over)(hcd, port1)) {
		if (status != -ENOTCONN && status != -ENODEV)
			dev_err(&port_dev->dev,
					"unable to enumerate USB device\n");
	}
#if defined (MY_ABC_HERE)
	 
	syno_usb_power_cycle(hub, port1, status);
#endif  

done:
	hub_port_disable(hub, port1, 1);
	if (hcd->driver->relinquish_port && !hub->hdev->parent)
		hcd->driver->relinquish_port(hcd, port1);

}

static void hub_port_connect_change(struct usb_hub *hub, int port1,
					u16 portstatus, u16 portchange)
		__must_hold(&port_dev->status_lock)
{
	struct usb_port *port_dev = hub->ports[port1 - 1];
	struct usb_device *udev = port_dev->child;
	int status = -ENODEV;

	dev_dbg(&port_dev->dev, "status %04x, change %04x, %s\n", portstatus,
			portchange, portspeed(hub, portstatus));

	if (hub->has_indicators) {
		set_port_led(hub, port1, HUB_LED_AUTO);
		hub->indicator[port1-1] = INDICATOR_AUTO;
	}

#ifdef	CONFIG_USB_OTG
	 
	if (hub->hdev->bus->is_b_host)
		portchange &= ~(USB_PORT_STAT_C_CONNECTION |
				USB_PORT_STAT_C_ENABLE);
#endif

	if ((portstatus & USB_PORT_STAT_CONNECTION) && udev &&
			udev->state != USB_STATE_NOTATTACHED) {
		if (portstatus & USB_PORT_STAT_ENABLE) {
			status = 0;		 
#ifdef MY_ABC_HERE
			if (unlikely((udev->syno_quirks &
							SYNO_USB_QUIRK_UPS_DISCONNECT_FILTER) &&
						 (hub->ups_discon_flt_status !=
							SYNO_UPS_DISCON_FLT_STATUS_NONE))) {
				dev_warn(&port_dev->dev, "UPS disconnect filter: re-connected but "
						"port %d still enabled, status: %04x, change: %04x\n",
						port1, portstatus, portchange);
			}
#endif  
#ifdef CONFIG_PM
		} else if (udev->state == USB_STATE_SUSPENDED &&
				udev->persist_enabled) {
			 
			usb_unlock_port(port_dev);
			status = usb_remote_wakeup(udev);
			usb_lock_port(port_dev);
#endif
		} else {
			 ;
		}
	}
	clear_bit(port1, hub->change_bits);

	if (status == 0)
		return;

	usb_unlock_port(port_dev);
	hub_port_connect(hub, port1, portstatus, portchange);
	usb_lock_port(port_dev);
}

static void port_event(struct usb_hub *hub, int port1)
		__must_hold(&port_dev->status_lock)
{
	int connect_change;
	struct usb_port *port_dev = hub->ports[port1 - 1];
	struct usb_device *udev = port_dev->child;
	struct usb_device *hdev = hub->hdev;
	u16 portstatus, portchange;

	connect_change = test_bit(port1, hub->change_bits);
	clear_bit(port1, hub->event_bits);
	clear_bit(port1, hub->wakeup_bits);

	if (hub_port_status(hub, port1, &portstatus, &portchange) < 0)
		return;

	if (portchange & USB_PORT_STAT_C_CONNECTION) {
		usb_clear_port_feature(hdev, port1, USB_PORT_FEAT_C_CONNECTION);
		connect_change = 1;
	}

	if (portchange & USB_PORT_STAT_C_ENABLE) {
		if (!connect_change)
			dev_dbg(&port_dev->dev, "enable change, status %08x\n",
					portstatus);
		usb_clear_port_feature(hdev, port1, USB_PORT_FEAT_C_ENABLE);

		if (!(portstatus & USB_PORT_STAT_ENABLE)
		    && !connect_change && udev) {
#ifdef MY_ABC_HERE
			int ret = 1;
#endif  
			dev_err(&port_dev->dev, "disabled by hub (EMI?), re-enabling...\n");
#ifdef MY_ABC_HERE
			 
			if (udev->syno_quirks &
					SYNO_USB_QUIRK_UPS_DISCONNECT_FILTER) {
				usb_unlock_port(port_dev);
				usb_lock_device(udev);
				ret = usb_reset_device(udev);
				usb_unlock_device(udev);
				usb_lock_port(port_dev);
			}

			if (ret)
#endif  
			connect_change = 1;
		}
	}

	if (portchange & USB_PORT_STAT_C_OVERCURRENT) {
		u16 status = 0, unused;

		dev_dbg(&port_dev->dev, "over-current change\n");
		usb_clear_port_feature(hdev, port1,
				USB_PORT_FEAT_C_OVER_CURRENT);
		msleep(100);	 
		hub_power_on(hub, true);
		hub_port_status(hub, port1, &status, &unused);
		if (status & USB_PORT_STAT_OVERCURRENT)
			dev_err(&port_dev->dev, "over-current condition\n");
	}

	if (portchange & USB_PORT_STAT_C_RESET) {
		dev_dbg(&port_dev->dev, "reset change\n");
		usb_clear_port_feature(hdev, port1, USB_PORT_FEAT_C_RESET);
	}
	if ((portchange & USB_PORT_STAT_C_BH_RESET)
	    && hub_is_superspeed(hdev)) {
		dev_dbg(&port_dev->dev, "warm reset change\n");
		usb_clear_port_feature(hdev, port1,
				USB_PORT_FEAT_C_BH_PORT_RESET);
	}
	if (portchange & USB_PORT_STAT_C_LINK_STATE) {
		dev_dbg(&port_dev->dev, "link state change\n");
		usb_clear_port_feature(hdev, port1,
				USB_PORT_FEAT_C_PORT_LINK_STATE);
	}
	if (portchange & USB_PORT_STAT_C_CONFIG_ERROR) {
		dev_warn(&port_dev->dev, "config error\n");
		usb_clear_port_feature(hdev, port1,
				USB_PORT_FEAT_C_PORT_CONFIG_ERROR);
	}

	if (!pm_runtime_active(&port_dev->dev))
		return;

	if (hub_handle_remote_wakeup(hub, port1, portstatus, portchange))
		connect_change = 1;

	if (hub_port_warm_reset_required(hub, port1, portstatus)) {
		dev_dbg(&port_dev->dev, "do warm reset\n");
		if (!udev || !(portstatus & USB_PORT_STAT_CONNECTION)
				|| udev->state == USB_STATE_NOTATTACHED) {
			if (hub_port_reset(hub, port1, NULL,
					HUB_BH_RESET_TIME, true) < 0)
				hub_port_disable(hub, port1, 1);
		} else {
			usb_unlock_port(port_dev);
			usb_lock_device(udev);
			usb_reset_device(udev);
			usb_unlock_device(udev);
			usb_lock_port(port_dev);
			connect_change = 0;
		}
	}

	if (connect_change)
		hub_port_connect_change(hub, port1, portstatus, portchange);
}

static void hub_event(struct work_struct *work)
{
	struct usb_device *hdev;
	struct usb_interface *intf;
	struct usb_hub *hub;
	struct device *hub_dev;
	u16 hubstatus;
	u16 hubchange;
	int i, ret;
#ifdef MY_ABC_HERE
	u16 portstatus;
	u16 portchange;
	int ups_discon_flt;
	int connect_change;
#endif  
	hub = container_of(work, struct usb_hub, events);
	hdev = hub->hdev;
	hub_dev = hub->intfdev;
	intf = to_usb_interface(hub_dev);

	dev_dbg(hub_dev, "state %d ports %d chg %04x evt %04x\n",
			hdev->state, hdev->maxchild,
			 
			(u16) hub->change_bits[0],
			(u16) hub->event_bits[0]);

	usb_lock_device(hdev);
	if (unlikely(hub->disconnected))
		goto out_hdev_lock;

	if (hdev->state == USB_STATE_NOTATTACHED) {
		hub->error = -ENODEV;
		hub_quiesce(hub, HUB_DISCONNECT);
		goto out_hdev_lock;
	}

	ret = usb_autopm_get_interface(intf);
	if (ret) {
		dev_dbg(hub_dev, "Can't autoresume: %d\n", ret);
		goto out_hdev_lock;
	}

	if (hub->quiescing)
		goto out_autopm;

	if (hub->error) {
		dev_dbg(hub_dev, "resetting for error %d\n", hub->error);

		ret = usb_reset_device(hdev);
		if (ret) {
			dev_dbg(hub_dev, "error resetting hub: %d\n", ret);
			goto out_autopm;
		}

		hub->nerrors = 0;
		hub->error = 0;
	}

#ifdef MY_ABC_HERE
	ups_discon_flt = 0;

	if (SYNO_UPS_DISCON_FLT_STATUS_NONE != hub->ups_discon_flt_status) {
		connect_change = 0;
		i = hub->ups_discon_flt_port;
		 
		connect_change = test_bit(i, hub->change_bits);

		ret = hub_port_status(hub, i,
				&portstatus, &portchange);

		if (0 >= ret &&
			portchange & USB_PORT_STAT_C_CONNECTION)
			connect_change = 1;

		if (connect_change)
			 
			ups_discon_flt = 1;
		else
			 
			goto out_hdev_lock;
	}
#endif  

#ifdef MY_ABC_HERE
	for (i = ups_discon_flt? hub->ups_discon_flt_port: 1;
		 i <= hdev->maxchild;
		 i = ups_discon_flt? 1: i + 1, ups_discon_flt = 0) {
#else
	for (i = 1; i <= hdev->maxchild; i++) {
#endif  
		struct usb_port *port_dev = hub->ports[i - 1];

		if (test_bit(i, hub->event_bits)
				|| test_bit(i, hub->change_bits)
				|| test_bit(i, hub->wakeup_bits)) {
			 
			pm_runtime_get_noresume(&port_dev->dev);
			pm_runtime_barrier(&port_dev->dev);
			usb_lock_port(port_dev);
			port_event(hub, i);
			usb_unlock_port(port_dev);
			pm_runtime_put_sync(&port_dev->dev);
		}
	}

	if (test_and_clear_bit(0, hub->event_bits) == 0)
		;	 
	else if (hub_hub_status(hub, &hubstatus, &hubchange) < 0)
		dev_err(hub_dev, "get_hub_status failed\n");
	else {
		if (hubchange & HUB_CHANGE_LOCAL_POWER) {
			dev_dbg(hub_dev, "power change\n");
			clear_hub_feature(hdev, C_HUB_LOCAL_POWER);
			if (hubstatus & HUB_STATUS_LOCAL_POWER)
				 
				hub->limited_power = 1;
			else
				hub->limited_power = 0;
		}
		if (hubchange & HUB_CHANGE_OVERCURRENT) {
			u16 status = 0;
			u16 unused;

			dev_dbg(hub_dev, "over-current change\n");
			clear_hub_feature(hdev, C_HUB_OVER_CURRENT);
			msleep(500);	 
			hub_power_on(hub, true);
			hub_hub_status(hub, &status, &unused);
			if (status & HUB_STATUS_OVERCURRENT)
				dev_err(hub_dev, "over-current condition\n");
		}
	}

out_autopm:
	 
	usb_autopm_put_interface_no_suspend(intf);
out_hdev_lock:
	usb_unlock_device(hdev);

	usb_autopm_put_interface(intf);
	kref_put(&hub->kref, hub_release);
}

static const struct usb_device_id hub_id_table[] = {
    { .match_flags = USB_DEVICE_ID_MATCH_VENDOR
			| USB_DEVICE_ID_MATCH_INT_CLASS,
      .idVendor = USB_VENDOR_GENESYS_LOGIC,
      .bInterfaceClass = USB_CLASS_HUB,
      .driver_info = HUB_QUIRK_CHECK_PORT_AUTOSUSPEND},
    { .match_flags = USB_DEVICE_ID_MATCH_DEV_CLASS,
      .bDeviceClass = USB_CLASS_HUB},
    { .match_flags = USB_DEVICE_ID_MATCH_INT_CLASS,
      .bInterfaceClass = USB_CLASS_HUB},
    { }						 
};

MODULE_DEVICE_TABLE(usb, hub_id_table);

static struct usb_driver hub_driver = {
	.name =		"hub",
	.probe =	hub_probe,
	.disconnect =	hub_disconnect,
	.suspend =	hub_suspend,
	.resume =	hub_resume,
	.reset_resume =	hub_reset_resume,
	.pre_reset =	hub_pre_reset,
	.post_reset =	hub_post_reset,
	.unlocked_ioctl = hub_ioctl,
	.id_table =	hub_id_table,
	.supports_autosuspend =	1,
};

int usb_hub_init(void)
{
	if (usb_register(&hub_driver) < 0) {
		printk(KERN_ERR "%s: can't register hub driver\n",
			usbcore_name);
		return -1;
	}

	hub_wq = alloc_workqueue("usb_hub_wq", WQ_FREEZABLE, 0);
	if (hub_wq)
		return 0;

	usb_deregister(&hub_driver);
	pr_err("%s: can't allocate workqueue for usb hub\n", usbcore_name);

	return -1;
}

void usb_hub_cleanup(void)
{
	destroy_workqueue(hub_wq);

	usb_deregister(&hub_driver);
}  

static int descriptors_changed(struct usb_device *udev,
		struct usb_device_descriptor *old_device_descriptor,
		struct usb_host_bos *old_bos)
{
	int		changed = 0;
	unsigned	index;
	unsigned	serial_len = 0;
	unsigned	len;
	unsigned	old_length;
	int		length;
	char		*buf;

	if (memcmp(&udev->descriptor, old_device_descriptor,
			sizeof(*old_device_descriptor)) != 0)
		return 1;

	if ((old_bos && !udev->bos) || (!old_bos && udev->bos))
		return 1;
	if (udev->bos) {
		len = le16_to_cpu(udev->bos->desc->wTotalLength);
		if (len != le16_to_cpu(old_bos->desc->wTotalLength))
			return 1;
		if (memcmp(udev->bos->desc, old_bos->desc, len))
			return 1;
	}

#if defined(MY_ABC_HERE)
	 
	if (udev->syno_old_serial)
		serial_len = strlen(udev->syno_old_serial) + 1;
#else
	if (udev->serial)
		serial_len = strlen(udev->serial) + 1;
#endif  

	len = serial_len;
	for (index = 0; index < udev->descriptor.bNumConfigurations; index++) {
		old_length = le16_to_cpu(udev->config[index].desc.wTotalLength);
		len = max(len, old_length);
	}

	buf = kmalloc(len, GFP_NOIO);
	if (buf == NULL) {
		dev_err(&udev->dev, "no mem to re-read configs after reset\n");
		 
		return 1;
	}
	for (index = 0; index < udev->descriptor.bNumConfigurations; index++) {
		old_length = le16_to_cpu(udev->config[index].desc.wTotalLength);
		length = usb_get_descriptor(udev, USB_DT_CONFIG, index, buf,
				old_length);
		if (length != old_length) {
			dev_dbg(&udev->dev, "config index %d, error %d\n",
					index, length);
			changed = 1;
			break;
		}
		if (memcmp(buf, udev->rawdescriptors[index], old_length)
				!= 0) {
			dev_dbg(&udev->dev, "config index %d changed (#%d)\n",
				index,
				((struct usb_config_descriptor *) buf)->
					bConfigurationValue);
			changed = 1;
			break;
		}
	}

	if (!changed && serial_len) {
		length = usb_string(udev, udev->descriptor.iSerialNumber,
				buf, serial_len);
		if (length + 1 != serial_len) {
			dev_dbg(&udev->dev, "serial string error %d\n",
					length);
			changed = 1;
#if defined(MY_ABC_HERE)
			 
		} else if (memcmp(buf, udev->syno_old_serial, length) != 0) {
#else
		} else if (memcmp(buf, udev->serial, length) != 0) {
#endif  
			dev_dbg(&udev->dev, "serial string changed\n");
			changed = 1;
		}
	}

	kfree(buf);
	return changed;
}

static int usb_reset_and_verify_device(struct usb_device *udev)
{
	struct usb_device		*parent_hdev = udev->parent;
	struct usb_hub			*parent_hub;
	struct usb_hcd			*hcd = bus_to_hcd(udev->bus);
	struct usb_device_descriptor	descriptor = udev->descriptor;
	struct usb_host_bos		*bos;
	int				i, j, ret = 0;
	int				port1 = udev->portnum;

	if (udev->state == USB_STATE_NOTATTACHED ||
			udev->state == USB_STATE_SUSPENDED) {
		dev_dbg(&udev->dev, "device reset not allowed in state %d\n",
				udev->state);
		return -EINVAL;
	}

	if (!parent_hdev)
		return -EISDIR;

	parent_hub = usb_hub_to_struct_hub(parent_hdev);

	if (udev->usb2_hw_lpm_enabled == 1)
		usb_set_usb2_hardware_lpm(udev, 0);

	ret = usb_unlocked_disable_lpm(udev);
	if (ret) {
		dev_err(&udev->dev, "%s Failed to disable LPM\n.", __func__);
		goto re_enumerate_no_bos;
	}
	ret = usb_disable_ltm(udev);
	if (ret) {
		dev_err(&udev->dev, "%s Failed to disable LTM\n.",
				__func__);
		goto re_enumerate_no_bos;
	}

	bos = udev->bos;
	udev->bos = NULL;

	for (i = 0; i < SET_CONFIG_TRIES; ++i) {

		usb_ep0_reinit(udev);
		ret = hub_port_init(parent_hub, udev, port1, i);
		if (ret >= 0 || ret == -ENOTCONN || ret == -ENODEV)
			break;
	}

	if (ret < 0)
		goto re_enumerate;

	if (descriptors_changed(udev, &descriptor, bos)) {
		dev_info(&udev->dev, "device firmware changed\n");
		udev->descriptor = descriptor;	 
		goto re_enumerate;
	}

	if (!udev->actconfig)
		goto done;

	mutex_lock(hcd->bandwidth_mutex);
	ret = usb_hcd_alloc_bandwidth(udev, udev->actconfig, NULL, NULL);
	if (ret < 0) {
		dev_warn(&udev->dev,
				"Busted HC?  Not enough HCD resources for "
				"old configuration.\n");
		mutex_unlock(hcd->bandwidth_mutex);
		goto re_enumerate;
	}
	ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			USB_REQ_SET_CONFIGURATION, 0,
			udev->actconfig->desc.bConfigurationValue, 0,
			NULL, 0, USB_CTRL_SET_TIMEOUT);
	if (ret < 0) {
		dev_err(&udev->dev,
			"can't restore configuration #%d (error=%d)\n",
			udev->actconfig->desc.bConfigurationValue, ret);
		mutex_unlock(hcd->bandwidth_mutex);
		goto re_enumerate;
	}
	mutex_unlock(hcd->bandwidth_mutex);
	usb_set_device_state(udev, USB_STATE_CONFIGURED);

	for (i = 0; i < udev->actconfig->desc.bNumInterfaces; i++) {
		struct usb_host_config *config = udev->actconfig;
		struct usb_interface *intf = config->interface[i];
		struct usb_interface_descriptor *desc;

		desc = &intf->cur_altsetting->desc;
		if (desc->bAlternateSetting == 0) {
			usb_disable_interface(udev, intf, true);
			usb_enable_interface(udev, intf, true);
			ret = 0;
		} else {
			 
			intf->resetting_device = 1;
			ret = usb_set_interface(udev, desc->bInterfaceNumber,
					desc->bAlternateSetting);
			intf->resetting_device = 0;
		}
		if (ret < 0) {
			dev_err(&udev->dev, "failed to restore interface %d "
				"altsetting %d (error=%d)\n",
				desc->bInterfaceNumber,
				desc->bAlternateSetting,
				ret);
			goto re_enumerate;
		}
		 
		for (j = 0; j < intf->cur_altsetting->desc.bNumEndpoints; j++)
			intf->cur_altsetting->endpoint[j].streams = 0;
	}

done:
	 
	usb_set_usb2_hardware_lpm(udev, 1);
	usb_unlocked_enable_lpm(udev);
	usb_enable_ltm(udev);
	usb_release_bos_descriptor(udev);
	udev->bos = bos;
	return 0;

re_enumerate:
	usb_release_bos_descriptor(udev);
	udev->bos = bos;
re_enumerate_no_bos:
	 
	hub_port_logical_disconnect(parent_hub, port1);
	return -ENODEV;
}

int usb_reset_device(struct usb_device *udev)
{
	int ret;
	int i;
	unsigned int noio_flag;
	struct usb_port *port_dev;
	struct usb_host_config *config = udev->actconfig;
	struct usb_hub *hub = usb_hub_to_struct_hub(udev->parent);

#if defined(CONFIG_USB_ETRON_HUB)
	if (usb_is_etron_hcd(udev))
		return ethub_usb_reset_device(udev);
#endif  

	if (udev->state == USB_STATE_NOTATTACHED ||
			udev->state == USB_STATE_SUSPENDED) {
		dev_dbg(&udev->dev, "device reset not allowed in state %d\n",
				udev->state);
		return -EINVAL;
	}

	if (!udev->parent) {
		 
		dev_dbg(&udev->dev, "%s for root hub!\n", __func__);
		return -EISDIR;
	}

	port_dev = hub->ports[udev->portnum - 1];

	noio_flag = memalloc_noio_save();

	usb_autoresume_device(udev);

	if (config) {
		for (i = 0; i < config->desc.bNumInterfaces; ++i) {
			struct usb_interface *cintf = config->interface[i];
			struct usb_driver *drv;
			int unbind = 0;

			if (cintf->dev.driver) {
				drv = to_usb_driver(cintf->dev.driver);
				if (drv->pre_reset && drv->post_reset)
					unbind = (drv->pre_reset)(cintf);
				else if (cintf->condition ==
						USB_INTERFACE_BOUND)
					unbind = 1;
				if (unbind)
					usb_forced_unbind_intf(cintf);
			}
		}
	}

	usb_lock_port(port_dev);
	ret = usb_reset_and_verify_device(udev);
	usb_unlock_port(port_dev);

	if (config) {
		for (i = config->desc.bNumInterfaces - 1; i >= 0; --i) {
			struct usb_interface *cintf = config->interface[i];
			struct usb_driver *drv;
			int rebind = cintf->needs_binding;

			if (!rebind && cintf->dev.driver) {
				drv = to_usb_driver(cintf->dev.driver);
				if (drv->post_reset)
					rebind = (drv->post_reset)(cintf);
				else if (cintf->condition ==
						USB_INTERFACE_BOUND)
					rebind = 1;
				if (rebind)
					cintf->needs_binding = 1;
			}
		}
		usb_unbind_and_rebind_marked_interfaces(udev);
	}

	usb_autosuspend_device(udev);
	memalloc_noio_restore(noio_flag);
	return ret;
}
EXPORT_SYMBOL_GPL(usb_reset_device);

void usb_queue_reset_device(struct usb_interface *iface)
{
	if (schedule_work(&iface->reset_ws))
		usb_get_intf(iface);
}
EXPORT_SYMBOL_GPL(usb_queue_reset_device);

struct usb_device *usb_hub_find_child(struct usb_device *hdev,
		int port1)
{
	struct usb_hub *hub = usb_hub_to_struct_hub(hdev);

	if (port1 < 1 || port1 > hdev->maxchild)
		return NULL;
	return hub->ports[port1 - 1]->child;
}
EXPORT_SYMBOL_GPL(usb_hub_find_child);

void usb_hub_adjust_deviceremovable(struct usb_device *hdev,
		struct usb_hub_descriptor *desc)
{
	struct usb_hub *hub = usb_hub_to_struct_hub(hdev);
	enum usb_port_connect_type connect_type;
	int i;

	if (!hub)
		return;

	if (!hub_is_superspeed(hdev)) {
		for (i = 1; i <= hdev->maxchild; i++) {
			struct usb_port *port_dev = hub->ports[i - 1];

			connect_type = port_dev->connect_type;
			if (connect_type == USB_PORT_CONNECT_TYPE_HARD_WIRED) {
				u8 mask = 1 << (i%8);

				if (!(desc->u.hs.DeviceRemovable[i/8] & mask)) {
					dev_dbg(&port_dev->dev, "DeviceRemovable is changed to 1 according to platform information.\n");
					desc->u.hs.DeviceRemovable[i/8]	|= mask;
				}
			}
		}
	} else {
		u16 port_removable = le16_to_cpu(desc->u.ss.DeviceRemovable);

		for (i = 1; i <= hdev->maxchild; i++) {
			struct usb_port *port_dev = hub->ports[i - 1];

			connect_type = port_dev->connect_type;
			if (connect_type == USB_PORT_CONNECT_TYPE_HARD_WIRED) {
				u16 mask = 1 << i;

				if (!(port_removable & mask)) {
					dev_dbg(&port_dev->dev, "DeviceRemovable is changed to 1 according to platform information.\n");
					port_removable |= mask;
				}
			}
		}

		desc->u.ss.DeviceRemovable = cpu_to_le16(port_removable);
	}
}

#ifdef CONFIG_ACPI
 
acpi_handle usb_get_hub_port_acpi_handle(struct usb_device *hdev,
	int port1)
{
	struct usb_hub *hub = usb_hub_to_struct_hub(hdev);

	if (!hub)
		return NULL;

	return ACPI_HANDLE(&hub->ports[port1 - 1]->dev);
}
#endif
