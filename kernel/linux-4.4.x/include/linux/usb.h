#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifndef __LINUX_USB_H
#define __LINUX_USB_H

#include <linux/mod_devicetable.h>
#include <linux/usb/ch9.h>

#define USB_MAJOR			180
#define USB_DEVICE_MAJOR		189

#ifdef __KERNEL__

#include <linux/errno.h>         
#include <linux/delay.h>	 
#include <linux/interrupt.h>	 
#include <linux/list.h>		 
#include <linux/kref.h>		 
#include <linux/device.h>	 
#include <linux/fs.h>		 
#include <linux/completion.h>	 
#include <linux/sched.h>	 
#include <linux/mutex.h>	 
#include <linux/pm_runtime.h>	 

struct usb_device;
struct usb_driver;
struct wusb_dev;

struct ep_device;

struct usb_host_endpoint {
	struct usb_endpoint_descriptor		desc;
	struct usb_ss_ep_comp_descriptor	ss_ep_comp;
	struct list_head		urb_list;
	void				*hcpriv;
	struct ep_device		*ep_dev;	 

	unsigned char *extra;    
	int extralen;
	int enabled;
	int streams;
};

struct usb_host_interface {
	struct usb_interface_descriptor	desc;

	int extralen;
	unsigned char *extra;    

	struct usb_host_endpoint *endpoint;

	char *string;		 
};

enum usb_interface_condition {
	USB_INTERFACE_UNBOUND = 0,
	USB_INTERFACE_BINDING,
	USB_INTERFACE_BOUND,
	USB_INTERFACE_UNBINDING,
};

struct usb_interface {
	 
	struct usb_host_interface *altsetting;

	struct usb_host_interface *cur_altsetting;	 
	unsigned num_altsetting;	 

	struct usb_interface_assoc_descriptor *intf_assoc;

	int minor;			 
	enum usb_interface_condition condition;		 
	unsigned sysfs_files_created:1;	 
	unsigned ep_devs_created:1;	 
	unsigned unregistering:1;	 
	unsigned needs_remote_wakeup:1;	 
	unsigned needs_altsetting0:1;	 
	unsigned needs_binding:1;	 
	unsigned resetting_device:1;	 
	unsigned authorized:1;		 

	struct device dev;		 
	struct device *usb_dev;
	atomic_t pm_usage_cnt;		 
	struct work_struct reset_ws;	 
};
#define	to_usb_interface(d) container_of(d, struct usb_interface, dev)

static inline void *usb_get_intfdata(struct usb_interface *intf)
{
	return dev_get_drvdata(&intf->dev);
}

static inline void usb_set_intfdata(struct usb_interface *intf, void *data)
{
	dev_set_drvdata(&intf->dev, data);
}

struct usb_interface *usb_get_intf(struct usb_interface *intf);
void usb_put_intf(struct usb_interface *intf);

#define USB_MAXENDPOINTS	30
 
#define USB_MAXINTERFACES	32
#define USB_MAXIADS		(USB_MAXINTERFACES/2)

#define USB_RESUME_TIMEOUT	40  

struct usb_interface_cache {
	unsigned num_altsetting;	 
	struct kref ref;		 

	struct usb_host_interface altsetting[0];
};
#define	ref_to_usb_interface_cache(r) \
		container_of(r, struct usb_interface_cache, ref)
#define	altsetting_to_usb_interface_cache(a) \
		container_of(a, struct usb_interface_cache, altsetting[0])

struct usb_host_config {
	struct usb_config_descriptor	desc;

	char *string;		 

	struct usb_interface_assoc_descriptor *intf_assoc[USB_MAXIADS];

	struct usb_interface *interface[USB_MAXINTERFACES];

	struct usb_interface_cache *intf_cache[USB_MAXINTERFACES];

	unsigned char *extra;    
	int extralen;
};

struct usb_host_bos {
	struct usb_bos_descriptor	*desc;

	struct usb_ext_cap_descriptor	*ext_cap;
	struct usb_ss_cap_descriptor	*ss_cap;
	struct usb_ssp_cap_descriptor	*ssp_cap;
	struct usb_ss_container_id_descriptor	*ss_id;
};

int __usb_get_extra_descriptor(char *buffer, unsigned size,
	unsigned char type, void **ptr);
#define usb_get_extra_descriptor(ifpoint, type, ptr) \
				__usb_get_extra_descriptor((ifpoint)->extra, \
				(ifpoint)->extralen, \
				type, (void **)ptr)

struct usb_devmap {
	unsigned long devicemap[128 / (8*sizeof(unsigned long))];
};

struct usb_bus {
	struct device *controller;	 
	int busnum;			 
	const char *bus_name;		 
	u8 uses_dma;			 
	u8 uses_pio_for_control;	 
	u8 otg_port;			 
	unsigned is_b_host:1;		 
	unsigned b_hnp_enable:1;	 
	unsigned no_stop_on_short:1;     
	unsigned no_sg_constraint:1;	 
	unsigned sg_tablesize;		 

	int devnum_next;		 
	struct mutex devnum_next_mutex;  

	struct usb_devmap devmap;	 
	struct usb_device *root_hub;	 
	struct usb_bus *hs_companion;	 
	struct list_head bus_list;	 

	int bandwidth_allocated;	 
	int bandwidth_int_reqs;		 
	int bandwidth_isoc_reqs;	 

	unsigned resuming_ports;	 

#if defined(CONFIG_USB_MON) || defined(CONFIG_USB_MON_MODULE)
	struct mon_bus *mon_bus;	 
	int monitored;			 
#endif
};

struct usb_dev_state;

struct usb_tt;

enum usb_device_removable {
	USB_DEVICE_REMOVABLE_UNKNOWN = 0,
	USB_DEVICE_REMOVABLE,
	USB_DEVICE_FIXED,
};

enum usb_port_connect_type {
	USB_PORT_CONNECT_TYPE_UNKNOWN = 0,
	USB_PORT_CONNECT_TYPE_HOT_PLUG,
	USB_PORT_CONNECT_TYPE_HARD_WIRED,
	USB_PORT_NOT_USED,
};

struct usb2_lpm_parameters {
	 
	unsigned int besl;

	int timeout;
};

struct usb3_lpm_parameters {
	 
	unsigned int mel;
	 
	unsigned int pel;

	unsigned int sel;
	 
	int timeout;
};

struct usb_device {
	int		devnum;
	char		devpath[16];
	u32		route;
	enum usb_device_state	state;
	enum usb_device_speed	speed;

	struct usb_tt	*tt;
	int		ttport;

	unsigned int toggle[2];

	struct usb_device *parent;
	struct usb_bus *bus;
	struct usb_host_endpoint ep0;

	struct device dev;

	struct usb_device_descriptor descriptor;
	struct usb_host_bos *bos;
	struct usb_host_config *config;

	struct usb_host_config *actconfig;
	struct usb_host_endpoint *ep_in[16];
	struct usb_host_endpoint *ep_out[16];

	char **rawdescriptors;

	unsigned short bus_mA;
	u8 portnum;
	u8 level;

	unsigned can_submit:1;
	unsigned persist_enabled:1;
	unsigned have_langid:1;
	unsigned authorized:1;
	unsigned authenticated:1;
	unsigned wusb:1;
	unsigned lpm_capable:1;
	unsigned usb2_hw_lpm_capable:1;
	unsigned usb2_hw_lpm_besl_capable:1;
	unsigned usb2_hw_lpm_enabled:1;
	unsigned usb2_hw_lpm_allowed:1;
	unsigned usb3_lpm_enabled:1;
	unsigned usb3_lpm_u1_enabled:1;
	unsigned usb3_lpm_u2_enabled:1;
	int string_langid;

	char *product;
	char *manufacturer;
	char *serial;

	struct list_head filelist;

	int maxchild;

	u32 quirks;
#ifdef MY_ABC_HERE
	char *syno_old_serial;
#endif  
#ifdef MY_ABC_HERE
	u32 syno_quirks;
#endif  
	atomic_t urbnum;

	unsigned long active_duration;

#ifdef CONFIG_PM
	unsigned long connect_time;

	unsigned do_remote_wakeup:1;
	unsigned reset_resume:1;
	unsigned port_is_suspended:1;
#endif
	struct wusb_dev *wusb_dev;
	int slot_id;
	enum usb_device_removable removable;
	struct usb2_lpm_parameters l1_params;
	struct usb3_lpm_parameters u1_params;
	struct usb3_lpm_parameters u2_params;
	unsigned lpm_disable_count;
};
#define	to_usb_device(d) container_of(d, struct usb_device, dev)

static inline struct usb_device *interface_to_usbdev(struct usb_interface *intf)
{
	return to_usb_device(intf->dev.parent);
}

extern struct usb_device *usb_get_dev(struct usb_device *dev);
extern void usb_put_dev(struct usb_device *dev);
extern struct usb_device *usb_hub_find_child(struct usb_device *hdev,
	int port1);

#define usb_hub_for_each_child(hdev, port1, child) \
	for (port1 = 1,	child =	usb_hub_find_child(hdev, port1); \
			port1 <= hdev->maxchild; \
			child = usb_hub_find_child(hdev, ++port1)) \
		if (!child) continue; else

#define usb_lock_device(udev)		device_lock(&(udev)->dev)
#define usb_unlock_device(udev)		device_unlock(&(udev)->dev)
#define usb_trylock_device(udev)	device_trylock(&(udev)->dev)
extern int usb_lock_device_for_reset(struct usb_device *udev,
				     const struct usb_interface *iface);

extern int usb_reset_device(struct usb_device *dev);
extern void usb_queue_reset_device(struct usb_interface *dev);

#ifdef CONFIG_ACPI
extern int usb_acpi_set_power_state(struct usb_device *hdev, int index,
	bool enable);
extern bool usb_acpi_power_manageable(struct usb_device *hdev, int index);
#else
static inline int usb_acpi_set_power_state(struct usb_device *hdev, int index,
	bool enable) { return 0; }
static inline bool usb_acpi_power_manageable(struct usb_device *hdev, int index)
	{ return true; }
#endif

#ifdef CONFIG_PM
extern void usb_enable_autosuspend(struct usb_device *udev);
extern void usb_disable_autosuspend(struct usb_device *udev);

extern int usb_autopm_get_interface(struct usb_interface *intf);
extern void usb_autopm_put_interface(struct usb_interface *intf);
extern int usb_autopm_get_interface_async(struct usb_interface *intf);
extern void usb_autopm_put_interface_async(struct usb_interface *intf);
extern void usb_autopm_get_interface_no_resume(struct usb_interface *intf);
extern void usb_autopm_put_interface_no_suspend(struct usb_interface *intf);

static inline void usb_mark_last_busy(struct usb_device *udev)
{
	pm_runtime_mark_last_busy(&udev->dev);
}

#else

static inline int usb_enable_autosuspend(struct usb_device *udev)
{ return 0; }
static inline int usb_disable_autosuspend(struct usb_device *udev)
{ return 0; }

static inline int usb_autopm_get_interface(struct usb_interface *intf)
{ return 0; }
static inline int usb_autopm_get_interface_async(struct usb_interface *intf)
{ return 0; }

static inline void usb_autopm_put_interface(struct usb_interface *intf)
{ }
static inline void usb_autopm_put_interface_async(struct usb_interface *intf)
{ }
static inline void usb_autopm_get_interface_no_resume(
		struct usb_interface *intf)
{ }
static inline void usb_autopm_put_interface_no_suspend(
		struct usb_interface *intf)
{ }
static inline void usb_mark_last_busy(struct usb_device *udev)
{ }
#endif

extern int usb_disable_lpm(struct usb_device *udev);
extern void usb_enable_lpm(struct usb_device *udev);
 
extern int usb_unlocked_disable_lpm(struct usb_device *udev);
extern void usb_unlocked_enable_lpm(struct usb_device *udev);

extern int usb_disable_ltm(struct usb_device *udev);
extern void usb_enable_ltm(struct usb_device *udev);

static inline bool usb_device_supports_ltm(struct usb_device *udev)
{
	if (udev->speed != USB_SPEED_SUPER || !udev->bos || !udev->bos->ss_cap)
		return false;
	return udev->bos->ss_cap->bmAttributes & USB_LTM_SUPPORT;
}

static inline bool usb_device_no_sg_constraint(struct usb_device *udev)
{
	return udev && udev->bus && udev->bus->no_sg_constraint;
}

extern int usb_get_current_frame_number(struct usb_device *usb_dev);

extern int usb_alloc_streams(struct usb_interface *interface,
		struct usb_host_endpoint **eps, unsigned int num_eps,
		unsigned int num_streams, gfp_t mem_flags);

extern int usb_free_streams(struct usb_interface *interface,
		struct usb_host_endpoint **eps, unsigned int num_eps,
		gfp_t mem_flags);

extern int usb_driver_claim_interface(struct usb_driver *driver,
			struct usb_interface *iface, void *priv);

static inline int usb_interface_claimed(struct usb_interface *iface)
{
	return (iface->dev.driver != NULL);
}

extern void usb_driver_release_interface(struct usb_driver *driver,
			struct usb_interface *iface);
const struct usb_device_id *usb_match_id(struct usb_interface *interface,
					 const struct usb_device_id *id);
extern int usb_match_one_id(struct usb_interface *interface,
			    const struct usb_device_id *id);

extern int usb_for_each_dev(void *data, int (*fn)(struct usb_device *, void *));
extern struct usb_interface *usb_find_interface(struct usb_driver *drv,
		int minor);
extern struct usb_interface *usb_ifnum_to_if(const struct usb_device *dev,
		unsigned ifnum);
extern struct usb_host_interface *usb_altnum_to_altsetting(
		const struct usb_interface *intf, unsigned int altnum);
extern struct usb_host_interface *usb_find_alt_setting(
		struct usb_host_config *config,
		unsigned int iface_num,
		unsigned int alt_num);

int usb_hub_claim_port(struct usb_device *hdev, unsigned port1,
		struct usb_dev_state *owner);
int usb_hub_release_port(struct usb_device *hdev, unsigned port1,
		struct usb_dev_state *owner);

static inline int usb_make_path(struct usb_device *dev, char *buf, size_t size)
{
	int actual;
	actual = snprintf(buf, size, "usb-%s-%s", dev->bus->bus_name,
			  dev->devpath);
	return (actual >= (int)size) ? -1 : actual;
}

#define USB_DEVICE_ID_MATCH_DEVICE \
		(USB_DEVICE_ID_MATCH_VENDOR | USB_DEVICE_ID_MATCH_PRODUCT)
#define USB_DEVICE_ID_MATCH_DEV_RANGE \
		(USB_DEVICE_ID_MATCH_DEV_LO | USB_DEVICE_ID_MATCH_DEV_HI)
#define USB_DEVICE_ID_MATCH_DEVICE_AND_VERSION \
		(USB_DEVICE_ID_MATCH_DEVICE | USB_DEVICE_ID_MATCH_DEV_RANGE)
#define USB_DEVICE_ID_MATCH_DEV_INFO \
		(USB_DEVICE_ID_MATCH_DEV_CLASS | \
		USB_DEVICE_ID_MATCH_DEV_SUBCLASS | \
		USB_DEVICE_ID_MATCH_DEV_PROTOCOL)
#define USB_DEVICE_ID_MATCH_INT_INFO \
		(USB_DEVICE_ID_MATCH_INT_CLASS | \
		USB_DEVICE_ID_MATCH_INT_SUBCLASS | \
		USB_DEVICE_ID_MATCH_INT_PROTOCOL)

#define USB_DEVICE(vend, prod) \
	.match_flags = USB_DEVICE_ID_MATCH_DEVICE, \
	.idVendor = (vend), \
	.idProduct = (prod)
 
#define USB_DEVICE_VER(vend, prod, lo, hi) \
	.match_flags = USB_DEVICE_ID_MATCH_DEVICE_AND_VERSION, \
	.idVendor = (vend), \
	.idProduct = (prod), \
	.bcdDevice_lo = (lo), \
	.bcdDevice_hi = (hi)

#define USB_DEVICE_INTERFACE_CLASS(vend, prod, cl) \
	.match_flags = USB_DEVICE_ID_MATCH_DEVICE | \
		       USB_DEVICE_ID_MATCH_INT_CLASS, \
	.idVendor = (vend), \
	.idProduct = (prod), \
	.bInterfaceClass = (cl)

#define USB_DEVICE_INTERFACE_PROTOCOL(vend, prod, pr) \
	.match_flags = USB_DEVICE_ID_MATCH_DEVICE | \
		       USB_DEVICE_ID_MATCH_INT_PROTOCOL, \
	.idVendor = (vend), \
	.idProduct = (prod), \
	.bInterfaceProtocol = (pr)

#define USB_DEVICE_INTERFACE_NUMBER(vend, prod, num) \
	.match_flags = USB_DEVICE_ID_MATCH_DEVICE | \
		       USB_DEVICE_ID_MATCH_INT_NUMBER, \
	.idVendor = (vend), \
	.idProduct = (prod), \
	.bInterfaceNumber = (num)

#define USB_DEVICE_INFO(cl, sc, pr) \
	.match_flags = USB_DEVICE_ID_MATCH_DEV_INFO, \
	.bDeviceClass = (cl), \
	.bDeviceSubClass = (sc), \
	.bDeviceProtocol = (pr)

#define USB_INTERFACE_INFO(cl, sc, pr) \
	.match_flags = USB_DEVICE_ID_MATCH_INT_INFO, \
	.bInterfaceClass = (cl), \
	.bInterfaceSubClass = (sc), \
	.bInterfaceProtocol = (pr)

#define USB_DEVICE_AND_INTERFACE_INFO(vend, prod, cl, sc, pr) \
	.match_flags = USB_DEVICE_ID_MATCH_INT_INFO \
		| USB_DEVICE_ID_MATCH_DEVICE, \
	.idVendor = (vend), \
	.idProduct = (prod), \
	.bInterfaceClass = (cl), \
	.bInterfaceSubClass = (sc), \
	.bInterfaceProtocol = (pr)

#define USB_VENDOR_AND_INTERFACE_INFO(vend, cl, sc, pr) \
	.match_flags = USB_DEVICE_ID_MATCH_INT_INFO \
		| USB_DEVICE_ID_MATCH_VENDOR, \
	.idVendor = (vend), \
	.bInterfaceClass = (cl), \
	.bInterfaceSubClass = (sc), \
	.bInterfaceProtocol = (pr)

struct usb_dynids {
	spinlock_t lock;
	struct list_head list;
};

struct usb_dynid {
	struct list_head node;
	struct usb_device_id id;
};

extern ssize_t usb_store_new_id(struct usb_dynids *dynids,
				const struct usb_device_id *id_table,
				struct device_driver *driver,
				const char *buf, size_t count);

extern ssize_t usb_show_dynids(struct usb_dynids *dynids, char *buf);

struct usbdrv_wrap {
	struct device_driver driver;
	int for_devices;
};

struct usb_driver {
	const char *name;

	int (*probe) (struct usb_interface *intf,
		      const struct usb_device_id *id);

	void (*disconnect) (struct usb_interface *intf);

	int (*unlocked_ioctl) (struct usb_interface *intf, unsigned int code,
			void *buf);

	int (*suspend) (struct usb_interface *intf, pm_message_t message);
	int (*resume) (struct usb_interface *intf);
	int (*reset_resume)(struct usb_interface *intf);

	int (*pre_reset)(struct usb_interface *intf);
	int (*post_reset)(struct usb_interface *intf);

	const struct usb_device_id *id_table;

	struct usb_dynids dynids;
	struct usbdrv_wrap drvwrap;
	unsigned int no_dynamic_id:1;
	unsigned int supports_autosuspend:1;
	unsigned int disable_hub_initiated_lpm:1;
	unsigned int soft_unbind:1;
};
#define	to_usb_driver(d) container_of(d, struct usb_driver, drvwrap.driver)

struct usb_device_driver {
	const char *name;

	int (*probe) (struct usb_device *udev);
	void (*disconnect) (struct usb_device *udev);

	int (*suspend) (struct usb_device *udev, pm_message_t message);
	int (*resume) (struct usb_device *udev, pm_message_t message);
	struct usbdrv_wrap drvwrap;
	unsigned int supports_autosuspend:1;
};
#define	to_usb_device_driver(d) container_of(d, struct usb_device_driver, \
		drvwrap.driver)

extern struct bus_type usb_bus_type;

struct usb_class_driver {
	char *name;
	char *(*devnode)(struct device *dev, umode_t *mode);
	const struct file_operations *fops;
	int minor_base;
};

extern int usb_register_driver(struct usb_driver *, struct module *,
			       const char *);

#define usb_register(driver) \
	usb_register_driver(driver, THIS_MODULE, KBUILD_MODNAME)

extern void usb_deregister(struct usb_driver *);

#define module_usb_driver(__usb_driver) \
	module_driver(__usb_driver, usb_register, \
		       usb_deregister)

extern int usb_register_device_driver(struct usb_device_driver *,
			struct module *);
extern void usb_deregister_device_driver(struct usb_device_driver *);

extern int usb_register_dev(struct usb_interface *intf,
			    struct usb_class_driver *class_driver);
#ifdef MY_ABC_HERE
extern int usb_register_dev1(struct usb_interface *intf,
				struct usb_class_driver *class_driver, int minor_offset);
#endif  
extern void usb_deregister_dev(struct usb_interface *intf,
			       struct usb_class_driver *class_driver);

extern int usb_disabled(void);

#define URB_SHORT_NOT_OK	0x0001	 
#define URB_ISO_ASAP		0x0002	 
#define URB_NO_TRANSFER_DMA_MAP	0x0004	 
#define URB_NO_FSBR		0x0020	 
#define URB_ZERO_PACKET		0x0040	 
#define URB_NO_INTERRUPT	0x0080	 
#define URB_FREE_BUFFER		0x0100	 

#define URB_DIR_IN		0x0200	 
#define URB_DIR_OUT		0
#define URB_DIR_MASK		URB_DIR_IN

#define URB_DMA_MAP_SINGLE	0x00010000	 
#define URB_DMA_MAP_PAGE	0x00020000	 
#define URB_DMA_MAP_SG		0x00040000	 
#define URB_MAP_LOCAL		0x00080000	 
#define URB_SETUP_MAP_SINGLE	0x00100000	 
#define URB_SETUP_MAP_LOCAL	0x00200000	 
#define URB_DMA_SG_COMBINED	0x00400000	 
#define URB_ALIGNED_TEMP_BUFFER	0x00800000	 

struct usb_iso_packet_descriptor {
	unsigned int offset;
	unsigned int length;		 
	unsigned int actual_length;
	int status;
};

struct urb;

struct usb_anchor {
	struct list_head urb_list;
	wait_queue_head_t wait;
	spinlock_t lock;
	atomic_t suspend_wakeups;
	unsigned int poisoned:1;
};

static inline void init_usb_anchor(struct usb_anchor *anchor)
{
	memset(anchor, 0, sizeof(*anchor));
	INIT_LIST_HEAD(&anchor->urb_list);
	init_waitqueue_head(&anchor->wait);
	spin_lock_init(&anchor->lock);
}

typedef void (*usb_complete_t)(struct urb *);

struct urb {
	 
	struct kref kref;		 
	void *hcpriv;			 
	atomic_t use_count;		 
	atomic_t reject;		 
	int unlinked;			 

	struct list_head urb_list;	 
	struct list_head anchor_list;	 
	struct usb_anchor *anchor;
	struct usb_device *dev;		 
	struct usb_host_endpoint *ep;	 
	unsigned int pipe;		 
	unsigned int stream_id;		 
	int status;			 
	unsigned int transfer_flags;	 
	void *transfer_buffer;		 
	dma_addr_t transfer_dma;	 
	struct scatterlist *sg;		 
	int num_mapped_sgs;		 
	int num_sgs;			 
	u32 transfer_buffer_length;	 
	u32 actual_length;		 
	unsigned char *setup_packet;	 
	dma_addr_t setup_dma;		 
	int start_frame;		 
	int number_of_packets;		 
	int interval;			 
	int error_count;		 
	void *context;			 
	usb_complete_t complete;	 
	struct usb_iso_packet_descriptor iso_frame_desc[0];
					 
};

static inline void usb_fill_control_urb(struct urb *urb,
					struct usb_device *dev,
					unsigned int pipe,
					unsigned char *setup_packet,
					void *transfer_buffer,
					int buffer_length,
					usb_complete_t complete_fn,
					void *context)
{
	urb->dev = dev;
	urb->pipe = pipe;
	urb->setup_packet = setup_packet;
	urb->transfer_buffer = transfer_buffer;
	urb->transfer_buffer_length = buffer_length;
	urb->complete = complete_fn;
	urb->context = context;
}

static inline void usb_fill_bulk_urb(struct urb *urb,
				     struct usb_device *dev,
				     unsigned int pipe,
				     void *transfer_buffer,
				     int buffer_length,
				     usb_complete_t complete_fn,
				     void *context)
{
	urb->dev = dev;
	urb->pipe = pipe;
	urb->transfer_buffer = transfer_buffer;
	urb->transfer_buffer_length = buffer_length;
	urb->complete = complete_fn;
	urb->context = context;
}

static inline void usb_fill_int_urb(struct urb *urb,
				    struct usb_device *dev,
				    unsigned int pipe,
				    void *transfer_buffer,
				    int buffer_length,
				    usb_complete_t complete_fn,
				    void *context,
				    int interval)
{
	urb->dev = dev;
	urb->pipe = pipe;
	urb->transfer_buffer = transfer_buffer;
	urb->transfer_buffer_length = buffer_length;
	urb->complete = complete_fn;
	urb->context = context;

	if (dev->speed == USB_SPEED_HIGH || dev->speed == USB_SPEED_SUPER) {
		 
		interval = clamp(interval, 1, 16);

		urb->interval = 1 << (interval - 1);
	} else {
		urb->interval = interval;
	}

	urb->start_frame = -1;
}

extern void usb_init_urb(struct urb *urb);
extern struct urb *usb_alloc_urb(int iso_packets, gfp_t mem_flags);
extern void usb_free_urb(struct urb *urb);
#define usb_put_urb usb_free_urb
extern struct urb *usb_get_urb(struct urb *urb);
extern int usb_submit_urb(struct urb *urb, gfp_t mem_flags);
extern int usb_unlink_urb(struct urb *urb);
extern void usb_kill_urb(struct urb *urb);
extern void usb_poison_urb(struct urb *urb);
extern void usb_unpoison_urb(struct urb *urb);
extern void usb_block_urb(struct urb *urb);
extern void usb_kill_anchored_urbs(struct usb_anchor *anchor);
extern void usb_poison_anchored_urbs(struct usb_anchor *anchor);
extern void usb_unpoison_anchored_urbs(struct usb_anchor *anchor);
extern void usb_unlink_anchored_urbs(struct usb_anchor *anchor);
extern void usb_anchor_suspend_wakeups(struct usb_anchor *anchor);
extern void usb_anchor_resume_wakeups(struct usb_anchor *anchor);
extern void usb_anchor_urb(struct urb *urb, struct usb_anchor *anchor);
extern void usb_unanchor_urb(struct urb *urb);
extern int usb_wait_anchor_empty_timeout(struct usb_anchor *anchor,
					 unsigned int timeout);
extern struct urb *usb_get_from_anchor(struct usb_anchor *anchor);
extern void usb_scuttle_anchored_urbs(struct usb_anchor *anchor);
extern int usb_anchor_empty(struct usb_anchor *anchor);

#define usb_unblock_urb	usb_unpoison_urb

static inline int usb_urb_dir_in(struct urb *urb)
{
	return (urb->transfer_flags & URB_DIR_MASK) == URB_DIR_IN;
}

static inline int usb_urb_dir_out(struct urb *urb)
{
	return (urb->transfer_flags & URB_DIR_MASK) == URB_DIR_OUT;
}

void *usb_alloc_coherent(struct usb_device *dev, size_t size,
	gfp_t mem_flags, dma_addr_t *dma);
void usb_free_coherent(struct usb_device *dev, size_t size,
	void *addr, dma_addr_t dma);

#if 0
struct urb *usb_buffer_map(struct urb *urb);
void usb_buffer_dmasync(struct urb *urb);
void usb_buffer_unmap(struct urb *urb);
#endif

struct scatterlist;
int usb_buffer_map_sg(const struct usb_device *dev, int is_in,
		      struct scatterlist *sg, int nents);
#if 0
void usb_buffer_dmasync_sg(const struct usb_device *dev, int is_in,
			   struct scatterlist *sg, int n_hw_ents);
#endif
void usb_buffer_unmap_sg(const struct usb_device *dev, int is_in,
			 struct scatterlist *sg, int n_hw_ents);

extern int usb_control_msg(struct usb_device *dev, unsigned int pipe,
	__u8 request, __u8 requesttype, __u16 value, __u16 index,
	void *data, __u16 size, int timeout);
extern int usb_interrupt_msg(struct usb_device *usb_dev, unsigned int pipe,
	void *data, int len, int *actual_length, int timeout);
extern int usb_bulk_msg(struct usb_device *usb_dev, unsigned int pipe,
	void *data, int len, int *actual_length,
	int timeout);

extern int usb_get_descriptor(struct usb_device *dev, unsigned char desctype,
	unsigned char descindex, void *buf, int size);
extern int usb_get_status(struct usb_device *dev,
	int type, int target, void *data);
extern int usb_string(struct usb_device *dev, int index,
	char *buf, size_t size);

extern int usb_clear_halt(struct usb_device *dev, int pipe);
extern int usb_reset_configuration(struct usb_device *dev);
extern int usb_set_interface(struct usb_device *dev, int ifnum, int alternate);
extern void usb_reset_endpoint(struct usb_device *dev, unsigned int epaddr);

extern int usb_driver_set_configuration(struct usb_device *udev, int config);

extern int usb_choose_configuration(struct usb_device *udev);
extern int usb_set_configuration(struct usb_device *dev, int configuration);

#define USB_CTRL_GET_TIMEOUT	5000
#define USB_CTRL_SET_TIMEOUT	5000

struct usb_sg_request {
	int			status;
	size_t			bytes;

	spinlock_t		lock;

	struct usb_device	*dev;
	int			pipe;

	int			entries;
	struct urb		**urbs;

	int			count;
	struct completion	complete;
};

int usb_sg_init(
	struct usb_sg_request	*io,
	struct usb_device	*dev,
	unsigned		pipe,
	unsigned		period,
	struct scatterlist	*sg,
	int			nents,
	size_t			length,
	gfp_t			mem_flags
);
void usb_sg_cancel(struct usb_sg_request *io);
void usb_sg_wait(struct usb_sg_request *io);

#define PIPE_ISOCHRONOUS		0
#define PIPE_INTERRUPT			1
#define PIPE_CONTROL			2
#define PIPE_BULK			3

#define usb_pipein(pipe)	((pipe) & USB_DIR_IN)
#define usb_pipeout(pipe)	(!usb_pipein(pipe))

#define usb_pipedevice(pipe)	(((pipe) >> 8) & 0x7f)
#define usb_pipeendpoint(pipe)	(((pipe) >> 15) & 0xf)

#define usb_pipetype(pipe)	(((pipe) >> 30) & 3)
#define usb_pipeisoc(pipe)	(usb_pipetype((pipe)) == PIPE_ISOCHRONOUS)
#define usb_pipeint(pipe)	(usb_pipetype((pipe)) == PIPE_INTERRUPT)
#define usb_pipecontrol(pipe)	(usb_pipetype((pipe)) == PIPE_CONTROL)
#define usb_pipebulk(pipe)	(usb_pipetype((pipe)) == PIPE_BULK)

static inline unsigned int __create_pipe(struct usb_device *dev,
		unsigned int endpoint)
{
	return (dev->devnum << 8) | (endpoint << 15);
}

#define usb_sndctrlpipe(dev, endpoint)	\
	((PIPE_CONTROL << 30) | __create_pipe(dev, endpoint))
#define usb_rcvctrlpipe(dev, endpoint)	\
	((PIPE_CONTROL << 30) | __create_pipe(dev, endpoint) | USB_DIR_IN)
#define usb_sndisocpipe(dev, endpoint)	\
	((PIPE_ISOCHRONOUS << 30) | __create_pipe(dev, endpoint))
#define usb_rcvisocpipe(dev, endpoint)	\
	((PIPE_ISOCHRONOUS << 30) | __create_pipe(dev, endpoint) | USB_DIR_IN)
#define usb_sndbulkpipe(dev, endpoint)	\
	((PIPE_BULK << 30) | __create_pipe(dev, endpoint))
#define usb_rcvbulkpipe(dev, endpoint)	\
	((PIPE_BULK << 30) | __create_pipe(dev, endpoint) | USB_DIR_IN)
#define usb_sndintpipe(dev, endpoint)	\
	((PIPE_INTERRUPT << 30) | __create_pipe(dev, endpoint))
#define usb_rcvintpipe(dev, endpoint)	\
	((PIPE_INTERRUPT << 30) | __create_pipe(dev, endpoint) | USB_DIR_IN)

static inline struct usb_host_endpoint *
usb_pipe_endpoint(struct usb_device *dev, unsigned int pipe)
{
	struct usb_host_endpoint **eps;
	eps = usb_pipein(pipe) ? dev->ep_in : dev->ep_out;
	return eps[usb_pipeendpoint(pipe)];
}

static inline __u16
usb_maxpacket(struct usb_device *udev, int pipe, int is_out)
{
	struct usb_host_endpoint	*ep;
	unsigned			epnum = usb_pipeendpoint(pipe);

	if (is_out) {
		WARN_ON(usb_pipein(pipe));
		ep = udev->ep_out[epnum];
	} else {
		WARN_ON(usb_pipeout(pipe));
		ep = udev->ep_in[epnum];
	}
	if (!ep)
		return 0;

	return usb_endpoint_maxp(&ep->desc);
}

static inline int usb_translate_errors(int error_code)
{
	switch (error_code) {
	case 0:
	case -ENOMEM:
	case -ENODEV:
	case -EOPNOTSUPP:
		return error_code;
	default:
		return -EIO;
	}
}

#define USB_DEVICE_ADD		0x0001
#define USB_DEVICE_REMOVE	0x0002
#define USB_BUS_ADD		0x0003
#define USB_BUS_REMOVE		0x0004
extern void usb_register_notify(struct notifier_block *nb);
extern void usb_unregister_notify(struct notifier_block *nb);

extern struct dentry *usb_debug_root;

enum usb_led_event {
	USB_LED_EVENT_HOST = 0,
	USB_LED_EVENT_GADGET = 1,
};

#ifdef CONFIG_USB_LED_TRIG
extern void usb_led_activity(enum usb_led_event ev);
#else
static inline void usb_led_activity(enum usb_led_event ev) {}
#endif

#endif   

#endif
