#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/usb.h>
#include <linux/usb/quirks.h>
#include <linux/usb/hcd.h>

#include "usb.h"

#ifdef MY_ABC_HERE
#include <linux/synobios.h>

extern int (*funcSYNOGetHwCapability)(CAPABILITY *);
extern int blIsCardReader(struct usb_device *usbdev);

static unsigned char has_cardreader(void)
{
	CAPABILITY Capability;
	unsigned char ret = 0;

	Capability.id = CAPABILITY_CARDREADER;
	Capability.support = 0;

	if (funcSYNOGetHwCapability) {
		if (funcSYNOGetHwCapability(&Capability)){
			goto END;
		}
	}

	ret = Capability.support;
END:
	return ret;
}

#endif  

ssize_t usb_store_new_id(struct usb_dynids *dynids,
			 const struct usb_device_id *id_table,
			 struct device_driver *driver,
			 const char *buf, size_t count)
{
	struct usb_dynid *dynid;
	u32 idVendor = 0;
	u32 idProduct = 0;
	unsigned int bInterfaceClass = 0;
	u32 refVendor, refProduct;
	int fields = 0;
	int retval = 0;

	fields = sscanf(buf, "%x %x %x %x %x", &idVendor, &idProduct,
			&bInterfaceClass, &refVendor, &refProduct);
	if (fields < 2)
		return -EINVAL;

	dynid = kzalloc(sizeof(*dynid), GFP_KERNEL);
	if (!dynid)
		return -ENOMEM;

	INIT_LIST_HEAD(&dynid->node);
	dynid->id.idVendor = idVendor;
	dynid->id.idProduct = idProduct;
	dynid->id.match_flags = USB_DEVICE_ID_MATCH_DEVICE;
	if (fields > 2 && bInterfaceClass) {
		if (bInterfaceClass > 255) {
			retval = -EINVAL;
			goto fail;
		}

		dynid->id.bInterfaceClass = (u8)bInterfaceClass;
		dynid->id.match_flags |= USB_DEVICE_ID_MATCH_INT_CLASS;
	}

	if (fields > 4) {
		const struct usb_device_id *id = id_table;

		if (!id) {
			retval = -ENODEV;
			goto fail;
		}

		for (; id->match_flags; id++)
			if (id->idVendor == refVendor && id->idProduct == refProduct)
				break;

		if (id->match_flags) {
			dynid->id.driver_info = id->driver_info;
		} else {
			retval = -ENODEV;
			goto fail;
		}
	}

	spin_lock(&dynids->lock);
	list_add_tail(&dynid->node, &dynids->list);
	spin_unlock(&dynids->lock);

	retval = driver_attach(driver);

	if (retval)
		return retval;
	return count;

fail:
	kfree(dynid);
	return retval;
}
EXPORT_SYMBOL_GPL(usb_store_new_id);

ssize_t usb_show_dynids(struct usb_dynids *dynids, char *buf)
{
	struct usb_dynid *dynid;
	size_t count = 0;

	list_for_each_entry(dynid, &dynids->list, node)
		if (dynid->id.bInterfaceClass != 0)
			count += scnprintf(&buf[count], PAGE_SIZE - count, "%04x %04x %02x\n",
					   dynid->id.idVendor, dynid->id.idProduct,
					   dynid->id.bInterfaceClass);
		else
			count += scnprintf(&buf[count], PAGE_SIZE - count, "%04x %04x\n",
					   dynid->id.idVendor, dynid->id.idProduct);
	return count;
}
EXPORT_SYMBOL_GPL(usb_show_dynids);

static ssize_t new_id_show(struct device_driver *driver, char *buf)
{
	struct usb_driver *usb_drv = to_usb_driver(driver);

	return usb_show_dynids(&usb_drv->dynids, buf);
}

static ssize_t new_id_store(struct device_driver *driver,
			    const char *buf, size_t count)
{
	struct usb_driver *usb_drv = to_usb_driver(driver);

	return usb_store_new_id(&usb_drv->dynids, usb_drv->id_table, driver, buf, count);
}
static DRIVER_ATTR_RW(new_id);

static ssize_t remove_id_store(struct device_driver *driver, const char *buf,
			       size_t count)
{
	struct usb_dynid *dynid, *n;
	struct usb_driver *usb_driver = to_usb_driver(driver);
	u32 idVendor;
	u32 idProduct;
	int fields;

	fields = sscanf(buf, "%x %x", &idVendor, &idProduct);
	if (fields < 2)
		return -EINVAL;

	spin_lock(&usb_driver->dynids.lock);
	list_for_each_entry_safe(dynid, n, &usb_driver->dynids.list, node) {
		struct usb_device_id *id = &dynid->id;

		if ((id->idVendor == idVendor) &&
		    (id->idProduct == idProduct)) {
			list_del(&dynid->node);
			kfree(dynid);
			break;
		}
	}
	spin_unlock(&usb_driver->dynids.lock);
	return count;
}

static ssize_t remove_id_show(struct device_driver *driver, char *buf)
{
	return new_id_show(driver, buf);
}
static DRIVER_ATTR_RW(remove_id);

static int usb_create_newid_files(struct usb_driver *usb_drv)
{
	int error = 0;

	if (usb_drv->no_dynamic_id)
		goto exit;

	if (usb_drv->probe != NULL) {
		error = driver_create_file(&usb_drv->drvwrap.driver,
					   &driver_attr_new_id);
		if (error == 0) {
			error = driver_create_file(&usb_drv->drvwrap.driver,
					&driver_attr_remove_id);
			if (error)
				driver_remove_file(&usb_drv->drvwrap.driver,
						&driver_attr_new_id);
		}
	}
exit:
	return error;
}

static void usb_remove_newid_files(struct usb_driver *usb_drv)
{
	if (usb_drv->no_dynamic_id)
		return;

	if (usb_drv->probe != NULL) {
		driver_remove_file(&usb_drv->drvwrap.driver,
				&driver_attr_remove_id);
		driver_remove_file(&usb_drv->drvwrap.driver,
				   &driver_attr_new_id);
	}
}

static void usb_free_dynids(struct usb_driver *usb_drv)
{
	struct usb_dynid *dynid, *n;

	spin_lock(&usb_drv->dynids.lock);
	list_for_each_entry_safe(dynid, n, &usb_drv->dynids.list, node) {
		list_del(&dynid->node);
		kfree(dynid);
	}
	spin_unlock(&usb_drv->dynids.lock);
}

static const struct usb_device_id *usb_match_dynamic_id(struct usb_interface *intf,
							struct usb_driver *drv)
{
	struct usb_dynid *dynid;

	spin_lock(&drv->dynids.lock);
	list_for_each_entry(dynid, &drv->dynids.list, node) {
		if (usb_match_one_id(intf, &dynid->id)) {
			spin_unlock(&drv->dynids.lock);
			return &dynid->id;
		}
	}
	spin_unlock(&drv->dynids.lock);
	return NULL;
}

static int usb_probe_device(struct device *dev)
{
	struct usb_device_driver *udriver = to_usb_device_driver(dev->driver);
	struct usb_device *udev = to_usb_device(dev);
	int error = 0;

	dev_dbg(dev, "%s\n", __func__);

	if (!udriver->supports_autosuspend)
		error = usb_autoresume_device(udev);

	if (!error)
		error = udriver->probe(udev);
	return error;
}

static int usb_unbind_device(struct device *dev)
{
	struct usb_device *udev = to_usb_device(dev);
	struct usb_device_driver *udriver = to_usb_device_driver(dev->driver);

	udriver->disconnect(udev);
	if (!udriver->supports_autosuspend)
		usb_autosuspend_device(udev);
	return 0;
}

#ifdef MY_ABC_HERE
 
static void syno_usb_shutdown_device(struct device *dev)
{
	struct usb_device *udev = to_usb_device(dev);
	int retval = 0;

	if (!udev->parent || 0 < udev->maxchild)
		return;

	retval = usb_unbind_device(dev);
	if (retval) {
		dev_warn(dev, "Fail to unbind device driver, ret %d\n", retval);
	}
}
#endif  

static int usb_probe_interface(struct device *dev)
{
	struct usb_driver *driver = to_usb_driver(dev->driver);
	struct usb_interface *intf = to_usb_interface(dev);
	struct usb_device *udev = interface_to_usbdev(intf);
	const struct usb_device_id *id;
	int error = -ENODEV;
	int lpm_disable_error = -ENODEV;

	dev_dbg(dev, "%s\n", __func__);

	intf->needs_binding = 0;

	if (usb_device_is_owned(udev))
		return error;

	if (udev->authorized == 0) {
		dev_err(&intf->dev, "Device is not authorized for usage\n");
		return error;
	} else if (intf->authorized == 0) {
		dev_err(&intf->dev, "Interface %d is not authorized for usage\n",
				intf->altsetting->desc.bInterfaceNumber);
		return error;
	}

	id = usb_match_dynamic_id(intf, driver);
	if (!id)
		id = usb_match_id(intf, driver->id_table);
	if (!id)
		return error;

	dev_dbg(dev, "%s - got id\n", __func__);

	error = usb_autoresume_device(udev);
	if (error)
		return error;

	intf->condition = USB_INTERFACE_BINDING;

	pm_runtime_set_active(dev);
	pm_suspend_ignore_children(dev, false);
	if (driver->supports_autosuspend)
		pm_runtime_enable(dev);

	if (driver->disable_hub_initiated_lpm) {
		lpm_disable_error = usb_unlocked_disable_lpm(udev);
		if (lpm_disable_error) {
			dev_err(&intf->dev, "%s Failed to disable LPM for driver %s\n.",
					__func__, driver->name);
			error = lpm_disable_error;
			goto err;
		}
	}

	if (intf->needs_altsetting0) {
		error = usb_set_interface(udev, intf->altsetting[0].
				desc.bInterfaceNumber, 0);
		if (error < 0)
			goto err;
		intf->needs_altsetting0 = 0;
	}

	error = driver->probe(intf, id);
	if (error)
		goto err;

	intf->condition = USB_INTERFACE_BOUND;

	if (!lpm_disable_error)
		usb_unlocked_enable_lpm(udev);

	usb_autosuspend_device(udev);
	return error;

 err:
	usb_set_intfdata(intf, NULL);
	intf->needs_remote_wakeup = 0;
	intf->condition = USB_INTERFACE_UNBOUND;

	if (!lpm_disable_error)
		usb_unlocked_enable_lpm(udev);

	if (driver->supports_autosuspend)
		pm_runtime_disable(dev);
	pm_runtime_set_suspended(dev);

	usb_autosuspend_device(udev);
	return error;
}

static int usb_unbind_interface(struct device *dev)
{
	struct usb_driver *driver = to_usb_driver(dev->driver);
	struct usb_interface *intf = to_usb_interface(dev);
	struct usb_host_endpoint *ep, **eps = NULL;
	struct usb_device *udev;
	int i, j, error, r;
	int lpm_disable_error = -ENODEV;

	intf->condition = USB_INTERFACE_UNBINDING;

	udev = interface_to_usbdev(intf);
	error = usb_autoresume_device(udev);

	if (driver->disable_hub_initiated_lpm)
		lpm_disable_error = usb_unlocked_disable_lpm(udev);

	if (!driver->soft_unbind || udev->state == USB_STATE_NOTATTACHED)
		usb_disable_interface(udev, intf, false);

	driver->disconnect(intf);

	for (i = 0, j = 0; i < intf->cur_altsetting->desc.bNumEndpoints; i++) {
		ep = &intf->cur_altsetting->endpoint[i];
		if (ep->streams == 0)
			continue;
		if (j == 0) {
			eps = kmalloc_array(USB_MAXENDPOINTS, sizeof(void *),
				      GFP_KERNEL);
			if (!eps)
				break;
		}
		eps[j++] = ep;
	}
	if (j) {
		usb_free_streams(intf, eps, j, GFP_KERNEL);
		kfree(eps);
	}

	if (intf->cur_altsetting->desc.bAlternateSetting == 0) {
		 
		usb_enable_interface(udev, intf, false);
	} else if (!error && !intf->dev.power.is_prepared) {
		r = usb_set_interface(udev, intf->altsetting[0].
				desc.bInterfaceNumber, 0);
		if (r < 0)
			intf->needs_altsetting0 = 1;
	} else {
		intf->needs_altsetting0 = 1;
	}
	usb_set_intfdata(intf, NULL);

	intf->condition = USB_INTERFACE_UNBOUND;
	intf->needs_remote_wakeup = 0;

	if (!lpm_disable_error)
		usb_unlocked_enable_lpm(udev);

	if (driver->supports_autosuspend)
		pm_runtime_disable(dev);
	pm_runtime_set_suspended(dev);

	for (r = atomic_read(&intf->pm_usage_cnt); r > 0; --r)
		usb_autopm_put_interface_no_suspend(intf);
	atomic_set(&intf->pm_usage_cnt, 0);

	if (!error)
		usb_autosuspend_device(udev);

	return 0;
}

int usb_driver_claim_interface(struct usb_driver *driver,
				struct usb_interface *iface, void *priv)
{
	struct device *dev;
	struct usb_device *udev;
	int retval = 0;
	int lpm_disable_error = -ENODEV;

	if (!iface)
		return -ENODEV;

	dev = &iface->dev;
	if (dev->driver)
		return -EBUSY;

	if (!iface->authorized)
		return -ENODEV;

	udev = interface_to_usbdev(iface);

	dev->driver = &driver->drvwrap.driver;
	usb_set_intfdata(iface, priv);
	iface->needs_binding = 0;

	iface->condition = USB_INTERFACE_BOUND;

	if (driver->disable_hub_initiated_lpm) {
		lpm_disable_error = usb_unlocked_disable_lpm(udev);
		if (lpm_disable_error) {
			dev_err(&iface->dev, "%s Failed to disable LPM for driver %s\n.",
					__func__, driver->name);
			return -ENOMEM;
		}
	}

	pm_suspend_ignore_children(dev, false);
	if (driver->supports_autosuspend)
		pm_runtime_enable(dev);
	else
		pm_runtime_set_active(dev);

	if (device_is_registered(dev))
		retval = device_bind_driver(dev);

	if (!lpm_disable_error)
		usb_unlocked_enable_lpm(udev);

	return retval;
}
EXPORT_SYMBOL_GPL(usb_driver_claim_interface);

void usb_driver_release_interface(struct usb_driver *driver,
					struct usb_interface *iface)
{
	struct device *dev = &iface->dev;

	if (!dev->driver || dev->driver != &driver->drvwrap.driver)
		return;

	if (iface->condition != USB_INTERFACE_BOUND)
		return;
	iface->condition = USB_INTERFACE_UNBINDING;

	if (device_is_registered(dev)) {
		device_release_driver(dev);
	} else {
		device_lock(dev);
		usb_unbind_interface(dev);
		dev->driver = NULL;
		device_unlock(dev);
	}
}
EXPORT_SYMBOL_GPL(usb_driver_release_interface);

int usb_match_device(struct usb_device *dev, const struct usb_device_id *id)
{
	if ((id->match_flags & USB_DEVICE_ID_MATCH_VENDOR) &&
	    id->idVendor != le16_to_cpu(dev->descriptor.idVendor))
		return 0;

	if ((id->match_flags & USB_DEVICE_ID_MATCH_PRODUCT) &&
	    id->idProduct != le16_to_cpu(dev->descriptor.idProduct))
		return 0;

	if ((id->match_flags & USB_DEVICE_ID_MATCH_DEV_LO) &&
	    (id->bcdDevice_lo > le16_to_cpu(dev->descriptor.bcdDevice)))
		return 0;

	if ((id->match_flags & USB_DEVICE_ID_MATCH_DEV_HI) &&
	    (id->bcdDevice_hi < le16_to_cpu(dev->descriptor.bcdDevice)))
		return 0;

	if ((id->match_flags & USB_DEVICE_ID_MATCH_DEV_CLASS) &&
	    (id->bDeviceClass != dev->descriptor.bDeviceClass))
		return 0;

	if ((id->match_flags & USB_DEVICE_ID_MATCH_DEV_SUBCLASS) &&
	    (id->bDeviceSubClass != dev->descriptor.bDeviceSubClass))
		return 0;

	if ((id->match_flags & USB_DEVICE_ID_MATCH_DEV_PROTOCOL) &&
	    (id->bDeviceProtocol != dev->descriptor.bDeviceProtocol))
		return 0;

	return 1;
}

int usb_match_one_id_intf(struct usb_device *dev,
			  struct usb_host_interface *intf,
			  const struct usb_device_id *id)
{
	 
	if (dev->descriptor.bDeviceClass == USB_CLASS_VENDOR_SPEC &&
			!(id->match_flags & USB_DEVICE_ID_MATCH_VENDOR) &&
			(id->match_flags & (USB_DEVICE_ID_MATCH_INT_CLASS |
				USB_DEVICE_ID_MATCH_INT_SUBCLASS |
				USB_DEVICE_ID_MATCH_INT_PROTOCOL |
				USB_DEVICE_ID_MATCH_INT_NUMBER)))
		return 0;

	if ((id->match_flags & USB_DEVICE_ID_MATCH_INT_CLASS) &&
	    (id->bInterfaceClass != intf->desc.bInterfaceClass))
		return 0;

	if ((id->match_flags & USB_DEVICE_ID_MATCH_INT_SUBCLASS) &&
	    (id->bInterfaceSubClass != intf->desc.bInterfaceSubClass))
		return 0;

	if ((id->match_flags & USB_DEVICE_ID_MATCH_INT_PROTOCOL) &&
	    (id->bInterfaceProtocol != intf->desc.bInterfaceProtocol))
		return 0;

	if ((id->match_flags & USB_DEVICE_ID_MATCH_INT_NUMBER) &&
	    (id->bInterfaceNumber != intf->desc.bInterfaceNumber))
		return 0;

	return 1;
}

int usb_match_one_id(struct usb_interface *interface,
		     const struct usb_device_id *id)
{
	struct usb_host_interface *intf;
	struct usb_device *dev;

	if (id == NULL)
		return 0;

	intf = interface->cur_altsetting;
	dev = interface_to_usbdev(interface);

	if (!usb_match_device(dev, id))
		return 0;

	return usb_match_one_id_intf(dev, intf, id);
}
EXPORT_SYMBOL_GPL(usb_match_one_id);

const struct usb_device_id *usb_match_id(struct usb_interface *interface,
					 const struct usb_device_id *id)
{
	 
	if (id == NULL)
		return NULL;

	for (; id->idVendor || id->idProduct || id->bDeviceClass ||
	       id->bInterfaceClass || id->driver_info; id++) {
		if (usb_match_one_id(interface, id))
			return id;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(usb_match_id);

static int usb_device_match(struct device *dev, struct device_driver *drv)
{
	 
	if (is_usb_device(dev)) {

		if (!is_usb_device_driver(drv))
			return 0;

		return 1;

	} else if (is_usb_interface(dev)) {
		struct usb_interface *intf;
		struct usb_driver *usb_drv;
		const struct usb_device_id *id;

		if (is_usb_device_driver(drv))
			return 0;

		intf = to_usb_interface(dev);
		usb_drv = to_usb_driver(drv);

		id = usb_match_id(intf, usb_drv->id_table);
		if (id)
			return 1;

		id = usb_match_dynamic_id(intf, usb_drv);
		if (id)
			return 1;
	}

	return 0;
}

static int usb_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	struct usb_device *usb_dev;

	if (is_usb_device(dev)) {
		usb_dev = to_usb_device(dev);
	} else if (is_usb_interface(dev)) {
		struct usb_interface *intf = to_usb_interface(dev);

		usb_dev = interface_to_usbdev(intf);
	} else {
		return 0;
	}

	if (usb_dev->devnum < 0) {
		 
		pr_debug("usb %s: already deleted?\n", dev_name(dev));
		return -ENODEV;
	}
	if (!usb_dev->bus) {
		pr_debug("usb %s: bus removed?\n", dev_name(dev));
		return -ENODEV;
	}

	if (add_uevent_var(env, "PRODUCT=%x/%x/%x",
			   le16_to_cpu(usb_dev->descriptor.idVendor),
			   le16_to_cpu(usb_dev->descriptor.idProduct),
			   le16_to_cpu(usb_dev->descriptor.bcdDevice)))
		return -ENOMEM;

	if (add_uevent_var(env, "TYPE=%d/%d/%d",
			   usb_dev->descriptor.bDeviceClass,
			   usb_dev->descriptor.bDeviceSubClass,
			   usb_dev->descriptor.bDeviceProtocol))
		return -ENOMEM;

#ifdef MY_ABC_HERE
	if(has_cardreader()) {
		if (blIsCardReader(usb_dev)) {
			if (add_uevent_var(env, "CARDREADER=1"))
				return -ENOMEM;
		}
	}
#endif  

	return 0;
}

int usb_register_device_driver(struct usb_device_driver *new_udriver,
		struct module *owner)
{
	int retval = 0;

	if (usb_disabled())
		return -ENODEV;

	new_udriver->drvwrap.for_devices = 1;
	new_udriver->drvwrap.driver.name = new_udriver->name;
	new_udriver->drvwrap.driver.bus = &usb_bus_type;
	new_udriver->drvwrap.driver.probe = usb_probe_device;
	new_udriver->drvwrap.driver.remove = usb_unbind_device;
	new_udriver->drvwrap.driver.owner = owner;
#ifdef MY_ABC_HERE
	new_udriver->drvwrap.driver.shutdown = syno_usb_shutdown_device;
#endif  

	retval = driver_register(&new_udriver->drvwrap.driver);

	if (!retval)
		pr_info("%s: registered new device driver %s\n",
			usbcore_name, new_udriver->name);
	else
		printk(KERN_ERR "%s: error %d registering device "
			"	driver %s\n",
			usbcore_name, retval, new_udriver->name);

	return retval;
}
EXPORT_SYMBOL_GPL(usb_register_device_driver);

void usb_deregister_device_driver(struct usb_device_driver *udriver)
{
	pr_info("%s: deregistering device driver %s\n",
			usbcore_name, udriver->name);

	driver_unregister(&udriver->drvwrap.driver);
}
EXPORT_SYMBOL_GPL(usb_deregister_device_driver);

int usb_register_driver(struct usb_driver *new_driver, struct module *owner,
			const char *mod_name)
{
	int retval = 0;

	if (usb_disabled())
		return -ENODEV;

	new_driver->drvwrap.for_devices = 0;
	new_driver->drvwrap.driver.name = new_driver->name;
	new_driver->drvwrap.driver.bus = &usb_bus_type;
	new_driver->drvwrap.driver.probe = usb_probe_interface;
	new_driver->drvwrap.driver.remove = usb_unbind_interface;
	new_driver->drvwrap.driver.owner = owner;
	new_driver->drvwrap.driver.mod_name = mod_name;
	spin_lock_init(&new_driver->dynids.lock);
	INIT_LIST_HEAD(&new_driver->dynids.list);

	retval = driver_register(&new_driver->drvwrap.driver);
	if (retval)
		goto out;

	retval = usb_create_newid_files(new_driver);
	if (retval)
		goto out_newid;

	pr_info("%s: registered new interface driver %s\n",
			usbcore_name, new_driver->name);

out:
	return retval;

out_newid:
	driver_unregister(&new_driver->drvwrap.driver);

	printk(KERN_ERR "%s: error %d registering interface "
			"	driver %s\n",
			usbcore_name, retval, new_driver->name);
	goto out;
}
EXPORT_SYMBOL_GPL(usb_register_driver);

void usb_deregister(struct usb_driver *driver)
{
	pr_info("%s: deregistering interface driver %s\n",
			usbcore_name, driver->name);

	usb_remove_newid_files(driver);
	driver_unregister(&driver->drvwrap.driver);
	usb_free_dynids(driver);
}
EXPORT_SYMBOL_GPL(usb_deregister);

void usb_forced_unbind_intf(struct usb_interface *intf)
{
	struct usb_driver *driver = to_usb_driver(intf->dev.driver);

	dev_dbg(&intf->dev, "forced unbind\n");
	usb_driver_release_interface(driver, intf);

	intf->needs_binding = 1;
}

static void unbind_marked_interfaces(struct usb_device *udev)
{
	struct usb_host_config	*config;
	int			i;
	struct usb_interface	*intf;

	config = udev->actconfig;
	if (config) {
		for (i = 0; i < config->desc.bNumInterfaces; ++i) {
			intf = config->interface[i];
			if (intf->dev.driver && intf->needs_binding)
				usb_forced_unbind_intf(intf);
		}
	}
}

static void usb_rebind_intf(struct usb_interface *intf)
{
	int rc;

	if (intf->dev.driver)
		usb_forced_unbind_intf(intf);

	if (!intf->dev.power.is_prepared) {
		intf->needs_binding = 0;
		rc = device_attach(&intf->dev);
		if (rc < 0)
			dev_warn(&intf->dev, "rebind failed: %d\n", rc);
	}
}

static void rebind_marked_interfaces(struct usb_device *udev)
{
	struct usb_host_config	*config;
	int			i;
	struct usb_interface	*intf;

	config = udev->actconfig;
	if (config) {
		for (i = 0; i < config->desc.bNumInterfaces; ++i) {
			intf = config->interface[i];
			if (intf->needs_binding)
				usb_rebind_intf(intf);
		}
	}
}

void usb_unbind_and_rebind_marked_interfaces(struct usb_device *udev)
{
	unbind_marked_interfaces(udev);
	rebind_marked_interfaces(udev);
}

#ifdef CONFIG_PM

static void unbind_no_pm_drivers_interfaces(struct usb_device *udev)
{
	struct usb_host_config	*config;
	int			i;
	struct usb_interface	*intf;
	struct usb_driver	*drv;

	config = udev->actconfig;
	if (config) {
		for (i = 0; i < config->desc.bNumInterfaces; ++i) {
			intf = config->interface[i];

			if (intf->dev.driver) {
				drv = to_usb_driver(intf->dev.driver);
				if (!drv->suspend || !drv->resume)
					usb_forced_unbind_intf(intf);
			}
		}
	}
}

static int usb_suspend_device(struct usb_device *udev, pm_message_t msg)
{
	struct usb_device_driver	*udriver;
	int				status = 0;

	if (udev->state == USB_STATE_NOTATTACHED ||
			udev->state == USB_STATE_SUSPENDED)
		goto done;

	if (udev->dev.driver)
		udriver = to_usb_device_driver(udev->dev.driver);
	else {
		udev->do_remote_wakeup = 0;
		udriver = &usb_generic_driver;
	}
	status = udriver->suspend(udev, msg);

 done:
	dev_vdbg(&udev->dev, "%s: status %d\n", __func__, status);
	return status;
}

static int usb_resume_device(struct usb_device *udev, pm_message_t msg)
{
	struct usb_device_driver	*udriver;
	int				status = 0;

	if (udev->state == USB_STATE_NOTATTACHED)
		goto done;

	if (udev->dev.driver == NULL) {
		status = -ENOTCONN;
		goto done;
	}

	if (!PMSG_IS_AUTO(msg) && udev->parent && udev->bus->hs_companion)
		device_pm_wait_for_dev(&udev->dev,
				&udev->bus->hs_companion->root_hub->dev);

	if (udev->quirks & USB_QUIRK_RESET_RESUME)
		udev->reset_resume = 1;

	udriver = to_usb_device_driver(udev->dev.driver);
	status = udriver->resume(udev, msg);

 done:
	dev_vdbg(&udev->dev, "%s: status %d\n", __func__, status);
	return status;
}

static int usb_suspend_interface(struct usb_device *udev,
		struct usb_interface *intf, pm_message_t msg)
{
	struct usb_driver	*driver;
	int			status = 0;

	if (udev->state == USB_STATE_NOTATTACHED ||
			intf->condition == USB_INTERFACE_UNBOUND)
		goto done;
	driver = to_usb_driver(intf->dev.driver);

	status = driver->suspend(intf, msg);
	if (status && !PMSG_IS_AUTO(msg))
		dev_err(&intf->dev, "suspend error %d\n", status);

 done:
	dev_vdbg(&intf->dev, "%s: status %d\n", __func__, status);
	return status;
}

static int usb_resume_interface(struct usb_device *udev,
		struct usb_interface *intf, pm_message_t msg, int reset_resume)
{
	struct usb_driver	*driver;
	int			status = 0;

	if (udev->state == USB_STATE_NOTATTACHED)
		goto done;

	if (intf->condition == USB_INTERFACE_UNBINDING)
		goto done;

	if (intf->condition == USB_INTERFACE_UNBOUND) {

		if (intf->needs_altsetting0 && !intf->dev.power.is_prepared) {
			usb_set_interface(udev, intf->altsetting[0].
					desc.bInterfaceNumber, 0);
			intf->needs_altsetting0 = 0;
		}
		goto done;
	}

	if (intf->needs_binding)
		goto done;
	driver = to_usb_driver(intf->dev.driver);

	if (reset_resume) {
		if (driver->reset_resume) {
			status = driver->reset_resume(intf);
			if (status)
				dev_err(&intf->dev, "%s error %d\n",
						"reset_resume", status);
		} else {
			intf->needs_binding = 1;
			dev_dbg(&intf->dev, "no reset_resume for driver %s?\n",
					driver->name);
		}
	} else {
		status = driver->resume(intf);
		if (status)
			dev_err(&intf->dev, "resume error %d\n", status);
	}

done:
	dev_vdbg(&intf->dev, "%s: status %d\n", __func__, status);

	return status;
}

static int usb_suspend_both(struct usb_device *udev, pm_message_t msg)
{
	int			status = 0;
	int			i = 0, n = 0;
	struct usb_interface	*intf;

	if (udev->state == USB_STATE_NOTATTACHED ||
			udev->state == USB_STATE_SUSPENDED)
		goto done;

	if (udev->actconfig) {
		n = udev->actconfig->desc.bNumInterfaces;
		for (i = n - 1; i >= 0; --i) {
			intf = udev->actconfig->interface[i];
			status = usb_suspend_interface(udev, intf, msg);

			if (!PMSG_IS_AUTO(msg))
				status = 0;
			if (status != 0)
				break;
		}
	}
	if (status == 0) {
		status = usb_suspend_device(udev, msg);

		if (udev->parent && !PMSG_IS_AUTO(msg))
			status = 0;
	}

	if (status != 0) {
		if (udev->actconfig) {
			msg.event ^= (PM_EVENT_SUSPEND | PM_EVENT_RESUME);
			while (++i < n) {
				intf = udev->actconfig->interface[i];
				usb_resume_interface(udev, intf, msg, 0);
			}
		}

	} else {
		udev->can_submit = 0;
		for (i = 0; i < 16; ++i) {
			usb_hcd_flush_endpoint(udev, udev->ep_out[i]);
			usb_hcd_flush_endpoint(udev, udev->ep_in[i]);
		}
	}

 done:
	dev_vdbg(&udev->dev, "%s: status %d\n", __func__, status);
	return status;
}

static int usb_resume_both(struct usb_device *udev, pm_message_t msg)
{
	int			status = 0;
	int			i;
	struct usb_interface	*intf;

	if (udev->state == USB_STATE_NOTATTACHED) {
		status = -ENODEV;
		goto done;
	}
	udev->can_submit = 1;

	if (udev->state == USB_STATE_SUSPENDED || udev->reset_resume)
		status = usb_resume_device(udev, msg);

	if (status == 0 && udev->actconfig) {
		for (i = 0; i < udev->actconfig->desc.bNumInterfaces; i++) {
			intf = udev->actconfig->interface[i];
			usb_resume_interface(udev, intf, msg,
					udev->reset_resume);
		}
	}
	usb_mark_last_busy(udev);

 done:
	dev_vdbg(&udev->dev, "%s: status %d\n", __func__, status);
	if (!status)
		udev->reset_resume = 0;
	return status;
}

static void choose_wakeup(struct usb_device *udev, pm_message_t msg)
{
	int	w;

	if (msg.event == PM_EVENT_FREEZE || msg.event == PM_EVENT_QUIESCE) {
		if (udev->state != USB_STATE_SUSPENDED)
			udev->do_remote_wakeup = 0;
		return;
	}

	w = device_may_wakeup(&udev->dev);

	if (udev->state == USB_STATE_SUSPENDED && w != udev->do_remote_wakeup)
		pm_runtime_resume(&udev->dev);
	udev->do_remote_wakeup = w;
}

int usb_suspend(struct device *dev, pm_message_t msg)
{
	struct usb_device	*udev = to_usb_device(dev);

	unbind_no_pm_drivers_interfaces(udev);

	choose_wakeup(udev, msg);
	return usb_suspend_both(udev, msg);
}

int usb_resume_complete(struct device *dev)
{
	struct usb_device *udev = to_usb_device(dev);

	if (udev->state != USB_STATE_NOTATTACHED)
		rebind_marked_interfaces(udev);
	return 0;
}

int usb_resume(struct device *dev, pm_message_t msg)
{
	struct usb_device	*udev = to_usb_device(dev);
	int			status;

	status = usb_resume_both(udev, msg);
	if (status == 0) {
		pm_runtime_disable(dev);
		pm_runtime_set_active(dev);
		pm_runtime_enable(dev);
		unbind_marked_interfaces(udev);
	}

	if (status == -ENODEV || status == -ESHUTDOWN)
		status = 0;
	return status;
}

void usb_enable_autosuspend(struct usb_device *udev)
{
	pm_runtime_allow(&udev->dev);
}
EXPORT_SYMBOL_GPL(usb_enable_autosuspend);

void usb_disable_autosuspend(struct usb_device *udev)
{
	pm_runtime_forbid(&udev->dev);
}
EXPORT_SYMBOL_GPL(usb_disable_autosuspend);

void usb_autosuspend_device(struct usb_device *udev)
{
	int	status;

	usb_mark_last_busy(udev);
	status = pm_runtime_put_sync_autosuspend(&udev->dev);
	dev_vdbg(&udev->dev, "%s: cnt %d -> %d\n",
			__func__, atomic_read(&udev->dev.power.usage_count),
			status);
}

int usb_autoresume_device(struct usb_device *udev)
{
	int	status;

	status = pm_runtime_get_sync(&udev->dev);
	if (status < 0)
		pm_runtime_put_sync(&udev->dev);
	dev_vdbg(&udev->dev, "%s: cnt %d -> %d\n",
			__func__, atomic_read(&udev->dev.power.usage_count),
			status);
	if (status > 0)
		status = 0;
	return status;
}

void usb_autopm_put_interface(struct usb_interface *intf)
{
	struct usb_device	*udev = interface_to_usbdev(intf);
	int			status;

	usb_mark_last_busy(udev);
	atomic_dec(&intf->pm_usage_cnt);
	status = pm_runtime_put_sync(&intf->dev);
	dev_vdbg(&intf->dev, "%s: cnt %d -> %d\n",
			__func__, atomic_read(&intf->dev.power.usage_count),
			status);
}
EXPORT_SYMBOL_GPL(usb_autopm_put_interface);

void usb_autopm_put_interface_async(struct usb_interface *intf)
{
	struct usb_device	*udev = interface_to_usbdev(intf);
	int			status;

	usb_mark_last_busy(udev);
	atomic_dec(&intf->pm_usage_cnt);
	status = pm_runtime_put(&intf->dev);
	dev_vdbg(&intf->dev, "%s: cnt %d -> %d\n",
			__func__, atomic_read(&intf->dev.power.usage_count),
			status);
}
EXPORT_SYMBOL_GPL(usb_autopm_put_interface_async);

void usb_autopm_put_interface_no_suspend(struct usb_interface *intf)
{
	struct usb_device	*udev = interface_to_usbdev(intf);

	usb_mark_last_busy(udev);
	atomic_dec(&intf->pm_usage_cnt);
	pm_runtime_put_noidle(&intf->dev);
}
EXPORT_SYMBOL_GPL(usb_autopm_put_interface_no_suspend);

int usb_autopm_get_interface(struct usb_interface *intf)
{
	int	status;

	status = pm_runtime_get_sync(&intf->dev);
	if (status < 0)
		pm_runtime_put_sync(&intf->dev);
	else
		atomic_inc(&intf->pm_usage_cnt);
	dev_vdbg(&intf->dev, "%s: cnt %d -> %d\n",
			__func__, atomic_read(&intf->dev.power.usage_count),
			status);
	if (status > 0)
		status = 0;
	return status;
}
EXPORT_SYMBOL_GPL(usb_autopm_get_interface);

int usb_autopm_get_interface_async(struct usb_interface *intf)
{
	int	status;

	status = pm_runtime_get(&intf->dev);
	if (status < 0 && status != -EINPROGRESS)
		pm_runtime_put_noidle(&intf->dev);
	else
		atomic_inc(&intf->pm_usage_cnt);
	dev_vdbg(&intf->dev, "%s: cnt %d -> %d\n",
			__func__, atomic_read(&intf->dev.power.usage_count),
			status);
	if (status > 0 || status == -EINPROGRESS)
		status = 0;
	return status;
}
EXPORT_SYMBOL_GPL(usb_autopm_get_interface_async);

void usb_autopm_get_interface_no_resume(struct usb_interface *intf)
{
	struct usb_device	*udev = interface_to_usbdev(intf);

	usb_mark_last_busy(udev);
	atomic_inc(&intf->pm_usage_cnt);
	pm_runtime_get_noresume(&intf->dev);
}
EXPORT_SYMBOL_GPL(usb_autopm_get_interface_no_resume);

static int autosuspend_check(struct usb_device *udev)
{
	int			w, i;
	struct usb_interface	*intf;

	w = 0;
	if (udev->actconfig) {
		for (i = 0; i < udev->actconfig->desc.bNumInterfaces; i++) {
			intf = udev->actconfig->interface[i];

			if (intf->dev.power.disable_depth)
				continue;
			if (atomic_read(&intf->dev.power.usage_count) > 0)
				return -EBUSY;
			w |= intf->needs_remote_wakeup;

			if (udev->quirks & USB_QUIRK_RESET_RESUME) {
				struct usb_driver *driver;

				driver = to_usb_driver(intf->dev.driver);
				if (!driver->reset_resume ||
						intf->needs_remote_wakeup)
					return -EOPNOTSUPP;
			}
		}
	}
	if (w && !device_can_wakeup(&udev->dev)) {
		dev_dbg(&udev->dev, "remote wakeup needed for autosuspend\n");
		return -EOPNOTSUPP;
	}

	if (w && udev->parent == udev->bus->root_hub &&
			bus_to_hcd(udev->bus)->cant_recv_wakeups) {
		dev_dbg(&udev->dev, "HCD doesn't handle wakeup requests\n");
		return -EOPNOTSUPP;
	}

	udev->do_remote_wakeup = w;
	return 0;
}

int usb_runtime_suspend(struct device *dev)
{
	struct usb_device	*udev = to_usb_device(dev);
	int			status;

	if (autosuspend_check(udev) != 0)
		return -EAGAIN;

	status = usb_suspend_both(udev, PMSG_AUTO_SUSPEND);

	if (status == -EAGAIN || status == -EBUSY)
		usb_mark_last_busy(udev);

	if (status != 0 && udev->parent)
		return -EBUSY;
	return status;
}

int usb_runtime_resume(struct device *dev)
{
	struct usb_device	*udev = to_usb_device(dev);
	int			status;

	status = usb_resume_both(udev, PMSG_AUTO_RESUME);
	return status;
}

int usb_runtime_idle(struct device *dev)
{
	struct usb_device	*udev = to_usb_device(dev);

	if (autosuspend_check(udev) == 0)
		pm_runtime_autosuspend(dev);
	 
	return -EBUSY;
}

int usb_set_usb2_hardware_lpm(struct usb_device *udev, int enable)
{
	struct usb_hcd *hcd = bus_to_hcd(udev->bus);
	int ret = -EPERM;

	if (enable && !udev->usb2_hw_lpm_allowed)
		return 0;

	if (hcd->driver->set_usb2_hw_lpm) {
		ret = hcd->driver->set_usb2_hw_lpm(hcd, udev, enable);
		if (!ret)
			udev->usb2_hw_lpm_enabled = enable;
	}

	return ret;
}

#endif  

struct bus_type usb_bus_type = {
	.name =		"usb",
	.match =	usb_device_match,
	.uevent =	usb_uevent,
};
