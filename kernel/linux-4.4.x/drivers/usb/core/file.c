#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/usb.h>

#include "usb.h"

#define MAX_USB_MINORS	256
static const struct file_operations *usb_minors[MAX_USB_MINORS];
static DECLARE_RWSEM(minor_rwsem);

static int usb_open(struct inode *inode, struct file *file)
{
	int err = -ENODEV;
	const struct file_operations *new_fops;

	down_read(&minor_rwsem);
	new_fops = fops_get(usb_minors[iminor(inode)]);

	if (!new_fops)
		goto done;

	replace_fops(file, new_fops);
	 
	if (file->f_op->open)
		err = file->f_op->open(inode, file);
 done:
	up_read(&minor_rwsem);
	return err;
}

static const struct file_operations usb_fops = {
	.owner =	THIS_MODULE,
	.open =		usb_open,
	.llseek =	noop_llseek,
};

static struct usb_class {
	struct kref kref;
	struct class *class;
} *usb_class;

static char *usb_devnode(struct device *dev, umode_t *mode)
{
	struct usb_class_driver *drv;

	drv = dev_get_drvdata(dev);
	if (!drv || !drv->devnode)
		return NULL;
	return drv->devnode(dev, mode);
}

static int init_usb_class(void)
{
	int result = 0;

	if (usb_class != NULL) {
		kref_get(&usb_class->kref);
		goto exit;
	}

	usb_class = kmalloc(sizeof(*usb_class), GFP_KERNEL);
	if (!usb_class) {
		result = -ENOMEM;
		goto exit;
	}

	kref_init(&usb_class->kref);
	usb_class->class = class_create(THIS_MODULE, "usbmisc");
	if (IS_ERR(usb_class->class)) {
		result = PTR_ERR(usb_class->class);
		printk(KERN_ERR "class_create failed for usb devices\n");
		kfree(usb_class);
		usb_class = NULL;
		goto exit;
	}
	usb_class->class->devnode = usb_devnode;

exit:
	return result;
}

static void release_usb_class(struct kref *kref)
{
	 
	class_destroy(usb_class->class);
	kfree(usb_class);
	usb_class = NULL;
}

static void destroy_usb_class(void)
{
	if (usb_class)
		kref_put(&usb_class->kref, release_usb_class);
}

int usb_major_init(void)
{
	int error;

	error = register_chrdev(USB_MAJOR, "usb", &usb_fops);
	if (error)
		printk(KERN_ERR "Unable to get major %d for usb devices\n",
		       USB_MAJOR);

	return error;
}

void usb_major_cleanup(void)
{
	unregister_chrdev(USB_MAJOR, "usb");
}

#ifdef MY_ABC_HERE
 
int usb_register_dev1(struct usb_interface *intf,
                     struct usb_class_driver *class_driver, int minor_offset)
{
	int retval = -EINVAL;
	int minor_base = class_driver->minor_base;
	int minor = 0;
	char name[20];
	char *temp;

	if (minor_offset < 0) {
		printk("%s (%d) Illegal minor_offset %d. Reset to 0\n",
				__FILE__, __LINE__, minor_offset);
		minor_offset = 0;
	}
#ifdef CONFIG_USB_DYNAMIC_MINORS
	 
	minor_base = 0;
#endif
	intf->minor = -1;

	dev_dbg(&intf->dev, "looking for a minor, starting at %d\n", minor_base);

	if (class_driver->fops == NULL)
		goto exit;

	down_write(&minor_rwsem);
	for (minor = minor_base+minor_offset; minor < MAX_USB_MINORS; ++minor) {
		if (usb_minors[minor])
				continue;

		printk("Get empty minor:%d\n", minor);
		usb_minors[minor] = class_driver->fops;

		retval = 0;
		break;
	}
	up_write(&minor_rwsem);

	if (retval)
		goto exit;

	retval = init_usb_class();
	if (retval)
		goto exit;

	intf->minor = minor;

	snprintf(name, sizeof(name), class_driver->name, minor - minor_base);
	temp = strrchr(name, '/');
	if (temp && (temp[1] != '\0'))
		++temp;
	else
		temp = name;
	intf->usb_dev = device_create(usb_class->class, &intf->dev,
				      MKDEV(USB_MAJOR, minor), class_driver,
				      "%s", temp);
	if (IS_ERR(intf->usb_dev)) {
		down_write(&minor_rwsem);
		usb_minors[intf->minor] = NULL;
		up_write(&minor_rwsem);
		retval = PTR_ERR(intf->usb_dev);
	}
exit:
	return retval;
}
EXPORT_SYMBOL(usb_register_dev1);
#endif  

int usb_register_dev(struct usb_interface *intf,
		     struct usb_class_driver *class_driver)
{
	int retval;
	int minor_base = class_driver->minor_base;
	int minor;
	char name[20];
	char *temp;

#ifdef CONFIG_USB_DYNAMIC_MINORS
	 
	minor_base = 0;
#endif

	if (class_driver->fops == NULL)
		return -EINVAL;
	if (intf->minor >= 0)
		return -EADDRINUSE;

	retval = init_usb_class();
	if (retval)
		return retval;

	dev_dbg(&intf->dev, "looking for a minor, starting at %d\n", minor_base);

	down_write(&minor_rwsem);
	for (minor = minor_base; minor < MAX_USB_MINORS; ++minor) {
		if (usb_minors[minor])
			continue;

		usb_minors[minor] = class_driver->fops;
		intf->minor = minor;
		break;
	}
	up_write(&minor_rwsem);
	if (intf->minor < 0)
		return -EXFULL;

	snprintf(name, sizeof(name), class_driver->name, minor - minor_base);
	temp = strrchr(name, '/');
	if (temp && (temp[1] != '\0'))
		++temp;
	else
		temp = name;
	intf->usb_dev = device_create(usb_class->class, &intf->dev,
				      MKDEV(USB_MAJOR, minor), class_driver,
				      "%s", temp);
	if (IS_ERR(intf->usb_dev)) {
		down_write(&minor_rwsem);
		usb_minors[minor] = NULL;
		intf->minor = -1;
		up_write(&minor_rwsem);
		retval = PTR_ERR(intf->usb_dev);
	}
	return retval;
}
EXPORT_SYMBOL_GPL(usb_register_dev);

void usb_deregister_dev(struct usb_interface *intf,
			struct usb_class_driver *class_driver)
{
	if (intf->minor == -1)
		return;

	dev_dbg(&intf->dev, "removing %d minor\n", intf->minor);

	down_write(&minor_rwsem);
	usb_minors[intf->minor] = NULL;
	up_write(&minor_rwsem);

	device_destroy(usb_class->class, MKDEV(USB_MAJOR, intf->minor));
	intf->usb_dev = NULL;
	intf->minor = -1;
	destroy_usb_class();
}
EXPORT_SYMBOL_GPL(usb_deregister_dev);
