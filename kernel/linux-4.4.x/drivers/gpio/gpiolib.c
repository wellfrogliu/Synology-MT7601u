#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/acpi.h>
#include <linux/gpio/driver.h>
#include <linux/gpio/machine.h>
#include <linux/pinctrl/consumer.h>

#include "gpiolib.h"

#define CREATE_TRACE_POINTS
#include <trace/events/gpio.h>

#ifdef	DEBUG
#define	extra_checks	1
#else
#define	extra_checks	0
#endif

DEFINE_SPINLOCK(gpio_lock);

static DEFINE_MUTEX(gpio_lookup_lock);
static LIST_HEAD(gpio_lookup_list);
LIST_HEAD(gpio_chips);

static void gpiochip_free_hogs(struct gpio_chip *chip);
static void gpiochip_irqchip_remove(struct gpio_chip *gpiochip);

static inline void desc_set_label(struct gpio_desc *d, const char *label)
{
	d->label = label;
}

struct gpio_desc *gpio_to_desc(unsigned gpio)
{
	struct gpio_chip *chip;
	unsigned long flags;
#ifdef MY_ABC_HERE
	unsigned int iBase;
#endif  

	spin_lock_irqsave(&gpio_lock, flags);

	list_for_each_entry(chip, &gpio_chips, list) {
#ifdef MY_ABC_HERE
		iBase = ARCH_NR_GPIOS - (chip->base+chip->ngpio);
		if (iBase <= gpio && iBase + chip->ngpio > gpio) {
			spin_unlock_irqrestore(&gpio_lock, flags);
			return &chip->desc[gpio - iBase];
		}
#else  
		if (chip->base <= gpio && chip->base + chip->ngpio > gpio) {
			spin_unlock_irqrestore(&gpio_lock, flags);
			return &chip->desc[gpio - chip->base];
		}
#endif  
	}

	spin_unlock_irqrestore(&gpio_lock, flags);

	if (!gpio_is_valid(gpio))
		WARN(1, "invalid GPIO %d\n", gpio);

	return NULL;
}
EXPORT_SYMBOL_GPL(gpio_to_desc);

struct gpio_desc *gpiochip_get_desc(struct gpio_chip *chip,
				    u16 hwnum)
{
	if (hwnum >= chip->ngpio)
		return ERR_PTR(-EINVAL);

	return &chip->desc[hwnum];
}

int desc_to_gpio(const struct gpio_desc *desc)
{
	return desc->chip->base + (desc - &desc->chip->desc[0]);
}
EXPORT_SYMBOL_GPL(desc_to_gpio);

struct gpio_chip *gpiod_to_chip(const struct gpio_desc *desc)
{
	return desc ? desc->chip : NULL;
}
EXPORT_SYMBOL_GPL(gpiod_to_chip);

static int gpiochip_find_base(int ngpio)
{
	struct gpio_chip *chip;
	int base = ARCH_NR_GPIOS - ngpio;

	list_for_each_entry_reverse(chip, &gpio_chips, list) {
		 
		if (chip->base + chip->ngpio <= base)
			break;
		else
			 
			base = chip->base - ngpio;
	}

	if (gpio_is_valid(base)) {
		pr_debug("%s: found new base at %d\n", __func__, base);
		return base;
	} else {
		pr_err("%s: cannot find free range\n", __func__);
		return -ENOSPC;
	}
}

int gpiod_get_direction(struct gpio_desc *desc)
{
	struct gpio_chip	*chip;
	unsigned		offset;
	int			status = -EINVAL;

	chip = gpiod_to_chip(desc);
	offset = gpio_chip_hwgpio(desc);

	if (!chip->get_direction)
		return status;

	status = chip->get_direction(chip, offset);
	if (status > 0) {
		 
		status = 1;
		clear_bit(FLAG_IS_OUT, &desc->flags);
	}
	if (status == 0) {
		 
		set_bit(FLAG_IS_OUT, &desc->flags);
	}
	return status;
}
EXPORT_SYMBOL_GPL(gpiod_get_direction);

static int gpiochip_add_to_list(struct gpio_chip *chip)
{
	struct list_head *pos;
	struct gpio_chip *_chip;
	int err = 0;

	list_for_each(pos, &gpio_chips) {
		_chip = list_entry(pos, struct gpio_chip, list);
		 
		if (_chip->base >= chip->base + chip->ngpio)
			break;
	}

	if (pos != &gpio_chips && pos->prev != &gpio_chips) {
		_chip = list_entry(pos->prev, struct gpio_chip, list);
		if (_chip->base + _chip->ngpio > chip->base) {
#if defined(MY_DEF_HERE)
			dev_err(chip->parent,
				"GPIO integer space overlap, cannot add chip\n");
#else  
			dev_err(chip->dev,
			       "GPIO integer space overlap, cannot add chip\n");
#endif  
			err = -EBUSY;
		}
	}

	if (!err)
		list_add_tail(&chip->list, pos);

	return err;
}

static struct gpio_desc *gpio_name_to_desc(const char * const name)
{
	struct gpio_chip *chip;
	unsigned long flags;

	spin_lock_irqsave(&gpio_lock, flags);

	list_for_each_entry(chip, &gpio_chips, list) {
		int i;

		for (i = 0; i != chip->ngpio; ++i) {
			struct gpio_desc *gpio = &chip->desc[i];

			if (!gpio->name || !name)
				continue;

			if (!strcmp(gpio->name, name)) {
				spin_unlock_irqrestore(&gpio_lock, flags);
				return gpio;
			}
		}
	}

	spin_unlock_irqrestore(&gpio_lock, flags);

	return NULL;
}

static int gpiochip_set_desc_names(struct gpio_chip *gc)
{
	int i;

	if (!gc->names)
		return 0;

	for (i = 0; i != gc->ngpio; ++i) {
		struct gpio_desc *gpio;

		gpio = gpio_name_to_desc(gc->names[i]);
		if (gpio)
#if defined(MY_DEF_HERE)
			dev_warn(gc->parent, "Detected name collision for "
#else  
			dev_warn(gc->dev, "Detected name collision for "
#endif  
				 "GPIO name '%s'\n",
				 gc->names[i]);
	}

	for (i = 0; i != gc->ngpio; ++i)
		gc->desc[i].name = gc->names[i];

	return 0;
}

int gpiochip_add(struct gpio_chip *chip)
{
	unsigned long	flags;
	int		status = 0;
	unsigned	id;
	int		base = chip->base;
	struct gpio_desc *descs;

	descs = kcalloc(chip->ngpio, sizeof(descs[0]), GFP_KERNEL);
	if (!descs)
		return -ENOMEM;

	spin_lock_irqsave(&gpio_lock, flags);

	if (base < 0) {
		base = gpiochip_find_base(chip->ngpio);
		if (base < 0) {
			status = base;
			spin_unlock_irqrestore(&gpio_lock, flags);
			goto err_free_descs;
		}
		chip->base = base;
	}

	status = gpiochip_add_to_list(chip);
	if (status) {
		spin_unlock_irqrestore(&gpio_lock, flags);
		goto err_free_descs;
	}

	for (id = 0; id < chip->ngpio; id++) {
		struct gpio_desc *desc = &descs[id];

		desc->chip = chip;

		desc->flags = !chip->direction_input ? (1 << FLAG_IS_OUT) : 0;
	}

	chip->desc = descs;

	spin_unlock_irqrestore(&gpio_lock, flags);

#ifdef CONFIG_PINCTRL
	INIT_LIST_HEAD(&chip->pin_ranges);
#endif

#if defined(MY_DEF_HERE)
	if (!chip->owner && chip->parent && chip->parent->driver)
		chip->owner = chip->parent->driver->owner;
#else  
	if (!chip->owner && chip->dev && chip->dev->driver)
		chip->owner = chip->dev->driver->owner;
#endif  

	status = gpiochip_set_desc_names(chip);
	if (status)
		goto err_remove_from_list;

	status = of_gpiochip_add(chip);
	if (status)
		goto err_remove_chip;

	acpi_gpiochip_add(chip);

	status = gpiochip_sysfs_register(chip);
	if (status)
		goto err_remove_chip;

	pr_debug("%s: registered GPIOs %d to %d on device: %s\n", __func__,
		chip->base, chip->base + chip->ngpio - 1,
		chip->label ? : "generic");

	return 0;

err_remove_chip:
	acpi_gpiochip_remove(chip);
	gpiochip_free_hogs(chip);
	of_gpiochip_remove(chip);
err_remove_from_list:
	spin_lock_irqsave(&gpio_lock, flags);
	list_del(&chip->list);
	spin_unlock_irqrestore(&gpio_lock, flags);
	chip->desc = NULL;
err_free_descs:
	kfree(descs);

	pr_err("%s: GPIOs %d..%d (%s) failed to register\n", __func__,
		chip->base, chip->base + chip->ngpio - 1,
		chip->label ? : "generic");
	return status;
}
EXPORT_SYMBOL_GPL(gpiochip_add);

void gpiochip_remove(struct gpio_chip *chip)
{
	struct gpio_desc *desc;
	unsigned long	flags;
	unsigned	id;
	bool		requested = false;

	gpiochip_sysfs_unregister(chip);

	gpiochip_irqchip_remove(chip);

	acpi_gpiochip_remove(chip);
	gpiochip_remove_pin_ranges(chip);
	gpiochip_free_hogs(chip);
	of_gpiochip_remove(chip);

	spin_lock_irqsave(&gpio_lock, flags);
	for (id = 0; id < chip->ngpio; id++) {
		desc = &chip->desc[id];
		desc->chip = NULL;
		if (test_bit(FLAG_REQUESTED, &desc->flags))
			requested = true;
	}
	list_del(&chip->list);
	spin_unlock_irqrestore(&gpio_lock, flags);

	if (requested)
#if defined(MY_DEF_HERE)
		dev_crit(chip->parent,
			 "REMOVING GPIOCHIP WITH GPIOS STILL REQUESTED\n");
#else  
		dev_crit(chip->dev, "REMOVING GPIOCHIP WITH GPIOS STILL REQUESTED\n");
#endif  

	kfree(chip->desc);
	chip->desc = NULL;
}
EXPORT_SYMBOL_GPL(gpiochip_remove);

struct gpio_chip *gpiochip_find(void *data,
				int (*match)(struct gpio_chip *chip,
					     void *data))
{
	struct gpio_chip *chip;
	unsigned long flags;

	spin_lock_irqsave(&gpio_lock, flags);
	list_for_each_entry(chip, &gpio_chips, list)
		if (match(chip, data))
			break;

	if (&chip->list == &gpio_chips)
		chip = NULL;
	spin_unlock_irqrestore(&gpio_lock, flags);

	return chip;
}
EXPORT_SYMBOL_GPL(gpiochip_find);

static int gpiochip_match_name(struct gpio_chip *chip, void *data)
{
	const char *name = data;

	return !strcmp(chip->label, name);
}

static struct gpio_chip *find_chip_by_name(const char *name)
{
	return gpiochip_find((void *)name, gpiochip_match_name);
}

#ifdef CONFIG_GPIOLIB_IRQCHIP

void gpiochip_set_chained_irqchip(struct gpio_chip *gpiochip,
				  struct irq_chip *irqchip,
				  int parent_irq,
				  irq_flow_handler_t parent_handler)
{
	unsigned int offset;

	if (!gpiochip->irqdomain) {
		chip_err(gpiochip, "called %s before setting up irqchip\n",
			 __func__);
		return;
	}

	if (parent_handler) {
		if (gpiochip->can_sleep) {
			chip_err(gpiochip,
				 "you cannot have chained interrupts on a "
				 "chip that may sleep\n");
			return;
		}
		 
		irq_set_chained_handler_and_data(parent_irq, parent_handler,
						 gpiochip);

		gpiochip->irq_parent = parent_irq;
	}

	for (offset = 0; offset < gpiochip->ngpio; offset++)
		irq_set_parent(irq_find_mapping(gpiochip->irqdomain, offset),
			       parent_irq);
}
EXPORT_SYMBOL_GPL(gpiochip_set_chained_irqchip);

static int gpiochip_irq_map(struct irq_domain *d, unsigned int irq,
			    irq_hw_number_t hwirq)
{
	struct gpio_chip *chip = d->host_data;

	irq_set_chip_data(irq, chip);
	 
	irq_set_lockdep_class(irq, chip->lock_key);
	irq_set_chip_and_handler(irq, chip->irqchip, chip->irq_handler);
	 
	if (chip->can_sleep && !chip->irq_not_threaded)
		irq_set_nested_thread(irq, 1);
	irq_set_noprobe(irq);

	if (chip->irq_default_type != IRQ_TYPE_NONE)
		irq_set_irq_type(irq, chip->irq_default_type);

	return 0;
}

static void gpiochip_irq_unmap(struct irq_domain *d, unsigned int irq)
{
	struct gpio_chip *chip = d->host_data;

	if (chip->can_sleep)
		irq_set_nested_thread(irq, 0);
	irq_set_chip_and_handler(irq, NULL, NULL);
	irq_set_chip_data(irq, NULL);
}

static const struct irq_domain_ops gpiochip_domain_ops = {
	.map	= gpiochip_irq_map,
	.unmap	= gpiochip_irq_unmap,
	 
	.xlate	= irq_domain_xlate_twocell,
};

static int gpiochip_irq_reqres(struct irq_data *d)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(d);

	if (!try_module_get(chip->owner))
		return -ENODEV;

	if (gpiochip_lock_as_irq(chip, d->hwirq)) {
		chip_err(chip,
			"unable to lock HW IRQ %lu for IRQ\n",
			d->hwirq);
		module_put(chip->owner);
		return -EINVAL;
	}
	return 0;
}

static void gpiochip_irq_relres(struct irq_data *d)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(d);

	gpiochip_unlock_as_irq(chip, d->hwirq);
	module_put(chip->owner);
}

static int gpiochip_to_irq(struct gpio_chip *chip, unsigned offset)
{
	return irq_find_mapping(chip->irqdomain, offset);
}

static void gpiochip_irqchip_remove(struct gpio_chip *gpiochip)
{
	unsigned int offset;

	acpi_gpiochip_free_interrupts(gpiochip);

	if (gpiochip->irq_parent) {
		irq_set_chained_handler(gpiochip->irq_parent, NULL);
		irq_set_handler_data(gpiochip->irq_parent, NULL);
	}

	if (gpiochip->irqdomain) {
		for (offset = 0; offset < gpiochip->ngpio; offset++)
			irq_dispose_mapping(
				irq_find_mapping(gpiochip->irqdomain, offset));
		irq_domain_remove(gpiochip->irqdomain);
	}

	if (gpiochip->irqchip) {
		gpiochip->irqchip->irq_request_resources = NULL;
		gpiochip->irqchip->irq_release_resources = NULL;
		gpiochip->irqchip = NULL;
	}
}

int _gpiochip_irqchip_add(struct gpio_chip *gpiochip,
			  struct irq_chip *irqchip,
			  unsigned int first_irq,
			  irq_flow_handler_t handler,
			  unsigned int type,
			  struct lock_class_key *lock_key)
{
	struct device_node *of_node;
	unsigned int offset;
	unsigned irq_base = 0;

	if (!gpiochip || !irqchip)
		return -EINVAL;

#if defined(MY_DEF_HERE)
	if (!gpiochip->parent) {
#else  
	if (!gpiochip->dev) {
#endif  
		pr_err("missing gpiochip .dev parent pointer\n");
		return -EINVAL;
	}
#if defined(MY_DEF_HERE)
	of_node = gpiochip->parent->of_node;
#else  
	of_node = gpiochip->dev->of_node;
#endif  
#ifdef CONFIG_OF_GPIO
	 
	if (gpiochip->of_node)
		of_node = gpiochip->of_node;
#endif
	gpiochip->irqchip = irqchip;
	gpiochip->irq_handler = handler;
	gpiochip->irq_default_type = type;
	gpiochip->to_irq = gpiochip_to_irq;
	gpiochip->lock_key = lock_key;
	gpiochip->irqdomain = irq_domain_add_simple(of_node,
					gpiochip->ngpio, first_irq,
					&gpiochip_domain_ops, gpiochip);
	if (!gpiochip->irqdomain) {
		gpiochip->irqchip = NULL;
		return -EINVAL;
	}

	if (!irqchip->irq_request_resources &&
	    !irqchip->irq_release_resources) {
		irqchip->irq_request_resources = gpiochip_irq_reqres;
		irqchip->irq_release_resources = gpiochip_irq_relres;
	}

	for (offset = 0; offset < gpiochip->ngpio; offset++) {
		irq_base = irq_create_mapping(gpiochip->irqdomain, offset);
		if (offset == 0)
			 
			gpiochip->irq_base = irq_base;
	}

	acpi_gpiochip_request_interrupts(gpiochip);

	return 0;
}
EXPORT_SYMBOL_GPL(_gpiochip_irqchip_add);

#else  

static void gpiochip_irqchip_remove(struct gpio_chip *gpiochip) {}

#endif  

int gpiochip_generic_request(struct gpio_chip *chip, unsigned offset)
{
	return pinctrl_request_gpio(chip->base + offset);
}
EXPORT_SYMBOL_GPL(gpiochip_generic_request);

void gpiochip_generic_free(struct gpio_chip *chip, unsigned offset)
{
	pinctrl_free_gpio(chip->base + offset);
}
EXPORT_SYMBOL_GPL(gpiochip_generic_free);

#ifdef CONFIG_PINCTRL

int gpiochip_add_pingroup_range(struct gpio_chip *chip,
			struct pinctrl_dev *pctldev,
			unsigned int gpio_offset, const char *pin_group)
{
	struct gpio_pin_range *pin_range;
	int ret;

	pin_range = kzalloc(sizeof(*pin_range), GFP_KERNEL);
	if (!pin_range) {
		chip_err(chip, "failed to allocate pin ranges\n");
		return -ENOMEM;
	}

	pin_range->range.id = gpio_offset;
	pin_range->range.gc = chip;
	pin_range->range.name = chip->label;
	pin_range->range.base = chip->base + gpio_offset;
	pin_range->pctldev = pctldev;

	ret = pinctrl_get_group_pins(pctldev, pin_group,
					&pin_range->range.pins,
					&pin_range->range.npins);
	if (ret < 0) {
		kfree(pin_range);
		return ret;
	}

	pinctrl_add_gpio_range(pctldev, &pin_range->range);

	chip_dbg(chip, "created GPIO range %d->%d ==> %s PINGRP %s\n",
		 gpio_offset, gpio_offset + pin_range->range.npins - 1,
		 pinctrl_dev_get_devname(pctldev), pin_group);

	list_add_tail(&pin_range->node, &chip->pin_ranges);

	return 0;
}
EXPORT_SYMBOL_GPL(gpiochip_add_pingroup_range);

int gpiochip_add_pin_range(struct gpio_chip *chip, const char *pinctl_name,
			   unsigned int gpio_offset, unsigned int pin_offset,
			   unsigned int npins)
{
	struct gpio_pin_range *pin_range;
	int ret;

	pin_range = kzalloc(sizeof(*pin_range), GFP_KERNEL);
	if (!pin_range) {
		chip_err(chip, "failed to allocate pin ranges\n");
		return -ENOMEM;
	}

	pin_range->range.id = gpio_offset;
	pin_range->range.gc = chip;
	pin_range->range.name = chip->label;
	pin_range->range.base = chip->base + gpio_offset;
	pin_range->range.pin_base = pin_offset;
	pin_range->range.npins = npins;
	pin_range->pctldev = pinctrl_find_and_add_gpio_range(pinctl_name,
			&pin_range->range);
	if (IS_ERR(pin_range->pctldev)) {
		ret = PTR_ERR(pin_range->pctldev);
		chip_err(chip, "could not create pin range\n");
		kfree(pin_range);
		return ret;
	}
	chip_dbg(chip, "created GPIO range %d->%d ==> %s PIN %d->%d\n",
		 gpio_offset, gpio_offset + npins - 1,
		 pinctl_name,
		 pin_offset, pin_offset + npins - 1);

	list_add_tail(&pin_range->node, &chip->pin_ranges);

	return 0;
}
EXPORT_SYMBOL_GPL(gpiochip_add_pin_range);

void gpiochip_remove_pin_ranges(struct gpio_chip *chip)
{
	struct gpio_pin_range *pin_range, *tmp;

	list_for_each_entry_safe(pin_range, tmp, &chip->pin_ranges, node) {
		list_del(&pin_range->node);
		pinctrl_remove_gpio_range(pin_range->pctldev,
				&pin_range->range);
		kfree(pin_range);
	}
}
EXPORT_SYMBOL_GPL(gpiochip_remove_pin_ranges);

#endif  

static int __gpiod_request(struct gpio_desc *desc, const char *label)
{
	struct gpio_chip	*chip = desc->chip;
	int			status;
	unsigned long		flags;

	spin_lock_irqsave(&gpio_lock, flags);

	if (test_and_set_bit(FLAG_REQUESTED, &desc->flags) == 0) {
		desc_set_label(desc, label ? : "?");
		status = 0;
	} else {
		status = -EBUSY;
		goto done;
	}

	if (chip->request) {
		 
		spin_unlock_irqrestore(&gpio_lock, flags);
		status = chip->request(chip, gpio_chip_hwgpio(desc));
		spin_lock_irqsave(&gpio_lock, flags);

		if (status < 0) {
			desc_set_label(desc, NULL);
			clear_bit(FLAG_REQUESTED, &desc->flags);
			goto done;
		}
	}
	if (chip->get_direction) {
		 
		spin_unlock_irqrestore(&gpio_lock, flags);
		gpiod_get_direction(desc);
		spin_lock_irqsave(&gpio_lock, flags);
	}
done:
	spin_unlock_irqrestore(&gpio_lock, flags);
	return status;
}

int gpiod_request(struct gpio_desc *desc, const char *label)
{
	int status = -EPROBE_DEFER;
	struct gpio_chip *chip;

	if (!desc) {
		pr_warn("%s: invalid GPIO\n", __func__);
		return -EINVAL;
	}

	chip = desc->chip;
	if (!chip)
		goto done;

	if (try_module_get(chip->owner)) {
		status = __gpiod_request(desc, label);
		if (status < 0)
			module_put(chip->owner);
	}

done:
	if (status)
		gpiod_dbg(desc, "%s: status %d\n", __func__, status);

	return status;
}

static bool __gpiod_free(struct gpio_desc *desc)
{
	bool			ret = false;
	unsigned long		flags;
	struct gpio_chip	*chip;

	might_sleep();

	gpiod_unexport(desc);

	spin_lock_irqsave(&gpio_lock, flags);

	chip = desc->chip;
	if (chip && test_bit(FLAG_REQUESTED, &desc->flags)) {
		if (chip->free) {
			spin_unlock_irqrestore(&gpio_lock, flags);
			might_sleep_if(chip->can_sleep);
			chip->free(chip, gpio_chip_hwgpio(desc));
			spin_lock_irqsave(&gpio_lock, flags);
		}
		desc_set_label(desc, NULL);
		clear_bit(FLAG_ACTIVE_LOW, &desc->flags);
		clear_bit(FLAG_REQUESTED, &desc->flags);
		clear_bit(FLAG_OPEN_DRAIN, &desc->flags);
		clear_bit(FLAG_OPEN_SOURCE, &desc->flags);
		clear_bit(FLAG_IS_HOGGED, &desc->flags);
		ret = true;
	}

	spin_unlock_irqrestore(&gpio_lock, flags);
	return ret;
}

void gpiod_free(struct gpio_desc *desc)
{
	if (desc && __gpiod_free(desc))
		module_put(desc->chip->owner);
	else
		WARN_ON(extra_checks);
}

const char *gpiochip_is_requested(struct gpio_chip *chip, unsigned offset)
{
	struct gpio_desc *desc;

	if (offset >= chip->ngpio)
		return NULL;

	desc = &chip->desc[offset];

	if (test_bit(FLAG_REQUESTED, &desc->flags) == 0)
		return NULL;
	return desc->label;
}
EXPORT_SYMBOL_GPL(gpiochip_is_requested);

struct gpio_desc *gpiochip_request_own_desc(struct gpio_chip *chip, u16 hwnum,
					    const char *label)
{
	struct gpio_desc *desc = gpiochip_get_desc(chip, hwnum);
	int err;

	if (IS_ERR(desc)) {
		chip_err(chip, "failed to get GPIO descriptor\n");
		return desc;
	}

	err = __gpiod_request(desc, label);
	if (err < 0)
		return ERR_PTR(err);

	return desc;
}
EXPORT_SYMBOL_GPL(gpiochip_request_own_desc);

void gpiochip_free_own_desc(struct gpio_desc *desc)
{
	if (desc)
		__gpiod_free(desc);
}
EXPORT_SYMBOL_GPL(gpiochip_free_own_desc);

int gpiod_direction_input(struct gpio_desc *desc)
{
	struct gpio_chip	*chip;
	int			status = -EINVAL;

	if (!desc || !desc->chip) {
		pr_warn("%s: invalid GPIO\n", __func__);
		return -EINVAL;
	}

	chip = desc->chip;
	if (!chip->get || !chip->direction_input) {
		gpiod_warn(desc,
			"%s: missing get() or direction_input() operations\n",
			__func__);
		return -EIO;
	}

	status = chip->direction_input(chip, gpio_chip_hwgpio(desc));
	if (status == 0)
		clear_bit(FLAG_IS_OUT, &desc->flags);

	trace_gpio_direction(desc_to_gpio(desc), 1, status);

	return status;
}
EXPORT_SYMBOL_GPL(gpiod_direction_input);

static int _gpiod_direction_output_raw(struct gpio_desc *desc, int value)
{
	struct gpio_chip	*chip;
	int			status = -EINVAL;

	if (test_bit(FLAG_USED_AS_IRQ, &desc->flags)) {
		gpiod_err(desc,
			  "%s: tried to set a GPIO tied to an IRQ as output\n",
			  __func__);
		return -EIO;
	}

	if (value && test_bit(FLAG_OPEN_DRAIN,  &desc->flags))
		return gpiod_direction_input(desc);

	if (!value && test_bit(FLAG_OPEN_SOURCE,  &desc->flags))
		return gpiod_direction_input(desc);

	chip = desc->chip;
	if (!chip->set || !chip->direction_output) {
		gpiod_warn(desc,
		       "%s: missing set() or direction_output() operations\n",
		       __func__);
		return -EIO;
	}

	status = chip->direction_output(chip, gpio_chip_hwgpio(desc), value);
	if (status == 0)
		set_bit(FLAG_IS_OUT, &desc->flags);
	trace_gpio_value(desc_to_gpio(desc), 0, value);
	trace_gpio_direction(desc_to_gpio(desc), 0, status);
	return status;
}

int gpiod_direction_output_raw(struct gpio_desc *desc, int value)
{
	if (!desc || !desc->chip) {
		pr_warn("%s: invalid GPIO\n", __func__);
		return -EINVAL;
	}
	return _gpiod_direction_output_raw(desc, value);
}
EXPORT_SYMBOL_GPL(gpiod_direction_output_raw);

int gpiod_direction_output(struct gpio_desc *desc, int value)
{
	if (!desc || !desc->chip) {
		pr_warn("%s: invalid GPIO\n", __func__);
		return -EINVAL;
	}
	if (test_bit(FLAG_ACTIVE_LOW, &desc->flags))
		value = !value;
	return _gpiod_direction_output_raw(desc, value);
}
EXPORT_SYMBOL_GPL(gpiod_direction_output);

int gpiod_set_debounce(struct gpio_desc *desc, unsigned debounce)
{
	struct gpio_chip	*chip;

	if (!desc || !desc->chip) {
		pr_warn("%s: invalid GPIO\n", __func__);
		return -EINVAL;
	}

	chip = desc->chip;
	if (!chip->set || !chip->set_debounce) {
		gpiod_dbg(desc,
			  "%s: missing set() or set_debounce() operations\n",
			  __func__);
		return -ENOTSUPP;
	}

	return chip->set_debounce(chip, gpio_chip_hwgpio(desc), debounce);
}
EXPORT_SYMBOL_GPL(gpiod_set_debounce);

int gpiod_is_active_low(const struct gpio_desc *desc)
{
	return test_bit(FLAG_ACTIVE_LOW, &desc->flags);
}
EXPORT_SYMBOL_GPL(gpiod_is_active_low);

static int _gpiod_get_raw_value(const struct gpio_desc *desc)
{
	struct gpio_chip	*chip;
	int offset;
	int value;

	chip = desc->chip;
	offset = gpio_chip_hwgpio(desc);
	value = chip->get ? chip->get(chip, offset) : -EIO;
	 
	value = !!value;
	trace_gpio_value(desc_to_gpio(desc), 1, value);
	return value;
}

int gpiod_get_raw_value(const struct gpio_desc *desc)
{
	if (!desc)
		return 0;
	 
	WARN_ON(desc->chip->can_sleep);
	return _gpiod_get_raw_value(desc);
}
EXPORT_SYMBOL_GPL(gpiod_get_raw_value);

int gpiod_get_value(const struct gpio_desc *desc)
{
	int value;
	if (!desc)
		return 0;
	 
	WARN_ON(desc->chip->can_sleep);

	value = _gpiod_get_raw_value(desc);
	if (value < 0)
		return value;

	if (test_bit(FLAG_ACTIVE_LOW, &desc->flags))
		value = !value;

	return value;
}
EXPORT_SYMBOL_GPL(gpiod_get_value);

static void _gpio_set_open_drain_value(struct gpio_desc *desc, bool value)
{
	int err = 0;
	struct gpio_chip *chip = desc->chip;
	int offset = gpio_chip_hwgpio(desc);

	if (value) {
		err = chip->direction_input(chip, offset);
		if (!err)
			clear_bit(FLAG_IS_OUT, &desc->flags);
	} else {
		err = chip->direction_output(chip, offset, 0);
		if (!err)
			set_bit(FLAG_IS_OUT, &desc->flags);
	}
	trace_gpio_direction(desc_to_gpio(desc), value, err);
	if (err < 0)
		gpiod_err(desc,
			  "%s: Error in set_value for open drain err %d\n",
			  __func__, err);
}

static void _gpio_set_open_source_value(struct gpio_desc *desc, bool value)
{
	int err = 0;
	struct gpio_chip *chip = desc->chip;
	int offset = gpio_chip_hwgpio(desc);

	if (value) {
		err = chip->direction_output(chip, offset, 1);
		if (!err)
			set_bit(FLAG_IS_OUT, &desc->flags);
	} else {
		err = chip->direction_input(chip, offset);
		if (!err)
			clear_bit(FLAG_IS_OUT, &desc->flags);
	}
	trace_gpio_direction(desc_to_gpio(desc), !value, err);
	if (err < 0)
		gpiod_err(desc,
			  "%s: Error in set_value for open source err %d\n",
			  __func__, err);
}

static void _gpiod_set_raw_value(struct gpio_desc *desc, bool value)
{
	struct gpio_chip	*chip;

	chip = desc->chip;
	trace_gpio_value(desc_to_gpio(desc), 0, value);
	if (test_bit(FLAG_OPEN_DRAIN, &desc->flags))
		_gpio_set_open_drain_value(desc, value);
	else if (test_bit(FLAG_OPEN_SOURCE, &desc->flags))
		_gpio_set_open_source_value(desc, value);
	else
		chip->set(chip, gpio_chip_hwgpio(desc), value);
}

static void gpio_chip_set_multiple(struct gpio_chip *chip,
				   unsigned long *mask, unsigned long *bits)
{
	if (chip->set_multiple) {
		chip->set_multiple(chip, mask, bits);
	} else {
		int i;
		for (i = 0; i < chip->ngpio; i++) {
			if (mask[BIT_WORD(i)] == 0) {
				 
				i = (BIT_WORD(i) + 1) * BITS_PER_LONG - 1;
				continue;
			}
			 
			if (__test_and_clear_bit(i, mask))
				chip->set(chip, i, test_bit(i, bits));
		}
	}
}

static void gpiod_set_array_value_priv(bool raw, bool can_sleep,
				       unsigned int array_size,
				       struct gpio_desc **desc_array,
				       int *value_array)
{
	int i = 0;

	while (i < array_size) {
		struct gpio_chip *chip = desc_array[i]->chip;
		unsigned long mask[BITS_TO_LONGS(chip->ngpio)];
		unsigned long bits[BITS_TO_LONGS(chip->ngpio)];
		int count = 0;

		if (!can_sleep)
			WARN_ON(chip->can_sleep);

		memset(mask, 0, sizeof(mask));
		do {
			struct gpio_desc *desc = desc_array[i];
			int hwgpio = gpio_chip_hwgpio(desc);
			int value = value_array[i];

			if (!raw && test_bit(FLAG_ACTIVE_LOW, &desc->flags))
				value = !value;
			trace_gpio_value(desc_to_gpio(desc), 0, value);
			 
			if (test_bit(FLAG_OPEN_DRAIN, &desc->flags)) {
				_gpio_set_open_drain_value(desc, value);
			} else if (test_bit(FLAG_OPEN_SOURCE, &desc->flags)) {
				_gpio_set_open_source_value(desc, value);
			} else {
				__set_bit(hwgpio, mask);
				if (value)
					__set_bit(hwgpio, bits);
				else
					__clear_bit(hwgpio, bits);
				count++;
			}
			i++;
		} while ((i < array_size) && (desc_array[i]->chip == chip));
		 
		if (count != 0)
			gpio_chip_set_multiple(chip, mask, bits);
	}
}

void gpiod_set_raw_value(struct gpio_desc *desc, int value)
{
	if (!desc)
		return;
	 
	WARN_ON(desc->chip->can_sleep);
	_gpiod_set_raw_value(desc, value);
}
EXPORT_SYMBOL_GPL(gpiod_set_raw_value);

void gpiod_set_value(struct gpio_desc *desc, int value)
{
	if (!desc)
		return;
	 
	WARN_ON(desc->chip->can_sleep);
	if (test_bit(FLAG_ACTIVE_LOW, &desc->flags))
		value = !value;
	_gpiod_set_raw_value(desc, value);
}
EXPORT_SYMBOL_GPL(gpiod_set_value);

void gpiod_set_raw_array_value(unsigned int array_size,
			 struct gpio_desc **desc_array, int *value_array)
{
	if (!desc_array)
		return;
	gpiod_set_array_value_priv(true, false, array_size, desc_array,
				   value_array);
}
EXPORT_SYMBOL_GPL(gpiod_set_raw_array_value);

void gpiod_set_array_value(unsigned int array_size,
			   struct gpio_desc **desc_array, int *value_array)
{
	if (!desc_array)
		return;
	gpiod_set_array_value_priv(false, false, array_size, desc_array,
				   value_array);
}
EXPORT_SYMBOL_GPL(gpiod_set_array_value);

int gpiod_cansleep(const struct gpio_desc *desc)
{
	if (!desc)
		return 0;
	return desc->chip->can_sleep;
}
EXPORT_SYMBOL_GPL(gpiod_cansleep);

int gpiod_to_irq(const struct gpio_desc *desc)
{
	struct gpio_chip	*chip;
	int			offset;

	if (!desc)
		return -EINVAL;
	chip = desc->chip;
	offset = gpio_chip_hwgpio(desc);
	return chip->to_irq ? chip->to_irq(chip, offset) : -ENXIO;
}
EXPORT_SYMBOL_GPL(gpiod_to_irq);

int gpiochip_lock_as_irq(struct gpio_chip *chip, unsigned int offset)
{
	if (offset >= chip->ngpio)
		return -EINVAL;

	if (test_bit(FLAG_IS_OUT, &chip->desc[offset].flags)) {
		chip_err(chip,
			  "%s: tried to flag a GPIO set as output for IRQ\n",
			  __func__);
		return -EIO;
	}

	set_bit(FLAG_USED_AS_IRQ, &chip->desc[offset].flags);
	return 0;
}
EXPORT_SYMBOL_GPL(gpiochip_lock_as_irq);

void gpiochip_unlock_as_irq(struct gpio_chip *chip, unsigned int offset)
{
	if (offset >= chip->ngpio)
		return;

	clear_bit(FLAG_USED_AS_IRQ, &chip->desc[offset].flags);
}
EXPORT_SYMBOL_GPL(gpiochip_unlock_as_irq);

int gpiod_get_raw_value_cansleep(const struct gpio_desc *desc)
{
	might_sleep_if(extra_checks);
	if (!desc)
		return 0;
	return _gpiod_get_raw_value(desc);
}
EXPORT_SYMBOL_GPL(gpiod_get_raw_value_cansleep);

int gpiod_get_value_cansleep(const struct gpio_desc *desc)
{
	int value;

	might_sleep_if(extra_checks);
	if (!desc)
		return 0;

	value = _gpiod_get_raw_value(desc);
	if (value < 0)
		return value;

	if (test_bit(FLAG_ACTIVE_LOW, &desc->flags))
		value = !value;

	return value;
}
EXPORT_SYMBOL_GPL(gpiod_get_value_cansleep);

void gpiod_set_raw_value_cansleep(struct gpio_desc *desc, int value)
{
	might_sleep_if(extra_checks);
	if (!desc)
		return;
	_gpiod_set_raw_value(desc, value);
}
EXPORT_SYMBOL_GPL(gpiod_set_raw_value_cansleep);

void gpiod_set_value_cansleep(struct gpio_desc *desc, int value)
{
	might_sleep_if(extra_checks);
	if (!desc)
		return;

	if (test_bit(FLAG_ACTIVE_LOW, &desc->flags))
		value = !value;
	_gpiod_set_raw_value(desc, value);
}
EXPORT_SYMBOL_GPL(gpiod_set_value_cansleep);

void gpiod_set_raw_array_value_cansleep(unsigned int array_size,
					struct gpio_desc **desc_array,
					int *value_array)
{
	might_sleep_if(extra_checks);
	if (!desc_array)
		return;
	gpiod_set_array_value_priv(true, true, array_size, desc_array,
				   value_array);
}
EXPORT_SYMBOL_GPL(gpiod_set_raw_array_value_cansleep);

void gpiod_set_array_value_cansleep(unsigned int array_size,
				    struct gpio_desc **desc_array,
				    int *value_array)
{
	might_sleep_if(extra_checks);
	if (!desc_array)
		return;
	gpiod_set_array_value_priv(false, true, array_size, desc_array,
				   value_array);
}
EXPORT_SYMBOL_GPL(gpiod_set_array_value_cansleep);

void gpiod_add_lookup_table(struct gpiod_lookup_table *table)
{
	mutex_lock(&gpio_lookup_lock);

	list_add_tail(&table->list, &gpio_lookup_list);

	mutex_unlock(&gpio_lookup_lock);
}

void gpiod_remove_lookup_table(struct gpiod_lookup_table *table)
{
	mutex_lock(&gpio_lookup_lock);

	list_del(&table->list);

	mutex_unlock(&gpio_lookup_lock);
}

static struct gpio_desc *of_find_gpio(struct device *dev, const char *con_id,
				      unsigned int idx,
				      enum gpio_lookup_flags *flags)
{
	char prop_name[32];  
	enum of_gpio_flags of_flags;
	struct gpio_desc *desc;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(gpio_suffixes); i++) {
		if (con_id)
			snprintf(prop_name, sizeof(prop_name), "%s-%s", con_id,
				 gpio_suffixes[i]);
		else
			snprintf(prop_name, sizeof(prop_name), "%s",
				 gpio_suffixes[i]);

		desc = of_get_named_gpiod_flags(dev->of_node, prop_name, idx,
						&of_flags);
		if (!IS_ERR(desc) || (PTR_ERR(desc) == -EPROBE_DEFER))
			break;
	}

	if (IS_ERR(desc))
		return desc;

	if (of_flags & OF_GPIO_ACTIVE_LOW)
		*flags |= GPIO_ACTIVE_LOW;

	if (of_flags & OF_GPIO_SINGLE_ENDED) {
		if (of_flags & OF_GPIO_ACTIVE_LOW)
			*flags |= GPIO_OPEN_DRAIN;
		else
			*flags |= GPIO_OPEN_SOURCE;
	}

	return desc;
}

static struct gpio_desc *acpi_find_gpio(struct device *dev, const char *con_id,
					unsigned int idx,
					enum gpio_lookup_flags *flags)
{
	struct acpi_device *adev = ACPI_COMPANION(dev);
	struct acpi_gpio_info info;
	struct gpio_desc *desc;
	char propname[32];
	int i;

	for (i = 0; i < ARRAY_SIZE(gpio_suffixes); i++) {
		if (con_id && strcmp(con_id, "gpios")) {
			snprintf(propname, sizeof(propname), "%s-%s",
				 con_id, gpio_suffixes[i]);
		} else {
			snprintf(propname, sizeof(propname), "%s",
				 gpio_suffixes[i]);
		}

		desc = acpi_get_gpiod_by_index(adev, propname, idx, &info);
		if (!IS_ERR(desc) || (PTR_ERR(desc) == -EPROBE_DEFER))
			break;
	}

	if (IS_ERR(desc)) {
		desc = acpi_get_gpiod_by_index(adev, NULL, idx, &info);
		if (IS_ERR(desc))
			return desc;
	}

	if (info.active_low)
		*flags |= GPIO_ACTIVE_LOW;

	return desc;
}

static struct gpiod_lookup_table *gpiod_find_lookup_table(struct device *dev)
{
	const char *dev_id = dev ? dev_name(dev) : NULL;
	struct gpiod_lookup_table *table;

	mutex_lock(&gpio_lookup_lock);

	list_for_each_entry(table, &gpio_lookup_list, list) {
		if (table->dev_id && dev_id) {
			 
			if (!strcmp(table->dev_id, dev_id))
				goto found;
		} else {
			 
			if (dev_id == table->dev_id)
				goto found;
		}
	}
	table = NULL;

found:
	mutex_unlock(&gpio_lookup_lock);
	return table;
}

static struct gpio_desc *gpiod_find(struct device *dev, const char *con_id,
				    unsigned int idx,
				    enum gpio_lookup_flags *flags)
{
	struct gpio_desc *desc = ERR_PTR(-ENOENT);
	struct gpiod_lookup_table *table;
	struct gpiod_lookup *p;

	table = gpiod_find_lookup_table(dev);
	if (!table)
		return desc;

	for (p = &table->table[0]; p->chip_label; p++) {
		struct gpio_chip *chip;

		if (p->idx != idx)
			continue;

		if (p->con_id && (!con_id || strcmp(p->con_id, con_id)))
			continue;

		chip = find_chip_by_name(p->chip_label);

		if (!chip) {
			dev_err(dev, "cannot find GPIO chip %s\n",
				p->chip_label);
			return ERR_PTR(-ENODEV);
		}

		if (chip->ngpio <= p->chip_hwnum) {
			dev_err(dev,
				"requested GPIO %d is out of range [0..%d] for chip %s\n",
				idx, chip->ngpio, chip->label);
			return ERR_PTR(-EINVAL);
		}

		desc = gpiochip_get_desc(chip, p->chip_hwnum);
		*flags = p->flags;

		return desc;
	}

	return desc;
}

static int dt_gpio_count(struct device *dev, const char *con_id)
{
	int ret;
	char propname[32];
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(gpio_suffixes); i++) {
		if (con_id)
			snprintf(propname, sizeof(propname), "%s-%s",
				 con_id, gpio_suffixes[i]);
		else
			snprintf(propname, sizeof(propname), "%s",
				 gpio_suffixes[i]);

		ret = of_gpio_named_count(dev->of_node, propname);
		if (ret >= 0)
			break;
	}
	return ret;
}

static int platform_gpio_count(struct device *dev, const char *con_id)
{
	struct gpiod_lookup_table *table;
	struct gpiod_lookup *p;
	unsigned int count = 0;

	table = gpiod_find_lookup_table(dev);
	if (!table)
		return -ENOENT;

	for (p = &table->table[0]; p->chip_label; p++) {
		if ((con_id && p->con_id && !strcmp(con_id, p->con_id)) ||
		    (!con_id && !p->con_id))
			count++;
	}
	if (!count)
		return -ENOENT;

	return count;
}

int gpiod_count(struct device *dev, const char *con_id)
{
	int count = -ENOENT;

	if (IS_ENABLED(CONFIG_OF) && dev && dev->of_node)
		count = dt_gpio_count(dev, con_id);
	else if (IS_ENABLED(CONFIG_ACPI) && dev && ACPI_HANDLE(dev))
		count = acpi_gpio_count(dev, con_id);

	if (count < 0)
		count = platform_gpio_count(dev, con_id);

	return count;
}
EXPORT_SYMBOL_GPL(gpiod_count);

struct gpio_desc *__must_check gpiod_get(struct device *dev, const char *con_id,
					 enum gpiod_flags flags)
{
	return gpiod_get_index(dev, con_id, 0, flags);
}
EXPORT_SYMBOL_GPL(gpiod_get);

struct gpio_desc *__must_check gpiod_get_optional(struct device *dev,
						  const char *con_id,
						  enum gpiod_flags flags)
{
	return gpiod_get_index_optional(dev, con_id, 0, flags);
}
EXPORT_SYMBOL_GPL(gpiod_get_optional);

static int gpiod_configure_flags(struct gpio_desc *desc, const char *con_id,
		unsigned long lflags, enum gpiod_flags dflags)
{
	int status;

	if (lflags & GPIO_ACTIVE_LOW)
		set_bit(FLAG_ACTIVE_LOW, &desc->flags);
	if (lflags & GPIO_OPEN_DRAIN)
		set_bit(FLAG_OPEN_DRAIN, &desc->flags);
	if (lflags & GPIO_OPEN_SOURCE)
		set_bit(FLAG_OPEN_SOURCE, &desc->flags);

	if (!(dflags & GPIOD_FLAGS_BIT_DIR_SET)) {
		pr_debug("no flags found for %s\n", con_id);
		return 0;
	}

	if (dflags & GPIOD_FLAGS_BIT_DIR_OUT)
		status = gpiod_direction_output(desc,
					      dflags & GPIOD_FLAGS_BIT_DIR_VAL);
	else
		status = gpiod_direction_input(desc);

	return status;
}

struct gpio_desc *__must_check gpiod_get_index(struct device *dev,
					       const char *con_id,
					       unsigned int idx,
					       enum gpiod_flags flags)
{
	struct gpio_desc *desc = NULL;
	int status;
	enum gpio_lookup_flags lookupflags = 0;

	dev_dbg(dev, "GPIO lookup for consumer %s\n", con_id);

	if (dev) {
		 
		if (IS_ENABLED(CONFIG_OF) && dev->of_node) {
			dev_dbg(dev, "using device tree for GPIO lookup\n");
			desc = of_find_gpio(dev, con_id, idx, &lookupflags);
		} else if (ACPI_COMPANION(dev)) {
			dev_dbg(dev, "using ACPI for GPIO lookup\n");
			desc = acpi_find_gpio(dev, con_id, idx, &lookupflags);
		}
	}

	if (!desc || desc == ERR_PTR(-ENOENT)) {
		dev_dbg(dev, "using lookup tables for GPIO lookup\n");
		desc = gpiod_find(dev, con_id, idx, &lookupflags);
	}

	if (IS_ERR(desc)) {
		dev_dbg(dev, "lookup for GPIO %s failed\n", con_id);
		return desc;
	}

	status = gpiod_request(desc, con_id);
	if (status < 0)
		return ERR_PTR(status);

	status = gpiod_configure_flags(desc, con_id, lookupflags, flags);
	if (status < 0) {
		dev_dbg(dev, "setup of GPIO %s failed\n", con_id);
		gpiod_put(desc);
		return ERR_PTR(status);
	}

	return desc;
}
EXPORT_SYMBOL_GPL(gpiod_get_index);

struct gpio_desc *fwnode_get_named_gpiod(struct fwnode_handle *fwnode,
					 const char *propname)
{
	struct gpio_desc *desc = ERR_PTR(-ENODEV);
	bool active_low = false;
	bool single_ended = false;
	int ret;

	if (!fwnode)
		return ERR_PTR(-EINVAL);

	if (is_of_node(fwnode)) {
		enum of_gpio_flags flags;

		desc = of_get_named_gpiod_flags(to_of_node(fwnode), propname, 0,
						&flags);
		if (!IS_ERR(desc)) {
			active_low = flags & OF_GPIO_ACTIVE_LOW;
			single_ended = flags & OF_GPIO_SINGLE_ENDED;
		}
	} else if (is_acpi_node(fwnode)) {
		struct acpi_gpio_info info;

		desc = acpi_node_get_gpiod(fwnode, propname, 0, &info);
		if (!IS_ERR(desc))
			active_low = info.active_low;
	}

	if (IS_ERR(desc))
		return desc;

	ret = gpiod_request(desc, NULL);
	if (ret)
		return ERR_PTR(ret);

	if (active_low)
		set_bit(FLAG_ACTIVE_LOW, &desc->flags);

	if (single_ended) {
		if (active_low)
			set_bit(FLAG_OPEN_DRAIN, &desc->flags);
		else
			set_bit(FLAG_OPEN_SOURCE, &desc->flags);
	}

	return desc;
}
EXPORT_SYMBOL_GPL(fwnode_get_named_gpiod);

struct gpio_desc *__must_check gpiod_get_index_optional(struct device *dev,
							const char *con_id,
							unsigned int index,
							enum gpiod_flags flags)
{
	struct gpio_desc *desc;

	desc = gpiod_get_index(dev, con_id, index, flags);
	if (IS_ERR(desc)) {
		if (PTR_ERR(desc) == -ENOENT)
			return NULL;
	}

	return desc;
}
EXPORT_SYMBOL_GPL(gpiod_get_index_optional);

int gpiod_hog(struct gpio_desc *desc, const char *name,
	      unsigned long lflags, enum gpiod_flags dflags)
{
	struct gpio_chip *chip;
	struct gpio_desc *local_desc;
	int hwnum;
	int status;

	chip = gpiod_to_chip(desc);
	hwnum = gpio_chip_hwgpio(desc);

	local_desc = gpiochip_request_own_desc(chip, hwnum, name);
	if (IS_ERR(local_desc)) {
		pr_err("requesting hog GPIO %s (chip %s, offset %d) failed\n",
		       name, chip->label, hwnum);
		return PTR_ERR(local_desc);
	}

	status = gpiod_configure_flags(desc, name, lflags, dflags);
	if (status < 0) {
		pr_err("setup of hog GPIO %s (chip %s, offset %d) failed\n",
		       name, chip->label, hwnum);
		gpiochip_free_own_desc(desc);
		return status;
	}

	set_bit(FLAG_IS_HOGGED, &desc->flags);

	pr_info("GPIO line %d (%s) hogged as %s%s\n",
		desc_to_gpio(desc), name,
		(dflags&GPIOD_FLAGS_BIT_DIR_OUT) ? "output" : "input",
		(dflags&GPIOD_FLAGS_BIT_DIR_OUT) ?
		  (dflags&GPIOD_FLAGS_BIT_DIR_VAL) ? "/high" : "/low":"");

	return 0;
}

static void gpiochip_free_hogs(struct gpio_chip *chip)
{
	int id;

	for (id = 0; id < chip->ngpio; id++) {
		if (test_bit(FLAG_IS_HOGGED, &chip->desc[id].flags))
			gpiochip_free_own_desc(&chip->desc[id]);
	}
}

struct gpio_descs *__must_check gpiod_get_array(struct device *dev,
						const char *con_id,
						enum gpiod_flags flags)
{
	struct gpio_desc *desc;
	struct gpio_descs *descs;
	int count;

	count = gpiod_count(dev, con_id);
	if (count < 0)
		return ERR_PTR(count);

	descs = kzalloc(sizeof(*descs) + sizeof(descs->desc[0]) * count,
			GFP_KERNEL);
	if (!descs)
		return ERR_PTR(-ENOMEM);

	for (descs->ndescs = 0; descs->ndescs < count; ) {
		desc = gpiod_get_index(dev, con_id, descs->ndescs, flags);
		if (IS_ERR(desc)) {
			gpiod_put_array(descs);
			return ERR_CAST(desc);
		}
		descs->desc[descs->ndescs] = desc;
		descs->ndescs++;
	}
	return descs;
}
EXPORT_SYMBOL_GPL(gpiod_get_array);

struct gpio_descs *__must_check gpiod_get_array_optional(struct device *dev,
							const char *con_id,
							enum gpiod_flags flags)
{
	struct gpio_descs *descs;

	descs = gpiod_get_array(dev, con_id, flags);
	if (IS_ERR(descs) && (PTR_ERR(descs) == -ENOENT))
		return NULL;

	return descs;
}
EXPORT_SYMBOL_GPL(gpiod_get_array_optional);

void gpiod_put(struct gpio_desc *desc)
{
	gpiod_free(desc);
}
EXPORT_SYMBOL_GPL(gpiod_put);

void gpiod_put_array(struct gpio_descs *descs)
{
	unsigned int i;

	for (i = 0; i < descs->ndescs; i++)
		gpiod_put(descs->desc[i]);

	kfree(descs);
}
EXPORT_SYMBOL_GPL(gpiod_put_array);

#ifdef CONFIG_DEBUG_FS

static void gpiolib_dbg_show(struct seq_file *s, struct gpio_chip *chip)
{
	unsigned		i;
	unsigned		gpio = chip->base;
	struct gpio_desc	*gdesc = &chip->desc[0];
	int			is_out;
	int			is_irq;

	for (i = 0; i < chip->ngpio; i++, gpio++, gdesc++) {
		if (!test_bit(FLAG_REQUESTED, &gdesc->flags)) {
			if (gdesc->name) {
				seq_printf(s, " gpio-%-3d (%-20.20s)\n",
					   gpio, gdesc->name);
			}
			continue;
		}

		gpiod_get_direction(gdesc);
		is_out = test_bit(FLAG_IS_OUT, &gdesc->flags);
		is_irq = test_bit(FLAG_USED_AS_IRQ, &gdesc->flags);
		seq_printf(s, " gpio-%-3d (%-20.20s|%-20.20s) %s %s %s",
			gpio, gdesc->name ? gdesc->name : "", gdesc->label,
			is_out ? "out" : "in ",
			chip->get
				? (chip->get(chip, i) ? "hi" : "lo")
				: "?  ",
			is_irq ? "IRQ" : "   ");
		seq_printf(s, "\n");
	}
}

static void *gpiolib_seq_start(struct seq_file *s, loff_t *pos)
{
	unsigned long flags;
	struct gpio_chip *chip = NULL;
	loff_t index = *pos;

	s->private = "";

	spin_lock_irqsave(&gpio_lock, flags);
	list_for_each_entry(chip, &gpio_chips, list)
		if (index-- == 0) {
			spin_unlock_irqrestore(&gpio_lock, flags);
			return chip;
		}
	spin_unlock_irqrestore(&gpio_lock, flags);

	return NULL;
}

static void *gpiolib_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	unsigned long flags;
	struct gpio_chip *chip = v;
	void *ret = NULL;

	spin_lock_irqsave(&gpio_lock, flags);
	if (list_is_last(&chip->list, &gpio_chips))
		ret = NULL;
	else
		ret = list_entry(chip->list.next, struct gpio_chip, list);
	spin_unlock_irqrestore(&gpio_lock, flags);

	s->private = "\n";
	++*pos;

	return ret;
}

static void gpiolib_seq_stop(struct seq_file *s, void *v)
{
}

static int gpiolib_seq_show(struct seq_file *s, void *v)
{
	struct gpio_chip *chip = v;
	struct device *dev;

	seq_printf(s, "%sGPIOs %d-%d", (char *)s->private,
			chip->base, chip->base + chip->ngpio - 1);
#if defined(MY_DEF_HERE)
	dev = chip->parent;
#else  
	dev = chip->dev;
#endif  
	if (dev)
		seq_printf(s, ", %s/%s", dev->bus ? dev->bus->name : "no-bus",
			dev_name(dev));
	if (chip->label)
		seq_printf(s, ", %s", chip->label);
	if (chip->can_sleep)
		seq_printf(s, ", can sleep");
	seq_printf(s, ":\n");

	if (chip->dbg_show)
		chip->dbg_show(s, chip);
	else
		gpiolib_dbg_show(s, chip);

	return 0;
}

static const struct seq_operations gpiolib_seq_ops = {
	.start = gpiolib_seq_start,
	.next = gpiolib_seq_next,
	.stop = gpiolib_seq_stop,
	.show = gpiolib_seq_show,
};

static int gpiolib_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &gpiolib_seq_ops);
}

static const struct file_operations gpiolib_operations = {
	.owner		= THIS_MODULE,
	.open		= gpiolib_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init gpiolib_debugfs_init(void)
{
	 
	(void) debugfs_create_file("gpio", S_IFREG | S_IRUGO,
				NULL, NULL, &gpiolib_operations);
	return 0;
}
subsys_initcall(gpiolib_debugfs_init);

#endif	 

#ifdef MY_ABC_HERE
int syno_gpio_value_set(int iPin, int iValue)
{
	int iRet = -1;
	struct gpio_desc *desc;
	desc = gpio_to_desc(iPin);  

	if (!desc) {
		goto END;
	}

	if (GPIOF_DIR_OUT != gpiod_get_direction(desc)) {
		printk("pin %d is not writable.\n", iPin);
		goto END;
	}

	gpiod_set_value(desc, iValue);

	iRet = 0;
END:
	return iRet;
}
EXPORT_SYMBOL(syno_gpio_value_set);

int syno_gpio_value_get(int iPin, int *pValue)
{
	int iRet = -1;
	struct gpio_desc *desc;
	desc = gpio_to_desc(iPin);  

	if (!desc) {
		goto END;
	}

	*pValue = gpiod_get_value(desc);

	iRet = 0;
END:
	return iRet;
}
EXPORT_SYMBOL(syno_gpio_value_get);
#endif  
