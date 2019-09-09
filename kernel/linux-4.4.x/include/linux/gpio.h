#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifndef __LINUX_GPIO_H
#define __LINUX_GPIO_H

#include <linux/errno.h>

#define GPIOF_DIR_OUT	(0 << 0)
#define GPIOF_DIR_IN	(1 << 0)

#define GPIOF_INIT_LOW	(0 << 1)
#define GPIOF_INIT_HIGH	(1 << 1)

#define GPIOF_IN		(GPIOF_DIR_IN)
#define GPIOF_OUT_INIT_LOW	(GPIOF_DIR_OUT | GPIOF_INIT_LOW)
#define GPIOF_OUT_INIT_HIGH	(GPIOF_DIR_OUT | GPIOF_INIT_HIGH)

#define GPIOF_ACTIVE_LOW        (1 << 2)

#define GPIOF_OPEN_DRAIN	(1 << 3)

#define GPIOF_OPEN_SOURCE	(1 << 4)

#define GPIOF_EXPORT		(1 << 5)
#define GPIOF_EXPORT_CHANGEABLE	(1 << 6)
#define GPIOF_EXPORT_DIR_FIXED	(GPIOF_EXPORT)
#define GPIOF_EXPORT_DIR_CHANGEABLE (GPIOF_EXPORT | GPIOF_EXPORT_CHANGEABLE)

struct gpio {
	unsigned	gpio;
	unsigned long	flags;
	const char	*label;
};

#ifdef MY_DEF_HERE
extern u32 syno_pch_lpc_gpio_pin(int pin, int *pValue, int isWrite);
#endif  

#if defined(MY_DEF_HERE)
extern void syno_rtd_set_gpio_input(int pin);
#endif  

#if defined(MY_ABC_HERE)
extern int SYNO_GPIO_READ(int pin);
extern void SYNO_GPIO_WRITE(int pin, int pValue);
#endif  

#ifdef CONFIG_GPIOLIB

#ifdef MY_ABC_HERE
extern int syno_gpio_value_set(int iPin, int iValue);
extern int syno_gpio_value_get(int iPin, int *pValue);
#endif  

#ifdef CONFIG_ARCH_HAVE_CUSTOM_GPIO_H
#include <asm/gpio.h>
#else

#include <asm-generic/gpio.h>

static inline int gpio_get_value(unsigned int gpio)
{
	return __gpio_get_value(gpio);
}

static inline void gpio_set_value(unsigned int gpio, int value)
{
	__gpio_set_value(gpio, value);
}

static inline int gpio_cansleep(unsigned int gpio)
{
	return __gpio_cansleep(gpio);
}

static inline int gpio_to_irq(unsigned int gpio)
{
	return __gpio_to_irq(gpio);
}

static inline int irq_to_gpio(unsigned int irq)
{
	return -EINVAL;
}

#endif  

struct device;

int devm_gpio_request(struct device *dev, unsigned gpio, const char *label);
int devm_gpio_request_one(struct device *dev, unsigned gpio,
			  unsigned long flags, const char *label);
void devm_gpio_free(struct device *dev, unsigned int gpio);

#else  

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/pinctrl/pinctrl.h>

struct device;
struct gpio_chip;

static inline bool gpio_is_valid(int number)
{
	return false;
}

static inline int gpio_request(unsigned gpio, const char *label)
{
	return -ENOSYS;
}

static inline int gpio_request_one(unsigned gpio,
					unsigned long flags, const char *label)
{
	return -ENOSYS;
}

static inline int gpio_request_array(const struct gpio *array, size_t num)
{
	return -ENOSYS;
}

static inline void gpio_free(unsigned gpio)
{
	might_sleep();

	WARN_ON(1);
}

static inline void gpio_free_array(const struct gpio *array, size_t num)
{
	might_sleep();

	WARN_ON(1);
}

static inline int gpio_direction_input(unsigned gpio)
{
	return -ENOSYS;
}

static inline int gpio_direction_output(unsigned gpio, int value)
{
	return -ENOSYS;
}

static inline int gpio_set_debounce(unsigned gpio, unsigned debounce)
{
	return -ENOSYS;
}

static inline int gpio_get_value(unsigned gpio)
{
	 
	WARN_ON(1);
	return 0;
}

static inline void gpio_set_value(unsigned gpio, int value)
{
	 
	WARN_ON(1);
}

static inline int gpio_cansleep(unsigned gpio)
{
	 
	WARN_ON(1);
	return 0;
}

static inline int gpio_get_value_cansleep(unsigned gpio)
{
	 
	WARN_ON(1);
	return 0;
}

static inline void gpio_set_value_cansleep(unsigned gpio, int value)
{
	 
	WARN_ON(1);
}

static inline int gpio_export(unsigned gpio, bool direction_may_change)
{
	 
	WARN_ON(1);
	return -EINVAL;
}

static inline int gpio_export_link(struct device *dev, const char *name,
				unsigned gpio)
{
	 
	WARN_ON(1);
	return -EINVAL;
}

static inline void gpio_unexport(unsigned gpio)
{
	 
	WARN_ON(1);
}

static inline int gpio_to_irq(unsigned gpio)
{
	 
	WARN_ON(1);
	return -EINVAL;
}

static inline int gpiochip_lock_as_irq(struct gpio_chip *chip,
				       unsigned int offset)
{
	WARN_ON(1);
	return -EINVAL;
}

static inline void gpiochip_unlock_as_irq(struct gpio_chip *chip,
					  unsigned int offset)
{
	WARN_ON(1);
}

static inline int irq_to_gpio(unsigned irq)
{
	 
	WARN_ON(1);
	return -EINVAL;
}

static inline int
gpiochip_add_pin_range(struct gpio_chip *chip, const char *pinctl_name,
		       unsigned int gpio_offset, unsigned int pin_offset,
		       unsigned int npins)
{
	WARN_ON(1);
	return -EINVAL;
}

static inline int
gpiochip_add_pingroup_range(struct gpio_chip *chip,
			struct pinctrl_dev *pctldev,
			unsigned int gpio_offset, const char *pin_group)
{
	WARN_ON(1);
	return -EINVAL;
}

static inline void
gpiochip_remove_pin_ranges(struct gpio_chip *chip)
{
	WARN_ON(1);
}

static inline int devm_gpio_request(struct device *dev, unsigned gpio,
				    const char *label)
{
	WARN_ON(1);
	return -EINVAL;
}

static inline int devm_gpio_request_one(struct device *dev, unsigned gpio,
					unsigned long flags, const char *label)
{
	WARN_ON(1);
	return -EINVAL;
}

static inline void devm_gpio_free(struct device *dev, unsigned int gpio)
{
	WARN_ON(1);
}

#endif  

#endif  
