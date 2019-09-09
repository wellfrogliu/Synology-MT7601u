#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/gpio.h>
#include <linux/slab.h>
#include <linux/synobios.h>
#include <linux/syno_gpio.h>

SYNO_GPIO syno_gpio = {
	.fan_ctrl =NULL,
	.fan_fail =NULL,
	.hdd_fail_led =NULL,
	.hdd_present_led =NULL,
	.hdd_act_led =NULL,
	.hdd_detect =NULL,
	.hdd_enable =NULL,
	.model_id =NULL,
	.alarm_led =NULL,
	.power_led =NULL,
	.disk_led_ctrl =NULL,
	.phy_led_ctrl =NULL,
	.copy_button_detect =NULL,
};
EXPORT_SYMBOL(syno_gpio);

#if defined(MY_DEF_HERE)
void syno_rtd_gpio_write(int pin, int pValue)
{
	int iErr = 0;
	iErr = gpio_request(pin, NULL);
	if (iErr) {
		printk("%s:%s(%d) gpio_request pin %d fail!\n", __FILE__, __FUNCTION__, __LINE__, pin);
		goto END;
	}
	iErr = gpio_direction_output(pin, pValue);
	if (iErr) {
		printk("%s:%s(%d) set gpio pin %d value %d fail!\n", __FILE__, __FUNCTION__, __LINE__, pin, pValue);
		goto UNLOCK;
	}
UNLOCK:
	gpio_free(pin);
END:
	return;
}
EXPORT_SYMBOL(syno_rtd_gpio_write);

void syno_rtd_set_gpio_input(int pin)
{
	int iErr = 0;
	iErr = gpio_request(pin, NULL);
	if (iErr) {
		printk("%s:%s(%d) gpio_request pin %d fail!\n", __FILE__, __FUNCTION__, __LINE__, pin);
		goto END;
	}
	iErr = gpio_direction_input(pin);
	if (iErr) {
		printk("%s:%s(%d) set gpio pin %d input fail!\n", __FILE__, __FUNCTION__, __LINE__, pin);
		goto UNLOCK;
	}
UNLOCK:
	gpio_free(pin);
END:
	return;
}
EXPORT_SYMBOL(syno_rtd_set_gpio_input);
#endif  

int SYNO_GPIO_READ(int pin)
{
#if defined(MY_ABC_HERE)
	int iVal=0;
	syno_gpio_value_get(pin, &iVal);
	return iVal;
#else
	return gpio_get_value(pin);
#endif
}
EXPORT_SYMBOL(SYNO_GPIO_READ);

void SYNO_GPIO_WRITE(int pin, int pValue)
{
#if defined(MY_ABC_HERE)
	syno_gpio_value_set(pin, pValue);
#elif defined(MY_DEF_HERE)
	syno_rtd_gpio_write(pin, pValue);
#else
	gpio_set_value(pin, pValue);
#endif
}
EXPORT_SYMBOL(SYNO_GPIO_WRITE);
