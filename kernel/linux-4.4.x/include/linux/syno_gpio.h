/* Copyright (c) 2009-2015 Synology Inc. All rights reserved. */
#ifndef SYNO_ARM_GPIO_TYPE_H
#define SYNO_ARM_GPIO_TYPE_H

#include <linux/synobios.h>
#include <linux/gpio.h>

#define GPIO_UNDEF 0xFF
#define SYNO_GPIO_PIN_MAX_NUM 8

#define INPUT 0
#define OUTPUT 1

#define INIT_LOW 0
#define INIT_HIGH 1
#define INIT_KEEP_VALUE 0xFF

#define ACTIVE_HIGH 0
#define ACTIVE_LOW 1
#define ACTIVE_IGNORE 0xFF

/* The following GPIO macro are 1-based */
#define HAVE_GPIO_PIN(index, type)             ((syno_gpio.type) && (0 < index) && (index <= syno_gpio.type->nr_gpio))
#define GPIO_PORT(index, type)                 syno_gpio.type->gpio_port[index-1]
#define GPIO_POLARITY(type)                    syno_gpio.type->gpio_polarity

#define HAVE_FAN_CTRL(index)                   HAVE_GPIO_PIN(index, fan_ctrl)
#define HAVE_FAN_FAIL(index)                   HAVE_GPIO_PIN(index, fan_fail)
#define HAVE_HDD_FAIL_LED(index)               HAVE_GPIO_PIN(index, hdd_fail_led)
#define HAVE_HDD_PRESENT_LED(index)            HAVE_GPIO_PIN(index, hdd_present_led)
#define HAVE_HDD_ACT_LED(index)                HAVE_GPIO_PIN(index, hdd_act_led)
#define HAVE_HDD_DETECT(index)                 HAVE_GPIO_PIN(index, hdd_detect)
#define HAVE_HDD_ENABLE(index)                 HAVE_GPIO_PIN(index, hdd_enable)
#define HAVE_MODEL_ID(index)                   HAVE_GPIO_PIN(index, model_id)
#define HAVE_ALARM_LED()                       HAVE_GPIO_PIN(1, alarm_led)
#define HAVE_POWER_LED()                       HAVE_GPIO_PIN(1, power_led)
#define HAVE_DISK_LED_CTRL()                   HAVE_GPIO_PIN(1, disk_led_ctrl)
#define HAVE_PHY_LED_CTRL()                    HAVE_GPIO_PIN(1, phy_led_ctrl)
#define HAVE_COPY_BUTTON_DETECT()              HAVE_GPIO_PIN(1, copy_button_detect)
#define HAVE_MUTE_BUTTON_DETECT()              HAVE_GPIO_PIN(1, mute_button_detect)
#define HAVE_BUZZER_MUTE_CTRL()                HAVE_GPIO_PIN(1, buzzer_mute_ctrl)

#define FAN_CTRL_PIN(index)                    GPIO_PORT(index, fan_ctrl)
#define FAN_FAIL_PIN(index)                    GPIO_PORT(index, fan_fail)
#define HDD_FAIL_LED_PIN(index)                GPIO_PORT(index, hdd_fail_led)
#define HDD_PRESENT_LED_PIN(index)             GPIO_PORT(index, hdd_present_led)
#define HDD_ACT_LED_PIN(index)                 GPIO_PORT(index, hdd_act_led)
#define HDD_DETECT_PIN(index)                  GPIO_PORT(index, hdd_detect)
#define HDD_ENABLE_PIN(index)                  GPIO_PORT(index, hdd_enable)
#define MODEL_ID_PIN(index)                    GPIO_PORT(index, model_id)
#define ALARM_LED_PIN()                        GPIO_PORT(1, alarm_led)
#define POWER_LED_PIN()                        GPIO_PORT(1, power_led)
#define DISK_LED_CTRL_PIN()                    GPIO_PORT(1, disk_led_ctrl)
#define PHY_LED_CTRL_PIN()                     GPIO_PORT(1, phy_led_ctrl)
#define COPY_BUTTON_DETECT_PIN()               GPIO_PORT(1, copy_button_detect)
#define MUTE_BUTTON_DETECT_PIN()               GPIO_PORT(1, mute_button_detect)
#define BUZZER_MUTE_CTRL_PIN()                 GPIO_PORT(1, buzzer_mute_ctrl)

#define FAN_CTRL_POLARITY()                    GPIO_POLARITY(fan_ctrl)
#define FAN_FAIL_POLARITY()                    GPIO_POLARITY(fan_fail)
#define HDD_FAIL_LED_POLARITY()                GPIO_POLARITY(hdd_fail_led)
#define HDD_PRESENT_LED_POLARITY()             GPIO_POLARITY(hdd_present_led)
#define HDD_ACT_LED_POLARITY()                 GPIO_POLARITY(hdd_act_led)
#define HDD_DETECT_POLARITY()                  GPIO_POLARITY(hdd_detect)
#define HDD_ENABLE_POLARITY()                  GPIO_POLARITY(hdd_enable)
#define MODEL_ID_POLARITY()                    GPIO_POLARITY(model_id)
#define ALARM_LED_POLARITY()                   GPIO_POLARITY(alarm_led)
#define POWER_LED_POLARITY()                   GPIO_POLARITY(power_led)
#define DISK_LED_CTRL_POLARITY()               GPIO_POLARITY(disk_led_ctrl)
#define PHY_LED_CTRL_POLARITY()                GPIO_POLARITY(phy_led_ctrl)
#define COPY_BUTTON_DETECT_POLARITY()          GPIO_POLARITY(copy_button_detect)
#define MUTE_BUTTON_DETECT_POLARITY()          GPIO_POLARITY(mute_button_detect)
#define BUZZER_MUTE_CTRL_POLARITY()            GPIO_POLARITY(buzzer_mute_ctrl)

typedef struct _tag_SYNO_GPIO_INFO {
	const char *name;
	u8 nr_gpio;
	u8 gpio_port[SYNO_GPIO_PIN_MAX_NUM];
	u8 gpio_direction;
	u8 gpio_init_value;
	u8 gpio_polarity;
} SYNO_GPIO_INFO;

typedef struct __tag_SYNO_GPIO {
	SYNO_GPIO_INFO *fan_ctrl;
	SYNO_GPIO_INFO *fan_fail;
	SYNO_GPIO_INFO *hdd_fail_led;
	SYNO_GPIO_INFO *hdd_present_led;
	SYNO_GPIO_INFO *hdd_act_led;
	SYNO_GPIO_INFO *hdd_detect;
	SYNO_GPIO_INFO *hdd_enable;
	SYNO_GPIO_INFO *model_id;
	SYNO_GPIO_INFO *alarm_led;
	SYNO_GPIO_INFO *power_led;
	SYNO_GPIO_INFO *disk_led_ctrl; // control all disk led on/off
	SYNO_GPIO_INFO *phy_led_ctrl;  // control all phy led on/off
	SYNO_GPIO_INFO *copy_button_detect;
	SYNO_GPIO_INFO *mute_button_detect;
	SYNO_GPIO_INFO *buzzer_mute_ctrl;
} SYNO_GPIO;

#endif /* SYNO_ARM_GPIO_TYPE_H */
