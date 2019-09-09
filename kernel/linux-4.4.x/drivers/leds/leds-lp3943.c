#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/err.h>
#include <linux/leds.h>
#include <linux/workqueue.h>
#include <linux/leds-lp3943.h>
#ifdef MY_ABC_HERE
#include <linux/spinlock.h>
#include <linux/synobios.h>
#endif  
#ifdef MY_ABC_HERE
#include <linux/acpi.h>
#endif  

#define MAX_NUM_LEDS		16
#define MAX_BRIGHTNESS		255
#define LED_OFF			0

#define LP3943_INPUT1		0x00
#define LP3943_PSC0		0x02
#define LP3943_PWM0		0x03
#define LP3943_PSC1		0x04
#define LP3943_PWM1		0x05
#define LP3943_LS0		0x06
#define LP3943_LS1		0x07
#define LP3943_LS2		0x08
#define LP3943_LS3		0x09

#define LP3943_SEL0_M		0x03
#define LP3943_SEL1_M		0x0C
#define LP3943_SEL2_M		0x30
#define LP3943_SEL3_M		0xC0
#define LP3943_SEL0_S		0
#define LP3943_SEL1_S		2
#define LP3943_SEL2_S		4
#define LP3943_SEL3_S		6

static const u8 mask_sel[] = {
	LP3943_SEL0_M,
	LP3943_SEL1_M,
	LP3943_SEL2_M,
	LP3943_SEL3_M,
};

static const u8 shift_sel[] = {
	LP3943_SEL0_S,
	LP3943_SEL1_S,
	LP3943_SEL2_S,
	LP3943_SEL3_S,
};

struct lp3943_led {
	int id;
	struct led_classdev cdev;
	struct lp3943_led_node *node;
	struct work_struct brtwork;
	u8 brightness;
};

struct lp3943 {
	struct i2c_client *client;
	struct device *dev;
	struct lp3943_led led[MAX_NUM_LEDS];
	int num_leds;
};

#ifdef MY_DEF_HERE
static struct i2c_client *gpClient = NULL;
#endif  

#ifdef MY_ABC_HERE
static DEFINE_MUTEX(ModeLock);

enum lp3943_led_channel ch0[] = {
	LP3943_LED0,
};

enum lp3943_led_channel ch1[] = {
	LP3943_LED1,
};

enum lp3943_led_channel ch2[] = {
	LP3943_LED2,
};

enum lp3943_led_channel ch3[] = {
	LP3943_LED3,
};

enum lp3943_led_channel ch4[] = {
	LP3943_LED4,
};

enum lp3943_led_channel ch5[] = {
	LP3943_LED5,
};

enum lp3943_led_channel ch6[] = {
	LP3943_LED6,
};

enum lp3943_led_channel ch7[] = {
	LP3943_LED7,
};

enum lp3943_led_channel ch8[] = {
	LP3943_LED8,
};

enum lp3943_led_channel ch9[] = {
	LP3943_LED9,
};

enum lp3943_led_channel ch10[] = {
	LP3943_LED10,
};

enum lp3943_led_channel ch11[] = {
	LP3943_LED11,
};

enum lp3943_led_channel ch12[] = {
	LP3943_LED12,
};

enum lp3943_led_channel ch13[] = {
	LP3943_LED13,
};

enum lp3943_led_channel ch14[] = {
	LP3943_LED14,
};

enum lp3943_led_channel ch15[] = {
	LP3943_LED15,
};

struct lp3943_led_node syno_led_nodes[] = {
	{
		.name = "syno_led0",
		.mode = LP3943_LED_DIM0,
		.prescale = 30,
		.channel = ch0,
		.num_channels = ARRAY_SIZE(ch0),
		.default_trigger = "syno_led0_ledtrig",
	},	{
		.name = "syno_led1",
		.mode = LP3943_LED_DIM0,
		.prescale = 30,
		.channel = ch1,
		.num_channels = ARRAY_SIZE(ch1),
		.default_trigger = "syno_led1_ledtrig",
	},	{
		.name = "syno_led2",
		.mode = LP3943_LED_DIM0,
		.prescale = 30,
		.channel = ch2,
		.num_channels = ARRAY_SIZE(ch2),
		.default_trigger = "syno_led2_ledtrig",
	},	{
		.name = "syno_led3",
		.mode = LP3943_LED_DIM0,
		.prescale = 30,
		.channel = ch3,
		.num_channels = ARRAY_SIZE(ch3),
		.default_trigger = "syno_led3_ledtrig",
	},	{
		.name = "syno_led4",
		.mode = LP3943_LED_DIM0,
		.prescale = 30,
		.channel = ch4,
		.num_channels = ARRAY_SIZE(ch4),
		.default_trigger = "syno_led4_ledtrig",
	},	{
		.name = "syno_led5",
		.mode = LP3943_LED_DIM0,
		.prescale = 30,
		.channel = ch5,
		.num_channels = ARRAY_SIZE(ch5),
		.default_trigger = "syno_led5_ledtrig",
	},	{
		.name = "syno_led6",
		.mode = LP3943_LED_DIM0,
		.prescale = 30,
		.channel = ch6,
		.num_channels = ARRAY_SIZE(ch6),
		.default_trigger = "syno_led6_ledtrig",
	},	{
		.name = "syno_led7",
		.mode = LP3943_LED_DIM0,
		.prescale = 30,
		.channel = ch7,
		.num_channels = ARRAY_SIZE(ch7),
		.default_trigger = "syno_led7_ledtrig",
	},	{
		.name = "syno_led8",
		.mode = LP3943_LED_DIM0,
		.prescale = 30,
		.channel = ch8,
		.num_channels = ARRAY_SIZE(ch8),
		.default_trigger = "syno_led8_ledtrig",
	},	{
		.name = "syno_led9",
		.mode = LP3943_LED_DIM0,
		.prescale = 30,
		.channel = ch9,
		.num_channels = ARRAY_SIZE(ch9),
		.default_trigger = "syno_led9_ledtrig",
	},	{
		.name = "syno_led10",
		.mode = LP3943_LED_DIM0,
		.prescale = 30,
		.channel = ch10,
		.num_channels = ARRAY_SIZE(ch10),
		.default_trigger = "syno_led10_ledtrig",
	},	{
		.name = "syno_led11",
		.mode = LP3943_LED_DIM0,
		.prescale = 30,
		.channel = ch11,
		.num_channels = ARRAY_SIZE(ch11),
		.default_trigger = "syno_led11_ledtrig",
	},	{
		.name = "syno_led12",
		.mode = LP3943_LED_DIM0,
		.prescale = 30,
		.channel = ch12,
		.num_channels = ARRAY_SIZE(ch12),
		.default_trigger = "syno_led12_ledtrig",
	},	{
		.name = "syno_led13",
		.mode = LP3943_LED_DIM0,
		.prescale = 30,
		.channel = ch13,
		.num_channels = ARRAY_SIZE(ch13),
		.default_trigger = "syno_led13_ledtrig",
	},	{
		.name = "syno_led14",
		.mode = LP3943_LED_DIM0,
		.prescale = 30,
		.channel = ch14,
		.num_channels = ARRAY_SIZE(ch14),
		.default_trigger = "syno_led14_ledtrig",
	},	{
		.name = "syno_led15",
		.mode = LP3943_LED_DIM0,
		.prescale = 30,
		.channel = ch15,
		.num_channels = ARRAY_SIZE(ch15),
		.default_trigger = "syno_led15_ledtrig",
	},
};

struct lp3943_platform_data syno_lp3943_pdata = {
	.node = syno_led_nodes,
	.num_nodes = ARRAY_SIZE(syno_led_nodes),
};

struct i2c_board_info __initdata LedI2CBoardInfo[] = {
	{
		I2C_BOARD_INFO("lp3943", 0x60),
		.platform_data = &syno_lp3943_pdata,
	},
};
#endif  

static int lp3943_read_byte(struct lp3943 *lp, u8 reg, u8 *data)
{
	int ret;

	ret = i2c_smbus_read_byte_data(lp->client, reg);
	if (ret < 0) {
		dev_err(lp->dev, "failed to read 0x%.2x\n", reg);
		return ret;
	}

	*data = (u8)ret;
	return 0;
}

static int lp3943_write_byte(struct lp3943 *lp, u8 reg, u8 data)
{
	return i2c_smbus_write_byte_data(lp->client, reg, data);
}

static int lp3943_update_bits(struct lp3943 *lp, u8 reg, u8 mask, u8 data)
{
	int ret;
	u8 tmp;

#ifdef MY_ABC_HERE
 
	mutex_lock(&ModeLock);
#endif  
	ret = lp3943_read_byte(lp, reg, &tmp);
	if (ret)
#ifdef MY_ABC_HERE
		goto END;
#else
		return ret;
#endif  

	tmp &= ~mask;
	tmp |= data & mask;

#ifdef MY_ABC_HERE
	ret = lp3943_write_byte(lp, reg, tmp);

END:
	mutex_unlock(&ModeLock);
	return ret;
#else
	return lp3943_write_byte(lp, reg, tmp);
#endif  
}

static int lp3943_update_selector(struct lp3943 *lp, enum lp3943_led_mode mode,
				enum lp3943_led_channel channel)
{
	u8 addr, mask, shift, idx;

	switch (channel) {
	case LP3943_LED0 ... LP3943_LED3:
		addr = LP3943_LS0;
		break;
	case LP3943_LED4 ... LP3943_LED7:
		addr = LP3943_LS1;
		break;
	case LP3943_LED8 ... LP3943_LED11:
		addr = LP3943_LS2;
		break;
	case LP3943_LED12 ... LP3943_LED15:
		addr = LP3943_LS3;
		break;
	default:
		return -EINVAL;
	}

	idx = channel % 4;
	mask = mask_sel[idx];
	shift = shift_sel[idx];

	return lp3943_update_bits(lp, addr, mask, mode << shift);
}

static int lp3943_update_scale(struct lp3943 *lp, enum lp3943_led_mode mode,
				u8 prescale)
{
	u8 addr;

	switch (mode) {
	case LP3943_LED_DIM0:
		addr = LP3943_PSC0;
		break;
	case LP3943_LED_DIM1:
		addr = LP3943_PSC1;
		break;
	default:
		return 0;
	}

	return lp3943_write_byte(lp, addr, prescale);
}

static int lp3943_update_pwm(struct lp3943 *lp, enum lp3943_led_mode mode,
				u8 pwm)
{
	u8 addr;

	switch (mode) {
	case LP3943_LED_DIM0:
		addr = LP3943_PWM0;
		break;
	case LP3943_LED_DIM1:
		addr = LP3943_PWM1;
		break;
	default:
		return 0;
	}

	return lp3943_write_byte(lp, addr, pwm);
}
#ifdef MY_ABC_HERE
static void lp3943_syno_brightness_set(u8 brightness, enum lp3943_led_mode *mode, enum lp3943_led_mode nodeMode)
{
	if (!mode) {
		goto END;
	}
	switch (brightness) {
		case 0:
			*mode = LP3943_LED_OFF;
			break;
		case 255:
			*mode = LP3943_LED_ON;
			break;
		default:
			*mode = nodeMode;
			break;
	}

END:
	return;
}
#endif  

static int lp3943_update_brightness(struct lp3943_led *led)
{
	struct lp3943 *lp = container_of(led, struct lp3943, led[led->id]);
	struct lp3943_led_node *node = led->node;
	enum lp3943_led_channel *channel;
	enum lp3943_led_mode mode;
	int i, ret;

	for (i = 0 ; i < node->num_channels ; i++) {
		channel = node->channel + i;

#ifdef MY_ABC_HERE
		lp3943_syno_brightness_set(led->brightness, &mode, node->mode);
#else  
		mode = led->brightness == 0 ? LP3943_LED_OFF : node->mode;
#endif  

		ret = lp3943_update_selector(lp, mode, *channel);
		if (ret)
			return ret;
#ifdef MY_ABC_HERE
		if (mode == LP3943_LED_OFF || mode == LP3943_LED_ON)
#else  
		if (mode == LP3943_LED_OFF)
#endif  
			continue;

		ret = lp3943_update_scale(lp, mode, node->prescale);
		if (ret)
			return ret;

		ret = lp3943_update_pwm(lp, mode, led->brightness);
		if (ret)
			return ret;
	}

	return 0;
}

static void lp3943_brightness_force_off(struct lp3943 *lp)
{
	int i;
	u8 addr[] = { LP3943_LS0, LP3943_LS1, LP3943_LS2, LP3943_LS3 };

	for (i = 0 ; i < ARRAY_SIZE(addr) ; i++)
		lp3943_write_byte(lp, addr[i], LED_OFF);
}

static void lp3943_brightness_work(struct work_struct *work)
{
	struct lp3943_led *led;

	led = container_of(work, struct lp3943_led, brtwork);
	lp3943_update_brightness(led);
}

static void lp3943_brightness_set(struct led_classdev *led_cdev,
			     enum led_brightness brightness)
{
	struct lp3943_led *led;

	led = container_of(led_cdev, struct lp3943_led, cdev);
	led->brightness = brightness;
	schedule_work(&led->brtwork);
}

static int lp3943_leds_register(struct lp3943 *lp,
				struct lp3943_platform_data *pdata)
{
	struct lp3943_led_node *node;
	int i, ret;

	for (i = 0 ; i < lp->num_leds ; i++) {
		node = pdata->node + i;

		if (!node || !node->name) {
			dev_err(lp->dev, "invalid data on node%d\n", i);
			ret = -EINVAL;
			goto err_dev;
		}

#ifdef MY_ABC_HERE
		INIT_WORK(&lp->led[i].brtwork, lp3943_brightness_work);
#endif  
		lp->led[i].id = i;
		lp->led[i].node = node;
		lp->led[i].cdev.name = node->name;
		lp->led[i].cdev.max_brightness = MAX_BRIGHTNESS;
		lp->led[i].cdev.brightness_set = lp3943_brightness_set;
#ifdef MY_ABC_HERE
		lp->led[i].cdev.default_trigger = node->default_trigger;
#endif  

		ret = led_classdev_register(lp->dev, &lp->led[i].cdev);
		if (ret) {
			dev_err(lp->dev, "led(%d/%d) register err: %d\n",
					i, lp->num_leds, ret);
			goto err_dev;
		}
#ifndef MY_ABC_HERE
		INIT_WORK(&lp->led[i].brtwork, lp3943_brightness_work);
#endif  
	}

	return 0;

err_dev:
	while (--i >= 0) {
		led_classdev_unregister(&lp->led[i].cdev);
		cancel_work_sync(&lp->led[i].brtwork);
	}
	return ret;
}

static void lp3943_leds_unregister(struct lp3943 *lp)
{
	int i;

	for (i = 0 ; i < lp->num_leds ; i++) {
		led_classdev_unregister(&lp->led[i].cdev);
		cancel_work_sync(&lp->led[i].brtwork);
	}
}

static int lp3943_validate_platform_data(struct device *dev,
				struct lp3943_platform_data *pdata)
{
	if (!pdata || !pdata->node) {
		dev_err(dev, "invalid platform data\n");
		goto err;
	}

	if (pdata->num_nodes == 0 || pdata->num_nodes > MAX_NUM_LEDS) {
		dev_err(dev, "invalid num_nodes: %d\n", pdata->num_nodes);
		goto err;
	}

	return 0;
err:
	return -EINVAL;
}

static int lp3943_chip_detect(struct lp3943 *lp)
{
	u8 val;
	return lp3943_read_byte(lp, LP3943_INPUT1, &val);
}

#ifdef MY_ABC_HERE
static const struct acpi_device_id lp3943_acpi_ids[] = {
	{ "LED3943", (kernel_ulong_t)&syno_lp3943_pdata },
	{ }
};
MODULE_DEVICE_TABLE(acpi, lp3943_acpi_ids);
#endif  

static int lp3943_probe(struct i2c_client *cl,
				const struct i2c_device_id *id)
{
	struct lp3943 *lp;
	struct lp3943_platform_data *pdata = cl->dev.platform_data;
	int ret;
#ifdef MY_ABC_HERE
	const struct acpi_device_id *aid;

	aid = acpi_match_device(lp3943_acpi_ids, &cl->dev);
	if (aid) {
		pdata = (struct lp3943_platform_data *) aid->driver_data;
	} else {
		return -ENODEV;
	}
#endif  

	if (!i2c_check_functionality(cl->adapter, I2C_FUNC_SMBUS_I2C_BLOCK))
		return -EIO;

	ret = lp3943_validate_platform_data(&cl->dev, pdata);
	if (ret)
		return ret;

	lp = devm_kzalloc(&cl->dev, sizeof(struct lp3943), GFP_KERNEL);
	if (!lp)
		return -ENOMEM;

	lp->client = cl;
	lp->dev = &cl->dev;
	lp->num_leds = pdata->num_nodes;
	i2c_set_clientdata(cl, lp);

	ret = lp3943_chip_detect(lp);
	if (ret) {
		dev_err(lp->dev, "chip detection err: %d\n", ret);
		return ret;
	}

	return lp3943_leds_register(lp, pdata);
}

static int lp3943_remove(struct i2c_client *cl)
{
	struct lp3943 *lp = i2c_get_clientdata(cl);

	lp3943_brightness_force_off(lp);
	lp3943_leds_unregister(lp);
	return 0;
}

static const struct i2c_device_id lp3943_id[] = {
	{"lp3943", 0},
	{}
};
MODULE_DEVICE_TABLE(i2c, lp3943_id);

static struct i2c_driver lp3943_driver = {
	.probe = lp3943_probe,
	.remove = lp3943_remove,
	.driver = {
		.name = "lp3943",
		.owner = THIS_MODULE,
#ifdef MY_ABC_HERE
		.acpi_match_table = ACPI_PTR(lp3943_acpi_ids),
#endif  
	},
	.id_table = lp3943_id,
};

static int __init lp3943_init(void)
{
#ifdef MY_DEF_HERE
	int iErr = -1;
	struct i2c_adapter *pAdapter = NULL;
	 
	pAdapter = i2c_get_adapter(0);
	if (pAdapter == NULL) {
		printk(KERN_ERR "led-lp3943 initial error: failed to get i2c adapter\n");
		goto END;
	}

	i2c_put_adapter(pAdapter);

	gpClient = i2c_new_device(pAdapter, &LedI2CBoardInfo[0]);
	if (gpClient == NULL) {
		printk(KERN_ERR "led-lp3943 initial error: failed to initial device\n");
		goto END;
	}
	iErr = i2c_add_driver(&lp3943_driver);

END:
	return iErr;
#else
	return i2c_add_driver(&lp3943_driver);
#endif  
}
module_init(lp3943_init);

static void __exit lp3943_exit(void)
{
#ifdef MY_DEF_HERE
	i2c_unregister_device(gpClient);
#endif  
	i2c_del_driver(&lp3943_driver);
}
module_exit(lp3943_exit);

MODULE_DESCRIPTION("National Semiconductor/TI LP3943 LED Driver");
MODULE_AUTHOR("Milo Kim");
MODULE_LICENSE("GPL");
