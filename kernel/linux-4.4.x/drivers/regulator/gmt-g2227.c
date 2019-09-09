#include <linux/module.h>
#include <linux/i2c.h>
#include <linux/regulator/driver.h>
#include <linux/regulator/of_regulator.h>
#include <linux/of.h>
#include <linux/of_address.h>

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/unistd.h>
#include <asm/uaccess.h>
#include <linux/io.h>
#include <linux/suspend.h>

#ifdef CONFIG_SUSPEND
extern int rtk_get_coolboot_mode(void);
#endif

enum g2227_regulator_id {
	G2227_ID_DCDC1 = 0,
	G2227_ID_DCDC2,
	G2227_ID_DCDC3,
	G2227_ID_DCDC4,
	G2227_ID_DCDC5,
	G2227_ID_DCDC6,
	G2227_ID_LDO2,
	G2227_ID_LDO3,
};

static const unsigned int g2227_dcdc1_vtbl[] = {
	3000000, 3100000, 3200000, 3300000,
};

static const unsigned int g2227_dcdc2_vtbl[] = {
	800000, 812500, 825000, 837500, 850000, 862500, 875000, 887500,
	900000, 912500, 925000, 937500, 950000, 962500, 975000, 987500,
	1000000, 1012500, 1025000, 1037500, 1050000, 1062500, 1075000, 1087500,
	1100000, 1112500, 1125000, 1137500, 1150000, 1162500, 1175000, 1187500,
};

static const unsigned int g2227_ldo_vtbl[] = {
	800000, 850000, 900000, 950000, 1000000, 1100000, 1200000, 1300000,
	1500000, 1600000, 1800000, 1900000, 2500000, 2600000, 3000000, 3100000,
};

static struct of_regulator_match g2227_matches[] = {
	{ .name = "dcdc1", .driver_data = NULL, },
	{ .name = "dcdc2", .driver_data = NULL, },
	{ .name = "dcdc3", .driver_data = NULL, },
	{ .name = "dcdc5", .driver_data = NULL, },
	{ .name = "dcdc6", .driver_data = NULL, },
	{ .name = "ldo2" , .driver_data = NULL, },
	{ .name = "ldo3" , .driver_data = NULL, },
};

struct rtk_pmic_dev {
	struct i2c_client *client;
	struct device *dev;
	unsigned int num_regulators;
	struct regmap *regmap;
	int chip_version;
};

#ifdef CONFIG_REGMAP_EN
#include <linux/regmap.h>

#define MAX_REGISTERS			0x30
static const struct regmap_config g2227_regmap_config = {
	.reg_bits = 8,
	.val_bits = 8,
	.max_register = MAX_REGISTERS,
};
#else
static DEFINE_MUTEX(rw_lock);

static int gmt_g2227_read(struct rtk_pmic_dev *pmic_dev, unsigned char reg, unsigned char *value)
{
	struct i2c_client *client = pmic_dev->client;
	unsigned char data = reg;
	struct i2c_msg msg;
	int ret;

    mutex_lock(&rw_lock);

	// Send out the register address...
	msg.addr = client->addr;
	msg.flags = 0;
	msg.len = 1;
	msg.buf = &data;
	ret = i2c_transfer(client->adapter, &msg, 1);
	if (ret < 0) {
		printk(KERN_ERR "Error %d on register write\n", ret);
		goto unlock;
	}
	// ...then read back the result
	msg.flags = I2C_M_RD;
	ret = i2c_transfer(client->adapter, &msg, 1);
	if (ret >= 0) {
		*value = data;
		ret = 0;
	}

unlock:
    mutex_unlock(&rw_lock);

	return ret;
}

static int gmt_g2227_write(struct rtk_pmic_dev *pmic_dev, unsigned char reg, unsigned char value)
{
	struct i2c_client *client = pmic_dev->client;
	unsigned char data[2] = { reg, value };
	struct i2c_msg msg;
	int ret;

    mutex_lock(&rw_lock);

	msg.addr = client->addr;
	msg.flags = 0;
	msg.len = 2;
	msg.buf = data;
	ret = i2c_transfer(client->adapter, &msg, 1);
	if (ret < 0) {
		printk(KERN_ERR "Error %d on register write\n", ret);
        mutex_unlock(&rw_lock);
		return ret;
	}
    mutex_unlock(&rw_lock);

	return 0;
}

static int gmt_g2227_list_voltage(struct regulator_dev *rdev, unsigned int sel)
{
//	struct rtk_pmic_dev *pmic_dev = rdev_get_drvdata(rdev);

	if (!rdev->desc->volt_table) {
		BUG_ON(!rdev->desc->volt_table);
		return -EINVAL;
	}

	if (sel >= rdev->desc->n_voltages)
		return -EINVAL;

	return rdev->desc->volt_table[sel];
}

static int gmt_g2227_get_voltage_sel(struct regulator_dev *rdev)
{
	struct rtk_pmic_dev *pmic_dev = rdev_get_drvdata(rdev);
	unsigned char val;
	int ret;

	ret = gmt_g2227_read(pmic_dev, rdev->desc->vsel_reg, &val);
	if (ret != 0)
		return ret;

	val &= rdev->desc->vsel_mask;
	val >>= ffs(rdev->desc->vsel_mask) - 1;

	return val;
}

static int gmt_g2227_set_voltage_sel(struct regulator_dev *rdev, unsigned sel)
{
	struct rtk_pmic_dev *pmic_dev = rdev_get_drvdata(rdev);
	int ret, cnt = 0;
	unsigned char val, temp;
    int retry;
    int val_mask = 0xff;

	ret = gmt_g2227_read(pmic_dev, rdev->desc->vsel_reg, &val);
	if (ret!=0) {
		printk(KERN_ERR "[PMIC] read i2c fail\n");
		return ret;
	}

    switch (rdev->desc->id)
    {
    case G2227_ID_LDO2:
    case G2227_ID_LDO3:
        while (cnt < 10) {
            if ((val & 0xf0) == 0xa0)
                break;

            pr_err("[PMIC] %s: read error = 0x%x\n", rdev->desc->name, val);
            gmt_g2227_read(pmic_dev, rdev->desc->vsel_reg, &val);
            cnt ++;
        }

        if ((val & 0xf0) != 0xa0) {
            val = (val & 0x0f) | 0xa0;
            pr_err("[PMIC] %s: read error do reset ldo2 voltage\n", rdev->desc->name);
        }
    case G2227_ID_DCDC1:
    case G2227_ID_DCDC6:
        val &= ~rdev->desc->vsel_mask;
        sel <<= ffs(rdev->desc->vsel_mask) - 1;
        val |= sel;
        val_mask = 0xff;
        break;

    case G2227_ID_DCDC2:
    case G2227_ID_DCDC3:
    case G2227_ID_DCDC5:
        val = sel;
        val_mask = rdev->desc->vsel_mask;
        break;
    }

	ret = gmt_g2227_write(pmic_dev, rdev->desc->vsel_reg, val);

    for (retry = 0; retry < 10; retry ++) {
	gmt_g2227_read(pmic_dev, rdev->desc->vsel_reg, &temp);
        if ((temp & val_mask) == (val & val_mask))
            break;
    }
    if ((temp & val_mask) != (val & val_mask))
		pr_err("[PMIC] %s: write error reg = 0x%x, wval = 0x%x, rval = 0x%x, retry = %d\n",
            rdev->desc->name, rdev->desc->vsel_reg, val, temp, retry);
	else if (retry != 0)
		pr_info("[PMIC] %s: write ok reg = 0x%x, val = 0x%x, retry = %d\n",
            rdev->desc->name, rdev->desc->vsel_reg, val, retry);

	return ret;
}

int gmt_g2227_enable(struct regulator_dev *rdev)
{
	struct rtk_pmic_dev *pmic_dev = rdev_get_drvdata(rdev);
	unsigned char val, temp;
	int ret;

	ret = gmt_g2227_read(pmic_dev, rdev->desc->enable_reg, &val);
	if (ret!=0)
		return ret;

	temp = val & rdev->desc->enable_mask;
	if(temp)
		return 0;

	val |= rdev->desc->enable_mask;

	return gmt_g2227_write(pmic_dev, rdev->desc->enable_reg, val);
}

int gmt_g2227_disable(struct regulator_dev *rdev)
{
	struct rtk_pmic_dev *pmic_dev = rdev_get_drvdata(rdev);
	unsigned char val, temp;
	int ret;

	ret = gmt_g2227_read(pmic_dev, rdev->desc->enable_reg, &val);
	if (ret!=0)
		return ret;

	temp = val & rdev->desc->enable_mask;
	if(!temp)
		return 0;

	val &= ~rdev->desc->enable_mask;

	return gmt_g2227_write(pmic_dev, rdev->desc->enable_reg, val);
}
#endif

static struct regulator_ops g2227_regulator_ops = {
#ifdef CONFIG_REGMAP_EN
	.list_voltage = regulator_list_voltage_table,
	.set_voltage_sel = regulator_set_voltage_sel_regmap,
	.get_voltage_sel = regulator_get_voltage_sel_regmap,
	.enable = regulator_enable_regmap,
	.disable = regulator_disable_regmap,
#else
	.list_voltage = gmt_g2227_list_voltage,
	.set_voltage_sel = gmt_g2227_set_voltage_sel,
	.get_voltage_sel = gmt_g2227_get_voltage_sel,
//	.enable = gmt_g2227_enable,
//	.disable = gmt_g2227_disable,
#endif
//	.is_enabled = regulator_is_enabled_regmap,
};
struct regulator_slpmode_desc {
	unsigned char name[10];
	int vsel;
	unsigned int vsel_reg;
	unsigned int vsel_mask;
	unsigned int enable_reg;
	unsigned int enable_mask;
};

static struct regulator_slpmode_desc g2227_slpmod_desc[] = {
	{
		.name = "dcdc1",
		.vsel = -1,
		.vsel_reg = 0x18,
		.vsel_mask = 0xC0,
		.enable_reg = 0x7,
		.enable_mask = 0x3 << 4,
	},
	{
		.name = "dcdc2",
		.vsel = -1,
		.vsel_reg = 0x15,
		.vsel_mask = 0x1F,
		.enable_reg = 0x7,
		.enable_mask = 0x3,
	},
	{
		.name = "dcdc3",
		.vsel = -1,
		.vsel_reg = 0x16,
		.vsel_mask = 0x1F,
		.enable_reg = 0x8,
		.enable_mask = 0x3 << 4,
	},
	{
		.name = "dcdc5",
		.vsel = -1,
		.vsel_reg = 0x17,
		.vsel_mask = 0x1F,
		.enable_reg = 0x9,
		.enable_mask = 0x3 << 4,
	},
	{
		.name = "dcdc6",
		.vsel = -1,
		.vsel_reg = 0x18,
		.vsel_mask = 0x1F,
		.enable_reg = 0x9,
		.enable_mask = 0x3,
	},
	{
		.name = "ldo2",
		.vsel = -1,
		.vsel_reg = 0x19,
		.vsel_mask = 0xF0,
		.enable_reg = 0xA,
		.enable_mask = 0x3 << 4,
	},
	{
		.name = "ldo3",
		.vsel = -1,
		.vsel_reg = 0x19,
		.vsel_mask = 0xF,
		.enable_reg = 0xA,
		.enable_mask = 0x3,
	},
};

static struct regulator_desc g2227_regulator_desc[] = {
	{
		.name = "dcdc1",
		.id = G2227_ID_DCDC1,
		.ops = &g2227_regulator_ops,
		.n_voltages = ARRAY_SIZE(g2227_dcdc1_vtbl),
		.volt_table = g2227_dcdc1_vtbl,
		.type = REGULATOR_VOLTAGE,
		.owner = THIS_MODULE,
		.vsel_reg = 0x13,
		.vsel_mask = 0xC0,
		.enable_reg = 0x5,
		.enable_mask = 1 << 7,
	},
	{
		.name = "dcdc2",
		.id = G2227_ID_DCDC2,
		.ops = &g2227_regulator_ops,
		.n_voltages = ARRAY_SIZE(g2227_dcdc2_vtbl),
		.volt_table = g2227_dcdc2_vtbl,
		.type = REGULATOR_VOLTAGE,
		.owner = THIS_MODULE,
		.vsel_reg = 0x10,
		.vsel_mask = 0x1F,
		.enable_reg = 0x5,
		.enable_mask = 1 << 6,
	},
	{
		.name = "dcdc3",
		.id = G2227_ID_DCDC3,
		.ops = &g2227_regulator_ops,
		.n_voltages = ARRAY_SIZE(g2227_dcdc2_vtbl),
		.volt_table = g2227_dcdc2_vtbl,
		.type = REGULATOR_VOLTAGE,
		.owner = THIS_MODULE,
		.vsel_reg = 0x11,
		.vsel_mask = 0x1F,
		.enable_reg = 0x5,
		.enable_mask = 1 << 5,
	},
	{
		.name = "dcdc5",
		.id = G2227_ID_DCDC5,
		.ops = &g2227_regulator_ops,
		.n_voltages = ARRAY_SIZE(g2227_dcdc2_vtbl),
		.volt_table = g2227_dcdc2_vtbl,
		.type = REGULATOR_VOLTAGE,
		.owner = THIS_MODULE,
		.vsel_reg = 0x12,
		.vsel_mask = 0x1F,
		.enable_reg = 0x5,
		.enable_mask = 1 << 3,
	},
	{
		.name = "dcdc6",
		.id = G2227_ID_DCDC6,
		.ops = &g2227_regulator_ops,
		.n_voltages = ARRAY_SIZE(g2227_dcdc2_vtbl),
		.volt_table = g2227_dcdc2_vtbl,
		.type = REGULATOR_VOLTAGE,
		.owner = THIS_MODULE,
		.vsel_reg = 0x13,
		.vsel_mask = 0x1F,
		.enable_reg = 0x5,
		.enable_mask = 1 << 1,
	},
	{
		.name = "ldo2",
		.id = G2227_ID_LDO2,
		.ops = &g2227_regulator_ops,
		.n_voltages = ARRAY_SIZE(g2227_ldo_vtbl),
		.volt_table = g2227_ldo_vtbl,
		.type = REGULATOR_VOLTAGE,
		.owner = THIS_MODULE,
		.vsel_reg = 0x14,
		.vsel_mask = 0xF0,
		.enable_reg = 0x5,
		.enable_mask = 1 << 1,
	},
	{
		.name = "ldo3",
		.id = G2227_ID_LDO3,
		.ops = &g2227_regulator_ops,
		.n_voltages = ARRAY_SIZE(g2227_ldo_vtbl),
		.volt_table = g2227_ldo_vtbl,
		.type = REGULATOR_VOLTAGE,
		.owner = THIS_MODULE,
		.vsel_reg = 0x14,
		.vsel_mask = 0x0F,
		.enable_reg = 0x5,
		.enable_mask = 1 << 0,
	},
};

static int gmt_g2227_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	struct rtk_pmic_dev *pmic_dev;
	struct regulator_desc *desc;
	struct regulator_config cfg = { };
	struct regulator_dev *rdev;
	struct device *dev = &client->dev;

	struct of_regulator_match *match;
	int num_matches;
	struct device_node *search;

	const __be32 *sleepvolt, *maxvolt;
	int i, ret;
	void __iomem *reg_base=NULL;
	unsigned char val;

	pmic_dev = devm_kzalloc(dev, sizeof(struct rtk_pmic_dev), GFP_KERNEL);
	if (!pmic_dev)
		return -ENOMEM;

	pmic_dev->client = client;
	pmic_dev->dev = dev;
//	pmic_dev->pdata = dev_get_platdata(&client->dev);
#ifdef CONFIG_REGMAP_EN
	pmic_dev->regmap = devm_regmap_init_i2c(client, &g2227_regmap_config);
#endif
	if (IS_ERR(pmic_dev->regmap)) {
		ret = PTR_ERR(pmic_dev->regmap);
		dev_err(dev, "regmap init i2c err: %d\n", ret);
		return ret;
	}

	reg_base = ioremap(0x9801a204, 0x10);
	if(reg_base!=NULL) {
		pmic_dev->chip_version = readl(reg_base);
		iounmap(reg_base);
	}

	match = g2227_matches;
	num_matches = ARRAY_SIZE(g2227_matches);
	of_regulator_match(dev, dev->of_node, match, num_matches);

	pmic_dev->num_regulators = num_matches;

	for (i = 0; i < pmic_dev->num_regulators; i++) {
		desc = &g2227_regulator_desc[i];

		cfg.dev = pmic_dev->dev;
		cfg.init_data = match[i].init_data;
		cfg.driver_data = pmic_dev;
#ifdef CONFIG_REGMAP_EN
		cfg.regmap = pmic_dev->regmap;
#endif
		rdev = devm_regulator_register(pmic_dev->dev, desc, &cfg);
		if (IS_ERR(rdev)) {
			dev_err(pmic_dev->dev, "regulator register err");
			return PTR_ERR(rdev);
		}
		search = of_get_child_by_name(dev->of_node, desc->name);
		sleepvolt = of_get_property(search, "sleep-volt", NULL);
		if(sleepvolt!=NULL) {
			maxvolt = of_get_property(search, "regulator-max-microvolt", NULL);
			if(pmic_dev->chip_version==0 && strcmp(desc->name, "dcdc6")==0)
				continue;
			else if(strcmp(desc->name, g2227_slpmod_desc[i].name)==0) {
				if(be32_to_cpu(*sleepvolt) <= be32_to_cpu(*maxvolt))
					g2227_slpmod_desc[i].vsel = be32_to_cpu(*sleepvolt);
				else
					printk(KERN_ERR "[PMIC] %s sleep voltage over max-volt\n", g2227_slpmod_desc[i].name);
			}
			else
				printk(KERN_ERR "[PMIC] table not match\n");
		}
	}

	i2c_set_clientdata(client, pmic_dev);

	ret = gmt_g2227_read(pmic_dev, 0x2, &val);
	if (ret!=0)
		printk(KERN_ERR "[PMIC] read i2c fail, ignore\n");
	else {
		val = (val & ~0x83) | 0x2;
		gmt_g2227_write(pmic_dev, 0x2, val);
	}

	return 0;
}

#ifdef CONFIG_PM
static int gmt_g2227_suspend(struct device *dev)
{
	struct rtk_pmic_dev *pmic_dev = dev_get_drvdata(dev);

	unsigned char val, temp;
	int cnt , i, j, ret, mode=0;
	int vsel = -1;

	printk("[PMIC] Enter %s\n", __FUNCTION__);

	mode = rtk_get_coolboot_mode();
	if(RTK_PM_STATE != PM_SUSPEND_STANDBY) {
		cnt = sizeof(g2227_slpmod_desc)/sizeof(struct regulator_slpmode_desc);
		for(i=0; i<cnt; i++) {
			if(g2227_slpmod_desc[i].vsel==0) {
				ret = gmt_g2227_read(pmic_dev, g2227_slpmod_desc[i].enable_reg, &val);
				if (ret!=0) {
					printk(KERN_ERR "[PMIC] read i2c fail, ignore\n");
					continue;
				}
				temp = val & g2227_slpmod_desc[i].enable_mask;
				if(temp == g2227_slpmod_desc[i].enable_mask)
					continue;
				val |= g2227_slpmod_desc[i].enable_mask;
				gmt_g2227_write(pmic_dev, g2227_slpmod_desc[i].enable_reg, val);
			} else if(g2227_slpmod_desc[i].vsel>0) {
				vsel = -1;
				for(j=0; j<g2227_regulator_desc[i].n_voltages; j++) {
					if(g2227_slpmod_desc[i].vsel == g2227_regulator_desc[i].volt_table[j]) {
						vsel = j;
						break;
					}
				}
				if(vsel>=0) {
					ret = gmt_g2227_read(pmic_dev, g2227_slpmod_desc[i].vsel_reg, &val);
					if(ret!=0) {
						printk(KERN_ERR "[PMIC] read i2c fail, ignore\n");
						continue;
					}
					val &= ~g2227_slpmod_desc[i].vsel_mask;
					vsel <<= ffs(g2227_slpmod_desc[i].vsel_mask) - 1;
					val |= vsel;
					gmt_g2227_write(pmic_dev, g2227_slpmod_desc[i].vsel_reg, val);
				} else
					printk(KERN_ERR "[PMIC] %s can't not find support voltage\n", g2227_slpmod_desc[i].name);
			}
		}
		if(mode) {
			ret = gmt_g2227_read(pmic_dev, 0x8, &val);
			if (ret!=0)
				printk(KERN_ERR "[PMIC] read i2c fail, ignore\n");
			else {
				val |= 0x3;
				gmt_g2227_write(pmic_dev, 0x8, val);
			}
		}
	}

	printk("[PMIC] Exit %s\n", __FUNCTION__);
	return 0;
}

static int gmt_g2227_resume(struct device *dev)
{
	printk("[PMIC] Enter %s\n", __FUNCTION__);

	printk("[PMIC] Exit %s\n", __FUNCTION__);
	return 0;
}
#else

#define gmt_g2227_suspend NULL
#define gmt_g2227_resume NULL

#endif

static const struct dev_pm_ops gmt_g2227_pm_ops = {
	.suspend    = gmt_g2227_suspend,
	.resume     = gmt_g2227_resume,
};

static const struct i2c_device_id gmt_g2227_ids[] = {
	{"gmt-g2227", 0},
	{ },
};
MODULE_DEVICE_TABLE(i2c, gmt_g2227_ids);

static struct i2c_driver gmt_g2227_driver = {
	.driver = {
		.name = "gmt-g2227",
		.owner = THIS_MODULE,
		.pm = &gmt_g2227_pm_ops,
	},
	.probe = gmt_g2227_probe,
	.id_table = gmt_g2227_ids,
};

module_i2c_driver(gmt_g2227_driver);

MODULE_DESCRIPTION("RTD1295 Giraffe PMU Regulator Driver");
MODULE_AUTHOR("Simon Hsu");
MODULE_LICENSE("GPL");
