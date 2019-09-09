#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/phy.h>
#include <linux/mdio.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/of.h>

#include <asm/irq.h>

MODULE_DESCRIPTION("PHY library");
MODULE_AUTHOR("Andy Fleming");
MODULE_LICENSE("GPL");

void phy_device_free(struct phy_device *phydev)
{
#if defined(MY_DEF_HERE)
	put_device(&phydev->mdio.dev);
#else  
	put_device(&phydev->dev);
#endif  
}
EXPORT_SYMBOL(phy_device_free);

static void phy_device_release(struct device *dev)
{
	kfree(to_phy_device(dev));
}

enum genphy_driver {
	GENPHY_DRV_1G,
	GENPHY_DRV_10G,
	GENPHY_DRV_MAX
};

static struct phy_driver genphy_driver[GENPHY_DRV_MAX];

static LIST_HEAD(phy_fixup_list);
static DEFINE_MUTEX(phy_fixup_lock);

int phy_register_fixup(const char *bus_id, u32 phy_uid, u32 phy_uid_mask,
		       int (*run)(struct phy_device *))
{
	struct phy_fixup *fixup = kzalloc(sizeof(*fixup), GFP_KERNEL);

	if (!fixup)
		return -ENOMEM;

	strlcpy(fixup->bus_id, bus_id, sizeof(fixup->bus_id));
	fixup->phy_uid = phy_uid;
	fixup->phy_uid_mask = phy_uid_mask;
	fixup->run = run;

	mutex_lock(&phy_fixup_lock);
	list_add_tail(&fixup->list, &phy_fixup_list);
	mutex_unlock(&phy_fixup_lock);

	return 0;
}
EXPORT_SYMBOL(phy_register_fixup);

int phy_register_fixup_for_uid(u32 phy_uid, u32 phy_uid_mask,
			       int (*run)(struct phy_device *))
{
	return phy_register_fixup(PHY_ANY_ID, phy_uid, phy_uid_mask, run);
}
EXPORT_SYMBOL(phy_register_fixup_for_uid);

int phy_register_fixup_for_id(const char *bus_id,
			      int (*run)(struct phy_device *))
{
	return phy_register_fixup(bus_id, PHY_ANY_UID, 0xffffffff, run);
}
EXPORT_SYMBOL(phy_register_fixup_for_id);

static int phy_needs_fixup(struct phy_device *phydev, struct phy_fixup *fixup)
{
#if defined(MY_DEF_HERE)
	if (strcmp(fixup->bus_id, phydev_name(phydev)) != 0)
#else  
	if (strcmp(fixup->bus_id, dev_name(&phydev->dev)) != 0)
#endif  
		if (strcmp(fixup->bus_id, PHY_ANY_ID) != 0)
			return 0;

	if ((fixup->phy_uid & fixup->phy_uid_mask) !=
	    (phydev->phy_id & fixup->phy_uid_mask))
		if (fixup->phy_uid != PHY_ANY_UID)
			return 0;

	return 1;
}

static int phy_scan_fixups(struct phy_device *phydev)
{
	struct phy_fixup *fixup;

	mutex_lock(&phy_fixup_lock);
	list_for_each_entry(fixup, &phy_fixup_list, list) {
		if (phy_needs_fixup(phydev, fixup)) {
			int err = fixup->run(phydev);

			if (err < 0) {
				mutex_unlock(&phy_fixup_lock);
				return err;
			}
			phydev->has_fixups = true;
		}
	}
	mutex_unlock(&phy_fixup_lock);

	return 0;
}

#if defined(MY_DEF_HERE)
static int phy_bus_match(struct device *dev, struct device_driver *drv)
{
	struct phy_device *phydev = to_phy_device(dev);
	struct phy_driver *phydrv = to_phy_driver(drv);
	const int num_ids = ARRAY_SIZE(phydev->c45_ids.device_ids);
	int i;

	if (!(phydrv->mdiodrv.flags & MDIO_DEVICE_IS_PHY))
		return 0;

	if (phydrv->match_phy_device)
		return phydrv->match_phy_device(phydev);

	if (phydev->is_c45) {
		for (i = 1; i < num_ids; i++) {
			if (!(phydev->c45_ids.devices_in_package & (1 << i)))
				continue;

			if ((phydrv->phy_id & phydrv->phy_id_mask) ==
			    (phydev->c45_ids.device_ids[i] &
			     phydrv->phy_id_mask))
				return 1;
		}
		return 0;
	} else {
		return (phydrv->phy_id & phydrv->phy_id_mask) ==
			(phydev->phy_id & phydrv->phy_id_mask);
	}
}
#endif  

struct phy_device *phy_device_create(struct mii_bus *bus, int addr, int phy_id,
				     bool is_c45,
				     struct phy_c45_device_ids *c45_ids)
{
	struct phy_device *dev;
#if defined(MY_DEF_HERE)
	struct mdio_device *mdiodev;
#endif  

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return ERR_PTR(-ENOMEM);

#if defined(MY_DEF_HERE)
	mdiodev = &dev->mdio;
	mdiodev->dev.release = phy_device_release;
	mdiodev->dev.parent = &bus->dev;
	mdiodev->dev.bus = &mdio_bus_type;
	mdiodev->bus = bus;
	mdiodev->bus_match = phy_bus_match;
	mdiodev->addr = addr;
	mdiodev->flags = MDIO_DEVICE_FLAG_PHY;
#else  
	dev->dev.release = phy_device_release;
#endif  

	dev->speed = 0;
	dev->duplex = -1;
	dev->pause = 0;
	dev->asym_pause = 0;
	dev->link = 1;
	dev->interface = PHY_INTERFACE_MODE_GMII;

	dev->autoneg = AUTONEG_ENABLE;

	dev->is_c45 = is_c45;
#if defined(MY_DEF_HERE)
 
#else  
	dev->addr = addr;
#endif  
	dev->phy_id = phy_id;
	if (c45_ids)
		dev->c45_ids = *c45_ids;
#if defined(MY_DEF_HERE)
 
#else  
	dev->bus = bus;
	dev->dev.parent = &bus->dev;
	dev->dev.bus = &mdio_bus_type;
#endif  
	dev->irq = bus->irq ? bus->irq[addr] : PHY_POLL;
#if defined(MY_DEF_HERE)
	dev_set_name(&mdiodev->dev, PHY_ID_FMT, bus->id, addr);
#else  
	dev_set_name(&dev->dev, PHY_ID_FMT, bus->id, addr);
#endif  

	dev->state = PHY_DOWN;

	mutex_init(&dev->lock);
	INIT_DELAYED_WORK(&dev->state_queue, phy_state_machine);
	INIT_WORK(&dev->phy_queue, phy_change);

	request_module(MDIO_MODULE_PREFIX MDIO_ID_FMT, MDIO_ID_ARGS(phy_id));

#if defined(MY_DEF_HERE)
	device_initialize(&mdiodev->dev);
#else  
	device_initialize(&dev->dev);
#endif  

	return dev;
}
EXPORT_SYMBOL(phy_device_create);

static int get_phy_c45_devs_in_pkg(struct mii_bus *bus, int addr, int dev_addr,
				   u32 *devices_in_package)
{
	int phy_reg, reg_addr;

	reg_addr = MII_ADDR_C45 | dev_addr << 16 | MDIO_DEVS2;
	phy_reg = mdiobus_read(bus, addr, reg_addr);
	if (phy_reg < 0)
		return -EIO;
	*devices_in_package = (phy_reg & 0xffff) << 16;

	reg_addr = MII_ADDR_C45 | dev_addr << 16 | MDIO_DEVS1;
	phy_reg = mdiobus_read(bus, addr, reg_addr);
	if (phy_reg < 0)
		return -EIO;
	*devices_in_package |= (phy_reg & 0xffff);

	return 0;
}

static int get_phy_c45_ids(struct mii_bus *bus, int addr, u32 *phy_id,
			   struct phy_c45_device_ids *c45_ids) {
	int phy_reg;
	int i, reg_addr;
	const int num_ids = ARRAY_SIZE(c45_ids->device_ids);
	u32 *devs = &c45_ids->devices_in_package;

	for (i = 1; i < num_ids && *devs == 0; i++) {
		phy_reg = get_phy_c45_devs_in_pkg(bus, addr, i, devs);
		if (phy_reg < 0)
			return -EIO;

		if ((*devs & 0x1fffffff) == 0x1fffffff) {
			 
			phy_reg = get_phy_c45_devs_in_pkg(bus, addr, 0, devs);
			if (phy_reg < 0)
				return -EIO;
			 
			if ((*devs & 0x1fffffff) == 0x1fffffff) {
				*phy_id = 0xffffffff;
				return 0;
			} else {
				break;
			}
		}
	}

	for (i = 1; i < num_ids; i++) {
		if (!(c45_ids->devices_in_package & (1 << i)))
			continue;

		reg_addr = MII_ADDR_C45 | i << 16 | MII_PHYSID1;
		phy_reg = mdiobus_read(bus, addr, reg_addr);
		if (phy_reg < 0)
			return -EIO;
		c45_ids->device_ids[i] = (phy_reg & 0xffff) << 16;

		reg_addr = MII_ADDR_C45 | i << 16 | MII_PHYSID2;
		phy_reg = mdiobus_read(bus, addr, reg_addr);
		if (phy_reg < 0)
			return -EIO;
		c45_ids->device_ids[i] |= (phy_reg & 0xffff);
	}
	*phy_id = 0;
	return 0;
}

static int get_phy_id(struct mii_bus *bus, int addr, u32 *phy_id,
		      bool is_c45, struct phy_c45_device_ids *c45_ids)
{
	int phy_reg;

	if (is_c45)
		return get_phy_c45_ids(bus, addr, phy_id, c45_ids);

	phy_reg = mdiobus_read(bus, addr, MII_PHYSID1);
	if (phy_reg < 0)
		return -EIO;

	*phy_id = (phy_reg & 0xffff) << 16;

	phy_reg = mdiobus_read(bus, addr, MII_PHYSID2);
	if (phy_reg < 0)
		return -EIO;

	*phy_id |= (phy_reg & 0xffff);

	return 0;
}

struct phy_device *get_phy_device(struct mii_bus *bus, int addr, bool is_c45)
{
	struct phy_c45_device_ids c45_ids = {0};
	u32 phy_id = 0;
	int r;

	r = get_phy_id(bus, addr, &phy_id, is_c45, &c45_ids);
	if (r)
		return ERR_PTR(r);

	if ((phy_id & 0x1fffffff) == 0x1fffffff)
		return NULL;

	return phy_device_create(bus, addr, phy_id, is_c45, &c45_ids);
}
EXPORT_SYMBOL(get_phy_device);

int phy_device_register(struct phy_device *phydev)
{
	int err;

#if defined(MY_DEF_HERE)
	err = mdiobus_register_device(&phydev->mdio);
	if (err)
		return err;
#else  
	 
	if (phydev->bus->phy_map[phydev->addr])
		return -EINVAL;
	phydev->bus->phy_map[phydev->addr] = phydev;
#endif  

	err = phy_scan_fixups(phydev);
	if (err) {
#if defined(MY_DEF_HERE)
		pr_err("PHY %d failed to initialize\n", phydev->mdio.addr);
#else  
		pr_err("PHY %d failed to initialize\n", phydev->addr);
#endif  
		goto out;
	}

#if defined(MY_DEF_HERE)
	err = device_add(&phydev->mdio.dev);
#else  
	err = device_add(&phydev->dev);
#endif  
	if (err) {
#if defined(MY_DEF_HERE)
		pr_err("PHY %d failed to add\n", phydev->mdio.addr);
#else  
		pr_err("PHY %d failed to add\n", phydev->addr);
#endif  
		goto out;
	}
	return 0;

 out:
#if defined(MY_DEF_HERE)
	mdiobus_unregister_device(&phydev->mdio);
#else  
	phydev->bus->phy_map[phydev->addr] = NULL;
#endif  
	return err;
}
EXPORT_SYMBOL(phy_device_register);

void phy_device_remove(struct phy_device *phydev)
{
#if defined(MY_DEF_HERE)
	device_del(&phydev->mdio.dev);
	mdiobus_unregister_device(&phydev->mdio);
#else  
	struct mii_bus *bus = phydev->bus;
	int addr = phydev->addr;

	device_del(&phydev->dev);
	bus->phy_map[addr] = NULL;
#endif  
}
EXPORT_SYMBOL(phy_device_remove);

struct phy_device *phy_find_first(struct mii_bus *bus)
{
#if defined(MY_DEF_HERE)
	struct phy_device *phydev;
#endif  
	int addr;

	for (addr = 0; addr < PHY_MAX_ADDR; addr++) {
#if defined(MY_DEF_HERE)
		phydev = mdiobus_get_phy(bus, addr);
		if (phydev)
			return phydev;
#else  
		if (bus->phy_map[addr])
			return bus->phy_map[addr];
#endif  
	}
	return NULL;
}
EXPORT_SYMBOL(phy_find_first);

static void phy_prepare_link(struct phy_device *phydev,
			     void (*handler)(struct net_device *))
{
	phydev->adjust_link = handler;
}

int phy_connect_direct(struct net_device *dev, struct phy_device *phydev,
		       void (*handler)(struct net_device *),
		       phy_interface_t interface)
{
	int rc;

	rc = phy_attach_direct(dev, phydev, phydev->dev_flags, interface);
	if (rc)
		return rc;

	phy_prepare_link(phydev, handler);
	phy_start_machine(phydev);
	if (phydev->irq > 0)
		phy_start_interrupts(phydev);

	return 0;
}
EXPORT_SYMBOL(phy_connect_direct);

struct phy_device *phy_connect(struct net_device *dev, const char *bus_id,
			       void (*handler)(struct net_device *),
			       phy_interface_t interface)
{
	struct phy_device *phydev;
	struct device *d;
	int rc;

	d = bus_find_device_by_name(&mdio_bus_type, NULL, bus_id);
	if (!d) {
		pr_err("PHY %s not found\n", bus_id);
		return ERR_PTR(-ENODEV);
	}
	phydev = to_phy_device(d);

	rc = phy_connect_direct(dev, phydev, handler, interface);
	if (rc)
		return ERR_PTR(rc);

	return phydev;
}
EXPORT_SYMBOL(phy_connect);

void phy_disconnect(struct phy_device *phydev)
{
	if (phydev->irq > 0)
		phy_stop_interrupts(phydev);

	phy_stop_machine(phydev);

	phydev->adjust_link = NULL;

	phy_detach(phydev);
}
EXPORT_SYMBOL(phy_disconnect);

static int phy_poll_reset(struct phy_device *phydev)
{
	 
	unsigned int retries = 12;
	int ret;

	do {
		msleep(50);
		ret = phy_read(phydev, MII_BMCR);
		if (ret < 0)
			return ret;
	} while (ret & BMCR_RESET && --retries);
	if (ret & BMCR_RESET)
		return -ETIMEDOUT;

	msleep(1);
	return 0;
}

int phy_init_hw(struct phy_device *phydev)
{
	int ret = 0;

	if (!phydev->drv || !phydev->drv->config_init)
		return 0;

	if (phydev->drv->soft_reset)
		ret = phydev->drv->soft_reset(phydev);
	else
		ret = genphy_soft_reset(phydev);

	if (ret < 0)
		return ret;

	ret = phy_scan_fixups(phydev);
	if (ret < 0)
		return ret;

	return phydev->drv->config_init(phydev);
}
EXPORT_SYMBOL(phy_init_hw);

#if defined(MY_DEF_HERE)
void phy_attached_info(struct phy_device *phydev)
{
	phy_attached_print(phydev, NULL);
}
EXPORT_SYMBOL(phy_attached_info);

#define ATTACHED_FMT "attached PHY driver [%s] (mii_bus:phy_addr=%s, irq=%d)"
void phy_attached_print(struct phy_device *phydev, const char *fmt, ...)
{
	if (!fmt) {
		dev_info(&phydev->mdio.dev, ATTACHED_FMT "\n",
			 phydev->drv->name, phydev_name(phydev),
			 phydev->irq);
	} else {
		va_list ap;

		dev_info(&phydev->mdio.dev, ATTACHED_FMT,
			 phydev->drv->name, phydev_name(phydev),
			 phydev->irq);

		va_start(ap, fmt);
		vprintk(fmt, ap);
		va_end(ap);
	}
}
EXPORT_SYMBOL(phy_attached_print);
#endif  

int phy_attach_direct(struct net_device *dev, struct phy_device *phydev,
		      u32 flags, phy_interface_t interface)
{
#if defined(MY_DEF_HERE)
	struct mii_bus *bus = phydev->mdio.bus;
	struct device *d = &phydev->mdio.dev;
#else  
	struct mii_bus *bus = phydev->bus;
	struct device *d = &phydev->dev;
#endif  
	int err;

	if (!try_module_get(bus->owner)) {
		dev_err(&dev->dev, "failed to get the bus module\n");
		return -EIO;
	}

	get_device(d);

	if (!d->driver) {
		if (phydev->is_c45)
#if defined(MY_DEF_HERE)
			d->driver =
				&genphy_driver[GENPHY_DRV_10G].mdiodrv.driver;
#else  
			d->driver = &genphy_driver[GENPHY_DRV_10G].driver;
#endif  
		else
#if defined(MY_DEF_HERE)
			d->driver =
				&genphy_driver[GENPHY_DRV_1G].mdiodrv.driver;
#else  
			d->driver = &genphy_driver[GENPHY_DRV_1G].driver;
#endif  

		err = d->driver->probe(d);
		if (err >= 0)
			err = device_bind_driver(d);

		if (err)
			goto error;
	}

	if (phydev->attached_dev) {
		dev_err(&dev->dev, "PHY already attached\n");
		err = -EBUSY;
		goto error;
	}

	phydev->attached_dev = dev;
	dev->phydev = phydev;

	phydev->dev_flags = flags;

	phydev->interface = interface;

	phydev->state = PHY_READY;

	err = phy_init_hw(phydev);
	if (err)
		phy_detach(phydev);
	else
		phy_resume(phydev);

	return err;

error:
	put_device(d);
	module_put(bus->owner);
	return err;
}
EXPORT_SYMBOL(phy_attach_direct);

struct phy_device *phy_attach(struct net_device *dev, const char *bus_id,
			      phy_interface_t interface)
{
	struct bus_type *bus = &mdio_bus_type;
	struct phy_device *phydev;
	struct device *d;
	int rc;

	d = bus_find_device_by_name(bus, NULL, bus_id);
	if (!d) {
		pr_err("PHY %s not found\n", bus_id);
		return ERR_PTR(-ENODEV);
	}
	phydev = to_phy_device(d);

	rc = phy_attach_direct(dev, phydev, phydev->dev_flags, interface);
	if (rc)
		return ERR_PTR(rc);

	return phydev;
}
EXPORT_SYMBOL(phy_attach);

void phy_detach(struct phy_device *phydev)
{
	struct mii_bus *bus;
	int i;

	phydev->attached_dev->phydev = NULL;
	phydev->attached_dev = NULL;
	phy_suspend(phydev);

	for (i = 0; i < ARRAY_SIZE(genphy_driver); i++) {
#if defined(MY_DEF_HERE)
		if (phydev->mdio.dev.driver ==
		    &genphy_driver[i].mdiodrv.driver) {
			device_release_driver(&phydev->mdio.dev);
#else  
		if (phydev->dev.driver == &genphy_driver[i].driver) {
			device_release_driver(&phydev->dev);
#endif  
			break;
		}
	}

#if defined(MY_DEF_HERE)
	bus = phydev->mdio.bus;

	put_device(&phydev->mdio.dev);
#else  
	bus = phydev->bus;

	put_device(&phydev->dev);
#endif  
	module_put(bus->owner);
}
EXPORT_SYMBOL(phy_detach);

int phy_suspend(struct phy_device *phydev)
{
#if defined(MY_DEF_HERE)
	struct phy_driver *phydrv = to_phy_driver(phydev->mdio.dev.driver);
#else  
	struct phy_driver *phydrv = to_phy_driver(phydev->dev.driver);
#endif  
	struct ethtool_wolinfo wol = { .cmd = ETHTOOL_GWOL };
	int ret = 0;

	phy_ethtool_get_wol(phydev, &wol);
	if (wol.wolopts)
		return -EBUSY;

	if (phydrv->suspend)
		ret = phydrv->suspend(phydev);

	if (ret)
		return ret;

	phydev->suspended = true;

	return ret;
}
EXPORT_SYMBOL(phy_suspend);

int phy_resume(struct phy_device *phydev)
{
#if defined(MY_DEF_HERE)
	struct phy_driver *phydrv = to_phy_driver(phydev->mdio.dev.driver);
#else  
	struct phy_driver *phydrv = to_phy_driver(phydev->dev.driver);
#endif  
	int ret = 0;

	if (phydrv->resume)
		ret = phydrv->resume(phydev);

	if (ret)
		return ret;

	phydev->suspended = false;

	return ret;
}
EXPORT_SYMBOL(phy_resume);

static int genphy_config_advert(struct phy_device *phydev)
{
	u32 advertise;
	int oldadv, adv, bmsr;
	int err, changed = 0;

	phydev->advertising &= phydev->supported;
	advertise = phydev->advertising;

	adv = phy_read(phydev, MII_ADVERTISE);
	if (adv < 0)
		return adv;

	oldadv = adv;
	adv &= ~(ADVERTISE_ALL | ADVERTISE_100BASE4 | ADVERTISE_PAUSE_CAP |
		 ADVERTISE_PAUSE_ASYM);
	adv |= ethtool_adv_to_mii_adv_t(advertise);

	if (adv != oldadv) {
		err = phy_write(phydev, MII_ADVERTISE, adv);

		if (err < 0)
			return err;
		changed = 1;
	}

	bmsr = phy_read(phydev, MII_BMSR);
	if (bmsr < 0)
		return bmsr;

	if (!(bmsr & BMSR_ESTATEN))
		return changed;

	adv = phy_read(phydev, MII_CTRL1000);
	if (adv < 0)
		return adv;

	oldadv = adv;
	adv &= ~(ADVERTISE_1000FULL | ADVERTISE_1000HALF);

	if (phydev->supported & (SUPPORTED_1000baseT_Half |
				 SUPPORTED_1000baseT_Full)) {
		adv |= ethtool_adv_to_mii_ctrl1000_t(advertise);
	}

	if (adv != oldadv)
		changed = 1;

	err = phy_write(phydev, MII_CTRL1000, adv);
	if (err < 0)
		return err;

	return changed;
}

int genphy_setup_forced(struct phy_device *phydev)
{
	int ctl = 0;

	phydev->pause = 0;
	phydev->asym_pause = 0;

	if (SPEED_1000 == phydev->speed)
		ctl |= BMCR_SPEED1000;
	else if (SPEED_100 == phydev->speed)
		ctl |= BMCR_SPEED100;

	if (DUPLEX_FULL == phydev->duplex)
		ctl |= BMCR_FULLDPLX;

	return phy_write(phydev, MII_BMCR, ctl);
}
EXPORT_SYMBOL(genphy_setup_forced);

int genphy_restart_aneg(struct phy_device *phydev)
{
	int ctl = phy_read(phydev, MII_BMCR);

	if (ctl < 0)
		return ctl;

	ctl |= BMCR_ANENABLE | BMCR_ANRESTART;

	ctl &= ~BMCR_ISOLATE;

	return phy_write(phydev, MII_BMCR, ctl);
}
EXPORT_SYMBOL(genphy_restart_aneg);

int genphy_config_aneg(struct phy_device *phydev)
{
	int result;

	if (AUTONEG_ENABLE != phydev->autoneg)
		return genphy_setup_forced(phydev);

	result = genphy_config_advert(phydev);
	if (result < 0)  
		return result;
	if (result == 0) {
		 
		int ctl = phy_read(phydev, MII_BMCR);

		if (ctl < 0)
			return ctl;

		if (!(ctl & BMCR_ANENABLE) || (ctl & BMCR_ISOLATE))
			result = 1;  
	}

	if (result > 0)
		result = genphy_restart_aneg(phydev);

	return result;
}
EXPORT_SYMBOL(genphy_config_aneg);

int genphy_aneg_done(struct phy_device *phydev)
{
	int retval = phy_read(phydev, MII_BMSR);

	return (retval < 0) ? retval : (retval & BMSR_ANEGCOMPLETE);
}
EXPORT_SYMBOL(genphy_aneg_done);

static int gen10g_config_aneg(struct phy_device *phydev)
{
	return 0;
}

int genphy_update_link(struct phy_device *phydev)
{
	int status;

	status = phy_read(phydev, MII_BMSR);
	if (status < 0)
		return status;

	status = phy_read(phydev, MII_BMSR);
	if (status < 0)
		return status;

	if ((status & BMSR_LSTATUS) == 0)
		phydev->link = 0;
	else
		phydev->link = 1;

	return 0;
}
EXPORT_SYMBOL(genphy_update_link);

int genphy_read_status(struct phy_device *phydev)
{
	int adv;
	int err;
	int lpa;
	int lpagb = 0;
	int common_adv;
	int common_adv_gb = 0;

	err = genphy_update_link(phydev);
	if (err)
		return err;

	phydev->lp_advertising = 0;

	if (AUTONEG_ENABLE == phydev->autoneg) {
		if (phydev->supported & (SUPPORTED_1000baseT_Half
					| SUPPORTED_1000baseT_Full)) {
			lpagb = phy_read(phydev, MII_STAT1000);
			if (lpagb < 0)
				return lpagb;

			adv = phy_read(phydev, MII_CTRL1000);
			if (adv < 0)
				return adv;

			phydev->lp_advertising =
				mii_stat1000_to_ethtool_lpa_t(lpagb);
			common_adv_gb = lpagb & adv << 2;
		}

		lpa = phy_read(phydev, MII_LPA);
		if (lpa < 0)
			return lpa;

		phydev->lp_advertising |= mii_lpa_to_ethtool_lpa_t(lpa);

		adv = phy_read(phydev, MII_ADVERTISE);
		if (adv < 0)
			return adv;

		common_adv = lpa & adv;

		phydev->speed = SPEED_10;
		phydev->duplex = DUPLEX_HALF;
		phydev->pause = 0;
		phydev->asym_pause = 0;

		if (common_adv_gb & (LPA_1000FULL | LPA_1000HALF)) {
			phydev->speed = SPEED_1000;

			if (common_adv_gb & LPA_1000FULL)
				phydev->duplex = DUPLEX_FULL;
		} else if (common_adv & (LPA_100FULL | LPA_100HALF)) {
			phydev->speed = SPEED_100;

			if (common_adv & LPA_100FULL)
				phydev->duplex = DUPLEX_FULL;
		} else
			if (common_adv & LPA_10FULL)
				phydev->duplex = DUPLEX_FULL;

		if (phydev->duplex == DUPLEX_FULL) {
			phydev->pause = lpa & LPA_PAUSE_CAP ? 1 : 0;
			phydev->asym_pause = lpa & LPA_PAUSE_ASYM ? 1 : 0;
		}
	} else {
		int bmcr = phy_read(phydev, MII_BMCR);

		if (bmcr < 0)
			return bmcr;

		if (bmcr & BMCR_FULLDPLX)
			phydev->duplex = DUPLEX_FULL;
		else
			phydev->duplex = DUPLEX_HALF;

		if (bmcr & BMCR_SPEED1000)
			phydev->speed = SPEED_1000;
		else if (bmcr & BMCR_SPEED100)
			phydev->speed = SPEED_100;
		else
			phydev->speed = SPEED_10;

		phydev->pause = 0;
		phydev->asym_pause = 0;
	}

	return 0;
}
EXPORT_SYMBOL(genphy_read_status);

static int gen10g_read_status(struct phy_device *phydev)
{
	int devad, reg;
	u32 mmd_mask = phydev->c45_ids.devices_in_package;

	phydev->link = 1;

	phydev->speed = SPEED_10000;
	phydev->duplex = DUPLEX_FULL;

	for (devad = 0; mmd_mask; devad++, mmd_mask = mmd_mask >> 1) {
		if (!(mmd_mask & 1))
			continue;

		phy_read_mmd(phydev, devad, MDIO_STAT1);
		reg = phy_read_mmd(phydev, devad, MDIO_STAT1);
		if (reg < 0 || !(reg & MDIO_STAT1_LSTATUS))
			phydev->link = 0;
	}

	return 0;
}

int genphy_soft_reset(struct phy_device *phydev)
{
	int ret;

	ret = phy_write(phydev, MII_BMCR, BMCR_RESET);
	if (ret < 0)
		return ret;

	return phy_poll_reset(phydev);
}
EXPORT_SYMBOL(genphy_soft_reset);

int genphy_config_init(struct phy_device *phydev)
{
	int val;
	u32 features;

	features = (SUPPORTED_TP | SUPPORTED_MII
			| SUPPORTED_AUI | SUPPORTED_FIBRE |
			SUPPORTED_BNC);

	val = phy_read(phydev, MII_BMSR);
	if (val < 0)
		return val;

	if (val & BMSR_ANEGCAPABLE)
		features |= SUPPORTED_Autoneg;

	if (val & BMSR_100FULL)
		features |= SUPPORTED_100baseT_Full;
	if (val & BMSR_100HALF)
		features |= SUPPORTED_100baseT_Half;
	if (val & BMSR_10FULL)
		features |= SUPPORTED_10baseT_Full;
	if (val & BMSR_10HALF)
		features |= SUPPORTED_10baseT_Half;

	if (val & BMSR_ESTATEN) {
		val = phy_read(phydev, MII_ESTATUS);
		if (val < 0)
			return val;

		if (val & ESTATUS_1000_TFULL)
			features |= SUPPORTED_1000baseT_Full;
		if (val & ESTATUS_1000_THALF)
			features |= SUPPORTED_1000baseT_Half;
	}

	phydev->supported &= features;
	phydev->advertising &= features;

	return 0;
}

static int gen10g_soft_reset(struct phy_device *phydev)
{
	 
	return 0;
}
EXPORT_SYMBOL(genphy_config_init);

static int gen10g_config_init(struct phy_device *phydev)
{
	 
	phydev->supported = SUPPORTED_10000baseT_Full;
	phydev->advertising = SUPPORTED_10000baseT_Full;

	return 0;
}

int genphy_suspend(struct phy_device *phydev)
{
	int value;

	mutex_lock(&phydev->lock);

	value = phy_read(phydev, MII_BMCR);
	phy_write(phydev, MII_BMCR, value | BMCR_PDOWN);

	mutex_unlock(&phydev->lock);

	return 0;
}
EXPORT_SYMBOL(genphy_suspend);

static int gen10g_suspend(struct phy_device *phydev)
{
	return 0;
}

int genphy_resume(struct phy_device *phydev)
{
	int value;

	mutex_lock(&phydev->lock);

	value = phy_read(phydev, MII_BMCR);
	phy_write(phydev, MII_BMCR, value & ~BMCR_PDOWN);

	mutex_unlock(&phydev->lock);

	return 0;
}
EXPORT_SYMBOL(genphy_resume);

static int gen10g_resume(struct phy_device *phydev)
{
	return 0;
}

static int __set_phy_supported(struct phy_device *phydev, u32 max_speed)
{
	 
	phydev->supported &= PHY_DEFAULT_FEATURES;

	switch (max_speed) {
	default:
		return -ENOTSUPP;
	case SPEED_1000:
		phydev->supported |= PHY_1000BT_FEATURES;
		 
	case SPEED_100:
		phydev->supported |= PHY_100BT_FEATURES;
		 
	case SPEED_10:
		phydev->supported |= PHY_10BT_FEATURES;
	}

	return 0;
}

int phy_set_max_speed(struct phy_device *phydev, u32 max_speed)
{
	int err;

	err = __set_phy_supported(phydev, max_speed);
	if (err)
		return err;

	phydev->advertising = phydev->supported;

	return 0;
}
EXPORT_SYMBOL(phy_set_max_speed);

static void of_set_phy_supported(struct phy_device *phydev)
{
#if defined(MY_DEF_HERE)
	struct device_node *node = phydev->mdio.dev.of_node;
#else  
	struct device_node *node = phydev->dev.of_node;
#endif  
	u32 max_speed;

	if (!IS_ENABLED(CONFIG_OF_MDIO))
		return;

	if (!node)
		return;

	if (!of_property_read_u32(node, "max-speed", &max_speed))
		__set_phy_supported(phydev, max_speed);
}

static int phy_probe(struct device *dev)
{
	struct phy_device *phydev = to_phy_device(dev);
#if defined(MY_DEF_HERE)
	struct device_driver *drv = phydev->mdio.dev.driver;
#else  
	struct device_driver *drv = phydev->dev.driver;
#endif  
	struct phy_driver *phydrv = to_phy_driver(drv);
	int err = 0;

	phydev->drv = phydrv;

	if (!(phydrv->flags & PHY_HAS_INTERRUPT) &&
	    phy_interrupt_is_valid(phydev))
		phydev->irq = PHY_POLL;

	if (phydrv->flags & PHY_IS_INTERNAL)
		phydev->is_internal = true;

	mutex_lock(&phydev->lock);

	phydev->supported = phydrv->features;
	of_set_phy_supported(phydev);
	phydev->advertising = phydev->supported;

	phydev->state = PHY_READY;

	if (phydev->drv->probe)
		err = phydev->drv->probe(phydev);

	mutex_unlock(&phydev->lock);

	return err;
}

static int phy_remove(struct device *dev)
{
	struct phy_device *phydev = to_phy_device(dev);

	mutex_lock(&phydev->lock);
	phydev->state = PHY_DOWN;
	mutex_unlock(&phydev->lock);

	if (phydev->drv->remove)
		phydev->drv->remove(phydev);
	phydev->drv = NULL;

	return 0;
}

#if defined(MY_DEF_HERE)
 
int phy_driver_register(struct phy_driver *new_driver, struct module *owner)
#else  
 
int phy_driver_register(struct phy_driver *new_driver)
#endif  
{
	int retval;

#if defined(MY_DEF_HERE)
	new_driver->mdiodrv.flags |= MDIO_DEVICE_IS_PHY;
	new_driver->mdiodrv.driver.name = new_driver->name;
	new_driver->mdiodrv.driver.bus = &mdio_bus_type;
	new_driver->mdiodrv.driver.probe = phy_probe;
	new_driver->mdiodrv.driver.remove = phy_remove;
	new_driver->mdiodrv.driver.owner = owner;

	retval = driver_register(&new_driver->mdiodrv.driver);
#else  
	new_driver->driver.name = new_driver->name;
	new_driver->driver.bus = &mdio_bus_type;
	new_driver->driver.probe = phy_probe;
	new_driver->driver.remove = phy_remove;

	retval = driver_register(&new_driver->driver);
#endif  
	if (retval) {
		pr_err("%s: Error %d in registering driver\n",
		       new_driver->name, retval);

		return retval;
	}

	pr_debug("%s: Registered new driver\n", new_driver->name);

	return 0;
}
EXPORT_SYMBOL(phy_driver_register);

#if defined(MY_DEF_HERE)
int phy_drivers_register(struct phy_driver *new_driver, int n,
			 struct module *owner)
#else  
int phy_drivers_register(struct phy_driver *new_driver, int n)
#endif  
{
	int i, ret = 0;

	for (i = 0; i < n; i++) {
#if defined(MY_DEF_HERE)
		ret = phy_driver_register(new_driver + i, owner);
#else  
		ret = phy_driver_register(new_driver + i);
#endif  
		if (ret) {
			while (i-- > 0)
				phy_driver_unregister(new_driver + i);
			break;
		}
	}
	return ret;
}
EXPORT_SYMBOL(phy_drivers_register);

void phy_driver_unregister(struct phy_driver *drv)
{
#if defined(MY_DEF_HERE)
	driver_unregister(&drv->mdiodrv.driver);
#else  
	driver_unregister(&drv->driver);
#endif  
}
EXPORT_SYMBOL(phy_driver_unregister);

void phy_drivers_unregister(struct phy_driver *drv, int n)
{
	int i;

	for (i = 0; i < n; i++)
		phy_driver_unregister(drv + i);
}
EXPORT_SYMBOL(phy_drivers_unregister);

static struct phy_driver genphy_driver[] = {
{
	.phy_id		= 0xffffffff,
	.phy_id_mask	= 0xffffffff,
	.name		= "Generic PHY",
	.soft_reset	= genphy_soft_reset,
	.config_init	= genphy_config_init,
	.features	= PHY_GBIT_FEATURES | SUPPORTED_MII |
			  SUPPORTED_AUI | SUPPORTED_FIBRE |
			  SUPPORTED_BNC,
	.config_aneg	= genphy_config_aneg,
	.aneg_done	= genphy_aneg_done,
	.read_status	= genphy_read_status,
	.suspend	= genphy_suspend,
	.resume		= genphy_resume,
#if defined(MY_DEF_HERE)
 
#else  
	.driver		= { .owner = THIS_MODULE, },
#endif  
}, {
	.phy_id         = 0xffffffff,
	.phy_id_mask    = 0xffffffff,
	.name           = "Generic 10G PHY",
	.soft_reset	= gen10g_soft_reset,
	.config_init    = gen10g_config_init,
	.features       = 0,
	.config_aneg    = gen10g_config_aneg,
	.read_status    = gen10g_read_status,
	.suspend        = gen10g_suspend,
	.resume         = gen10g_resume,
#if defined(MY_DEF_HERE)
 
#else  
	.driver         = {.owner = THIS_MODULE, },
#endif  
} };

static int __init phy_init(void)
{
	int rc;

	rc = mdio_bus_init();
	if (rc)
		return rc;

#if defined(MY_DEF_HERE)
	rc = phy_drivers_register(genphy_driver,
				  ARRAY_SIZE(genphy_driver), THIS_MODULE);
#else  
	rc = phy_drivers_register(genphy_driver,
				  ARRAY_SIZE(genphy_driver));
#endif  
	if (rc)
		mdio_bus_exit();

	return rc;
}

static void __exit phy_exit(void)
{
	phy_drivers_unregister(genphy_driver,
			       ARRAY_SIZE(genphy_driver));
	mdio_bus_exit();
}

subsys_initcall(phy_init);
module_exit(phy_exit);
