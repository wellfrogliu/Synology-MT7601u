#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/libata.h>
#ifdef MY_ABC_HERE
#include <linux/sched.h>
#endif  
#include <linux/slab.h>
#ifdef MY_ABC_HERE
#include <linux/pci.h>
#endif  
#include "libata.h"
#include "libata-transport.h"

const struct ata_port_operations sata_pmp_port_ops = {
	.inherits		= &sata_port_ops,
	.pmp_prereset		= ata_std_prereset,
	.pmp_hardreset		= sata_std_hardreset,
	.pmp_postreset		= ata_std_postreset,
	.error_handler		= sata_pmp_error_handler,
};

static unsigned int sata_pmp_read(struct ata_link *link, int reg, u32 *r_val)
{
	struct ata_port *ap = link->ap;
	struct ata_device *pmp_dev = ap->link.device;
	struct ata_taskfile tf;
	unsigned int err_mask;

	ata_tf_init(pmp_dev, &tf);
	tf.command = ATA_CMD_PMP_READ;
	tf.protocol = ATA_PROT_NODATA;
	tf.flags |= ATA_TFLAG_ISADDR | ATA_TFLAG_DEVICE | ATA_TFLAG_LBA48;
#ifdef MY_ABC_HERE
	tf.feature = reg & 0xff;
	tf.hob_feature = (reg >> 8) & 0xff;
#else
	tf.feature = reg;
#endif  
	tf.device = link->pmp;

	err_mask = ata_exec_internal(pmp_dev, &tf, NULL, DMA_NONE, NULL, 0,
				     SATA_PMP_RW_TIMEOUT);
	if (err_mask)
		return err_mask;

	*r_val = tf.nsect | tf.lbal << 8 | tf.lbam << 16 | tf.lbah << 24;
	return 0;
}

static unsigned int sata_pmp_write(struct ata_link *link, int reg, u32 val)
{
	struct ata_port *ap = link->ap;
	struct ata_device *pmp_dev = ap->link.device;
	struct ata_taskfile tf;

	ata_tf_init(pmp_dev, &tf);
	tf.command = ATA_CMD_PMP_WRITE;
	tf.protocol = ATA_PROT_NODATA;
	tf.flags |= ATA_TFLAG_ISADDR | ATA_TFLAG_DEVICE | ATA_TFLAG_LBA48;
#ifdef MY_ABC_HERE
	tf.feature = reg & 0xff;
	tf.hob_feature = (reg >> 8) & 0xff;
#else
	tf.feature = reg;
#endif  
	tf.device = link->pmp;
	tf.nsect = val & 0xff;
	tf.lbal = (val >> 8) & 0xff;
	tf.lbam = (val >> 16) & 0xff;
	tf.lbah = (val >> 24) & 0xff;

	return ata_exec_internal(pmp_dev, &tf, NULL, DMA_NONE, NULL, 0,
				 SATA_PMP_RW_TIMEOUT);
}

#ifdef MY_ABC_HERE
 
static inline void
syno_pm_gpio_config(struct ata_port *ap)
{
	if (syno_pm_is_9705(sata_pmp_gscr_vendor(ap->link.device->gscr),
				        sata_pmp_gscr_devid(ap->link.device->gscr))) {
		 
		sata_pmp_write(&(ap->link), SATA_PMP_GSCR_9705_GPO_EN, 0xFFFFF);

		sata_pmp_write(&(ap->link), SATA_PMP_GSCR_9705_GPI_POLARITY, 0xFFFFF);

		sata_pmp_write(&(ap->link), SATA_PMP_GSCR_9705_SATA_0_TO_3_BLINK_RATE, 0x2082082);
		sata_pmp_write(&(ap->link), SATA_PMP_GSCR_9705_SATA_4_BLINK_RATE, 0x00000082);

		sata_pmp_write(&(ap->link), 0x090, 0x00001F1F);
		sata_pmp_write(&(ap->link), 0x091, 0xFFF0003A);

		sata_pmp_write(&(ap->link), 0x248, 0x62D8);
	}
}

static inline int
syno_pm_device_config_set(struct ata_port *ap, int pmp, int reg, u32 val)
{
	struct ata_link *pmp_link = NULL;
	int iRet = -1;

	if (!ap) {
		goto END;
	}
	pmp_link = &(ap->pmp_link[pmp]);
	if (!pmp_link) {
		goto END;
	}
	iRet = sata_pmp_write(pmp_link, reg, val);

END:
	return iRet;
}

static inline void
syno_pm_device_config(struct ata_port *ap)
{
	 
	if (syno_pm_is_9705(sata_pmp_gscr_vendor(ap->link.device->gscr),
				        sata_pmp_gscr_devid(ap->link.device->gscr))) {
		syno_pm_device_config_set(ap, 0, 0x48, 0x62D8);
		syno_pm_device_config_set(ap, 1, 0x48, 0x62D8);
		syno_pm_device_config_set(ap, 2, 0x48, 0x62D8);
		syno_pm_device_config_set(ap, 3, 0x48, 0x62D8);
		syno_pm_device_config_set(ap, 4, 0x48, 0x62D8);
	}
	 
	if (syno_is_hw_version(HW_DS3615xs) ||
			IS_SYNOLOGY_DX1215(ap->PMSynoUnique)) {  
		syno_pm_device_config_set(ap, 0, 0x91, 0xE7F);
		syno_pm_device_config_set(ap, 1, 0x91, 0xE7F);
		syno_pm_device_config_set(ap, 2, 0x91, 0xE7F);
		syno_pm_device_config_set(ap, 3, 0x91, 0xE7F);
		syno_pm_device_config_set(ap, 4, 0x91, 0xE7F);
	}
	if (IS_SYNOLOGY_RX1217(ap->PMSynoUnique)) {
		if (0 == ap->PMSynoEMID) {
			syno_pm_device_config_set(ap, 0, 0x91, 0xEFF);
		} else if (1 == ap->PMSynoEMID) {
			syno_pm_device_config_set(ap, 0, 0x91, 0xEFF);
			syno_pm_device_config_set(ap, 1, 0x91, 0xE7F);
		} else if (2 == ap->PMSynoEMID) {
			syno_pm_device_config_set(ap, 1, 0x91, 0xE79);
			syno_pm_device_config_set(ap, 2, 0x91, 0xF7F);
		} else if (3 == ap->PMSynoEMID) {
			syno_pm_device_config_set(ap, 0, 0x91, 0xEFF);
			syno_pm_device_config_set(ap, 2, 0x91, 0xF7F);
		}
	}
	if (IS_SYNOLOGY_DX517(ap->PMSynoUnique)) {
		syno_pm_device_config_set(ap, 4, 0x91, 0xE7F);
	}
	if (IS_SYNOLOGY_RX418(ap->PMSynoUnique)) {
		syno_pm_device_config_set(ap, 0, 0x91, 0xD75);
		syno_pm_device_config_set(ap, 1, 0x91, 0xD75);
		syno_pm_device_config_set(ap, 2, 0x91, 0xE75);
		syno_pm_device_config_set(ap, 3, 0x91, 0xEF5);
	}
}

void
syno_pm_device_info_set(struct ata_port *ap, u8 rw, SYNO_PM_PKG *pm_pkg)
{
	if (syno_pm_is_3xxx(sata_pmp_gscr_vendor(ap->link.device->gscr),
						sata_pmp_gscr_devid(ap->link.device->gscr))) {
		pm_pkg->decode = SIMG3xxx_gpio_decode;
		pm_pkg->encode = SIMG3xxx_gpio_encode;
		pm_pkg->gpio_addr = SATA_PMP_GSCR_3XXX_GPIO;
		return;
	} else if (syno_pm_is_9705(sata_pmp_gscr_vendor(ap->link.device->gscr),
				               sata_pmp_gscr_devid(ap->link.device->gscr))) {
		pm_pkg->decode = SIMG9705_gpio_decode;
		pm_pkg->encode = SIMG9705_gpio_encode;
		pm_pkg->gpio_addr = READ == rw ? SATA_PMP_GSCR_9705_GPI : SATA_PMP_GSCR_9705_GPO;
		return;
	}
}

unsigned int
syno_pm_gpio_output_disable(struct ata_link *link)
{
	unsigned int uiRet = 0;

	if (syno_pm_is_9705(sata_pmp_gscr_vendor(link->device->gscr),
		               sata_pmp_gscr_devid(link->device->gscr))) {
		 
		uiRet = sata_pmp_write(link, SATA_PMP_GSCR_9705_GPO_EN, 0xFC7C0);
	}

	return uiRet;
}

unsigned int
syno_pm_gpio_output_enable(struct ata_link *link)
{
	unsigned int uiRet = 0;

	if (syno_pm_is_9705(sata_pmp_gscr_vendor(link->device->gscr),
		               sata_pmp_gscr_devid(link->device->gscr))) {
		 
		uiRet = sata_pmp_write(link, SATA_PMP_GSCR_9705_GPO_EN, 0xFFFFF);
	}

	return uiRet;
}

unsigned int
syno_sata_pmp_read_gpio_scmd(struct ata_port *ap, SYNO_PM_PKG *pPkg)
{
	unsigned int uiRet = 1;
	struct scsi_device *sdev = ap->link.device->sdev;

	if ( syno_pm_is_3xxx(sata_pmp_gscr_vendor(ap->link.device->gscr),
			     sata_pmp_gscr_devid(ap->link.device->gscr))) {
		uiRet = syno_gpio_with_scmd(ap, sdev, pPkg, WRITE);
		if ( 0!= uiRet) {
			goto END;
		}
		uiRet = syno_gpio_with_scmd(ap, sdev, pPkg, READ);
		if ( 0!= uiRet) {
			goto END;
		}
	} else if ( syno_pm_is_9705(sata_pmp_gscr_vendor(ap->link.device->gscr),
				sata_pmp_gscr_devid(ap->link.device->gscr))) {
		 
		unsigned int uiVar = pPkg->var;
		unsigned int uiVarActive = pPkg->var & ~(1 << 9);  
		unsigned int uiResult = 0;

		uiRet = syno_gpio_with_scmd(ap, sdev, pPkg, WRITE);
		if ( 0 != uiRet ) {
			goto END;
		}
		pPkg->var = uiVarActive;
		uiRet = syno_gpio_with_scmd(ap, sdev, pPkg, WRITE);
		if ( 0 != uiRet ) {
			goto END;
		}
		pPkg->var = uiVarActive;
		uiRet = syno_gpio_with_scmd(ap, sdev, pPkg, READ);
		if ( 0 != uiRet ) {
			goto END;
		}
		uiResult = pPkg->var;
		pPkg->var = uiVar;
		uiRet = syno_gpio_with_scmd(ap, sdev, pPkg, WRITE);
		if ( 0 != uiRet ) {
			goto END;
		}
		pPkg->var = uiResult;
	}
	uiRet = 0;
END:
	return uiRet;

}

unsigned int
syno_sata_pmp_write_gpio_scmd(struct ata_port *ap, SYNO_PM_PKG *pPkg)
{
	unsigned int uiRet = 1;
	struct scsi_device *sdev = ap->link.device->sdev;

	if ( syno_pm_is_3xxx(sata_pmp_gscr_vendor(ap->link.device->gscr),
				sata_pmp_gscr_devid(ap->link.device->gscr))) {
		uiRet = syno_gpio_with_scmd(ap, sdev, pPkg, WRITE);
		if ( 0 != uiRet ) {
			goto END;
		}
	} else if (syno_pm_is_9705(sata_pmp_gscr_vendor(ap->link.device->gscr),
				sata_pmp_gscr_devid(ap->link.device->gscr))) {
		 
		unsigned int uiVar = pPkg->var;
		unsigned int uiVarActive = pPkg->var & ~(1 << 8);  

		uiRet = syno_gpio_with_scmd(ap, sdev, pPkg, WRITE);
		if ( 0 != uiRet ) {
			goto END;
		}
		pPkg->var = uiVarActive;
		uiRet = syno_gpio_with_scmd(ap, sdev, pPkg, WRITE);
		if ( 0 != uiRet ) {
			goto END;
		}
		pPkg->var = uiVar;
		uiRet = syno_gpio_with_scmd(ap, sdev, pPkg, WRITE);
		if ( 0 != uiRet ) {
			goto END;
		}
	}
END:
	return uiRet;
}

unsigned int
syno_sata_pmp_read_gpio_acmd(struct ata_link* link, SYNO_PM_PKG *pPM_pkg)
{
	unsigned int uiRet = 1;

	if (syno_pm_is_3xxx(sata_pmp_gscr_vendor(link->device->gscr),
						sata_pmp_gscr_devid(link->device->gscr))) {
		uiRet = syno_sata_pmp_write_gpio_core(link, pPM_pkg);
		if (0 != uiRet) {
			goto END;
		}
		uiRet = syno_sata_pmp_read_gpio_core(link, pPM_pkg);
		if (0 != uiRet) {
			goto END;
		}
	} else if (syno_pm_is_9705(sata_pmp_gscr_vendor(link->device->gscr),
				               sata_pmp_gscr_devid(link->device->gscr))) {
		 
		unsigned int uiVar = pPM_pkg->var;
		unsigned int uiVarActive = pPM_pkg->var & ~(1 << 9);  
		unsigned int uiResult = 0;

		uiRet = syno_sata_pmp_write_gpio_core(link, pPM_pkg);
		if (0 != uiRet) {
			goto END;
		}
		pPM_pkg->var = uiVarActive;
		uiRet = syno_sata_pmp_write_gpio_core(link, pPM_pkg);
		if (0 != uiRet) {
			goto END;
		}
		pPM_pkg->var = uiVarActive;
		uiRet = syno_sata_pmp_read_gpio_core(link, pPM_pkg);
		if (0 != uiRet) {
			goto END;
		}
		uiResult = pPM_pkg->var;
		pPM_pkg->var = uiVar;
		uiRet = syno_sata_pmp_write_gpio_core(link, pPM_pkg);
		if (0 != uiRet) {
			goto END;
		}
		pPM_pkg->var = uiResult;
	}
	uiRet = 0;
END:
	return uiRet;
}

unsigned int
syno_sata_pmp_write_gpio_acmd(struct ata_link *link, SYNO_PM_PKG *pPM_pkg)
{
	unsigned int uiRet = 1;
	if (syno_pm_is_3xxx(sata_pmp_gscr_vendor(link->device->gscr),
						sata_pmp_gscr_devid(link->device->gscr))) {
		uiRet = syno_sata_pmp_write_gpio_core(link, pPM_pkg);
		if (0 != uiRet) {
			goto END;
		}
	} else if (syno_pm_is_9705(sata_pmp_gscr_vendor(link->device->gscr),
				               sata_pmp_gscr_devid(link->device->gscr))) {
		 
		unsigned int uiVar = pPM_pkg->var;
		unsigned int uiVarActive = pPM_pkg->var & ~(1 << 8);  
		uiRet = syno_sata_pmp_write_gpio_core(link, pPM_pkg);
		if (0 != uiRet) {
			goto END;
		}
		pPM_pkg->var = uiVarActive;
		uiRet = syno_sata_pmp_write_gpio_core(link, pPM_pkg);
		if (0 != uiRet) {
			goto END;
		}
		pPM_pkg->var = uiVar;
		uiRet = syno_sata_pmp_write_gpio_core(link, pPM_pkg);
		if (0 != uiRet) {
			goto END;
		}
	}
END:
	return uiRet;
}

unsigned int
syno_sata_pmp_read_gpio_core(struct ata_link *link, SYNO_PM_PKG *pPM_pkg)
{
	unsigned int uiRet = 1;
	unsigned long flags = 0;
	int iRetries = 0;

	spin_lock_irqsave(link->ap->lock, flags);
	while ((link->uiStsFlags & SYNO_STATUS_GPIO_CTRL) && (SYNO_PMP_GPIO_TRIES > iRetries)) {
		spin_unlock_irqrestore(link->ap->lock, flags);
		schedule_timeout_uninterruptible(HZ/2);
		spin_lock_irqsave(link->ap->lock, flags);
		++iRetries;
	}

	if (SYNO_PMP_GPIO_TRIES <= iRetries) {
		DBGMESG("syno_sata_pmp_read_gpio_core get gpio lock timeout\n");
		spin_unlock_irqrestore(link->ap->lock, flags);
		goto END;
	}

	link->uiStsFlags |= SYNO_STATUS_GPIO_CTRL;
	spin_unlock_irqrestore(link->ap->lock, flags);

	syno_pm_device_info_set(link->ap, READ, pPM_pkg);

	uiRet = syno_pm_gpio_output_disable(link);
	if (0 != uiRet) {
		goto END;
	}

	uiRet = sata_pmp_read(link, pPM_pkg->gpio_addr, &(pPM_pkg->var));
	if (0 != uiRet) {
		goto END;
	}

	if (pPM_pkg->decode) {
		pPM_pkg->decode(pPM_pkg, READ);
	}

END:
	 
	spin_lock_irqsave(link->ap->lock, flags);
	link->uiStsFlags &= ~SYNO_STATUS_GPIO_CTRL;
	spin_unlock_irqrestore(link->ap->lock, flags);

	return uiRet;
}

unsigned int
syno_sata_pmp_write_gpio_core(struct ata_link *link, SYNO_PM_PKG *pPM_pkg)
{
	unsigned int uiRet = 1;
	unsigned long flags = 0;
	int iRetries = 0;

	spin_lock_irqsave(link->ap->lock, flags);
	while ((link->uiStsFlags & SYNO_STATUS_GPIO_CTRL) && (SYNO_PMP_GPIO_TRIES > iRetries)) {
		spin_unlock_irqrestore(link->ap->lock, flags);
		schedule_timeout_uninterruptible(HZ/2);
		spin_lock_irqsave(link->ap->lock, flags);
		++iRetries;
	}

	if (SYNO_PMP_GPIO_TRIES <= iRetries) {
		DBGMESG("syno_sata_pmp_write_gpio_core get gpio lock timeout\n");
		spin_unlock_irqrestore(link->ap->lock, flags);
		goto END;
	}

	link->uiStsFlags |= SYNO_STATUS_GPIO_CTRL;
	spin_unlock_irqrestore(link->ap->lock, flags);

	syno_pm_device_info_set(link->ap, WRITE, pPM_pkg);

	uiRet = syno_pm_gpio_output_enable(link);
	if (0 != uiRet) {
		goto END;
	}

	if (pPM_pkg->encode) {
		pPM_pkg->encode(pPM_pkg, WRITE);
	}

	uiRet = sata_pmp_write(link, pPM_pkg->gpio_addr, pPM_pkg->var);
	if (0 != uiRet) {
		goto END;
	}

	mdelay(5);
END:

	spin_lock_irqsave(link->ap->lock, flags);
	link->uiStsFlags &= ~SYNO_STATUS_GPIO_CTRL;
	spin_unlock_irqrestore(link->ap->lock, flags);

	return uiRet;
}

unsigned int syno_sata_pmp_read_gpio(struct ata_port *ap, SYNO_PM_PKG *pPM_pkg)
{
	if ((ap->pflags & (ATA_PFLAG_RECOVERED)) || (!ap->link.device->sdev) || (ap->pflags & ATA_PFLAG_PMP_PMCTL))
		return syno_sata_pmp_read_gpio_acmd(&(ap->link), pPM_pkg);
	else
		return syno_sata_pmp_read_gpio_scmd(ap, pPM_pkg);
}

unsigned int syno_sata_pmp_write_gpio(struct ata_port *ap, SYNO_PM_PKG *pPM_pkg)
{
	if ((ap->pflags & ATA_PFLAG_RECOVERED) || (!ap->link.device->sdev) || (ap->pflags & ATA_PFLAG_PMP_PMCTL))
		return syno_sata_pmp_write_gpio_acmd(&(ap->link), pPM_pkg);
	else
		return syno_sata_pmp_write_gpio_scmd(ap, pPM_pkg);
}

u8 syno_pm_is_synology_3xxx(const struct ata_port *ap)
{
	u8 ret = 0;

	if (!syno_pm_is_3xxx(sata_pmp_gscr_vendor(ap->link.device->gscr),
						sata_pmp_gscr_devid(ap->link.device->gscr))) {
		goto END;
	}

	if (!IS_SYNOLOGY_RX4(ap->PMSynoUnique) &&
		!IS_SYNOLOGY_DX5(ap->PMSynoUnique) &&
		!IS_SYNOLOGY_DX513(ap->PMSynoUnique) &&
		!IS_SYNOLOGY_DXC(ap->PMSynoUnique) &&
		!IS_SYNOLOGY_RXC(ap->PMSynoUnique) &&
		!IS_SYNOLOGY_DX213(ap->PMSynoUnique) &&
		!IS_SYNOLOGY_RX415(ap->PMSynoUnique)) {
		goto END;
	}

	ret = 1;
END:
	return ret;
}

u8 syno_pm_is_synology_9705(const struct ata_port *ap)
{
	u8 ret = 0;

	if (!syno_pm_is_9705(sata_pmp_gscr_vendor(ap->link.device->gscr),
						sata_pmp_gscr_devid(ap->link.device->gscr))) {
		goto END;
	}

	if (!IS_SYNOLOGY_RX413(ap->PMSynoUnique) &&
		!IS_SYNOLOGY_RX1214(ap->PMSynoUnique) &&
		!IS_SYNOLOGY_RX1217(ap->PMSynoUnique) &&
		!IS_SYNOLOGY_DX1215(ap->PMSynoUnique) &&
		!IS_SYNOLOGY_DX517(ap->PMSynoUnique) &&
		!IS_SYNOLOGY_RX418(ap->PMSynoUnique)) {
		goto END;
	}

	ret = 1;
END:
	return ret;
}

unsigned int
syno_sata_pmp_is_rp(struct ata_port *ap)
{
#define GPI_3XXX_PSU1_STAT(GPIO)        ((1<<5)&GPIO)>>5
#define GPI_3XXX_PSU2_STAT(GPIO)        ((1<<6)&GPIO)>>6
#define GPI_9705_PSU1_STAT(GPIO)        ((1<<6)&GPIO)>>6
#define GPI_9705_PSU2_STAT(GPIO)        ((1<<7)&GPIO)>>7
	int res = 0;
	SYNO_PM_PKG pm_pkg;

	if (NULL == ap) {
		goto END;
	}

	if (0 != ap->PMSynoEMID) {
		goto END;
	}

	if (syno_pm_is_synology_3xxx(ap)) {
		syno_pm_systemstate_pkg_init(sata_pmp_gscr_vendor(ap->link.device->gscr),
									  sata_pmp_gscr_devid(ap->link.device->gscr),
									  &pm_pkg);

		res = syno_sata_pmp_read_gpio(ap, &pm_pkg);
		if (0 != res) {
			goto END;
		}

		if (GPI_3XXX_PSU1_STAT(pm_pkg.var) || GPI_3XXX_PSU2_STAT(pm_pkg.var)) {
			res = 1;
		}
	} else if (syno_pm_is_synology_9705(ap)) {
		syno_pm_fanstatus_pkg_init(sata_pmp_gscr_vendor(ap->link.device->gscr),
								  sata_pmp_gscr_devid(ap->link.device->gscr),
								  &pm_pkg);

		res = syno_sata_pmp_read_gpio(ap, &pm_pkg);
		if (0 != res) {
			goto END;
		}

		if (GPI_9705_PSU1_STAT(pm_pkg.var) || GPI_9705_PSU2_STAT(pm_pkg.var)) {
			res = 1;
		}
	}

END:
	return res;
}

static unsigned int
syno_sata_pmp_read_cpld_ver(struct ata_port *ap)
{
#define GPI_3XXX_CPLDVER_BIT1(GPIO)	((1<<4)&GPIO)>>2
#define GPI_3XXX_CPLDVER_BIT2(GPIO)	((1<<5)&GPIO)>>4
#define GPI_3XXX_CPLDVER_BIT3(GPIO)	((1<<6)&GPIO)>>6
#define GPI_9705_CPLDVER_BIT0(GPIO)	((1<<1)&GPIO)>>1
#define GPI_9705_CPLDVER_BIT1(GPIO)	((1<<2)&GPIO)>>1
	int iRes = 0;
	SYNO_PM_PKG stPmPkg;

	if (NULL == ap) {
		goto END;
	}

	if (syno_pm_is_synology_3xxx(ap)) {
		syno_pm_raidledstate_pkg_init(sata_pmp_gscr_vendor(ap->link.device->gscr),
									sata_pmp_gscr_devid(ap->link.device->gscr),
									&stPmPkg);

		iRes = syno_sata_pmp_read_gpio(ap, &stPmPkg);
		if (0 != iRes) {
			goto END;
		}
		if (IS_SYNOLOGY_DX513(ap->PMSynoUnique) || IS_SYNOLOGY_DX213(ap->PMSynoUnique)) {
			ap->PMSynoCpldVer =	GPI_3XXX_CPLDVER_BIT3(stPmPkg.var);
		} else {
			ap->PMSynoCpldVer =	GPI_3XXX_CPLDVER_BIT1(stPmPkg.var) |
				GPI_3XXX_CPLDVER_BIT2(stPmPkg.var) |
				GPI_3XXX_CPLDVER_BIT3(stPmPkg.var);
		}
		 
		ap->PMSynoCpldVer = ap->PMSynoCpldVer + 1;
	} else if (syno_pm_is_synology_9705(ap)) {
		syno_pm_systemstate_pkg_init(sata_pmp_gscr_vendor(ap->link.device->gscr),
									sata_pmp_gscr_devid(ap->link.device->gscr),
									&stPmPkg);

		iRes = syno_sata_pmp_read_gpio(ap, &stPmPkg);
		if (0 != iRes) {
			goto END;
		}
		ap->PMSynoCpldVer = GPI_9705_CPLDVER_BIT1(stPmPkg.var) |
							GPI_9705_CPLDVER_BIT0(stPmPkg.var);
	}
END:
	return iRes;
}

unsigned int
syno_sata_pmp_read_emid(struct ata_port *ap)
{
#define GPI_3XXX_EMID_BIT1(GPIO)	((1<<10)&GPIO)>>10
#define GPI_3XXX_EMID_BIT2(GPIO)	((1<<11)&GPIO)>>10
#define GPI_3XXX_EMID_BIT3(GPIO)	((1<<12)&GPIO)>>10
#define GPI_9705_EMID_BIT1(GPIO)	((1<<5)&GPIO)>>5
#define GPI_9705_EMID_BIT2(GPIO)	((1<<6)&GPIO)>>5
#define GPI_9705_EMID_BIT3(GPIO)	((1<<7)&GPIO)>>5
	int res = 0;
	SYNO_PM_PKG pm_pkg;

	if (NULL == ap) {
		goto END;
	}

	if (syno_pm_is_synology_3xxx(ap)) {
		syno_pm_unique_pkg_init(sata_pmp_gscr_vendor(ap->link.device->gscr),
								sata_pmp_gscr_devid(ap->link.device->gscr),
								&pm_pkg);

		syno_sata_pmp_write_gpio(ap, &pm_pkg);
		syno_pm_device_info_set(ap->link.ap, READ, &pm_pkg);
		res = sata_pmp_read(&(ap->link), pm_pkg.gpio_addr, &(pm_pkg.var));
		if (0 != res) {
			goto END;
		}

		ap->PMSynoEMID  =	GPI_3XXX_EMID_BIT1(pm_pkg.var)|
							GPI_3XXX_EMID_BIT2(pm_pkg.var)|
							GPI_3XXX_EMID_BIT3(pm_pkg.var);
	} else if (syno_pm_is_synology_9705(ap)) {
		syno_pm_unique_pkg_init(sata_pmp_gscr_vendor(ap->link.device->gscr),
								sata_pmp_gscr_devid(ap->link.device->gscr),
								&pm_pkg);

		res = syno_sata_pmp_read_gpio(ap, &pm_pkg);
		if (0 != res) {
			goto END;
		}

		ap->PMSynoEMID  =	GPI_9705_EMID_BIT1(pm_pkg.var)|
							GPI_9705_EMID_BIT2(pm_pkg.var)|
							GPI_9705_EMID_BIT3(pm_pkg.var);
	}

END:
	return res;
}

static unsigned int
syno_sata_pmp_read_switch_mode(struct ata_port *ap)
{
#define GPI_3XXX_SWITCHMODE_BIT(GPIO)	((1<<5)&GPIO)>>5
#define GPI_9705_SWITCHMODE_BIT(GPIO)	(1&GPIO)
	int iRes = 0;
	SYNO_PM_PKG stPmPkg;

	if (NULL == ap) {
		goto END;
	}

	if (IS_SYNOLOGY_RX4(ap->PMSynoUnique) ||
		IS_SYNOLOGY_DX5(ap->PMSynoUnique) ||
		IS_SYNOLOGY_DXC(ap->PMSynoUnique) ||
		IS_SYNOLOGY_RXC(ap->PMSynoUnique)) {
		ap->PMSynoSwitchMode = PMP_SWITCH_MODE_UNKNOWN;
		goto END;
	}

	if (syno_pm_is_synology_3xxx(ap)) {
		syno_pm_raidledstate_pkg_init(sata_pmp_gscr_vendor(ap->link.device->gscr),
				sata_pmp_gscr_devid(ap->link.device->gscr),
				&stPmPkg);

		iRes = syno_sata_pmp_read_gpio(ap, &stPmPkg);
		if (0 != iRes) {
			goto END;
		}

		if (0 == GPI_3XXX_SWITCHMODE_BIT(stPmPkg.var)){
			ap->PMSynoSwitchMode = PMP_SWITCH_MODE_MANUAL;
		} else {
			ap->PMSynoSwitchMode = PMP_SWITCH_MODE_AUTO;
		}
	} else if (syno_pm_is_synology_9705(ap)) {
		syno_pm_systemstate_pkg_init(sata_pmp_gscr_vendor(ap->link.device->gscr),
									sata_pmp_gscr_devid(ap->link.device->gscr),
									&stPmPkg);

		iRes = syno_sata_pmp_read_gpio(ap, &stPmPkg);
		if (0 != iRes) {
			goto END;
		}

		if (0 == GPI_9705_SWITCHMODE_BIT(stPmPkg.var)){
			ap->PMSynoSwitchMode = PMP_SWITCH_MODE_MANUAL;
		} else {
			ap->PMSynoSwitchMode = PMP_SWITCH_MODE_AUTO;
		}
	}
END:
	return iRes;
}

static unsigned int
syno_sata_pmp_check_powerbtn(struct ata_port *ap)
{
#define GPI_3826_POWERDISABLE_BIT(GPIO)	((1<<4)&GPIO)>>4
#define GPI_9705_POWERDISABLE_BIT(GPIO)	((1<<5)&GPIO)>>5
	int iRes = 0;
	SYNO_PM_PKG stPmPkg;

	if (NULL == ap) {
		goto END;
	}

	if (IS_SYNOLOGY_RX4(ap->PMSynoUnique) ||
		IS_SYNOLOGY_DX5(ap->PMSynoUnique) ||
		IS_SYNOLOGY_DXC(ap->PMSynoUnique) ||
		IS_SYNOLOGY_RXC(ap->PMSynoUnique)) {
		goto END;
	}

	syno_pm_raidledstate_pkg_init(sata_pmp_gscr_vendor(ap->link.device->gscr),
							sata_pmp_gscr_devid(ap->link.device->gscr),
							&stPmPkg);

	iRes = syno_sata_pmp_read_gpio(ap, &stPmPkg);

	if (0 != iRes) {
		goto END;
	}

	if ((syno_pm_is_synology_3xxx(ap) && 0 == GPI_3826_POWERDISABLE_BIT(stPmPkg.var)) ||
		(syno_pm_is_synology_9705(ap) && 1 == GPI_9705_POWERDISABLE_BIT(stPmPkg.var))) {
		goto END;
	}

	syno_pm_enable_powerbtn_pkg_init(sata_pmp_gscr_vendor(ap->link.device->gscr),
									sata_pmp_gscr_devid(ap->link.device->gscr),
									&stPmPkg);

	syno_sata_pmp_write_gpio(ap, &stPmPkg);

END:
	return iRes;
}

u8
syno_is_synology_pm(const struct ata_port *ap)
{
	u8 ret = 0;

	if (!sata_pmp_gscr_ports(ap->link.device->gscr)) {
		goto END;
	}

	if (!is_ebox_support()) {
		goto END;
	}

	if (0 >= ap->PMSynoUnique) {
		goto END;
	}

	if (syno_pm_is_synology_3xxx(ap)) {
		ret = 1;
		goto END;
	}

	if (syno_pm_is_synology_9705(ap)) {
		ret = 1;
		goto END;
	}

END:
	return ret;
}

u32
syno_pmp_ports_num(struct ata_port *ap)
{
	u32 ret = 1;

	if (syno_is_synology_pm(ap)) {
		ret = sata_pmp_gscr_ports(ap->link.device->gscr);

		if (syno_pm_is_synology_3xxx(ap) ||
			syno_pm_is_synology_9705(ap)) {
			 
			ret = 5;
		}
		 
#ifdef MY_ABC_HERE
		 
		if (syno_pm_is_synology_3xxx(ap) && (ap->link.uiStsFlags & SYNO_STATUS_IS_MV9235)) {
			if (syno_is_hw_version(HW_DS1517p) ||
					syno_is_hw_version(HW_DS1817p)) {
				 
			} else {
				ata_port_printk(ap, KERN_ERR, "This expansion unit is unsupported\n");
				ret = 0;
			}
		}
#endif  
	}
	return ret;
}

static unsigned char
syno_pm_is_poweron(struct ata_port *ap)
{
#define GPI_3XXX_PSU_OFF(GPIO)		(0x2&GPIO)
#define GPI_9705_PSU_OFF(GPIO)		!(0x20&GPIO)
	int iRes = 0;
	SYNO_PM_PKG stPmPkg;

	if (NULL == ap) {
		goto END;
	}

	syno_pm_fanstatus_pkg_init(sata_pmp_gscr_vendor(ap->link.device->gscr),
								sata_pmp_gscr_devid(ap->link.device->gscr),
								&stPmPkg);

	iRes = syno_sata_pmp_read_gpio(ap, &stPmPkg);

	if (0 != iRes) {
		goto END;
	}

	if ((syno_pm_is_synology_3xxx(ap) && GPI_3XXX_PSU_OFF(stPmPkg.var)) ||
	    (syno_pm_is_synology_9705(ap) && GPI_9705_PSU_OFF(stPmPkg.var))) {
		goto END;
	}

	iRes = 1;
END:
	return iRes;
}

static inline void
syno_prepare_custom_info(struct ata_port *ap)
{
	syno_libata_pm_power_ctl(ap, 1, 1);
}

void
syno_9705_workaround(struct ata_port *ap)
{
	struct Scsi_Host *pMaster_host = NULL;
	struct ata_port *pAp_master = NULL;
	int i = 0;
	int iAtaPrintIdMax;

	iAtaPrintIdMax = atomic_read(&ata_print_id) + 1;
	for (i = 1; i < iAtaPrintIdMax; i++) {
		if (NULL == (pMaster_host = scsi_host_lookup(i - 1))) {
			continue;
		}

		if (NULL == (pAp_master = ata_shost_to_port(pMaster_host))) {
			goto CONTINUE_FOR;
		}

		if (ap->host == pAp_master->host || ap->port_no == pAp_master->port_no) {
			if (ap->PMSynoUnique != pAp_master->PMSynoUnique) {
				if (syno_pm_is_synology_9705(pAp_master)) {
					ata_port_printk(ap, KERN_ERR,
							"replace unique %x with master unique %x\n",
							ap->PMSynoUnique, pAp_master->PMSynoUnique);
					ap->PMSynoUnique = pAp_master->PMSynoUnique;
				} else {
					ata_port_printk(ap, KERN_ERR,
							"WARNING : master unique is not syno 9705, don't replace\n");
				}

				break;
			}
		}

CONTINUE_FOR:
		scsi_host_put(pMaster_host);
		pMaster_host = NULL;
		pAp_master = NULL;
	}

	if (NULL != pMaster_host) {
		scsi_host_put(pMaster_host);
	}
}

int
syno_libata_pm_power_ctl(struct ata_port *ap, u8 blPowerOn, u8 blCustomInfo)
{
	SYNO_PM_PKG pm_pkg;
	int iRet = -1;
	int iRetry = 0;
	unsigned long flags = 0;

	if (NULL == ap) {
		goto END;
	}

	spin_lock_irqsave(ap->lock, flags);
	while (ap->pflags & ATA_PFLAG_PMP_PMCTL) {
		DBGMESG("port %d can't do pmp power ctl %d, must waiting for others\n", ap->print_id, blPowerOn);
		spin_unlock_irqrestore(ap->lock, flags);
		schedule_timeout_uninterruptible(HZ);
		spin_lock_irqsave(ap->lock, flags);
	}
	 
	ap->pflags |= ATA_PFLAG_PMP_PMCTL;
	 
	if (ap->pflags & ATA_PFLAG_FROZEN) {
		printk("ata%u: is FROZEN, thaw it now\n", ap->print_id);
		spin_unlock_irqrestore(ap->lock, flags);
		ata_eh_thaw_port(ap);
		spin_lock_irqsave(ap->lock, flags);
	}
	DBGMESG("port %d do pmp power ctl %d, and thaw it\n", ap->print_id, blPowerOn);
	spin_unlock_irqrestore(ap->lock, flags);
	syno_pm_unique_pkg_init(sata_pmp_gscr_vendor(ap->link.device->gscr),
							sata_pmp_gscr_devid(ap->link.device->gscr),
							&pm_pkg);

	if (syno_sata_pmp_read_gpio(ap, &pm_pkg)) {
		printk("ata%d pm unique read fail\n", ap->print_id);
		ap->uiStsFlags |= SYNO_STATUS_DEEP_SLEEP_FAILED;
		goto END;
	}

	if (blCustomInfo) {
		if (syno_pm_is_3xxx(sata_pmp_gscr_vendor(ap->link.device->gscr),
							sata_pmp_gscr_devid(ap->link.device->gscr))) {
			ap->PMSynoUnique = pm_pkg.var;
		} else if (syno_pm_is_9705(sata_pmp_gscr_vendor(ap->link.device->gscr),
								   sata_pmp_gscr_devid(ap->link.device->gscr))) {
			ap->PMSynoUnique = pm_pkg.var & 0x1f;

			if (!syno_pm_is_synology_9705(ap)) {
				syno_9705_workaround(ap);
			}
		}
	}

	if(IS_SYNOLOGY_DXC(ap->PMSynoUnique) ||
	   IS_SYNOLOGY_RXC(ap->PMSynoUnique) ||
	   IS_SYNOLOGY_RX1214(ap->PMSynoUnique) ||
	   IS_SYNOLOGY_RX1217(ap->PMSynoUnique) ||
	   IS_SYNOLOGY_DX1215(ap->PMSynoUnique)) {
		if(0 != ap->PMSynoEMID) {
			goto END;
		}
	}

	if (1 == ap->PMSynoPowerDisable) {
		goto SKIP_POWER_ON;
	}

	for (iRetry = 0; blPowerOn ^ syno_pm_is_poweron(ap)
					 && iRetry < SYNO_PMP_PWR_TRIES; ++iRetry) {

		if (!blPowerOn) {
			if (syno_sata_pmp_check_powerbtn(ap)) {
				printk("check Eunit port %d power button fail\n", ap->print_id);
			}

		}

		syno_pm_poweron_pkg_init(sata_pmp_gscr_vendor(ap->link.device->gscr),
								 sata_pmp_gscr_devid(ap->link.device->gscr),
								 &pm_pkg, 0);
		if (syno_sata_pmp_write_gpio(ap, &pm_pkg)) {
			printk("ata%d pm poweron write 0 fail\n", ap->print_id);
			goto END;
		}

		if (blPowerOn) {
			if (IS_SYNOLOGY_DX213(ap->PMSynoUnique)) {
				mdelay(700);  
			} else {
				mdelay(5);  
			}
		} else {
			mdelay(7000);  
		}

		syno_pm_poweron_pkg_init(sata_pmp_gscr_vendor(ap->link.device->gscr),
								 sata_pmp_gscr_devid(ap->link.device->gscr),
								 &pm_pkg, 1);
		if (syno_sata_pmp_write_gpio(ap, &pm_pkg)) {
			if (system_state != SYSTEM_POWER_OFF) {
				printk("ata%d pm poweron write 1 fail\n", ap->print_id);
			}
			goto END;
		}

		if (blPowerOn) {
			DBGMESG("port %d delay 3000ms wait for HW ready\n", ap->print_id);
			mdelay(3000);

			ata_port_printk(ap, KERN_INFO, "PMP Power control set ATA_EH_SYNO_PWON\n");
			ap->link.eh_context.i.action |= ATA_EH_SYNO_PWON;
		}

		mdelay(1000);

		syno_pm_unique_pkg_init(sata_pmp_gscr_vendor(ap->link.device->gscr),
				sata_pmp_gscr_devid(ap->link.device->gscr),
				&pm_pkg);

		if (syno_sata_pmp_read_gpio(ap, &pm_pkg)) {
			printk("ata%d re-check pm unique read fail\n", ap->print_id);
			goto END;
		}

		if (blPowerOn ^ syno_pm_is_poweron(ap)) {
			if (iRetry == (SYNO_PMP_PWR_TRIES - 1)) {
				printk("port %d do pmp power ctl %d after %d tries fail\n",
						ap->print_id, blPowerOn, SYNO_PMP_PWR_TRIES);
			} else {
				printk("port %d do pmp power ctl %d fail, retry it\n", ap->print_id, blPowerOn);
			}
		} else {
			break;
		}
	}

	if (blCustomInfo && blPowerOn) {
		syno_sata_pmp_read_cpld_ver(ap);

		syno_sata_pmp_read_emid(ap);

		mdelay(1000);

		if(syno_sata_pmp_is_rp(ap)) {
			ap->PMSynoIsRP = 1;
		}else{
			ap->PMSynoIsRP = 0;
		}
	}

SKIP_POWER_ON:
	syno_sata_pmp_read_switch_mode(ap);

	iRet = 0;

END:
	 
	DBGMESG("port %d do pmp power ctl %d done iRet %d\n", ap->print_id, blPowerOn, iRet);
	spin_lock_irqsave(ap->lock, flags);
	ap->pflags &= ~ATA_PFLAG_PMP_PMCTL;
	spin_unlock_irqrestore(ap->lock, flags);
	return iRet;
}
#endif  

int sata_pmp_qc_defer_cmd_switch(struct ata_queued_cmd *qc)
{
	struct ata_link *link = qc->dev->link;
	struct ata_port *ap = link->ap;

	if (ap->excl_link == NULL || ap->excl_link == link) {
		if (ap->nr_active_links == 0 || ata_link_active(link)) {
			qc->flags |= ATA_QCFLAG_CLEAR_EXCL;
			return ata_std_qc_defer(qc);
		}

		ap->excl_link = link;
	}

	return ATA_DEFER_PORT;
}

int sata_pmp_scr_read(struct ata_link *link, int reg, u32 *r_val)
{
	unsigned int err_mask;

	if (reg > SATA_PMP_PSCR_CONTROL)
		return -EINVAL;

	err_mask = sata_pmp_read(link, reg, r_val);
	if (err_mask) {
		ata_link_warn(link, "failed to read SCR %d (Emask=0x%x)\n",
			      reg, err_mask);
		return -EIO;
	}
	return 0;
}

int sata_pmp_scr_write(struct ata_link *link, int reg, u32 val)
{
	unsigned int err_mask;

	if (reg > SATA_PMP_PSCR_CONTROL)
		return -EINVAL;

	err_mask = sata_pmp_write(link, reg, val);
	if (err_mask) {
		ata_link_warn(link, "failed to write SCR %d (Emask=0x%x)\n",
			      reg, err_mask);
		return -EIO;
	}
	return 0;
}

int sata_pmp_set_lpm(struct ata_link *link, enum ata_lpm_policy policy,
		     unsigned hints)
{
	return sata_link_scr_lpm(link, policy, true);
}

static int sata_pmp_read_gscr(struct ata_device *dev, u32 *gscr)
{
	static const int gscr_to_read[] = { 0, 1, 2, 32, 33, 64, 96 };
	int i;

	for (i = 0; i < ARRAY_SIZE(gscr_to_read); i++) {
		int reg = gscr_to_read[i];
		unsigned int err_mask;

		err_mask = sata_pmp_read(dev->link, reg, &gscr[reg]);
		if (err_mask) {
			ata_dev_err(dev, "failed to read PMP GSCR[%d] (Emask=0x%x)\n",
				    reg, err_mask);
			return -EIO;
		}
	}

	return 0;
}

static const char *sata_pmp_spec_rev_str(const u32 *gscr)
{
	u32 rev = gscr[SATA_PMP_GSCR_REV];

	if (rev & (1 << 3))
		return "1.2";
	if (rev & (1 << 2))
		return "1.1";
	if (rev & (1 << 1))
		return "1.0";
	return "<unknown>";
}

#define PMP_GSCR_SII_POL 129

static int sata_pmp_configure(struct ata_device *dev, int print_info)
{
	struct ata_port *ap = dev->link->ap;
	u32 *gscr = dev->gscr;
	u16 vendor = sata_pmp_gscr_vendor(gscr);
	u16 devid = sata_pmp_gscr_devid(gscr);
	unsigned int err_mask = 0;
	const char *reason;
	int nr_ports, rc;

#ifdef MY_ABC_HERE
	nr_ports = syno_pmp_ports_num(ap);
#else
	nr_ports = sata_pmp_gscr_ports(gscr);
#endif  

	if (nr_ports <= 0 || nr_ports > SATA_PMP_MAX_PORTS) {
		rc = -EINVAL;
		reason = "invalid nr_ports";
		goto fail;
	}

	if ((ap->flags & ATA_FLAG_AN) &&
	    (gscr[SATA_PMP_GSCR_FEAT] & SATA_PMP_FEAT_NOTIFY))
		dev->flags |= ATA_DFLAG_AN;

	err_mask = sata_pmp_write(dev->link, SATA_PMP_GSCR_ERROR_EN,
				  SERR_PHYRDY_CHG);
	if (err_mask) {
		rc = -EIO;
		reason = "failed to write GSCR_ERROR_EN";
		goto fail;
	}

	if (vendor == 0x1095 && (devid == 0x3726 || devid == 0x3826)) {
		u32 reg;

		err_mask = sata_pmp_read(&ap->link, PMP_GSCR_SII_POL, &reg);
		if (err_mask) {
			rc = -EIO;
			reason = "failed to read Sil3x26 Private Register";
			goto fail;
		}
		reg &= ~0x1;
		err_mask = sata_pmp_write(&ap->link, PMP_GSCR_SII_POL, reg);
		if (err_mask) {
			rc = -EIO;
			reason = "failed to write Sil3x26 Private Register";
			goto fail;
		}
#ifdef MY_ABC_HERE
		ap->uiStsFlags |= SYNO_STATUS_IS_SIL3x26;
#endif  
	}

	if (print_info) {
		ata_dev_info(dev, "Port Multiplier %s, "
			     "0x%04x:0x%04x r%d, %d ports, feat 0x%x/0x%x\n",
			     sata_pmp_spec_rev_str(gscr), vendor, devid,
			     sata_pmp_gscr_rev(gscr),
			     nr_ports, gscr[SATA_PMP_GSCR_FEAT_EN],
			     gscr[SATA_PMP_GSCR_FEAT]);

		if (!(dev->flags & ATA_DFLAG_AN))
			ata_dev_info(dev,
				"Asynchronous notification not supported, "
				"hotplug won't work on fan-out ports. Use warm-plug instead.\n");
	}

	return 0;

 fail:
	ata_dev_err(dev,
		    "failed to configure Port Multiplier (%s, Emask=0x%x)\n",
		    reason, err_mask);
	return rc;
}

static int sata_pmp_init_links (struct ata_port *ap, int nr_ports)
{
	struct ata_link *pmp_link = ap->pmp_link;
	int i, err;

	if (!pmp_link) {
		pmp_link = kzalloc(sizeof(pmp_link[0]) * SATA_PMP_MAX_PORTS,
				   GFP_NOIO);
		if (!pmp_link)
			return -ENOMEM;

		for (i = 0; i < SATA_PMP_MAX_PORTS; i++)
			ata_link_init(ap, &pmp_link[i], i);

		ap->pmp_link = pmp_link;

		for (i = 0; i < SATA_PMP_MAX_PORTS; i++) {
			err = ata_tlink_add(&pmp_link[i]);
			if (err) {
				goto err_tlink;
			}
		}
	}

	for (i = 0; i < nr_ports; i++) {
		struct ata_link *link = &pmp_link[i];
		struct ata_eh_context *ehc = &link->eh_context;

		link->flags = 0;
		ehc->i.probe_mask |= ATA_ALL_DEVICES;
		ehc->i.action |= ATA_EH_RESET;
	}

	return 0;
  err_tlink:
	while (--i >= 0)
		ata_tlink_delete(&pmp_link[i]);
	kfree(pmp_link);
	ap->pmp_link = NULL;
	return err;
}

static void sata_pmp_quirks(struct ata_port *ap)
{
	u32 *gscr = ap->link.device->gscr;
	u16 vendor = sata_pmp_gscr_vendor(gscr);
	u16 devid = sata_pmp_gscr_devid(gscr);
	struct ata_link *link;
#ifdef MY_ABC_HERE
	u32 scontrol = 0;
#endif  

	if (vendor == 0x1095 && (devid == 0x3726 || devid == 0x3826)) {
		 
		ata_for_each_link(link, ap, EDGE) {
			 
			link->flags |= ATA_LFLAG_NO_LPM;

			if (link->pmp < 5)
#ifdef MY_ABC_HERE
				link->flags |= ATA_LFLAG_ASSUME_ATA;
#else
				link->flags |= ATA_LFLAG_NO_SRST |
					       ATA_LFLAG_ASSUME_ATA;
#endif  

			if (link->pmp == 5)
				link->flags |= ATA_LFLAG_NO_SRST |
					       ATA_LFLAG_ASSUME_SEMB;
#ifdef MY_ABC_HERE
			sata_pmp_scr_read(link, SATA_PMP_PSCR_CONTROL, &scontrol);

			if (scontrol & 0x0f0) {
				sata_pmp_scr_write(link, SATA_PMP_PSCR_CONTROL, (scontrol & (~0x0f0)));
			}
#endif  
		}
	} else if (vendor == 0x1095 && devid == 0x4723) {
		 
		ata_for_each_link(link, ap, EDGE)
			link->flags |= ATA_LFLAG_NO_LPM |
				       ATA_LFLAG_NO_SRST |
				       ATA_LFLAG_ASSUME_ATA;
	} else if (vendor == 0x1095 && devid == 0x4726) {
		 
		ata_for_each_link(link, ap, EDGE) {
			 
			link->flags |= ATA_LFLAG_NO_LPM;

			if (link->pmp <= 5)
				link->flags |= ATA_LFLAG_NO_SRST |
					       ATA_LFLAG_ASSUME_ATA;

			if (link->pmp == 6)
				link->flags |= ATA_LFLAG_NO_SRST |
					       ATA_LFLAG_ASSUME_SEMB;
		}
	} else if (vendor == 0x1095 && (devid == 0x5723 || devid == 0x5733 ||
					devid == 0x5734 || devid == 0x5744)) {
		 
		ap->pmp_link[ap->nr_pmp_links - 1].flags |= ATA_LFLAG_NO_RETRY;
	} else if (vendor == 0x197b && (devid == 0x2352 || devid == 0x0325)) {
		 
		ata_for_each_link(link, ap, EDGE) {
			 
			link->flags |= ATA_LFLAG_NO_LPM |
				       ATA_LFLAG_NO_SRST |
				       ATA_LFLAG_ASSUME_ATA;
		}
	} else if (vendor == 0x11ab && devid == 0x4140) {
		 
		ata_for_each_link(link, ap, EDGE) {
			 
			if (link->pmp == 4)
				link->flags |= ATA_LFLAG_DISABLED;
		}
	}
}

int sata_pmp_attach(struct ata_device *dev)
{
	struct ata_link *link = dev->link;
	struct ata_port *ap = link->ap;
	unsigned long flags;
	struct ata_link *tlink;
	int rc;
#ifdef MY_ABC_HERE
	u32 target = 0, target_limit = 0;
#endif  
#ifdef MY_ABC_HERE
	struct pci_dev *pdev = NULL;
#endif  

	if (!sata_pmp_supported(ap)) {
		ata_dev_err(dev, "host does not support Port Multiplier\n");
		return -EINVAL;
	}

	if (!ata_is_host_link(link)) {
		ata_dev_err(dev, "Port Multipliers cannot be nested\n");
		return -EINVAL;
	}

	if (dev->devno) {
		ata_dev_err(dev, "Port Multiplier must be the first device\n");
		return -EINVAL;
	}

	WARN_ON(link->pmp != 0);
	link->pmp = SATA_PMP_CTRL_PORT;

	rc = sata_pmp_read_gscr(dev, dev->gscr);
	if (rc)
		goto fail;

#ifdef MY_ABC_HERE
	 
	syno_pm_gpio_config(ap);
	syno_prepare_custom_info(ap);
#ifdef MY_ABC_HERE
	 
	if (IS_SYNOLOGY_DX510(ap->PMSynoUnique)) {
		target = 1;
		target_limit = (1 << target) - 1;

		if (link->sata_spd_limit != target_limit) {
			ata_dev_printk(dev, KERN_ERR,
					"Enhance DX510 compatibility, limit the speed to 1.5 Gbps\n");

			link->sata_spd_limit = target_limit;
		}
	}
#endif  
#ifdef MY_ABC_HERE
	if (0 == ap->PMSynoEMID) {
		ap->pflags |= ATA_PFLAG_SYNO_BOOT_PROBE;
	}
#endif  
#endif  
	 
	rc = sata_pmp_configure(dev, 1);
	if (rc)
		goto fail;

#ifdef MY_ABC_HERE
	if (ap->host) {
		pdev = to_pci_dev(ap->host->dev);
	}
	 
	if (pdev && ((pdev->vendor == 0x1095 && pdev->device == 0x3132) ||
				 (pdev->vendor == 0x1095 && pdev->device == 0x3531) ||
				 (pdev->vendor == 0x1b4b && pdev->device == 0x9215)) ) {
		ap->syno_pm_need_retry = PM_RETRY;
	}else if (pdev && ((pdev->vendor == 0x1b4b && pdev->device == 0x9170))) {
		 
		ap->syno_pm_need_retry = PM_ALWAYS_RETRY;
	}

#endif  

#ifdef MY_ABC_HERE
	rc = sata_pmp_init_links(ap, syno_pmp_ports_num(ap));
#else
	rc = sata_pmp_init_links(ap, sata_pmp_gscr_ports(dev->gscr));
#endif  
	if (rc) {
		ata_dev_info(dev, "failed to initialize PMP links\n");
		goto fail;
	}

	spin_lock_irqsave(ap->lock, flags);
	WARN_ON(ap->nr_pmp_links);
#ifdef MY_ABC_HERE
	ap->nr_pmp_links = syno_pmp_ports_num(ap);
#else
	ap->nr_pmp_links = sata_pmp_gscr_ports(dev->gscr);
#endif  
	spin_unlock_irqrestore(ap->lock, flags);

	sata_pmp_quirks(ap);

#ifdef MY_ABC_HERE
	syno_pm_device_config(ap);
#endif

	if (ap->ops->pmp_attach)
		ap->ops->pmp_attach(ap);

	ata_for_each_link(tlink, ap, EDGE)
		sata_link_init_spd(tlink);

#ifdef MY_ABC_HERE
	ap->pflags |= ATA_PFLAG_PMP_CONNECT;
#endif  

	return 0;

 fail:
	link->pmp = 0;
	return rc;
}

static void sata_pmp_detach(struct ata_device *dev)
{
	struct ata_link *link = dev->link;
	struct ata_port *ap = link->ap;
	struct ata_link *tlink;
	unsigned long flags;

	ata_dev_info(dev, "Port Multiplier detaching\n");

	WARN_ON(!ata_is_host_link(link) || dev->devno ||
		link->pmp != SATA_PMP_CTRL_PORT);

#ifdef MY_ABC_HERE
	ata_for_each_link(tlink, ap, EDGE) {
		unsigned int *classes = tlink->eh_context.classes;
		struct ata_device *tdev = tlink->device;
		classes[tdev->devno] = ATA_DEV_UNKNOWN;
	}
#endif  
#ifdef MY_ABC_HERE
	ap->PMSynoUnique = 0;
#endif  

	if (ap->ops->pmp_detach)
		ap->ops->pmp_detach(ap);

	ata_for_each_link(tlink, ap, EDGE)
		ata_eh_detach_dev(tlink->device);

	spin_lock_irqsave(ap->lock, flags);
	ap->nr_pmp_links = 0;
	link->pmp = 0;
	spin_unlock_irqrestore(ap->lock, flags);

#ifdef MY_ABC_HERE
	ap->pflags |= ATA_PFLAG_PMP_DISCONNECT;
	ata_dev_printk(dev, KERN_WARNING, "flag ATA_PFLAG_PMP_DISCONNECT on (pflags=0x%x)\n", dev->link->ap->pflags);
#endif  
#ifdef MY_ABC_HERE
	ap->uiStsFlags &= !SYNO_STATUS_IS_SIL3x26;
#endif  
}

static int sata_pmp_same_pmp(struct ata_device *dev, const u32 *new_gscr)
{
	const u32 *old_gscr = dev->gscr;
	u16 old_vendor, new_vendor, old_devid, new_devid;
	int old_nr_ports, new_nr_ports;
#ifdef MY_ABC_HERE
	struct ata_port *ap = dev->link->ap;
	u32 old_syno_unique = ap->PMSynoUnique;
#endif  

	old_vendor = sata_pmp_gscr_vendor(old_gscr);
	new_vendor = sata_pmp_gscr_vendor(new_gscr);
	old_devid = sata_pmp_gscr_devid(old_gscr);
	new_devid = sata_pmp_gscr_devid(new_gscr);
#ifdef MY_ABC_HERE
	new_nr_ports = old_nr_ports = syno_pmp_ports_num(ap);
#else
	old_nr_ports = sata_pmp_gscr_ports(old_gscr);
	new_nr_ports = sata_pmp_gscr_ports(new_gscr);
#endif  

	if (old_vendor != new_vendor) {
		ata_dev_info(dev,
			     "Port Multiplier vendor mismatch '0x%x' != '0x%x'\n",
			     old_vendor, new_vendor);
		return 0;
	}

	if (old_devid != new_devid) {
		ata_dev_info(dev,
			     "Port Multiplier device ID mismatch '0x%x' != '0x%x'\n",
			     old_devid, new_devid);
		return 0;
	}

	if (old_nr_ports != new_nr_ports) {
		ata_dev_info(dev,
			     "Port Multiplier nr_ports mismatch '0x%x' != '0x%x'\n",
			     old_nr_ports, new_nr_ports);
		return 0;
	}

#ifdef MY_ABC_HERE
	 
	syno_pm_gpio_config(ap);
	syno_prepare_custom_info(ap);
	if (SYNO_UNIQUE(old_syno_unique) != SYNO_UNIQUE(ap->PMSynoUnique)) {
		ata_dev_printk(dev, KERN_ERR,
					   "Got different EBox Model old [0x%x], new [0x%x]\n", SYNO_UNIQUE(old_syno_unique), SYNO_UNIQUE(ap->PMSynoUnique));
		return 0;
	}
	syno_pm_device_config(ap);
#endif  

	return 1;
}

static int sata_pmp_revalidate(struct ata_device *dev, unsigned int new_class)
{
	struct ata_link *link = dev->link;
	struct ata_port *ap = link->ap;
	u32 *gscr = (void *)ap->sector_buf;
	int rc;
#if defined(MY_DEF_HERE)
	struct ata_port *master_ap = NULL;
#endif  

	DPRINTK("ENTER\n");

	ata_eh_about_to_do(link, NULL, ATA_EH_REVALIDATE);

	if (!ata_dev_enabled(dev)) {
		rc = -ENODEV;
		goto fail;
	}

	if (ata_class_enabled(new_class) && new_class != ATA_DEV_PMP) {
		rc = -ENODEV;
		goto fail;
	}

	rc = sata_pmp_read_gscr(dev, gscr);
	if (rc)
		goto fail;

	if (!sata_pmp_same_pmp(dev, gscr)) {
		rc = -ENODEV;
		goto fail;
	}

	memcpy(dev->gscr, gscr, sizeof(gscr[0]) * SATA_PMP_GSCR_DWORDS);

	rc = sata_pmp_configure(dev, 0);
	if (rc)
		goto fail;

	ata_eh_done(link, NULL, ATA_EH_REVALIDATE);

	DPRINTK("EXIT, rc=0\n");
	return 0;

 fail:

	ata_dev_err(dev, "PMP revalidation failed (errno=%d)\n", rc);
	DPRINTK("EXIT, rc=%d\n", rc);
	return rc;
}

static int sata_pmp_revalidate_quick(struct ata_device *dev)
{
	unsigned int err_mask;
	u32 prod_id;

	err_mask = sata_pmp_read(dev->link, SATA_PMP_GSCR_PROD_ID, &prod_id);
	if (err_mask) {
		ata_dev_err(dev,
			    "failed to read PMP product ID (Emask=0x%x)\n",
			    err_mask);
		return -EIO;
	}

	if (prod_id != dev->gscr[SATA_PMP_GSCR_PROD_ID]) {
		ata_dev_err(dev, "PMP product ID mismatch\n");
		 
		return -EIO;
	}

	return 0;
}

static int sata_pmp_eh_recover_pmp(struct ata_port *ap,
		ata_prereset_fn_t prereset, ata_reset_fn_t softreset,
		ata_reset_fn_t hardreset, ata_postreset_fn_t postreset)
{
	struct ata_link *link = &ap->link;
	struct ata_eh_context *ehc = &link->eh_context;
	struct ata_device *dev = link->device;
	int tries = ATA_EH_PMP_TRIES;
	int detach = 0, rc = 0;
	int reval_failed = 0;

	DPRINTK("ENTER\n");

	if (dev->flags & ATA_DFLAG_DETACH) {
		detach = 1;
#ifdef MY_ABC_HERE
		ata_dev_printk(dev, KERN_WARNING, "ATA_DFLAG_DETACH (flags=0x%x)\n", dev->flags);
#endif  
		goto fail;
	}

 retry:
	ehc->classes[0] = ATA_DEV_UNKNOWN;

	if (ehc->i.action & ATA_EH_RESET) {
		struct ata_link *tlink;

		rc = ata_eh_reset(link, 0, prereset, softreset, hardreset,
				  postreset);
		if (rc) {
			ata_link_err(link, "failed to reset PMP, giving up\n");
			goto fail;
		}

		ata_for_each_link(tlink, ap, EDGE) {
			struct ata_eh_context *ehc = &tlink->eh_context;

			ehc->i.probe_mask |= ATA_ALL_DEVICES;
			ehc->i.action |= ATA_EH_RESET;
		}
	}

	if (ehc->i.action & ATA_EH_REVALIDATE)
		rc = sata_pmp_revalidate(dev, ehc->classes[0]);
	else
		rc = sata_pmp_revalidate_quick(dev);

	if (rc) {
		tries--;

		if (rc == -ENODEV) {
			ehc->i.probe_mask |= ATA_ALL_DEVICES;
			detach = 1;
			 
			tries = min(tries, 2);
		}

		if (tries) {
			 
			if (reval_failed)
				sata_down_spd_limit(link, 0);
			else
				reval_failed = 1;

			ehc->i.action |= ATA_EH_RESET;
			goto retry;
		} else {
			ata_dev_err(dev,
				    "failed to recover PMP after %d tries, giving up\n",
				    ATA_EH_PMP_TRIES);
			goto fail;
		}
	}

	ehc->i.flags = 0;

	DPRINTK("EXIT, rc=0\n");
	return 0;

 fail:
	sata_pmp_detach(dev);
	if (detach)
		ata_eh_detach_dev(dev);
	else
		ata_dev_disable(dev);

	DPRINTK("EXIT, rc=%d\n", rc);
	return rc;
}

static int sata_pmp_eh_handle_disabled_links(struct ata_port *ap)
{
	struct ata_link *link;
	unsigned long flags;
	int rc;

	spin_lock_irqsave(ap->lock, flags);

	ata_for_each_link(link, ap, EDGE) {
		if (!(link->flags & ATA_LFLAG_DISABLED))
			continue;

		spin_unlock_irqrestore(ap->lock, flags);

		sata_link_hardreset(link, sata_deb_timing_normal,
				ata_deadline(jiffies, ATA_TMOUT_INTERNAL_QUICK),
				NULL, NULL);

		rc = sata_scr_write(link, SCR_ERROR, SERR_PHYRDY_CHG);
		if (rc) {
			ata_link_err(link,
				     "failed to clear SError.N (errno=%d)\n",
				     rc);
			return rc;
		}

		spin_lock_irqsave(ap->lock, flags);
	}

	spin_unlock_irqrestore(ap->lock, flags);

	return 0;
}

static int sata_pmp_handle_link_fail(struct ata_link *link, int *link_tries)
{
	struct ata_port *ap = link->ap;
	unsigned long flags;

	if (link_tries[link->pmp] && --link_tries[link->pmp])
		return 1;

	if (!(link->flags & ATA_LFLAG_DISABLED)) {
		ata_link_warn(link,
			"failed to recover link after %d tries, disabling\n",
			ATA_EH_PMP_LINK_TRIES);

		spin_lock_irqsave(ap->lock, flags);
		link->flags |= ATA_LFLAG_DISABLED;
		spin_unlock_irqrestore(ap->lock, flags);
	}

	ata_dev_disable(link->device);
	link->eh_context.i.action = 0;

	return 0;
}

static int sata_pmp_eh_recover(struct ata_port *ap)
{
	struct ata_port_operations *ops = ap->ops;
	int pmp_tries, link_tries[SATA_PMP_MAX_PORTS];
	struct ata_link *pmp_link = &ap->link;
	struct ata_device *pmp_dev = pmp_link->device;
	struct ata_eh_context *pmp_ehc = &pmp_link->eh_context;
	u32 *gscr = pmp_dev->gscr;
	struct ata_link *link;
	struct ata_device *dev;
	unsigned int err_mask;
	u32 gscr_error, sntf;
	int cnt, rc;

	pmp_tries = ATA_EH_PMP_TRIES;
	ata_for_each_link(link, ap, EDGE)
		link_tries[link->pmp] = ATA_EH_PMP_LINK_TRIES;

 retry:
	 
	if (!sata_pmp_attached(ap)) {
		rc = ata_eh_recover(ap, ops->prereset, ops->softreset,
				    ops->hardreset, ops->postreset, NULL);
		if (rc) {
			ata_for_each_dev(dev, &ap->link, ALL)
				ata_dev_disable(dev);
			return rc;
		}

		if (pmp_dev->class != ATA_DEV_PMP)
			return 0;

		ata_for_each_link(link, ap, EDGE)
			link_tries[link->pmp] = ATA_EH_PMP_LINK_TRIES;

	}

	rc = sata_pmp_eh_recover_pmp(ap, ops->prereset, ops->softreset,
				     ops->hardreset, ops->postreset);
	if (rc)
		goto pmp_fail;

	if (gscr[SATA_PMP_GSCR_FEAT_EN] & SATA_PMP_FEAT_NOTIFY) {
		gscr[SATA_PMP_GSCR_FEAT_EN] &= ~SATA_PMP_FEAT_NOTIFY;

		err_mask = sata_pmp_write(pmp_link, SATA_PMP_GSCR_FEAT_EN,
					  gscr[SATA_PMP_GSCR_FEAT_EN]);
		if (err_mask) {
			ata_link_warn(pmp_link,
				"failed to disable NOTIFY (err_mask=0x%x)\n",
				err_mask);
			goto pmp_fail;
		}
	}

	rc = sata_pmp_eh_handle_disabled_links(ap);
	if (rc)
		goto pmp_fail;

	rc = ata_eh_recover(ap, ops->pmp_prereset, ops->pmp_softreset,
			    ops->pmp_hardreset, ops->pmp_postreset, &link);
	if (rc)
		goto link_fail;

	rc = sata_scr_read(&ap->link, SCR_NOTIFICATION, &sntf);
	if (rc == 0)
		sata_scr_write(&ap->link, SCR_NOTIFICATION, sntf);

	ata_for_each_link(link, ap, EDGE)
		if (link->lpm_policy > ATA_LPM_MAX_POWER)
			return 0;

	if (pmp_dev->flags & ATA_DFLAG_AN) {
		gscr[SATA_PMP_GSCR_FEAT_EN] |= SATA_PMP_FEAT_NOTIFY;

		err_mask = sata_pmp_write(pmp_link, SATA_PMP_GSCR_FEAT_EN,
					  gscr[SATA_PMP_GSCR_FEAT_EN]);
		if (err_mask) {
			ata_dev_err(pmp_dev,
				    "failed to write PMP_FEAT_EN (Emask=0x%x)\n",
				    err_mask);
			rc = -EIO;
			goto pmp_fail;
		}
	}

	err_mask = sata_pmp_read(pmp_link, SATA_PMP_GSCR_ERROR, &gscr_error);
	if (err_mask) {
		ata_dev_err(pmp_dev,
			    "failed to read PMP_GSCR_ERROR (Emask=0x%x)\n",
			    err_mask);
		rc = -EIO;
		goto pmp_fail;
	}

	cnt = 0;
	ata_for_each_link(link, ap, EDGE) {
		if (!(gscr_error & (1 << link->pmp)))
			continue;

		if (sata_pmp_handle_link_fail(link, link_tries)) {
			ata_ehi_hotplugged(&link->eh_context.i);
			cnt++;
		} else {
			ata_link_warn(link,
				"PHY status changed but maxed out on retries, giving up\n");
			ata_link_warn(link,
				"Manually issue scan to resume this link\n");
		}
	}

	if (cnt) {
		ata_port_info(ap,
			"PMP SError.N set for some ports, repeating recovery\n");
		goto retry;
	}

	return 0;

 link_fail:
	if (sata_pmp_handle_link_fail(link, link_tries)) {
		pmp_ehc->i.action |= ATA_EH_RESET;
		goto retry;
	}

 pmp_fail:
	 
	if (ap->pflags & ATA_PFLAG_UNLOADING)
		return rc;

	if (!sata_pmp_attached(ap))
		goto retry;

	if (--pmp_tries) {
		pmp_ehc->i.action |= ATA_EH_RESET;
		goto retry;
	}

	ata_port_err(ap, "failed to recover PMP after %d tries, giving up\n",
		     ATA_EH_PMP_TRIES);
	sata_pmp_detach(pmp_dev);
	ata_dev_disable(pmp_dev);

	return rc;
}

void sata_pmp_error_handler(struct ata_port *ap)
{
	ata_eh_autopsy(ap);
	ata_eh_report(ap);
	sata_pmp_eh_recover(ap);
	ata_eh_finish(ap);
}

EXPORT_SYMBOL_GPL(sata_pmp_port_ops);
EXPORT_SYMBOL_GPL(sata_pmp_qc_defer_cmd_switch);
EXPORT_SYMBOL_GPL(sata_pmp_error_handler);
