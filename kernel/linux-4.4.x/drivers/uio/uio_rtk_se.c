#include <linux/device.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>

#include <linux/miscdevice.h>

#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/uio_driver.h>

#include "reg_se.h"
#include "uio_rtk_se.h"

static struct uio_info    *se_uio_info = NULL;
static struct se_hw       *se_hw = NULL;
static struct se_resource *se_resource = NULL;  //se irq and register area
static SEREG_INFO         se_reg;

//struct semaphore sem_checkfinish;

typedef enum {
	SeClearWriteData	= 0,
	SeWriteData			= BIT(0),
	SeGo				= BIT(1),
	SeEndianSwap		= BIT(2),
} SE_CTRL_REG;

inline void InitSeReg(void)
{
	int i;
	volatile SEREG_INFO  *SeRegInfo = (volatile SEREG_INFO  *)se_resource->base;

	for(i=0; i<SE_NUM_ENGINES; i++){
		//Stop Streaming Engine
		SeRegInfo->SeCtrl[i].Value            = (SeGo | SeEndianSwap | SeClearWriteData);
		SeRegInfo->SeCtrl[i].Value            = (SeEndianSwap | SeWriteData);
		SeRegInfo->SeCmdBase[i].Value         = (uint32_t) se_hw->engine[i].CmdBase;
		SeRegInfo->SeCmdReadPtr[i].Value      = (uint32_t) se_hw->engine[i].CmdBase;
		SeRegInfo->SeCmdWritePtr[i].Value     = (uint32_t) se_hw->engine[i].CmdBase;
		SeRegInfo->SeCmdLimit[i].Value        = (uint32_t) se_hw->engine[i].CmdLimit;
		SeRegInfo->SeInstCntL[i].Value        = 0;
		SeRegInfo->SeInstCntH[i].Value        = 0;

		pr_info("Engine[%d] Ctrl:%08x Base:%08x ReadPtr:%08x WritePtr:%08x Limit:%08x\n",
				i,
				SeRegInfo->SeCtrl[i].Value,
				SeRegInfo->SeCmdBase[i].Value,
				SeRegInfo->SeCmdReadPtr[i].Value,
				SeRegInfo->SeCmdWritePtr[i].Value,
				SeRegInfo->SeCmdLimit[i].Value);

		se_hw->engine[i].CmdWritePtr      = se_hw->engine[i].CmdBase;
	}
}

//static irqreturn_t se_irq_handler(int irq, void* dev_id)
static irqreturn_t se_irq_handler(int irq, struct uio_info *dev_info)
{
//	struct se_dev *dev = dev_id;
	volatile SEREG_INFO *SeRegInfo = (volatile SEREG_INFO*)se_resource->base;
	int i;

	pr_debug("%s:%d interrupt. ...\n", __func__, __LINE__);
	for(i=0; i<SE_NUM_ENGINES; i++){
		if(SeRegInfo->SeInte[i].Fields.com_empty && SeRegInfo->SeInts[i].Fields.com_empty) {
			//dbg_info("se com empty interrupt");
			pr_debug("%s:%d se com empty interrupt. ...\n", __func__, __LINE__);
			SeRegInfo->SeInte[i].Value = 0x8;//inte.Value;  //disable com_empty interrupt
			//SeRegInfo->SeInts[i].Value = 0x8;//ints.Value;  //clear com_empty interrupt status
			/*
			if((SeRegInfo->SeCtrl[i].Value & 0x2) && ((SeRegInfo->SeIdle[i].Value & 0x1) == 0)) {
				//dbg_info("se is not idle");
			}
			*/
		}
	}

	return IRQ_HANDLED;
}

/*
static const struct file_operations se_fops = {
	.owner			= THIS_MODULE,
	.open			= se_open,
	.release		= se_release,
	.unlocked_ioctl	= se_ioctl,
	.write			= se_write,
	.mmap			= se_mmap,
};
*/

void se_drv_init(struct device *dev)
{
	int i;
	void *virt = se_uio_info->mem[2].internal_addr;
	dma_addr_t phys = se_uio_info->mem[2].addr;

	for(i=0; i<SE_NUM_ENGINES; i++){
		se_hw->engine[i].CmdBuf = (unsigned long)virt + SE_CMDBUF_SIZE * i;
		se_hw->engine[i].CmdBase = phys + SE_CMDBUF_SIZE * i;
		se_hw->engine[i].CmdLimit = se_hw->engine[i].CmdBase + SE_CMDBUF_SIZE;
		se_hw->engine[i].BufSize = SE_CMDBUF_SIZE;
	}

	InitSeReg();

//	if (request_irq(se_resource->irq, se_irq_handler, IRQF_SHARED, "se", (void*)se_hw)) {
//		dbg_err("se: cannot register IRQ %d", se_resource->irq);
//	}
}

static int rtk_se_probe(struct platform_device *pdev)
{
	int ret;
	size_t size = 0;
	void *virt = NULL;
	dma_addr_t phys = 0;
	struct resource res;

	//dbg_info("%s %s:%d",__FILE__, __func__, __LINE__);
	//se_hw = kzalloc(ALIGN(sizeof(struct se_dev), PAGE_SIZE), GFP_KERNEL);
	//if (unlikely(!se_hw))
	//	return -ENOMEM;

	se_uio_info = (struct uio_info *)kzalloc(sizeof(struct uio_info), GFP_KERNEL);

	//se register space
	ret = of_address_to_resource(pdev->dev.of_node, 0, &res);
	se_uio_info->mem[0].name = "SE reg space";
	se_uio_info->mem[0].addr = res.start;
	se_uio_info->mem[0].size = ALIGN(res.end - res.start + 1, PAGE_SIZE);
	se_uio_info->mem[0].internal_addr = ioremap(se_uio_info->mem[0].addr, se_uio_info->mem[0].size);
	se_uio_info->mem[0].memtype = UIO_MEM_PHYS;
	pr_info("%s: res.start=0x%p res.end=0x%p\n", __func__,  (void *)res.start, (void *)res.end);
	pr_info("%s: mem[%d] phys:0x%p virt:0x%p size:0x%llx type:%d name:%s\n", __func__, 0, (void *)se_uio_info->mem[0].addr, se_uio_info->mem[0].internal_addr, se_uio_info->mem[0].size, se_uio_info->mem[0].memtype, se_uio_info->mem[0].name);

	//se driver data
	size = ALIGN(sizeof(struct se_hw), PAGE_SIZE);
	virt = dma_alloc_coherent(&pdev->dev, size, &phys, GFP_KERNEL);
	se_hw = virt;
	se_uio_info->mem[1].name = "SE driver data";
	se_uio_info->mem[1].addr = phys;
	se_uio_info->mem[1].size = size;
	se_uio_info->mem[1].internal_addr = virt;
	se_uio_info->mem[1].memtype = UIO_MEM_PHYS;
	pr_info("%s: mem[%d] phys:0x%p virt:0x%p size:0x%llx type:%d name:%s\n", __func__, 1, (void *)se_uio_info->mem[1].addr, se_uio_info->mem[1].internal_addr, se_uio_info->mem[1].size, se_uio_info->mem[1].memtype, se_uio_info->mem[1].name);

	//se command queue
	size = ALIGN(SE_CMDBUF_SIZE * SE_NUM_ENGINES, PAGE_SIZE);
	virt = dma_alloc_coherent(&pdev->dev, size, &phys, GFP_KERNEL);
	se_uio_info->mem[2].name = "SE command queue";
	se_uio_info->mem[2].addr = phys;
	se_uio_info->mem[2].size = size;
	se_uio_info->mem[2].internal_addr = virt;
	se_uio_info->mem[2].memtype = UIO_MEM_PHYS;
	pr_info("%s: mem[%d] phys:0x%p virt:0x%p size:0x%llx type:%d name:%s\n", __func__, 2, (void *)se_uio_info->mem[2].addr, se_uio_info->mem[2].internal_addr, se_uio_info->mem[2].size, se_uio_info->mem[2].memtype, se_uio_info->mem[2].name);

#ifdef CONFIG_UIO_ASSIGN_MINOR
	se_uio_info->minor = 251;
#endif
    se_uio_info->version = "0.0.1";
    se_uio_info->name = "RTK-SE";
    se_uio_info->irq = platform_get_irq(pdev, 0);
	se_uio_info->irq_flags = IRQF_SHARED;
	se_uio_info->handler = se_irq_handler;
	pr_info("%s: irq=%ld\n", __func__, se_uio_info->irq);
	if (uio_register_device(&pdev->dev, se_uio_info))
	{
		iounmap(se_uio_info->mem[0].internal_addr);
		dma_free_coherent(&pdev->dev, se_uio_info->mem[1].size, se_uio_info->mem[1].internal_addr, se_uio_info->mem[1].addr);
		dma_free_coherent(&pdev->dev, se_uio_info->mem[2].size, se_uio_info->mem[2].internal_addr, se_uio_info->mem[2].addr);
		pr_err("uio_register failed\n");
		return -ENODEV;
	}
	platform_set_drvdata(pdev, se_uio_info);

	se_drv_init(&pdev->dev);

	return 0;
}

static int rtk_se_remove(struct platform_device *pdev)
{
	struct uio_info *info = platform_get_drvdata(pdev);

	//dbg_info("%s %s",__FILE__, __func__);
	uio_unregister_device(info);
	platform_set_drvdata(pdev, NULL);
	iounmap(info->mem[0].internal_addr);
	dma_free_coherent(&pdev->dev, info->mem[1].size, info->mem[1].internal_addr, info->mem[1].addr);
	dma_free_coherent(&pdev->dev, info->mem[2].size, info->mem[2].internal_addr, info->mem[2].addr);
	kfree(info);
	kfree(se_hw);

	return 0;
}

static int rtk_se_suspend(struct platform_device *pdev, pm_message_t state)
{
    int i;
    uint8_t *regbak = (uint8_t *)&se_reg;
    uint8_t *reghw  = (uint8_t *)se_resource->base;

	printk(KERN_INFO "[RTK_SE] Enter %s\n", __func__);

    for(i = 0; i < sizeof(SEREG_INFO); i += 4){
        //skip reserved registers to avoid sb2 timeout issue
        if(i >= 0x64 && i < 0x70) continue;     //Reserved
        if(i >= 0xF4 && i < 0x128) continue;    //Reserved
        if(i >= 0x440 && i < 0x458) continue;   //Reserved
        if(i >= 0x4CC && i < 0x4E0) continue;   //Reserved
        if(i >= 0x504 && i < 0x510) continue;   //Reserved

        *(uint32_t *)(regbak + i) = *(uint32_t *)(reghw + i);
    }

	printk(KERN_INFO "[RTK_SE] Exit %s\n", __func__);

	return 0;
}

static int rtk_se_resume(struct platform_device *pdev)
{
    int i;
    uint8_t *regbak = (uint8_t *)&se_reg;
    uint8_t *reghw  = (uint8_t *)se_resource->base;
	volatile SEREG_INFO  *SeRegInfo = (volatile SEREG_INFO  *)se_resource->base;

	printk(KERN_INFO "[RTK_SE] Enter %s\n", __func__);

#if 0
	InitSeReg();
#else
    for(i = 0; i < sizeof(SEREG_INFO); i += 4){
        //skip restoring reserved, read-only, special registers
        if(i >= 0x30 && i < 0x3C) continue;     //SRWORDCNT
        if(i >= 0x40 && i < 0x4C) continue;     //CLR_FMT
        if(i >= 0x64 && i < 0x70) continue;     //Reserved
        if(i >= 0xF4 && i < 0x128) continue;    //Reserved
        if(i >= 0x440 && i < 0x458) continue;   //Reserved
        if(i >= 0x458 && i < 0x464) continue;   //CTRL
        if(i >= 0x474 && i < 0x480) continue;   //INTS
        if(i >= 0x48C && i < 0x498) continue;   //INSTCNT
        if(i == 0x4C8) continue;                //CLUT_LOCK_ST
        if(i >= 0x4CC && i < 0x4E0) continue;   //Reserved
        if(i >= 0x4F8 && i < 0x504) continue;   //SYNC_VO_LOCATION
        if(i >= 0x504 && i < 0x510) continue;   //Reserved
        if(i >= 0x510 && i < 0x51C) continue;   //INSTCNT_H

        *(uint32_t *)(reghw + i) = *(uint32_t *)(regbak + i);
    }

    se_reg.SeColorFormat[0].Fields.write_enable1 = 1;
    se_reg.SeColorFormat[0].Fields.write_enable2 = 1;
    se_reg.SeColorFormat[0].Fields.write_enable5 = 1;
    se_reg.SeColorFormat[0].Fields.write_enable6 = 1;
    se_reg.SeColorFormat[0].Fields.write_enable7 = 1;
    se_reg.SeColorFormat[0].Fields.write_enable8 = 1;
    se_reg.SeColorFormat[0].Fields.write_enable10 = 1;
    SeRegInfo->SeColorFormat[0].Value = se_reg.SeColorFormat[0].Value;
    se_reg.SeColorFormat[1].Fields.write_enable1 = 1;
    se_reg.SeColorFormat[1].Fields.write_enable2 = 1;
    se_reg.SeColorFormat[1].Fields.write_enable5 = 1;
    se_reg.SeColorFormat[1].Fields.write_enable6 = 1;
    se_reg.SeColorFormat[1].Fields.write_enable7 = 1;
    se_reg.SeColorFormat[1].Fields.write_enable8 = 1;
    se_reg.SeColorFormat[1].Fields.write_enable10 = 1;
    SeRegInfo->SeColorFormat[1].Value = se_reg.SeColorFormat[1].Value;
    se_reg.SeColorFormat[2].Fields.write_enable1 = 1;
    se_reg.SeColorFormat[2].Fields.write_enable2 = 1;
    se_reg.SeColorFormat[2].Fields.write_enable5 = 1;
    se_reg.SeColorFormat[2].Fields.write_enable6 = 1;
    se_reg.SeColorFormat[2].Fields.write_enable7 = 1;
    se_reg.SeColorFormat[2].Fields.write_enable8 = 1;
    se_reg.SeColorFormat[2].Fields.write_enable10 = 1;
    SeRegInfo->SeColorFormat[2].Value = se_reg.SeColorFormat[2].Value;

    //clear interrupt status?
    SeRegInfo->SeInts[0].Value = se_reg.SeInts[0].Value;
    SeRegInfo->SeInts[1].Value = se_reg.SeInts[1].Value;
    SeRegInfo->SeInts[2].Value = se_reg.SeInts[2].Value;

    //restore the go bit?
    SeRegInfo->SeCtrl[0].Value = se_reg.SeCtrl[0].Value;
    SeRegInfo->SeCtrl[1].Value = se_reg.SeCtrl[1].Value;
    SeRegInfo->SeCtrl[2].Value = se_reg.SeCtrl[2].Value;
#endif

	printk(KERN_INFO "[RTK_SE] Exit %s\n", __func__);

	return 0;
}

static const struct of_device_id rtk_se_ids[] = {
	{ .compatible = "Realtek,rtk1295-se" },
	{ /* Sentinel */ },
};

static struct platform_driver rtk_se_driver = {
	.probe		= rtk_se_probe,
	.remove		= rtk_se_remove,
	.driver		= {
		.name	= "rtk-se",
		.owner	= THIS_MODULE,
		.of_match_table = rtk_se_ids,
	},
	.suspend        = rtk_se_suspend,
	.resume         = rtk_se_resume,

};

static int __init rtk_se_init(void)
{
	int ret=0;
	struct device_node *np;

	//dbg_info("%s %s",__FILE__, __func__);

	se_resource = kzalloc(sizeof(struct se_resource), GFP_KERNEL);
	if (!se_resource)
		return -ENOMEM;

	np = of_find_matching_node(NULL, rtk_se_ids);
	if (!np)
		panic("No SE device node");

	//se register space and irq for driver access
	se_resource->base = of_iomap(np, 0);
	se_resource->irq = irq_of_parse_and_map(np, 0);
	//dbg_info("base:0x%x irq:%d", (unsigned int)se_resource->base, se_resource->irq);

	ret = platform_driver_register(&rtk_se_driver);
	return ret;
}

static void __exit rtk_se_exit(void)
{
	//dbg_info("%s %s",__FILE__, __func__);

	platform_driver_unregister(&rtk_se_driver);
//	misc_deregister(&se_resource->dev);
	kfree(se_resource);
}

module_init(rtk_se_init);
module_exit(rtk_se_exit);
//module_platform_driver_probe(rtk_se_driver, rtk_se_probe);
