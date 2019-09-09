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

#include "reg_md.h"
#include "uio_rtk_md.h"

struct uio_info    *md_uio_info = NULL;
struct md_hw       *md_hw = NULL;
struct md_resource *md_resource = NULL;  //md irq and register area

//struct semaphore sem_checkfinish;

typedef enum {
	MdClearWriteData	= 0,
	MdWriteData			= BIT(0),
	MdGo				= BIT(1),
	MdEndianSwap		= BIT(2),
} MD_CTRL_REG;

inline void InitMdReg(void)
{
	int i;
	volatile MDREG_INFO  *MdRegInfo = (volatile MDREG_INFO  *)md_resource->base;

	for(i=0; i<MD_NUM_ENGINES; i++){
		//Stop Moving Data
		MdRegInfo->MdCtrl[i].Value            = (MdGo | MdEndianSwap | MdClearWriteData);
		MdRegInfo->MdCtrl[i].Value            = (MdEndianSwap | MdWriteData);
		MdRegInfo->MdCmdBase[i].Value         = (uint32_t) md_hw->engine[i].CmdBase;
		MdRegInfo->MdCmdReadPtr[i].Value      = (uint32_t) md_hw->engine[i].CmdBase;
		MdRegInfo->MdCmdWritePtr[i].Value     = (uint32_t) md_hw->engine[i].CmdBase;
		MdRegInfo->MdCmdLimit[i].Value        = (uint32_t) md_hw->engine[i].CmdLimit;
		MdRegInfo->MdInstCnt[i].Value        = 0;

		pr_info("Engine[%d] Ctrl:%08x Base:%08x ReadPtr:%08x WritePtr:%08x Limit:%08x\n",
				i,
				MdRegInfo->MdCtrl[i].Value,
				MdRegInfo->MdCmdBase[i].Value,
				MdRegInfo->MdCmdReadPtr[i].Value,
				MdRegInfo->MdCmdWritePtr[i].Value,
				MdRegInfo->MdCmdLimit[i].Value);

		md_hw->engine[i].CmdWritePtr      = md_hw->engine[i].CmdBase;
	}
}

//static irqreturn_t md_irq_handler(int irq, void* dev_id)
static irqreturn_t md_irq_handler(int irq, struct uio_info *dev_info)
{
//	struct md_dev *dev = dev_id;
	volatile MDREG_INFO *MdRegInfo = (volatile MDREG_INFO*)md_resource->base;
	int i;

	pr_debug("%s:%d interrupt. ...\n", __func__, __LINE__);
	for(i=0; i<MD_NUM_ENGINES; i++){
		if(MdRegInfo->MdInte[i].Fields.smq_empty_en && MdRegInfo->MdInts[i].Fields.smq_empty) {
			pr_debug("%s:%d md smq empty interrupt. ...\n", __func__, __LINE__);
			MdRegInfo->MdInte[i].Value = 0x8;//inte.Value;  //disable smq_empty interrupt
			//MdRegInfo->MdInts[i].Value = 0x8;//ints.Value;  //clear smq_empty interrupt status
			/*
			if((MdRegInfo->MdCtrl[i].Value & 0x2) && ((MdRegInfo->SeIdle[i].Value & 0x1) == 0)) {
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

void md_drv_init(struct device *dev)
{
	int i;
	void *virt = md_uio_info->mem[2].internal_addr;
	dma_addr_t phys = md_uio_info->mem[2].addr;

	for(i=0; i<MD_NUM_ENGINES; i++){
		md_hw->engine[i].CmdBuf = (unsigned long)virt + MD_CMDBUF_SIZE * i;
		md_hw->engine[i].CmdBase = phys + MD_CMDBUF_SIZE * i;
		md_hw->engine[i].CmdLimit = md_hw->engine[i].CmdBase + MD_CMDBUF_SIZE;
		md_hw->engine[i].BufSize = MD_CMDBUF_SIZE;
	}

	InitMdReg();

//	if (request_irq(se_resource->irq, se_irq_handler, IRQF_SHARED, "se", (void*)md_hw)) {
//		dbg_err("se: cannot register IRQ %d", se_resource->irq);
//	}
}

static int rtk_md_probe(struct platform_device *pdev)
{
	int ret;
	size_t size = 0;
	void *virt = NULL;
	dma_addr_t phys = 0;
	struct resource res;

	//dbg_info("%s %s:%d",__FILE__, __func__, __LINE__);
	//md_hw = kzalloc(ALIGN(sizeof(struct md_dev), PAGE_SIZE), GFP_KERNEL);
	//if (unlikely(!md_hw))
	//	return -ENOMEM;

	md_uio_info = (struct uio_info *)kzalloc(sizeof(struct uio_info), GFP_KERNEL);

	//md register space
	ret = of_address_to_resource(pdev->dev.of_node, 0, &res);
	md_uio_info->mem[0].name = "MD reg space";
	md_uio_info->mem[0].addr = res.start;
	md_uio_info->mem[0].size = ALIGN(res.end - res.start + 1, PAGE_SIZE);
	md_uio_info->mem[0].internal_addr = ioremap(md_uio_info->mem[0].addr, md_uio_info->mem[0].size);
	md_uio_info->mem[0].memtype = UIO_MEM_PHYS;
	pr_info("%s: res.start=0x%p res.end=0x%p\n", __func__,  (void *)res.start, (void *)res.end);
	pr_info("%s: mem[%d] phys:0x%p virt:0x%p size:0x%llx type:%d name:%s\n", __func__, 0, (void *)md_uio_info->mem[0].addr, md_uio_info->mem[0].internal_addr, md_uio_info->mem[0].size, md_uio_info->mem[0].memtype, md_uio_info->mem[0].name);

	//md driver data
	size = ALIGN(sizeof(struct md_hw), PAGE_SIZE);
	virt = dma_alloc_coherent(&pdev->dev, size, &phys, GFP_KERNEL);
	md_hw = virt;
	md_uio_info->mem[1].name = "MD driver data";
	md_uio_info->mem[1].addr = phys;
	md_uio_info->mem[1].size = size;
	md_uio_info->mem[1].internal_addr = virt;
	md_uio_info->mem[1].memtype = UIO_MEM_PHYS;
	pr_info("%s: mem[%d] phys:0x%p virt:0x%p size:0x%llx type:%d name:%s\n", __func__, 1, (void *)md_uio_info->mem[1].addr, md_uio_info->mem[1].internal_addr, md_uio_info->mem[1].size, md_uio_info->mem[1].memtype, md_uio_info->mem[1].name);

	//md command queue
	size = ALIGN(MD_CMDBUF_SIZE * MD_NUM_ENGINES, PAGE_SIZE);
	virt = dma_alloc_coherent(&pdev->dev, size, &phys, GFP_KERNEL);
	md_uio_info->mem[2].name = "MD command queue";
	md_uio_info->mem[2].addr = phys;
	md_uio_info->mem[2].size = size;
	md_uio_info->mem[2].internal_addr = virt;
	md_uio_info->mem[2].memtype = UIO_MEM_PHYS;
	pr_info("%s: mem[%d] phys:0x%p virt:0x%p size:0x%llx type:%d name:%s\n", __func__, 2, (void *)md_uio_info->mem[2].addr, md_uio_info->mem[2].internal_addr, md_uio_info->mem[2].size, md_uio_info->mem[2].memtype, md_uio_info->mem[2].name);

#ifdef CONFIG_UIO_ASSIGN_MINOR
	md_uio_info->minor = 252;
#endif
    md_uio_info->version = "0.0.1";
    md_uio_info->name = "RTK-MD";
    md_uio_info->irq = platform_get_irq(pdev, 0);
	md_uio_info->irq_flags = IRQF_SHARED;
	md_uio_info->handler = md_irq_handler;
	pr_info("%s: irq=%ld\n", __func__, md_uio_info->irq);
	if (uio_register_device(&pdev->dev, md_uio_info))
	{
		iounmap(md_uio_info->mem[0].internal_addr);
		dma_free_coherent(&pdev->dev, md_uio_info->mem[1].size, md_uio_info->mem[1].internal_addr, md_uio_info->mem[1].addr);
		dma_free_coherent(&pdev->dev, md_uio_info->mem[2].size, md_uio_info->mem[2].internal_addr, md_uio_info->mem[2].addr);
		pr_err("uio_register failed\n");
		return -ENODEV;
	}
	platform_set_drvdata(pdev, md_uio_info);

	md_drv_init(&pdev->dev);

	return 0;
}

static int rtk_md_remove(struct platform_device *pdev)
{
	struct uio_info *info = platform_get_drvdata(pdev);

	//dbg_info("%s %s",__FILE__, __func__);
	uio_unregister_device(info);
	platform_set_drvdata(pdev, NULL);
	iounmap(info->mem[0].internal_addr);
	dma_free_coherent(&pdev->dev, info->mem[1].size, info->mem[1].internal_addr, info->mem[1].addr);
	dma_free_coherent(&pdev->dev, info->mem[2].size, info->mem[2].internal_addr, info->mem[2].addr);
	kfree(info);
	kfree(md_hw);

	return 0;
}

static const struct of_device_id rtk_md_ids[] = {
	{ .compatible = "Realtek,rtk1295-md" },
	{ /* Sentinel */ },
};

static struct platform_driver rtk_md_driver = {
	.probe		= rtk_md_probe,
	.remove		= rtk_md_remove,
	.driver		= {
		.name	= "rtk-md",
		.owner	= THIS_MODULE,
		.of_match_table = rtk_md_ids,
	},
};

static int __init rtk_md_init(void)
{
	int ret=0;
	struct device_node *np;

	//dbg_info("%s %s",__FILE__, __func__);

	md_resource = kzalloc(sizeof(struct md_resource), GFP_KERNEL);
	if (!md_resource)
		return -ENOMEM;

	np = of_find_matching_node(NULL, rtk_md_ids);
	if (!np)
		panic("No MD device node");

	//md register space and irq for driver access
	md_resource->base = of_iomap(np, 0);
	md_resource->irq = irq_of_parse_and_map(np, 0);
	//dbg_info("base:0x%x irq:%d", (unsigned int)md_resource->base, md_resource->irq);

	ret = platform_driver_register(&rtk_md_driver);
	return ret;
}

static void __exit rtk_md_exit(void)
{
	//dbg_info("%s %s",__FILE__, __func__);

	platform_driver_unregister(&rtk_md_driver);
//	misc_deregister(&md_resource->dev);
	kfree(md_resource);
}

module_init(rtk_md_init);
module_exit(rtk_md_exit);
//module_platform_driver_probe(rtk_md_driver, rtk_md_probe);
