#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/kernel.h>
#include <linux/clk.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/dma-mapping.h>
#include <linux/device.h>
#include <linux/crypto.h>
#include <crypto/algapi.h>
#include <crypto/cryptd.h>
#include <linux/ioport.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm/mutex.h>
#include <asm/io.h>
#include <linux/vmalloc.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/irqreturn.h>
#include <linux/completion.h>
#include <linux/kthread.h>

#include <linux/uaccess.h>
#include <asm/page.h>
#include <crypto/aes.h>
#include "rtk_mcp_nas.h"
#include <linux/time.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>

//#include <crypto/internal/hash.h>
//#include <crypto/hash.h>
//#include <crypto/sha.h>
#include <linux/err.h>
#include <linux/irqflags.h>
#include <linux/sched.h>

/*
if define INTERRUPT, mcp run in interrupt mode else in polling mode.
WORK means workqueue else softirq.
if choose ASYNC_NAPI, MUST define COPY_CTX, suitable for dm-crypt.
and use queue to block ablk requests.
ecryptfs case usally mark them, then it runs in synchormous mode.*/
//#define DEBUG
//#define INTERRUPT
#ifndef CONFIG_RTK_MCP_INTERRUPT
#define DESC_LEN  10
#else
#define ASYNC_NAPI
#define COPY_CTX
#define DESC_LEN  128
#endif
#define WORK
#define REQ_LEN  64

/*#define WORK
//#define DESC_LEN  10
#define ASYNC_NAPI
#define COPY_CTX
#define DESC_LEN  128
#define REQ_LEN  64
*/

#define AES_IV_LENGTH  16
#define AES_KEY_LENGTH 16
#define AES_MIN_BLOCK_SIZE 16
#define KEY_FROM_DT

#define AES_DIR_DECRYPT 0
#define AES_DIR_ENCRYPT 1
static struct device* mcp_device;
#define _mcp_map_single(p_data, len, dir)      dma_map_single(mcp_device, (void*) p_data, (size_t) len, dir)
#define _mcp_unmap_single(p_data, len, dir)    dma_unmap_single(mcp_device, (dma_addr_t) p_data, (size_t)  len, dir)
#define IV_PLAIN 0
#define IV_PLAIN64 1
#define IV_NULL 2

#define AES_PRIO 400

static mcp_desc *desc_static=NULL;
#ifdef COPY_CTX
static unsigned int ctx_count = 0;
static unsigned int ctx_base = 0;
#endif

struct rtk_aes_ctx {
    struct rtk_sha_dev	*dd;
    uint8_t key[AES_KEYSIZE_256] __aligned(sizeof(u32));
    uint32_t keylen;
    uint32_t ende;
    uint32_t mode;
    unsigned int desc_total;
} __aligned(sizeof(u32));

struct rtk_sha_ctx {
    struct rtk_sha_dev	*dd;
    void * src;
    uint32_t length;
    uint32_t key[8];
    uint32_t keylen;
    struct crypto_shash	*fallback;
};

struct rtk_sha_dev {
#ifdef WORK
    struct work_struct work;
#else
    struct tasklet_struct task;
#endif
    struct list_head	list;
    struct device		*dev;
    struct clk			*iclk;
    int					irq;
    mcp_desc *desc_list;
    struct completion complete;
    struct completion full_complete;
    int complete_req_count;
    spinlock_t		lock;
    int			err;
    struct semaphore	sem;
    unsigned long		flags;
    struct crypto_queue	queue;
    struct crypto_queue	todo_queue;
    mcp_desc *desc ,*desc_base;
    unsigned int desc_num;
    struct ablkcipher_request  *aes_req;
    struct task_struct *queue_th;
#ifdef COPY_CTX
    struct rtk_aes_ctx *ctx;
#endif
} __aligned(sizeof(u32));

struct rtk_aes_drv {
    struct list_head        dev_list;
    spinlock_t              lock;
};
static struct rtk_aes_drv rtk_aes = {
    .dev_list = LIST_HEAD_INIT(rtk_aes.dev_list),
    .lock = __SPIN_LOCK_UNLOCKED(rtk_aes.lock),
};

static void __iomem *cpioaddr=0;
static void __iomem *tpioaddr=0;

int mcp_do_command(mcp_desc* p_desc, int n_desc, uint32_t key_len, char *key, uint32_t mode);
void mcp_dump_mem(unsigned char* data, unsigned int len);
void* mcp_malloc(unsigned long size);
void mcp_free(void* addr, unsigned long size);
static int mcp_init(void);
static DEFINE_MUTEX(mcp_mutex);
static int rtk_mcp_sg(struct scatterlist* in,struct scatterlist* out, struct rtk_aes_ctx * ctx, char* iv, uint32_t mode, uint32_t ende, struct ablkcipher_request *req);

#ifdef CONFIG_RTK_MCP_INTERRUPT
#ifdef WORK
void complete_irq(struct work_struct *work);
#else
void complete_irq(unsigned long data);
#endif
int rtk_irq_done(int irq, void *dev_id)
{
    struct rtk_sha_dev *dd=dev_id;
    uint32_t status = GET_MCP_STATUS(cpioaddr);
    if (!(status & GET_MCP_EN(cpioaddr)))
        return 0;

//	SET_MCP_EN(0xFE, cpioaddr);
    SET_MCP_STATUS(status&0xFFFE, cpioaddr);
    if (status & 0x2) {
    }
    if (status & 0x8) {
        if (GET_MCP_DES_COUNT(cpioaddr) == GET_MCP_DES_COMPARE(cpioaddr)) {
        }
    }
    if (status & 0x4) {
        SET_MCP_CTRL(MCP_CLEAR | MCP_WRITE_DATA, cpioaddr);
        SET_MCP_STATUS(status&0xFFFE, cpioaddr);
        SET_MCP_CTRL(MCP_GO, cpioaddr);
    }

#ifdef WORK
    schedule_work(&(dd->work));
#else
    tasklet_schedule(&(dd->task));
#endif
//	SET_MCP_EN(0x0F, cpioaddr);
    return IRQ_HANDLED;
}

#ifdef WORK
void complete_irq(struct work_struct *work)
#else
void complete_irq(unsigned long data)
#endif
{
    struct scatterlist* sg_in, *sg_out;
    int i;
#ifdef WORK
    struct rtk_sha_dev *dd = container_of(work, struct rtk_sha_dev, work);
#else
    struct rtk_sha_dev *dd = (struct rtk_sha_dev *) data;
#endif
#ifdef ASYNC_NAPI
    struct crypto_async_request *async_req;
//	struct crypto_async_request *backlog;
    unsigned long flags;
#endif
    struct scatterlist* src, *dst;
    struct ablkcipher_request *req;
    unsigned int sg_in_count;
    unsigned int sg_out_count;
    unsigned int j=0;
    while (1) {
#ifdef ASYNC_NAPI
        spin_lock_irqsave(&dd->lock, flags);
        async_req = crypto_dequeue_request(&dd->queue);
        if (async_req == NULL) {
            spin_unlock_irqrestore(&dd->lock, flags);
            break;
        }
        j++;
        spin_unlock_irqrestore(&dd->lock, flags);
        req = ablkcipher_request_cast(async_req);
#else
        req = dd->aes_req;
        dd->aes_req = NULL;
#endif
        if (req) {
            src = req->src;
            dst = req->dst;
            sg_in_count = sg_nents(src);
            sg_out_count = sg_nents(dst);
            if (src && (src != 0x0)) {
                for_each_sg(src, sg_in, sg_in_count, i)
                _mcp_unmap_single(sg_phys(sg_in), sg_in->length, DMA_FROM_DEVICE);
            }

            if (dst && (dst != 0x0)) {
                for_each_sg(dst, sg_out, sg_out_count, i)
                _mcp_unmap_single(sg_phys(sg_out), sg_out->length, DMA_TO_DEVICE);
            }
            req->base.complete(&(req->base), 0);
#ifndef ASYNC_NAPI
            break;
#endif
        }
    }
    complete(&dd->complete);
    return;
}
#endif

#ifdef ASYNC_NAPI
int _mcp_start_xfer(void);
static void rtk_mcp_prepare_sg(struct ablkcipher_request *req, struct rtk_aes_ctx *ctx);
int _mcp_set_desc_buffer(
    unsigned long           base,
    unsigned long           limit,
    unsigned long           rp,
    unsigned long           wp
);
static int rtk_handler(void *data)
{
    struct rtk_sha_dev *dd =(struct rtk_sha_dev *)data;
    do {
        __set_current_state(TASK_INTERRUPTIBLE);
        unsigned int count =0;
        unsigned int tmp_count=0;
        unsigned int len;
        dma_addr_t addr;
        struct ablkcipher_request *req;
        struct rtk_aes_ctx *ctx;
        mcp_desc *old_desc=NULL;
        struct crypto_async_request *backlog;
        old_desc = desc_static;
        spin_lock_irq(&dd->lock);
        backlog = crypto_get_backlog(&dd->todo_queue);
        while (1) {
            struct crypto_async_request *async_req = NULL;
            async_req = crypto_dequeue_request(&dd->todo_queue);
            if (!async_req) {
                break;
            }
            dd->complete_req_count--;
            req = ablkcipher_request_cast(async_req);
#ifndef COPY_CTX
            ctx = crypto_ablkcipher_ctx(crypto_ablkcipher_reqtfm(req));
#else
            ctx = dd->ctx + ctx_base;
            ctx_base =(ctx_base+1)%DESC_LEN;
#endif
            ablkcipher_enqueue_request(&dd->queue, req);
            count += ctx->desc_total;
            async_req=NULL;

            if (desc_static +ctx->desc_total > dd->desc_base+DESC_LEN-1) {
                tmp_count = ((unsigned long)desc_static - (unsigned long)(dd->desc_base))/56;
                desc_static = dd->desc_base+(tmp_count+ctx->desc_total)%DESC_LEN;
                break;
            } else
                desc_static = desc_static+ctx->desc_total;
        }
        spin_unlock_irq(&dd->lock);
        up(&dd->sem);
        if (backlog) {
            backlog->complete(backlog, -EINPROGRESS);
            backlog = NULL;
        }

        tmp_count = (((unsigned long)dd->desc_base+DESC_LEN*56)-(unsigned long)old_desc)/56;
        if (count) {
            SET_MCP_DES_COMPARE(count, cpioaddr);
            len = sizeof(mcp_desc)*count;
            addr = _mcp_map_single(old_desc, len, DMA_TO_DEVICE);

            old_desc->iv[0]=cpu_to_be32(old_desc->iv[0]);
            old_desc->iv[1]=cpu_to_be32(old_desc->iv[1]);
            old_desc->iv[2]=cpu_to_be32(old_desc->iv[2]);
            old_desc->iv[3]=cpu_to_be32(old_desc->iv[3]);

            SET_MCP_IV0(old_desc->iv[0], cpioaddr);
            SET_MCP_IV1(old_desc->iv[1], cpioaddr);
            SET_MCP_IV2(old_desc->iv[2], cpioaddr);
            SET_MCP_IV3(old_desc->iv[3], cpioaddr);
            _mcp_set_desc_buffer(addr, addr+len + sizeof(mcp_desc), addr, addr + len);
            _mcp_start_xfer();
            wait_for_completion(&dd->complete);
            _mcp_unmap_single(addr, len, DMA_TO_DEVICE);
        }
        schedule();
    } while (!kthread_should_stop());

    return 0;
}
#endif

static struct crypto_alg rtk_ecb_alg;
static struct crypto_alg rtk_cbc_alg;
static int mcp_probe(struct platform_device *pdev)
{
    struct rtk_sha_dev *mcp_dd;
    struct device *dev = &pdev->dev;
    int err;
    mcp_desc *desc_list=NULL;

    mcp_dd = kzalloc(sizeof(struct rtk_sha_dev), GFP_KERNEL);
    if (mcp_dd == NULL) {
        dev_err(dev, "unable to alloc data struct.\n");
        err = -ENOMEM;
        return -ENODEV;
    }
    mcp_dd->dev = dev;
    mcp_dd->flags = 0;

    platform_set_drvdata(pdev, mcp_dd);
    INIT_LIST_HEAD(&mcp_dd->list);
    mcp_device = &(pdev->dev);

    cpioaddr =  ioremap(0x98015000, 0x1000);
    tpioaddr =  ioremap(0x98014000, 0x1000);
    if (mcp_init()<0)
        return -ENODEV;

#ifdef CONFIG_RTK_MCP_INTERRUPT
    mcp_dd->irq = irq_of_parse_and_map(pdev->dev.of_node, 0);
    err = request_irq(mcp_dd->irq, rtk_irq_done, 0, "rtk-mcp", mcp_dd);
    if (err) {
        dev_err(dev, "unable to request sha irq.\n");
        return -ENODEV;
    }
#endif
    desc_list=mcp_malloc(2*DESC_LEN*sizeof(mcp_desc)+7);
    memset(desc_list,0, 2*DESC_LEN*sizeof(mcp_desc)+7);
    mcp_dd->desc=(mcp_desc*)(((uint64_t)(desc_list)+7)&(~0x7));
    mcp_dd->desc_base = mcp_dd->desc;
    mcp_dd->desc_num = 0;
    memset(mcp_dd->desc,0, 2*DESC_LEN*sizeof(mcp_desc));
#ifdef CONFIG_RTK_MCP_INTERRUPT
#ifndef WORK
    tasklet_init(&mcp_dd->task, complete_irq, (unsigned long)mcp_dd);
#else
    INIT_WORK(&mcp_dd->work, complete_irq);
#endif
#endif

#ifdef COPY_CTX
    struct rtk_aes_ctx *ctx_list;
    ctx_list=mcp_malloc(DESC_LEN*sizeof(struct rtk_aes_ctx)+7);
    memset(ctx_list,0, DESC_LEN*sizeof(struct rtk_aes_ctx)+7);
    mcp_dd->ctx = (struct rtk_aes_ctx*)(((uint64_t)(ctx_list)+7)&(~0x7));
#endif
    mcp_dd->aes_req =NULL;

#ifdef ASYNC_NAPI
    crypto_init_queue(&mcp_dd->queue, DESC_LEN);
    crypto_init_queue(&mcp_dd->todo_queue, REQ_LEN);
#endif

    spin_lock(&rtk_aes.lock);
    list_add_tail(&mcp_dd->list, &rtk_aes.dev_list);
    spin_unlock(&rtk_aes.lock);
    init_completion(&mcp_dd->complete);
    init_completion(&mcp_dd->full_complete);
    desc_static = mcp_dd->desc_base;
#ifdef ASYNC_NAPI
    sema_init(&mcp_dd->sem, 0);
    mcp_dd->queue_th = kthread_run(rtk_handler, mcp_dd, "rtk_crypto");
#endif
    mcp_dd->complete_req_count = 0;

    err = crypto_register_alg(&rtk_ecb_alg);
    if (err) {
        crypto_unregister_alg(&rtk_ecb_alg);
        return err;
    }

    err = crypto_register_alg(&rtk_cbc_alg);
    if (err) {
        crypto_unregister_alg(&rtk_cbc_alg);
        return err;
    }
    return 0;
}
void mcp_free(void* addr, unsigned long size);
static int mcp_remove(struct platform_device *pdev)
{
    struct device *dev = &pdev->dev;
    struct rtk_sha_dev *mcp_dd;
    mcp_dd = container_of(dev, struct rtk_sha_dev, dev);
    mcp_free(mcp_dd->desc_list, (2*DESC_LEN*sizeof(mcp_desc)+7));
#ifdef COPY_CTX
    mcp_free(mcp_dd->ctx, (DESC_LEN*sizeof(struct rtk_aes_ctx)));
#endif
    mcp_free(mcp_dd, sizeof(*mcp_dd));

    dbg_info("%s %s %d",__FILE__, __func__,__LINE__);
    return 0;
}

static int mcp_suspend(struct platform_device *dev, pm_message_t state)
{
    dbg_info("%s %s %d",__FILE__, __func__,__LINE__);
    return 0;
}

static int mcp_resume(struct platform_device *dev)
{
    dbg_info("%s %s %d",__FILE__, __func__,__LINE__);
    return 0;
}

static const struct of_device_id rtk_mcp_ids[] = {
    { .compatible = "Realtek,rtk-mcp", },
    {},
};
MODULE_DEVICE_TABLE(of, rtk_mcp_ids);

static struct platform_driver rtk_mcp_driver = {
    .probe      = mcp_probe,
    .remove     = mcp_remove,
    .suspend    = mcp_suspend,
    .resume     = mcp_resume,
    .driver     = {
        .name   = "rtk_mcp",
        //.bus = &platform_bus_type,
        .owner  = THIS_MODULE,
        .of_match_table	= of_match_ptr(rtk_mcp_ids),
    },
};

/********************************************************************************
  AES
 ********************************************************************************/
static int writeSRAM(unsigned int id, uint32_t *data, unsigned int cnt, mcp_desc* p_desc)
{
    int i=0,y=0;
    for (i=0; i<cnt; i++) {
        SET_TP_KEYINFO_0(data[y++], tpioaddr);
        SET_TP_KEYINFO_1(data[y++], tpioaddr);
        SET_TP_KEY_CTRL((id+i) | 0x80, tpioaddr);  // write 8 bytes
    }
    SET_TP_KEYINFO_0(0x0, tpioaddr);
    SET_TP_KEYINFO_1(0x0, tpioaddr);
    return 0;
}

static int _sg_write_key(uint32_t keylen, char *Key, mcp_desc* p_desc)
{
    uint32_t aes_key[8];
    memcpy(aes_key, Key, keylen);
    if (Key) {
        aes_key[0]=cpu_to_be32(aes_key[0]);
        aes_key[1]=cpu_to_be32(aes_key[1]);
        aes_key[2]=cpu_to_be32(aes_key[2]);
        aes_key[3]=cpu_to_be32(aes_key[3]);
        aes_key[4]=cpu_to_be32(aes_key[4]);
        aes_key[5]=cpu_to_be32(aes_key[5]);
        aes_key[6]=cpu_to_be32(aes_key[6]);
        aes_key[7]=cpu_to_be32(aes_key[7]);

        if (keylen==AES_KEYSIZE_128)
            writeSRAM(0, aes_key, 2, p_desc);
        else if (keylen==AES_KEYSIZE_192)
            writeSRAM(0, aes_key, 3, p_desc);
        else
            writeSRAM(0, aes_key, 4, p_desc);
        return 0;
    } else
        return -1;
}

/***************************************************************************
  ------------------- MISC ----------------
 ****************************************************************************/
/*------------------------------------------------------------------
 * Func : mcp_malloc
 *
 * Desc : allocate memory
 *
 * Parm : size      : size of data
 *
 * Retn : start address of data
 *------------------------------------------------------------------*/
void* mcp_malloc(unsigned long size)
{
    return (size >= PAGE_SIZE) ? (void*) __get_free_pages(GFP_KERNEL, get_order(size))
           : (void*) kmalloc(size, GFP_KERNEL) ;
}

void* hash_malloc(unsigned long size)
{
    return (size >= PAGE_SIZE) ? (void*) __get_free_pages(GFP_USER, get_order(size))
           : (void*) kmalloc(size, GFP_USER) ;
}

/*------------------------------------------------------------------
 * Func : mcp_free
 *
 * Desc : release memory
 *
 * Parm : addr      : Start address of data
 *        size      : size of data
 *
 * Retn : N/A
 *------------------------------------------------------------------*/
void mcp_free(void* addr, unsigned long size)
{
    if (system_state == SYSTEM_BOOTING) {
        kfree(addr) ;
        return;
    }
    //pointer in 64 bit system is 8bytes.
    if (size >= PAGE_SIZE)
        free_pages((unsigned long)addr, get_order(size));//unsigned int:4bytes; unsigned long:8bytes
    else
        kfree(addr) ;
}

/*------------------------------------------------------------------
 * Func : _mcp_load_otp
 *
 * Desc : load otp key
 *
 * Parm : N/A
 *
 * Retn : N/A
 *------------------------------------------------------------------*/
static void _mcp_load_otp(void)
{
    int i = 0;
    SET_MCP_OTP_LOAD(1, cpioaddr);
//udelay(10);
    while(GET_MCP_OTP_LOAD(cpioaddr)) {
        if (i++ > 100) {
            mcp_warning("Load OTP Key Timeout\n");
        }

        udelay(10);
    }
}

/*------------------------------------------------------------------
 * Func : _mcp_phy_init
 *
 * Desc : init mcp engine
 *
 * Parm : N/A
 *
 * Retn : N/A
 *------------------------------------------------------------------*/
static int _mcp_phy_init(void)
{
    _mcp_load_otp();

    SET_MCP_CTRL(MCP_GO, cpioaddr);       // dessert go bit
    SET_MCP_EN(0xFE, cpioaddr);           // disable all interrupts
    SET_MCP_STATUS(0xFE, cpioaddr);       // clear interrupts status
#ifdef CONFIG_RTK_MCP_INTERRUPT
    SET_MCP_EN(0x0f, cpioaddr);
#endif
    SET_MCP_BASE (0, cpioaddr);
    SET_MCP_LIMIT(0, cpioaddr);
    SET_MCP_RDPTR(0, cpioaddr);
    SET_MCP_WRPTR(0, cpioaddr);

    //SET_MCP_CTRL(MCP_ARB_MODE(1) | MCP_WRITE_DATA);     // set arbitraction mode to mode 1

    //SET_MCP_CTRL1(MCP_AES_PAD_OFF(1) |                  // disable AES_H auto padding
    //             MCP_CSA_ENTROPY(ORIGIONAL_MODE) |     // setup csa mode
    //             MCP_ROUND_NO(0));                     // set round number of multi-2 to 1

    return 0;
}

/*------------------------------------------------------------------
 * Func : mcp_init
 *
 * Desc : init mcp engine
 *
 * Parm : N/A
 *
 * Retn : N/A
 *------------------------------------------------------------------*/
static int mcp_init(void)
{
    if (_mcp_phy_init()<0)
        return -1;

#if 0//def MCP_INTERRUPT_ENABLE
    if (request_irq(MCP_IRQ, mcp_isr, SA_INTERRUPT | SA_SHIRQ, "MCP", &mcp_wait_queue) < 0) {
        mcp_warning("Request irq %d failed\n", MCP_IRQ);
        return -ENODEV;
    }
#endif

    return 0;
}

/*------------------------------------------------------------------
 * Func : mcp_uninit
 *
 * Desc : uninit mcp engine
 *
 * Parm : N/A
 *
 * Retn : N/A
 *------------------------------------------------------------------*/
static void mcp_uninit(void)
{
    SET_MCP_CTRL(MCP_GO, cpioaddr);           // dessert go bit
    SET_MCP_EN(0xFE, cpioaddr);               // disable all interrupts
#ifdef CONFIG_RTK_MCP_INTERRUPT
    SET_MCP_EN(0x0f, cpioaddr);
#endif
    msleep(10);                     // wait for hw stop
    SET_MCP_BASE (0, cpioaddr);
    SET_MCP_LIMIT(0, cpioaddr);
    SET_MCP_RDPTR(0, cpioaddr);
    SET_MCP_WRPTR(0, cpioaddr);
#if 0 //def MCP_INTERRUPT_ENABLE
    free_irq(MCP_IRQ, &mcp_wait_queue);
#endif
}

/*----------------------------------------------------------------------
 * Func : mcp_dump_mem
 *
 * Desc : dump data in memory
 *
 * Parm : data : start address of data
 *        len  : length of data
 *
 * Retn : N/A
 *----------------------------------------------------------------------*/
void mcp_dump_mem(unsigned char* data, unsigned int len)
{
    int i;
    for (i=0; i<len; i++) {
        if ((i & 0xF)==0)
            dbg_info("\n %04x | ", i);
        dbg_info("%02x ", data[i]);
    }
    printk("\n");
}

/*------------------------------------------------------------------
 * Func : _mcp_set_desc_buffer
 *
 * Desc : set descriptors buffer
 *
 * Parm : base  : base address of descriptor buffer
 *        limit : limit address of descriptor buffer
 *        rp    : read pointer of descriptor buffer
 *        wp    : write pointer of descriptor buffer
 *
 * Retn : 0
 *------------------------------------------------------------------*/
int _mcp_set_desc_buffer(
    unsigned long           base,
    unsigned long           limit,
    unsigned long           rp,
    unsigned long           wp
)
{
    SET_MCP_BASE (base, cpioaddr);
    SET_MCP_LIMIT(limit, cpioaddr);
    SET_MCP_RDPTR(rp, cpioaddr);
    SET_MCP_WRPTR(wp, cpioaddr);
    return 0;
}

/*------------------------------------------------------------------
 * Func : _mcp_start_xfer
 *
 * Desc : Start Xfer
 *
 * Parm : N/A
 *
 * Retn : S_OK /  S_FALSE
 *------------------------------------------------------------------*/
int _mcp_start_xfer(void)
{
    int wiat_clear_timeout = 0;
    SET_MCP_CTRL(MCP_CLEAR | MCP_WRITE_DATA, cpioaddr);    // issue clear
    while (GET_MCP_CTRL(cpioaddr) & MCP_CLEAR && wiat_clear_timeout++<30);
    if (GET_MCP_CTRL(cpioaddr) & MCP_CLEAR) {
        mcp_warning("wait clear bit deassert timeout,  force unset clear bit, (CTRL=%08x, STATUS=%08x)\n",
                    GET_MCP_CTRL(cpioaddr), GET_MCP_STATUS(cpioaddr));
        SET_MCP_CTRL(MCP_CLEAR, cpioaddr);    // issue clear
        mcp_warning("CTRL=%08x, STATUS=%08x)\n",GET_MCP_CTRL(cpioaddr), GET_MCP_STATUS(cpioaddr));
    }
#ifndef CONFIG_RTK_MCP_INTERRUPT
    SET_MCP_EN(0xFE, cpioaddr);
#endif
    SET_MCP_STATUS(0xFE, cpioaddr);    // clear status

    SET_MCP_CTRL(MCP_GO | MCP_WRITE_DATA, cpioaddr);

#ifndef CONFIG_RTK_MCP_INTERRUPT
    int ret = -1;
    uint32_t WaitTime = -1;
    // here we use busy-wait due to performance consideration
    // 1195's CP engine needs to poll about 50 times to encrypt/decrypt 1kbytes AES data
    while (WaitTime--) {
        if (!(GET_MCP_CTRL(cpioaddr) & MCP_GO))
            break;

        if(GET_MCP_STATUS(cpioaddr)&0x6)
            break;
        if (WaitTime==0) {
            printk(KERN_ERR "WaitTime is small, set bigger!!!");
	    break;
        }
    }

    ret = ((GET_MCP_STATUS(cpioaddr) & ~(MCP_RING_EMPTY | MCP_COMPARE))) ? -1 : 0;
    if (ret <0)
        mcp_warning("do mcp command failed, (MCP_Status %08x), (MCP_CRTL %08x), (MCP_En %08x) \n", GET_MCP_STATUS(cpioaddr), GET_MCP_CTRL(cpioaddr), GET_MCP_EN(cpioaddr));

    SET_MCP_CTRL(MCP_GO, cpioaddr);               // clear go bit

    SET_MCP_STATUS(0xFE, cpioaddr);               // clear ring empty
    return ret;
#else
    return -EINPROGRESS;
    //return -EBUSY;
#endif
}

void _mcp_dump_desc_buffer(mcp_desc *p_desc)
{
    int i = 0;

    dbg_info("****** MCP Descriptor ******\n");
    dbg_info("p_desc->flags:0x%0x\n", p_desc->flags);

    for (i = 0; i < sizeof(p_desc->key)/sizeof(p_desc->key[0]); i++) {
        dbg_info("p_desc->key[%d]:0x%0x\n", i, p_desc->key[i]);
    }

    for (i = 0; i < sizeof(p_desc->iv)/sizeof(p_desc->iv[0]); i++) {
        dbg_info("p_desc->iv[%d]:0x%0x\n", i, p_desc->iv[i]);
    }

    dbg_info("p_desc->data_in:0x%0x\n", p_desc->data_in);
    dbg_info("p_desc->data_out:0x%0x\n", p_desc->data_out);
    dbg_info("p_desc->length:0x%0x\n", p_desc->length);
}

/*------------------------------------------------------------------
 * Func : mcp_do_command
 *
 * Desc : Do Command
 *
 * Parm : p_desc : number of Descriptor to be Execute
 *        n_desc  : number of Descriptor to be Execute
 *
 * Retn : 0 : success, others fail
 *------------------------------------------------------------------*/
int mcp_do_command(mcp_desc* p_desc, int n_desc, uint32_t key_len, char *key, uint32_t mode)
{
    dma_addr_t  addr;
    int         len = sizeof(mcp_desc) * n_desc;
    int         ret = 0;
    int         i;
#ifdef KEY_FROM_DT
    unsigned int * new = NULL;
#endif
    if (n_desc) {
        mutex_lock(&mcp_mutex);

        if ((mode == MCP_BCM_ECB) || (mode == MCP_BCM_CBC)) {
            if (p_desc->iv) {
                p_desc->iv[0]=cpu_to_be32(p_desc->iv[0]);
                p_desc->iv[1]=cpu_to_be32(p_desc->iv[1]);
                p_desc->iv[2]=cpu_to_be32(p_desc->iv[2]);
                p_desc->iv[3]=cpu_to_be32(p_desc->iv[3]);

                SET_MCP_IV0(p_desc->iv[0], cpioaddr);
                SET_MCP_IV1(p_desc->iv[1], cpioaddr);
                SET_MCP_IV2(p_desc->iv[2], cpioaddr);
                SET_MCP_IV3(p_desc->iv[3], cpioaddr);
            }
//does not support key from addr/sram
#ifdef KEY_FROM_DT
            new =(unsigned int *)key;
            for (i=0; i< key_len/4; i++)
                p_desc->key[i]=*(new+i);
#else
            _mcp_load_otp();
#endif
        }
        addr = _mcp_map_single(p_desc, len, DMA_TO_DEVICE);
        _mcp_set_desc_buffer(addr, addr+len + sizeof(mcp_desc), addr, addr + len);
        ret = _mcp_start_xfer();
        _mcp_unmap_single(addr, len, DMA_TO_DEVICE);
        mutex_unlock(&mcp_mutex);
    }
    return ret;
}

static int sg_nents_total_len(struct scatterlist *sg, uint64_t* len)
{
    uint64_t total;

    if (!len)
        return 0;

    for (total = 0; sg!=NULL; sg = sg_next(sg)) {
        total += sg->length;
    }
    *len=total;
    return -EINVAL;
}

static struct rtk_sha_dev *rtk_aes_find_dev(struct rtk_aes_ctx *ctx)
{
    struct rtk_sha_dev *rtk_dd = NULL;
    struct rtk_sha_dev *tmp;

    spin_lock(&rtk_aes.lock);
    if (!ctx->dd) {
        list_for_each_entry(tmp, &rtk_aes.dev_list, list) {
            rtk_dd = tmp;
            break;
        }
        ctx->dd = rtk_dd;
    } else {
        rtk_dd = ctx->dd;
    }
    spin_unlock(&rtk_aes.lock);
    if (rtk_dd == NULL)
        printk(KERN_ERR "in rtk_aes_find_dev rtk_dd is NULL.\n");
    return rtk_dd;
}

static int fallback_init_blk(struct crypto_tfm *tfm)
{

    tfm->crt_ablkcipher.reqsize = sizeof(struct rtk_aes_ctx);

    return 0;
}

static void fallback_exit_blk(struct crypto_tfm *tfm)
{

}

static int rtk_setkey_blk(struct crypto_ablkcipher *tfm, const u8 *key,
                          unsigned int len)
{
    struct rtk_aes_ctx *op = crypto_ablkcipher_ctx(tfm);
    op->keylen = len;
    if ((len == AES_KEYSIZE_128)||(len == AES_KEYSIZE_192)||(len == AES_KEYSIZE_256)) {
        if (key) {
            memcpy(op->key, key, len);
        } else {
            memset(op->key, 0, len);
        }
    }
    return 0;

}

#ifdef ASYNC_NAPI
static void rtk_mcp_prepare_sg(struct ablkcipher_request *req, struct rtk_aes_ctx *ctx)
{
    struct scatterlist* in, *out;
    char* iv = NULL;
    unsigned int desc_total=0, i=0,sg_in_count=0, sg_out_count=0;
    uint32_t desc_flags=0, sg_in_anchor, sg_in_len, sg_out_anchor, sg_out_len;
    uint64_t total_in_len, total_out_len;
    struct scatterlist* sg_in, *sg_out;
    mcp_desc *desc;
    struct rtk_sha_dev *dd=NULL;

    in= req->src;
    out=req->dst;
    sg_in_count =sg_nents(in);
    sg_out_count=sg_nents(out);
    sg_nents_total_len(in, &total_in_len);
    sg_nents_total_len(out, &total_out_len);
    if (total_in_len>total_out_len) {
        mcp_warning("output buffer is too small in %lluB, out %lluB\n", total_in_len, total_out_len);
        return;
    }
    iv = req->info;
    dd = rtk_aes_find_dev(ctx);
    desc_total=sg_in_count+sg_out_count-1;
    if (dd == NULL)
        printk(KERN_ERR "rtk_aes_find_dev return NULL.\n");
    desc = dd->desc;

    if (ctx->keylen==AES_KEYSIZE_128)
        desc_flags = MARS_MCP_MODE(MCP_ALGO_AES) | MARS_MCP_IV_SEL(MCP_IV_SEL_REG) | MARS_MCP_BCM(ctx->mode) | MARS_MCP_ENC(ctx->ende)  | MARS_MCP_KEY_SEL(MCP_KEY_SEL_DESC);
    else if (ctx->keylen==AES_KEYSIZE_192)
        desc_flags = MARS_MCP_MODE(MCP_ALGO_AES_192) | MARS_MCP_IV_SEL(MCP_IV_SEL_REG) | MARS_MCP_BCM(ctx->mode) | MARS_MCP_ENC(ctx->ende) | MARS_MCP_KEY_SEL(MCP_KEY_SEL_DESC);
    else if (ctx->keylen==AES_KEYSIZE_256)
        desc_flags = MARS_MCP_MODE(MCP_ALGO_AES_256) | MARS_MCP_IV_SEL(MCP_IV_SEL_REG) | MARS_MCP_BCM(ctx->mode) | MARS_MCP_ENC(ctx->ende) | MARS_MCP_KEY_SEL(MCP_KEY_SEL_DESC);

    sg_in_len=in->length;
    sg_in_anchor=_mcp_map_single(sg_virt(in), sg_in_len, DMA_TO_DEVICE);

    sg_out_len=out->length;
    sg_out_anchor=_mcp_map_single(sg_virt(out), sg_out_len, DMA_FROM_DEVICE);
//	ctx->desc =desc;
    for(i=0, sg_in=in, sg_out=out; (sg_in!=NULL)&&(desc_total>=i); i++) {
        memset(desc+i, 0, sizeof(mcp_desc));
        desc[i].data_in=sg_in_anchor;
        desc[i].data_out=sg_out_anchor;
        desc[i].length=(sg_in_len>sg_out_len)? sg_out_len:sg_in_len;
        desc[i].flags=desc_flags;
        sg_in_anchor+=desc[i].length;
        sg_in_len-=desc[i].length;
        if (sg_in_len==0) {
            if ((sg_in=sg_next(sg_in))!=NULL) {
                sg_in_len=sg_in->length;
                sg_in_anchor=_mcp_map_single(sg_virt(sg_in), sg_in_len, DMA_TO_DEVICE);
            }
        }

        if (iv) {
            memset(desc[i].iv, 0, 4*sizeof(unsigned int));
            memcpy(desc[i].iv, iv, AES_IV_LENGTH);
        }
        memset(desc[i].key, 0, 6*sizeof(unsigned int));
        memcpy(desc[i].key, ctx->key, ctx->keylen);

        sg_out_anchor+=desc[i].length;
        sg_out_len-=desc[i].length;
        if (sg_out_len==0) {
            if ((sg_out=sg_next(sg_out))!=NULL) {
                sg_out_len=sg_out->length;
                sg_out_anchor=_mcp_map_single(sg_virt(sg_out), sg_out_len, DMA_FROM_DEVICE);
            }
        }
    }
    ctx->desc_total=i;
    dd->desc_num = (dd->desc_num + i)%DESC_LEN;
    dd->desc =dd->desc_base + dd->desc_num;
    return ;
}

static int rtk_aes_enqueue(struct ablkcipher_request *req, struct rtk_aes_ctx *ctx)
{
    struct rtk_sha_dev *dd = rtk_aes_find_dev(ctx);
    int err;

requeue:
   if (dd->complete_req_count == REQ_LEN) {
        goto down_sem;
    }
    rtk_mcp_prepare_sg(req, ctx);
#ifdef COPY_CTX
    struct rtk_aes_ctx *ctx_tmp=NULL;
    ctx_tmp = dd->ctx+ctx_count;
    memcpy(ctx_tmp->key, ctx->key, ctx->keylen);
    ctx_tmp->keylen = ctx->keylen;
    ctx_tmp->ende = ctx->ende;
    ctx_tmp->mode = ctx->mode;
    ctx_tmp->desc_total = ctx->desc_total;
    ctx_tmp->dd = ctx->dd;
    ctx_count = (ctx_count+1)%DESC_LEN;
#endif
    spin_lock_irq(&dd->lock);
    err = ablkcipher_enqueue_request(&dd->todo_queue, req);
    dd->complete_req_count++;
    spin_unlock_irq(&dd->lock);
    wake_up_process(dd->queue_th);
    return err;
down_sem:
    down(&dd->sem);
    goto requeue;
}
#endif
static int rtk_mcp_sg(struct scatterlist* in,struct scatterlist* out, struct rtk_aes_ctx * ctx, char* iv, uint32_t mode, uint32_t ende, struct ablkcipher_request *req)
{
    unsigned int desc_total=0, i=0,sg_in_count=sg_nents(in), sg_out_count=sg_nents(out);
    uint32_t desc_flags=0, sg_in_anchor, sg_in_len, sg_out_anchor, sg_out_len;
    uint64_t total_in_len, total_out_len;
    struct scatterlist* sg_in, *sg_out;
    mcp_desc *desc;
    int ret;
    unsigned int nbytes=0;
    struct rtk_sha_dev *dd=NULL;
    sg_nents_total_len(in, &total_in_len);
    sg_nents_total_len(out, &total_out_len);

    SET_SRAM_CHECK(0x00000001 , cpioaddr);
    if (total_in_len>total_out_len) {
        mcp_warning("output buffer is too small in %lluB, out %lluB\n", total_in_len, total_out_len);
        return -1;
    }
    dd = rtk_aes_find_dev(ctx);

    desc_total=sg_in_count+sg_out_count-1;
    if (dd == NULL)
        printk(KERN_ERR "rtk_aes_find_dev return NULL.\n");
    desc = dd->desc;

    if (ctx->keylen==AES_KEYSIZE_128)
        desc_flags = MARS_MCP_MODE(MCP_ALGO_AES) | MARS_MCP_IV_SEL(MCP_IV_SEL_REG) | MARS_MCP_BCM(mode) | MARS_MCP_ENC(ende)  | MARS_MCP_KEY_SEL(MCP_KEY_SEL_DESC);
    else if (ctx->keylen==AES_KEYSIZE_192)
        desc_flags = MARS_MCP_MODE(MCP_ALGO_AES_192) | MARS_MCP_IV_SEL(MCP_IV_SEL_REG) | MARS_MCP_BCM(mode) | MARS_MCP_ENC(ende) | MARS_MCP_KEY_SEL(MCP_KEY_SEL_DESC);
    else if (ctx->keylen==AES_KEYSIZE_256)
        desc_flags = MARS_MCP_MODE(MCP_ALGO_AES_256) | MARS_MCP_IV_SEL(MCP_IV_SEL_REG) | MARS_MCP_BCM(mode) | MARS_MCP_ENC(ende) | MARS_MCP_KEY_SEL(MCP_KEY_SEL_DESC);

    sg_in_len=in->length;
    sg_in_anchor=_mcp_map_single(sg_virt(in), sg_in_len, DMA_TO_DEVICE);

    sg_out_len=out->length;
    sg_out_anchor=_mcp_map_single(sg_virt(out), sg_out_len, DMA_FROM_DEVICE);
//	pr_err("rtk_mcp_sg sg_in_anchor is 0x%x, sg_out_anchor is 0x%x\n", sg_in_anchor, sg_out_anchor);
    for(i=0, sg_in=in, sg_out=out; (sg_in!=NULL)&&(desc_total>=i); i++) {
        desc[i].data_in=sg_in_anchor;
        desc[i].data_out=sg_out_anchor;
        desc[i].length=(sg_in_len>sg_out_len)? sg_out_len:sg_in_len;
        nbytes += desc[i].length;
        desc[i].flags=desc_flags;
        sg_in_anchor+=desc[i].length;
        sg_in_len-=desc[i].length;
        if (sg_in_len==0) {
            if ((sg_in=sg_next(sg_in))!=NULL) {
                sg_in_len=sg_in->length;
                sg_in_anchor=_mcp_map_single(sg_virt(sg_in), sg_in_len, DMA_TO_DEVICE);
            }
        }
        if ((mode != MCP_SHA_1) && (mode != MCP_SHA_256)) {
            sg_out_anchor+=desc[i].length;
            sg_out_len-=desc[i].length;
            if (sg_out_len==0) {
                if ((sg_out=sg_next(sg_out))!=NULL) {
                    sg_out_len=sg_out->length;
                    sg_out_anchor=_mcp_map_single(sg_virt(sg_out), sg_out_len, DMA_FROM_DEVICE);
                }
            }
        }
    }
    desc_total=i;
    dd->desc_num = (dd->desc_num + i)%DESC_LEN;
    dd->desc =dd->desc_base + dd->desc_num;

#ifdef CONFIG_RTK_MCP_INTERRUPT
    SET_MCP_DES_COMPARE(desc_total, cpioaddr);
    dd->aes_req = req;
#endif

    ret = mcp_do_command(desc, desc_total, ctx->keylen, ctx->key, mode);

#ifndef CONFIG_RTK_MCP_INTERRUPT
    for_each_sg(in, sg_in, sg_in_count, i)
    _mcp_unmap_single(sg_phys(sg_in), sg_in->length, DMA_FROM_DEVICE);

    for_each_sg(out, sg_out, sg_out_count, i)
    _mcp_unmap_single(sg_phys(sg_out), sg_out->length, DMA_TO_DEVICE);
#endif
    return ret;
}

static int rtk_cbc_decrypt(struct ablkcipher_request *req)
{
    int err;
    struct rtk_aes_ctx *ctx = crypto_ablkcipher_ctx(crypto_ablkcipher_reqtfm(req));
#ifdef ASYNC_NAPI
    ctx->mode = MCP_BCM_CBC;
    ctx->ende = AES_DIR_DECRYPT;
    mutex_lock(&mcp_mutex);
    err = rtk_aes_enqueue(req, ctx);
    mutex_unlock(&mcp_mutex);
#else
    err=rtk_mcp_sg(req->src, req->dst, ctx, req->info, MCP_BCM_CBC, AES_DIR_DECRYPT, req);
#endif
    return err;
}

static int rtk_cbc_encrypt(struct ablkcipher_request *req)
{
    int err;
    struct rtk_aes_ctx *ctx = crypto_ablkcipher_ctx(crypto_ablkcipher_reqtfm(req));
#ifdef ASYNC_NAPI
    ctx->mode = MCP_BCM_CBC;
    ctx->ende = AES_DIR_ENCRYPT;
    mutex_lock(&mcp_mutex);
    err = rtk_aes_enqueue(req, ctx);
    mutex_unlock(&mcp_mutex);
#else
    err=rtk_mcp_sg(req->src, req->dst, ctx, req->info, MCP_BCM_CBC, AES_DIR_ENCRYPT, req);
#endif
    return err;
}

static int rtk_ecb_decrypt(struct ablkcipher_request *req)
{
    int err;
    struct rtk_aes_ctx *ctx = crypto_ablkcipher_ctx(crypto_ablkcipher_reqtfm(req));
#ifdef ASYNC_NAPI
    ctx->mode = MCP_BCM_ECB;
    ctx->ende = AES_DIR_DECRYPT;
    mutex_lock(&mcp_mutex);
    err = rtk_aes_enqueue(req, ctx);
    mutex_unlock(&mcp_mutex);
#else
    err=rtk_mcp_sg(req->src, req->dst, ctx, NULL, MCP_BCM_ECB, AES_DIR_DECRYPT, req);
#endif
    return err;
}

static int rtk_ecb_encrypt(struct ablkcipher_request *req)
{
    int err;
    struct rtk_aes_ctx *ctx = crypto_ablkcipher_ctx(crypto_ablkcipher_reqtfm(req));
#ifdef ASYNC_NAPI
    ctx->mode = MCP_BCM_ECB;
    ctx->ende = AES_DIR_ENCRYPT;
    mutex_lock(&mcp_mutex);
    err = rtk_aes_enqueue(req, ctx);
    mutex_unlock(&mcp_mutex);
#else
    err=rtk_mcp_sg(req->src, req->dst, ctx, NULL, MCP_BCM_ECB, AES_DIR_ENCRYPT, req);
#endif
    return err;
}

static struct crypto_alg rtk_ecb_alg = {
    .cra_name		=	"ecb(aes)",
    .cra_driver_name	=	"ecb-aes-rtk",
    .cra_priority		=	AES_PRIO,
    .cra_flags		=	CRYPTO_ALG_TYPE_ABLKCIPHER |
    CRYPTO_ALG_KERN_DRIVER_ONLY |
    CRYPTO_ALG_NEED_FALLBACK,
    .cra_init		=	fallback_init_blk,
    .cra_exit		=	fallback_exit_blk,
    .cra_blocksize		=	AES_MIN_BLOCK_SIZE,
    .cra_ctxsize		=	sizeof(struct rtk_aes_ctx),
    .cra_alignmask		=	15,
    .cra_type		=	&crypto_ablkcipher_type,
    .cra_module		=	THIS_MODULE,
    .cra_u			=	{
        .ablkcipher		=	{
            .min_keysize	=	AES_MIN_KEY_SIZE,
            .max_keysize	=	AES_MAX_KEY_SIZE,
            .setkey		=	rtk_setkey_blk,
            .encrypt	=	rtk_ecb_encrypt,
            .decrypt	=	rtk_ecb_decrypt,
        }
    }
};

static struct crypto_alg rtk_cbc_alg = {
    .cra_name		=	"cbc(aes)",
    .cra_driver_name	=	"cbc-aes-rtk",
    .cra_priority		=	AES_PRIO,
    .cra_flags			=	CRYPTO_ALG_TYPE_ABLKCIPHER |
    CRYPTO_ALG_KERN_DRIVER_ONLY |
    CRYPTO_ALG_NEED_FALLBACK,
    .cra_init			=	fallback_init_blk,
    .cra_exit			=	fallback_exit_blk,
    .cra_blocksize		=	AES_MIN_BLOCK_SIZE,
    .cra_ctxsize		=	sizeof(struct rtk_aes_ctx),
    .cra_alignmask		=	15,
    .cra_type			=	&crypto_ablkcipher_type,
    .cra_module			=	THIS_MODULE,
    .cra_u				=	{
        .ablkcipher	=	{
            .min_keysize	=	AES_MIN_KEY_SIZE,
            .max_keysize	=	AES_MAX_KEY_SIZE,
            .setkey			=	rtk_setkey_blk,
            .encrypt		=	rtk_cbc_encrypt,
            .decrypt		=	rtk_cbc_decrypt,
            .ivsize			=	AES_IV_LENGTH,
        }
    }
};

static int __init rtk_mcp_init(void)
{
    return platform_driver_register(&rtk_mcp_driver);
}

static void __exit rtk_mcp_exit(void)
{
    mcp_uninit();

    crypto_unregister_alg(&rtk_ecb_alg);
    crypto_unregister_alg(&rtk_cbc_alg);

    platform_driver_unregister(&rtk_mcp_driver);
}

module_init(rtk_mcp_init);
module_exit(rtk_mcp_exit);
MODULE_DESCRIPTION("Realtek AES(cbc/ecb) hw acceleration support.");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Nicolas Royer - Eukréa Electromatique");
