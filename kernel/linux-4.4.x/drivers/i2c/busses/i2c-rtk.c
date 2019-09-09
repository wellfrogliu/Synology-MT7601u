#include <linux/module.h>
#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/completion.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/slab.h>
#include <linux/pm_runtime.h>
#include <linux/pinctrl/consumer.h>

#include "i2c-rtk.h"
#include "i2c-rtk-priv.h"

#include <linux/clkdev.h>   // clk_get
#include <linux/clk.h>   // clk_get
#include <linux/clk-provider.h>
#include "i2c-venus-config-saturn.h"

#define VENUS_MASTER_7BIT_ADDR  0x24

#define  rtk_i2c_mdelay(x)  \
		 set_current_state(TASK_INTERRUPTIBLE); \
		 schedule_timeout(msecs_to_jiffies(x))

#define IsReadMsg(x)        (x.flags & I2C_M_RD)
#define IsGPIORW(x)         (x.flags & I2C_GPIO_RW)
#define IsSameTarget(x,y)   ((x.addr == y.addr) && !((x.flags ^ y.flags) & (~I2C_M_RD)))

struct rtk_i2c_dev {
	struct device *dev;
	struct i2c_adapter adapter;
	struct clk *div_clk;
	void __iomem *base;
	unsigned int id;
	bool is_suspended;
	u32 bus_clk_rate;
	int cont_id;
	int irq;
	int is_dvc;
    venus_i2c_reg_map   reg_map;
    venus_i2c * p_this;
};

void i2c_venus_dump_msg(const struct i2c_msg* p_msg){
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    printk("msg->addr  = %02x\n",p_msg->addr);
    printk("msg->flags = %04x\n",p_msg->flags);
    printk("msg->len   = %d  \n",p_msg->len);
    printk("msg->buf   = %p  \n",p_msg->buf);
}

static u32 rtk_i2c_func(struct i2c_adapter *adap){

	u32 ret = I2C_FUNC_I2C | I2C_FUNC_SMBUS_EMUL | I2C_FUNC_10BIT_ADDR | I2C_FUNC_PROTOCOL_MANGLING;

	return ret;
}

static int  i2c_venus_xfer(struct i2c_adapter *adap, struct i2c_msg msgs[], int num){

	struct rtk_i2c_dev *i2c_dev = i2c_get_adapdata(adap);
    venus_i2c* p_this = (venus_i2c*) i2c_dev->p_this;

    int ret = 0;
    int i = 0;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);

#ifdef EDID_4BLOCK_SUPPORT
	if(p_this->id==1 && num==3)
	{
		if(msgs[0].addr==0x30 && msgs[1].addr==0x50)
		{
			ret = p_this->read_edid_seg(p_this, msgs[0].buf[0]/*seg_point*/, msgs[1].buf[0]/*offset*/,msgs[2].buf,msgs[2].len);
			if(ret<0)
				goto err_occur;
			else
				return 3;
		}
	}
#endif

    for (i = 0; i < num ; i++){

        ret = p_this->set_tar(p_this, msgs[i].addr, ADDR_MODE_7BITS);

        if (ret<0)
            goto err_occur;

        switch(msgs[i].flags & I2C_M_SPEED_MASK){
        case I2C_M_FAST_SPEED:
            p_this->set_spd(p_this, 400);
			break;
        case I2C_M_HIGH_SPEED:
            p_this->set_spd(p_this, 800);
			break;
        case I2C_M_LOW_SPEED:
            p_this->set_spd(p_this, 50);
            break;
        case I2C_M_LOW_SPEED_80:
            p_this->set_spd(p_this, 80);
			break;
        case I2C_M_LOW_SPEED_66:
            p_this->set_spd(p_this, 66);
			break;
        case I2C_M_LOW_SPEED_33:
            p_this->set_spd(p_this, 33);
			break;
        case I2C_M_LOW_SPEED_10:
            p_this->set_spd(p_this, 10);
			break;
        default:
        case I2C_M_NORMAL_SPEED:
            p_this->set_spd(p_this, 100);
			break;
        }

        p_this->set_guard_interval(p_this, (msgs[i].flags & I2C_M_NO_GUARD_TIME) ? 0 : 1000);

        if (IsReadMsg(msgs[i])){
		if(0)// (IsGPIORW(msgs[i]))
                ret = p_this->gpio_read(p_this, NULL, 0, msgs[i].buf, msgs[i].len);
            else
                ret = p_this->read(p_this, NULL, 0, msgs[i].buf, msgs[i].len);
        }else{
            if ((i < (num-1)) && IsReadMsg(msgs[i+1]) && IsSameTarget(msgs[i], msgs[i+1])){
                // Random Read = Write + Read (same addr)
                if(0) //(IsGPIORW(msgs[i]))
                    ret = p_this->gpio_read(p_this, msgs[i].buf, msgs[i].len, msgs[i+1].buf, msgs[i+1].len);
                else
                    ret = p_this->read(p_this, msgs[i].buf, msgs[i].len, msgs[i+1].buf, msgs[i+1].len);
                i++;
            }else{
                // Single Write
                if(0)// (IsGPIORW(msgs[i]))
                    ret = p_this->gpio_write(p_this, msgs[i].buf, msgs[i].len, (i==(num-1)) ? WAIT_STOP : NON_STOP);
                else
                    ret = p_this->write(p_this, msgs[i].buf, msgs[i].len, (i==(num-1)) ? WAIT_STOP : NON_STOP);
            }
        }

        if (ret < 0)
            goto err_occur;
    }

    return i;

err_occur:

    switch(ret){
    case -ECMDSPLIT:
        printk("[I2C%d] Xfer fail - MSG SPLIT (%d/%d)\n", p_this->id, i,num);
        break;
    case -ETXABORT:
        printk("[I2C%d] Xfer fail - TXABORT (%d/%d), Reason=%04x\n",p_this->id, i,num, p_this->get_tx_abort_reason(p_this));
        break;
    case -ETIMEOUT:
        printk("[I2C%d] Xfer fail - TIMEOUT (%d/%d)\n", p_this->id, i,num);
        break;
    case -EILLEGALMSG:
        printk("[I2C%d] Xfer fail - ILLEGAL MSG (%d/%d)\n",p_this->id, i,num);
        break;
    case -EADDROVERRANGE:
        printk("[I2C%d] Xfer fail - ADDRESS OUT OF RANGE (%d/%d)\n",p_this->id, i,num);
        break;
    default:
        printk("[I2C%d] Xfer fail - Unkonwn Return Value (%d/%d)\n", p_this->id, i,num);
        break;
    }

    i2c_venus_dump_msg(&msgs[i]);

    ret = -EACCES;
    return ret;
}

static const struct i2c_algorithm rtk_i2c_algo = {
	.master_xfer	= i2c_venus_xfer,
	.functionality	= rtk_i2c_func,
};

/*
void rtk_i2c_dump_register(struct rtk_i2c_dev *i2c_dev){

	u32 base = i2c_dev->base;

	printk("i2c_dev->p_this->reg_map.IC_CON = %x\n", i2c_dev->p_this->reg_map.IC_CON);
	printk("i2c_dev->p_this->reg_map.IC_TAR = %x\n", i2c_dev->p_this->reg_map.IC_TAR);
	printk("i2c_dev->p_this->reg_map.IC_SAR = %x\n", i2c_dev->p_this->reg_map.IC_SAR);
	printk("i2c_dev->p_this->reg_map.IC_HS_MADDR = %x\n", i2c_dev->p_this->reg_map.IC_HS_MADDR);
	printk("i2c_dev->p_this->reg_map.IC_DATA_CMD = %x\n", i2c_dev->p_this->reg_map.IC_DATA_CMD);
	printk("i2c_dev->p_this->reg_map.IC_FS_SCL_HCNT = %x\n", i2c_dev->p_this->reg_map.IC_FS_SCL_HCNT);
	printk("i2c_dev->p_this->reg_map.IC_FS_SCL_LCNT = %x\n", i2c_dev->p_this->reg_map.IC_FS_SCL_LCNT);
	printk("i2c_dev->p_this->reg_map.IC_SS_SCL_HCNT = %x\n", i2c_dev->p_this->reg_map.IC_SS_SCL_HCNT);
	printk("i2c_dev->p_this->reg_map.IC_SS_SCL_HCNT = %x\n", i2c_dev->p_this->reg_map.IC_SS_SCL_LCNT);
	printk("i2c_dev->p_this->reg_map.IC_INTR_STAT = %x\n", i2c_dev->p_this->reg_map.IC_INTR_STAT);
	printk("i2c_dev->p_this->reg_map.IC_INTR_MASK = %x\n", i2c_dev->p_this->reg_map.IC_INTR_MASK);
	printk("i2c_dev->p_this->reg_map.IC_RAW_INTR_STAT = %x\n", i2c_dev->p_this->reg_map.IC_RAW_INTR_STAT);
	printk("i2c_dev->p_this->reg_map.IC_RX_TL = %x\n", i2c_dev->p_this->reg_map.IC_RX_TL);
	printk("i2c_dev->p_this->reg_map.IC_TX_TL = %x\n", i2c_dev->p_this->reg_map.IC_TX_TL);
	printk("i2c_dev->p_this->reg_map.IC_CLR_INTR = %x\n", i2c_dev->p_this->reg_map.IC_CLR_INTR);
	printk("i2c_dev->p_this->reg_map.IC_CLR_RX_UNDER = %x\n", i2c_dev->p_this->reg_map.IC_CLR_RX_UNDER);
	printk("i2c_dev->p_this->reg_map.IC_CLR_RX_OVER = %x\n", i2c_dev->p_this->reg_map.IC_CLR_RX_OVER);
	printk("i2c_dev->p_this->reg_map.IC_CLR_TX_OVER = %x\n", i2c_dev->p_this->reg_map.IC_CLR_TX_OVER);
	printk("i2c_dev->p_this->reg_map.IC_CLR_RD_REQ = %x\n", i2c_dev->p_this->reg_map.IC_CLR_RD_REQ);
	printk("i2c_dev->p_this->reg_map.IC_CLR_TX_ABRT = %x\n", i2c_dev->p_this->reg_map.IC_CLR_TX_ABRT);
	printk("i2c_dev->p_this->reg_map.IC_CLR_RX_DONE = %x\n", i2c_dev->p_this->reg_map.IC_CLR_RX_DONE);
	printk("i2c_dev->p_this->reg_map.IC_CLR_ACTIVITY = %x\n", i2c_dev->p_this->reg_map.IC_CLR_ACTIVITY);
	printk("i2c_dev->p_this->reg_map.IC_CLR_STOP_DET = %x\n", i2c_dev->p_this->reg_map.IC_CLR_STOP_DET);
	printk("i2c_dev->p_this->reg_map.IC_CLR_START_DET = %x\n", i2c_dev->p_this->reg_map.IC_CLR_START_DET);
	printk("i2c_dev->p_this->reg_map.IC_CLR_GEN_CALL = %x\n", i2c_dev->p_this->reg_map.IC_CLR_GEN_CALL);
	printk("i2c_dev->p_this->reg_map.IC_ENABLE = %x\n", i2c_dev->p_this->reg_map.IC_ENABLE);
	printk("i2c_dev->p_this->reg_map.IC_STATUS = %x\n", i2c_dev->p_this->reg_map.IC_STATUS);
	printk("i2c_dev->p_this->reg_map.IC_TXFLR = %x\n", i2c_dev->p_this->reg_map.IC_TXFLR);
	printk("i2c_dev->p_this->reg_map.IC_RXFLR = %x\n", i2c_dev->p_this->reg_map.IC_RXFLR);
	printk("i2c_dev->p_this->reg_map.IC_SDA_HOLD = %x\n", i2c_dev->p_this->reg_map.IC_SDA_HOLD);
	printk("i2c_dev->p_this->reg_map.IC_TX_ABRT_SOURCE = %x\n", i2c_dev->p_this->reg_map.IC_TX_ABRT_SOURCE);
	printk("i2c_dev->p_this->reg_map.IC_SLV_DATA_NACK_ONLY = %x\n", i2c_dev->p_this->reg_map.IC_SLV_DATA_NACK_ONLY);
	printk("i2c_dev->p_this->reg_map.IC_DMA_CR = %x\n", i2c_dev->p_this->reg_map.IC_DMA_CR);
	printk("i2c_dev->p_this->reg_map.IC_DMA_TDLR = %x\n", i2c_dev->p_this->reg_map.IC_DMA_TDLR);
	printk("i2c_dev->p_this->reg_map.IC_DMA_RDLR = %x\n", i2c_dev->p_this->reg_map.IC_DMA_RDLR);
	printk("i2c_dev->p_this->reg_map.IC_SDA_SETUP = %x\n", i2c_dev->p_this->reg_map.IC_SDA_SETUP);
	printk("i2c_dev->p_this->reg_map.IC_ACK_GENERAL_CALL = %x\n", i2c_dev->p_this->reg_map.IC_ACK_GENERAL_CALL);
	printk("i2c_dev->p_this->reg_map.IC_ENABLE_STATUS = %x\n", i2c_dev->p_this->reg_map.IC_ENABLE_STATUS);
	printk("i2c_dev->p_this->reg_map.IC_COMP_PARAM_1 = %x\n", i2c_dev->p_this->reg_map.IC_COMP_PARAM_1);
	printk("i2c_dev->p_this->reg_map.IC_COMP_VERSION = %x\n", i2c_dev->p_this->reg_map.IC_COMP_VERSION);
	printk("i2c_dev->p_this->reg_map.IC_COMP_TYPE = %x\n", i2c_dev->p_this->reg_map.IC_COMP_TYPE);
}
*/

static void rtk_i2c_setup_reg_base(struct rtk_i2c_dev *i2c_dev){

//	u32 base = (u32)i2c_dev->base;
	unsigned long long base = (unsigned long long)i2c_dev->base;

	switch(i2c_dev->id){
		case 0:
			i2c_dev->p_this->reg_map.I2C_ISR = (base & ~0xFFF);
			i2c_dev->p_this->reg_map.I2C_INT = ISO_ISR_I2C0;
			i2c_dev->p_this->reg_map.IC_SDA_DEL = (base & ~0xFFF) | ISO_I2C0_SDA_DEL;
			break;
		case 1:
			i2c_dev->p_this->reg_map.I2C_ISR = (base & ~0xFFF);
			i2c_dev->p_this->reg_map.I2C_INT = ISO_ISR_I2C1;
			i2c_dev->p_this->reg_map.IC_SDA_DEL = (base & ~0xFFF) | ISO_I2C1_SDA_DEL;
			break;
		case 2:
			i2c_dev->p_this->reg_map.I2C_ISR = (base & ~0xFFF) | 0x000C;
			i2c_dev->p_this->reg_map.I2C_INT = MIS_ISR_I2C2;
			i2c_dev->p_this->reg_map.IC_SDA_DEL = (base & ~0xFFF) | MIS_I2C2_SDA_DEL;
			break;
		case 3:
			i2c_dev->p_this->reg_map.I2C_ISR = (base & ~0xFFF) | 0x000C;
			i2c_dev->p_this->reg_map.I2C_INT = MIS_ISR_I2C3;
			i2c_dev->p_this->reg_map.IC_SDA_DEL = (base & ~0xFFF) | MIS_I2C3_SDA_DEL;
			break;
		case 4:
			i2c_dev->p_this->reg_map.I2C_ISR = (base & ~0xFFF) | 0x000C;
			i2c_dev->p_this->reg_map.I2C_INT = MIS_ISR_I2C4;
			i2c_dev->p_this->reg_map.IC_SDA_DEL = (base & ~0xFFF) | MIS_I2C4_SDA_DEL;
			break;
		case 5:
			i2c_dev->p_this->reg_map.I2C_ISR = (base & ~0xFFF) | 0x000C;
			i2c_dev->p_this->reg_map.I2C_INT = MIS_ISR_I2C5;
			i2c_dev->p_this->reg_map.IC_SDA_DEL = (base & ~0xFFF) | MIS_I2C5_SDA_DEL;
			break;
		case 6:
			i2c_dev->p_this->reg_map.I2C_ISR = (base & ~0xFFF);
			i2c_dev->p_this->reg_map.I2C_INT = ISO_ISR_I2C6;
			i2c_dev->p_this->reg_map.IC_SDA_DEL = (base & ~0xFFF) | ISO_I2C6_SDA_DEL;
			break;
		default:
			break;
	}

	i2c_dev->p_this->reg_map.IC_CON = base | I2C_CON;
	i2c_dev->p_this->reg_map.IC_TAR = base | I2C_TAR;
	i2c_dev->p_this->reg_map.IC_SAR = base | I2C_SAR;
	i2c_dev->p_this->reg_map.IC_HS_MADDR = base | I2C_HS_MADDR;
	i2c_dev->p_this->reg_map.IC_DATA_CMD = base | I2C_DATA_CMD;

	i2c_dev->p_this->reg_map.IC_FS_SCL_HCNT = base | I2C_FS_SCL_HCNT;
	i2c_dev->p_this->reg_map.IC_FS_SCL_LCNT = base | I2C_FS_SCL_LCNT;
	i2c_dev->p_this->reg_map.IC_SS_SCL_HCNT = base | I2C_SS_SCL_HCNT;
	i2c_dev->p_this->reg_map.IC_SS_SCL_LCNT = base | I2C_SS_SCL_LCNT;
	i2c_dev->p_this->reg_map.IC_INTR_STAT = base | I2C_INTR_STAT;
	i2c_dev->p_this->reg_map.IC_INTR_MASK = base | I2C_INTR_MASK;
	i2c_dev->p_this->reg_map.IC_RAW_INTR_STAT = base | I2C_RAW_INTR_STAT;
	i2c_dev->p_this->reg_map.IC_RX_TL = base | I2C_RX_TL;
	i2c_dev->p_this->reg_map.IC_TX_TL = base | I2C_TX_TL;

	i2c_dev->p_this->reg_map.IC_CLR_INTR = base | I2C_CLR_INTR;
	i2c_dev->p_this->reg_map.IC_CLR_RX_UNDER = base | I2C_CLR_RX_UNDER;
	i2c_dev->p_this->reg_map.IC_CLR_RX_OVER = base | I2C_CLR_RX_OVER;
	i2c_dev->p_this->reg_map.IC_CLR_TX_OVER = base | I2C_CLR_TX_OVER;
	i2c_dev->p_this->reg_map.IC_CLR_RD_REQ = base | I2C_CLR_RD_REQ;;
	i2c_dev->p_this->reg_map.IC_CLR_TX_ABRT = base | I2C_CLR_TX_ABRT;
	i2c_dev->p_this->reg_map.IC_CLR_RX_DONE = base | I2C_CLR_RX_DONE;
	i2c_dev->p_this->reg_map.IC_CLR_ACTIVITY = base | I2C_CLR_ACTIVITY;
	i2c_dev->p_this->reg_map.IC_CLR_STOP_DET = base | I2C_CLR_STOP_DET;
	i2c_dev->p_this->reg_map.IC_CLR_START_DET = base | I2C_CLR_START_DET;
	i2c_dev->p_this->reg_map.IC_CLR_GEN_CALL = base | I2C_CLR_GEN_CALL;

	i2c_dev->p_this->reg_map.IC_ENABLE = base | I2C_ENABLE;
	i2c_dev->p_this->reg_map.IC_STATUS = base | I2C_STATUS;
	i2c_dev->p_this->reg_map.IC_TXFLR = base | I2C_TXFLR;
	i2c_dev->p_this->reg_map.IC_RXFLR = base | I2C_RXFLR;
	i2c_dev->p_this->reg_map.IC_SDA_HOLD = base | I2C_SDA_HOLD;
	i2c_dev->p_this->reg_map.IC_TX_ABRT_SOURCE = base | I2C_TX_ABRT_SOURCE;
	i2c_dev->p_this->reg_map.IC_SLV_DATA_NACK_ONLY = base | I2C_SLV_DATA_NACK_ONLY;
	i2c_dev->p_this->reg_map.IC_DMA_CR = base | I2C_DMA_CR;
	i2c_dev->p_this->reg_map.IC_DMA_TDLR = base | I2C_DMA_TDLR;
	i2c_dev->p_this->reg_map.IC_DMA_RDLR = base | I2C_DMA_RDLR;
	i2c_dev->p_this->reg_map.IC_SDA_SETUP = base | I2C_SDA_SETUP;
	i2c_dev->p_this->reg_map.IC_ACK_GENERAL_CALL = base | I2C_ACK_GENERAL_CALL;
	i2c_dev->p_this->reg_map.IC_ENABLE_STATUS = base | I2C_ENABLE_STATUS;
	i2c_dev->p_this->reg_map.IC_COMP_PARAM_1 = base | I2C_COMP_PARAM_1;
	i2c_dev->p_this->reg_map.IC_COMP_VERSION = base | I2C_COMP_VERSION;
	i2c_dev->p_this->reg_map.IC_COMP_TYPE = base | I2C_COMP_TYPE;

}

static int  rtk_i2c_init(struct rtk_i2c_dev *i2c_dev){

	int i = 0;

	i2c_dev->p_this = create_venus_i2c_handle(i2c_dev->id, VENUS_MASTER_7BIT_ADDR, ADDR_MODE_7BITS, SPD_MODE_SS, i2c_dev->irq);

    if (i2c_dev->p_this==NULL)
        printk("[I2C%d] p_this is NULL, FAIL!!!!!!!!!!!!!!\n", i);

	rtk_i2c_setup_reg_base(i2c_dev);

	i2c_dev->p_this->n_port = i2c_phy[i2c_dev->p_this->id].n_port;
	i2c_dev->p_this->p_port = (venus_i2c_port *)i2c_phy[i2c_dev->p_this->id].p_port;
//	i2c_dev->p_this->current_port = venus_i2c_find_current_port(i2c_dev->p_this);

    if (i2c_dev->p_this->current_port && i2c_dev->p_this->current_port->gpio_mapped){
	i2c_dev->p_this->gpio_map.muxpad      = i2c_dev->p_this->current_port->pin_mux[0].addr;
	i2c_dev->p_this->gpio_map.muxpad_mask = i2c_dev->p_this->current_port->pin_mux[0].mask;
	i2c_dev->p_this->gpio_map.muxpad_gpio = i2c_dev->p_this->current_port->pin_mux[0].gpio_val;
	i2c_dev->p_this->gpio_map.muxpad_i2c  = i2c_dev->p_this->current_port->pin_mux[0].i2c_val;
	i2c_dev->p_this->gpio_map.sda         = i2c_dev->p_this->current_port->g2c_sda;
	i2c_dev->p_this->gpio_map.scl         = i2c_dev->p_this->current_port->g2c_scl;
	i2c_dev->p_this->gpio_map.valid       = 1;
    }else{
	i2c_dev->p_this->gpio_map.valid = 0;
    }

	i2c_dev->p_this->flags = VENUS_I2C_IRQ_RDY;
	i2c_dev->p_this->rx_fifo_depth = ((GET_IC_COMP_PARAM_1(i2c_dev->p_this) >>  8) & 0xFF)+1;
	i2c_dev->p_this->tx_fifo_depth = ((GET_IC_COMP_PARAM_1(i2c_dev->p_this) >> 16) & 0xFF)+1;

	init_waitqueue_head(&i2c_dev->p_this->wq);

	return venus_i2c_phy_init(i2c_dev->p_this);
}

/* Match table for of_platform binding */
static const struct of_device_id rtk_i2c_of_match[] = {
	{ .compatible = "Realtek,rtk-i2c", },
	{},
};
MODULE_DEVICE_TABLE(of, rtk_i2c_of_match);

static int rtk_i2c_probe(struct platform_device *pdev){

	struct rtk_i2c_dev *i2c_dev;
	struct clk *div_clk = NULL;
	//struct clk *fast_clk;
	void __iomem *base;
	int irq;
	u32 i2c_id;
	int ret = 0;
	char clkname[20];

	base = of_iomap(pdev->dev.of_node, 0);
	if (!base) {
		printk(KERN_ERR "i2c no mmio space\n");
		return -EINVAL;
	}

	irq = irq_of_parse_and_map(pdev->dev.of_node, 0);
	if (irq < 0) {
		printk(KERN_ERR "i2c no irq\n");
		return -EINVAL;
	}

	if(of_property_read_u32(pdev->dev.of_node, "i2c-num", &i2c_id)){
		printk(KERN_ERR "Get I2C ID fail\n");
		return -EINVAL;
	}

	if(i2c_id==0 || i2c_id==1)
		sprintf(clkname, "clk_en_i2c%d", i2c_id);
	else
		sprintf(clkname, "clk_en_misc_i2c_%d", i2c_id);

	div_clk = clk_get(NULL, clkname);
	if (IS_ERR(div_clk))
		return PTR_ERR(div_clk);
	else
		clk_prepare_enable(div_clk);
/*
	div_clk = devm_clk_get(&pdev->dev, "div-clk");
	if (IS_ERR(div_clk)) {
		dev_err(&pdev->dev, "missing controller clock");
		return PTR_ERR(div_clk);
	}
*/
	i2c_dev = devm_kzalloc(&pdev->dev, sizeof(*i2c_dev), GFP_KERNEL);
	if (!i2c_dev) {
		dev_err(&pdev->dev, "Could not allocate struct tegra_i2c_dev");
		return -ENOMEM;
	}

	i2c_dev->base = base;
	i2c_dev->div_clk = div_clk;
	i2c_dev->adapter.algo = &rtk_i2c_algo;
	i2c_dev->irq = irq;
	i2c_dev->cont_id = pdev->id;
	i2c_dev->id = i2c_id;
	i2c_dev->dev = &pdev->dev;

	ret = of_property_read_u32(i2c_dev->dev->of_node, "clock-frequency",
					&i2c_dev->bus_clk_rate);
	if (ret)
		i2c_dev->bus_clk_rate = 100000; /* default clock rate */

	if (pdev->dev.of_node) {
		const struct of_device_id *match;
		match = of_match_device(rtk_i2c_of_match, &pdev->dev);
		i2c_dev->is_dvc = of_device_is_compatible(pdev->dev.of_node, "Realtek,rtk-i2c");
	} else if (pdev->id == 3) {
		i2c_dev->is_dvc = 1;
	}

	/*if (!i2c_dev->hw->has_single_clk_source) {
		fast_clk = devm_clk_get(&pdev->dev, "fast-clk");
		if (IS_ERR(fast_clk)) {
			dev_err(&pdev->dev, "missing fast clock");
			return PTR_ERR(fast_clk);
		}
		i2c_dev->fast_clk = fast_clk;
	}*/

	platform_set_drvdata(pdev, i2c_dev);

	ret = rtk_i2c_init(i2c_dev);

	if (ret) {
		dev_err(&pdev->dev, "Failed to initialize i2c controller");
		return ret;
	}

	ret = devm_request_irq(&pdev->dev, i2c_dev->irq, venus_i2c_isr, IRQF_SHARED, dev_name(&pdev->dev), (void*)i2c_dev->p_this);
	if (ret) {
		dev_err(&pdev->dev, "Failed to request irq %i\n", i2c_dev->irq);
		return ret;
	}

	i2c_set_adapdata(&i2c_dev->adapter, i2c_dev);
	i2c_dev->adapter.owner = THIS_MODULE;
	i2c_dev->adapter.class = I2C_CLASS_HWMON;
	strlcpy(i2c_dev->adapter.name, "Realtek I2C adapter", sizeof(i2c_dev->adapter.name));
	i2c_dev->adapter.dev.parent = &pdev->dev;
	i2c_dev->adapter.nr = pdev->id;
	i2c_dev->adapter.dev.of_node = pdev->dev.of_node;

	ret = i2c_add_numbered_adapter(&i2c_dev->adapter);
	if (ret) {
		dev_err(&pdev->dev, "Failed to add I2C adapter\n");
		return ret;
	}
//	of_i2c_register_devices(&i2c_dev->adapter);

	return 0;
}

static int rtk_i2c_remove(struct platform_device *pdev){

	struct rtk_i2c_dev *i2c_dev = platform_get_drvdata(pdev);
	i2c_del_adapter(&i2c_dev->adapter);
	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int rtk_i2c_suspend(struct device *dev)
{
	struct rtk_i2c_dev *i2c_dev = dev_get_drvdata(dev);

	printk("[I2C] Enter %s\n", __FUNCTION__);

	i2c_lock_adapter(&i2c_dev->adapter);
	i2c_dev->is_suspended = true;
	clk_disable_unprepare(i2c_dev->div_clk);
	i2c_unlock_adapter(&i2c_dev->adapter);

	printk("[I2C] Exit %s\n", __FUNCTION__);

	return 0;
}

static int rtk_i2c_resume(struct device *dev)
{
	struct rtk_i2c_dev *i2c_dev = dev_get_drvdata(dev);
	int ret;

	printk("[I2C] Enter %s\n", __FUNCTION__);

	i2c_lock_adapter(&i2c_dev->adapter);

	clk_prepare_enable(i2c_dev->div_clk);
	ret = rtk_i2c_init(i2c_dev);

	if (ret) {
		i2c_unlock_adapter(&i2c_dev->adapter);
		return ret;
	}

	i2c_dev->is_suspended = false;

	i2c_unlock_adapter(&i2c_dev->adapter);

	printk("[I2C] Exit %s\n", __FUNCTION__);

	return 0;
}

//static SIMPLE_DEV_PM_OPS(rtk_i2c_pm, rtk_i2c_suspend, rtk_i2c_resume);
static const struct dev_pm_ops rtk_i2c_pm_ops = {
	.suspend_noirq = rtk_i2c_suspend,
	.resume_noirq = rtk_i2c_resume,
};

#define RTK_I2C_PM_OPS	(&rtk_i2c_pm_ops)
#else
#define RTK_I2C_PM_OPS	NULL
#endif

static struct platform_driver rtk_i2c_driver = {
	.probe		= rtk_i2c_probe,
	.remove		= rtk_i2c_remove,
	.driver		= {
		.name	= "rtk_i2c",
		.owner	= THIS_MODULE,
		.pm	= RTK_I2C_PM_OPS,
		.of_match_table = of_match_ptr(rtk_i2c_of_match),
	},
};

/* I2C may be needed to bring up other drivers */
static int __init rtk_i2c_init_driver(void){
	return platform_driver_register(&rtk_i2c_driver);
}
subsys_initcall(rtk_i2c_init_driver);

static void __exit rtk_i2c_exit_driver(void){
	platform_driver_unregister(&rtk_i2c_driver);
}
module_exit(rtk_i2c_exit_driver);

MODULE_AUTHOR("James Tai <james.tai@realtek.com>");
MODULE_DESCRIPTION("Realtek I2C bus adapter");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:rtk_i2c");
