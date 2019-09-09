/* ------------------------------------------------------------------------- */
/* i2c-venus-priv.c  venus i2c hw driver for Realtek Venus DVR I2C           */
/* ------------------------------------------------------------------------- */
/*   Copyright (C) 2008 Kevin Wang <kevin_wang@realtek.com.tw>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
-------------------------------------------------------------------------
Update List :
-------------------------------------------------------------------------
    1.1     |   20080530    | Using for loop instead of while loop
-------------------------------------------------------------------------
    1.1a    |   20080531    | Add 1 ms delay at the end of each xfer
                            | for timing compatibility with old i2c driver
-------------------------------------------------------------------------
    1.1b    |   20080531    | After Xfer complete, ISR will Disable All Interrupts
                            | and Disable I2C first, then wakeup the caller
-------------------------------------------------------------------------
    1.1c    |   20080617    | Add API get_tx_abort_reason
-------------------------------------------------------------------------
    1.1d    |   20080630    | Add I2C bus jammed recover feature.
            |               | send 10 bits clock with gpio 4 to recover bus jam problem.
-------------------------------------------------------------------------
    1.1e    |   20080702    | Disable GP 4/5 interript during detect bus jam
-------------------------------------------------------------------------
    1.1f    |   20080707    | Only do bus jam detect/recover after timeout occurs
-------------------------------------------------------------------------
    1.2     |   20080711    | modified to support mars i2c
-------------------------------------------------------------------------
    1.2a    |   20080714    | modified the way of i2c/GPIO selection
-------------------------------------------------------------------------
    1.3     |   20080729    | Support Non Stop Write Transfer
-------------------------------------------------------------------------
    1.3a    |   20080729    | Fix bug of non stop write transfer
            |               |    1) MSB first
            |               |    2) no stop after write ack
-------------------------------------------------------------------------
    1.3b    |   20080730    | Support non stop write in Mars
            |               | Support bus jam recorver in Mars
-------------------------------------------------------------------------
    1.3c    |   20080807    | Support minimum delay feature
-------------------------------------------------------------------------
    1.4     |   20081016    | Mars I2C_1 Support
-------------------------------------------------------------------------
    1.5     |   20090330    | Add Spin Lock to Protect venus_i2c data structure
-------------------------------------------------------------------------
    1.6     |   20090407    | Add FIFO threshold to avoid timing issue caused
            |               | by performance issue
-------------------------------------------------------------------------
    1.7     |   20090423    | Add Suspen/Resume Feature
-------------------------------------------------------------------------
    2.0     |   20091019    | Add Set Speed feature
-------------------------------------------------------------------------
    2.0a    |   20091020    | change speed of bus jam recover via spd argument
-------------------------------------------------------------------------
    2.1     |   20100511    | Support GPIO Read Write
-------------------------------------------------------------------------*/
#include <linux/kernel.h>
#include <linux/kernel.h>
#include <linux/ioport.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/i2c.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/delay.h>

#include "i2c-rtk-priv.h"
////////////////////////////////////////////////////////////////////
#ifdef CONFIG_REALTEK_JUPITER
#include "i2c-venus-config-jupiter.h"
#endif

#ifdef CONFIG_REALTEK_SATURN
#include "i2c-venus-config-saturn.h"
#endif

#ifdef CONFIG_REALTEK_DARWIN
#include "i2c-venus-config-darwin.h"
#endif

#ifdef CONFIG_REALTEK_MACARTHUR
#include "i2c-venus-config-macarthur.h"
#endif

#ifdef CONFIG_REALTEK_NIKE
#include "i2c-venus-config-nike.h"
#endif

#include "i2c-venus-config-saturn.h"
//#include "i2c-phoenix-config.h"

// for debug

#define i2c_print                       printk
#define dbg_char(x)                     wr_reg(0xb801b200, (unsigned long) (x))

#ifdef SPIN_LOCK_PROTECT_EN
    #define LOCK_VENUS_I2C(a,b)         spin_lock_irqsave(a, b)
    #define UNLOCK_VENUS_I2C(a, b)      spin_unlock_irqrestore(a, b)
#else
    #define LOCK_VENUS_I2C(a,b)         do { b = 1; }while(0)
    #define UNLOCK_VENUS_I2C(a, b)      do { b = 0; }while(0)
#endif

#ifdef I2C_PROFILEING_EN
#define LOG_EVENT(x)                    log_event(x)
#else
#define LOG_EVENT(x)
#endif

#ifdef CONFIG_I2C_RTK_BUS_JAM_RECOVER
void venus_i2c_bus_jam_recover(venus_i2c* p_this);
int  venus_i2c_bus_jam_detect(venus_i2c* p_this);
void venus_i2c_bus_jam_recover_proc(venus_i2c* p_this);
#endif

#define SA_SHIRQ IRQF_SHARED

#define  phoenix_i2c_mdelay(x)  \
            set_current_state(TASK_INTERRUPTIBLE); \
            schedule_timeout(msecs_to_jiffies(x))

static int phoenix_i2c_gpio_set_dir (VENUS_GPIO_ID gid,  unsigned char out)
{
	/* Fix me */
	return 0;
}
static int phoenix_i2c_gpio_input (VENUS_GPIO_ID gid)
{
	/* Fix me */
	return 0;
}
static int phoenix_i2c_gpio_output (VENUS_GPIO_ID gid, unsigned char    val)
{
	/* Fix me */
	return 0;
}
static int phoenix_i2c_gpio_set_irq_enable (VENUS_GPIO_ID gid,  unsigned char     on)
{
	/* Fix me */
	return 0;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_msater_write
 *
 * Desc : master write handler for venus i2c
 *
 * Parm : p_this : handle of venus i2c
 *        event  : INT event of venus i2c
 *
 * Retn : N/A
 *------------------------------------------------------------------*/
void venus_i2c_msater_write(venus_i2c* p_this, unsigned int event, unsigned int tx_abort_source)
{
#define TxComplete()              (p_this->xfer.tx_len >= p_this->xfer.tx_buff_len)

    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    while(!TxComplete() && NOT_TXFULL(p_this))
    {
		RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
		if(p_this->xfer.tx_len == p_this->xfer.tx_buff_len-1)
		{
			SET_IC_DATA_CMD(p_this, ((p_this->xfer.tx_buff[p_this->xfer.tx_len++]) |(0x1<<9)));//TODO: stop victor add 2014.3.3
			RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
		}else{
			SET_IC_DATA_CMD(p_this, p_this->xfer.tx_buff[p_this->xfer.tx_len++]);
			RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
		}
    }

    if (TxComplete())
    {
        SET_IC_INTR_MASK(p_this, GET_IC_INTR_MASK(p_this) & ~TX_EMPTY_BIT);
    }

    if (event & TX_ABRT_BIT)
    {
        p_this->xfer.ret = -ETXABORT;
        p_this->xfer.tx_abort_source = tx_abort_source;
    }
    else if (event & STOP_DET_BIT)
    {
        p_this->xfer.ret = TxComplete() ? p_this->xfer.tx_len : -ECMDSPLIT;
    }

    if (p_this->xfer.ret)
    {
        SET_IC_INTR_MASK(p_this, 0);
        SET_IC_ENABLE(p_this, 0);
        p_this->xfer.mode = I2C_IDEL;	// change to idle state
        wake_up(&p_this->wq);
    }

#undef TxComplete
}

/*------------------------------------------------------------------
 * Func : venus_i2c_msater_read
 *
 * Desc : master read handler for venus i2c
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : N/A
 *------------------------------------------------------------------*/
void venus_i2c_msater_read(venus_i2c* p_this, unsigned int event, unsigned int tx_abort_source)
{
#define TxComplete()        (p_this->xfer.tx_len >= p_this->xfer.rx_buff_len)
#define RxComplete()        (p_this->xfer.rx_len >= p_this->xfer.rx_buff_len)
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    // TX Thread
    while(!TxComplete() && NOT_TXFULL(p_this))
    {
		if(p_this->xfer.tx_len == ((p_this->xfer.rx_buff_len + p_this->xfer.tx_buff_len)-1)){
			RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
			SET_IC_DATA_CMD(p_this, (READ_CMD|(0x1<<9)) );  // send stop command to rx fifo   //TODO: stop victor add 2014.3.3
		}else{
			SET_IC_DATA_CMD(p_this, READ_CMD);  // send read command to rx fifo
		}
		p_this->xfer.tx_len++;
		while (!RxComplete() && NOT_RXEMPTY(p_this))
		{
		p_this->xfer.rx_buff[p_this->xfer.rx_len++] = (unsigned char)(GET_IC_DATA_CMD(p_this) & 0xFF);
		}
    }

    // RX Thread
    while (!RxComplete() && NOT_RXEMPTY(p_this))
    {
        p_this->xfer.rx_buff[p_this->xfer.rx_len++] = (unsigned char)(GET_IC_DATA_CMD(p_this) & 0xFF);
    }

    if (TxComplete())
    {
        SET_IC_INTR_MASK(p_this, GET_IC_INTR_MASK(p_this) & ~TX_EMPTY_BIT);
    }

    if (event & TX_ABRT_BIT)
    {
        p_this->xfer.ret = -ETXABORT;
        p_this->xfer.tx_abort_source = tx_abort_source;
    }
    else if ((event & STOP_DET_BIT) || RxComplete())
    {
        SET_IC_INTR_MASK(p_this, GET_IC_INTR_MASK(p_this) & ~RX_FULL_BIT);

        p_this->xfer.ret = RxComplete() ? p_this->xfer.rx_len : -ECMDSPLIT;
    }

    if (p_this->xfer.ret)
    {
        SET_IC_INTR_MASK(p_this, 0);
        SET_IC_ENABLE(p_this, 0);
        p_this->xfer.mode = I2C_IDEL;	// change to idle state
        wake_up(&p_this->wq);
    }

#undef TxComplete
#undef RxComplete
}

/*------------------------------------------------------------------
 * Func : venus_i2c_msater_read
 *
 * Desc : master read handler for venus i2c
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : N/A
 *------------------------------------------------------------------*/
void venus_i2c_msater_random_read(venus_i2c* p_this, unsigned int event, unsigned int tx_abort_source)
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
#define TxComplete()        (p_this->xfer.tx_len >= (p_this->xfer.rx_buff_len + p_this->xfer.tx_buff_len))    // it should add the same number of read command to tx fifo
#define RxComplete()        (p_this->xfer.rx_len >=  p_this->xfer.rx_buff_len)

    // TX Thread
	while(!TxComplete() && NOT_TXFULL(p_this))
	{
		if (p_this->xfer.tx_len < p_this->xfer.tx_buff_len)
	    {
			RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
		SET_IC_DATA_CMD(p_this, p_this->xfer.tx_buff[p_this->xfer.tx_len]);

		}else{
			if( (p_this->xfer.tx_len == (p_this->xfer.tx_buff_len))	&&
				(p_this->xfer.tx_len == ((p_this->xfer.rx_buff_len + p_this->xfer.tx_buff_len)-1))	)
			{
				RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
				SET_IC_DATA_CMD(p_this, (READ_CMD|(0x3<<9)) );  // send Restart command and STOP to rx fifo  : first also last read cmd
			}
			else
			if ( (p_this->xfer.tx_len == (p_this->xfer.tx_buff_len)) &&
				(!(p_this->xfer.tx_len == ((p_this->xfer.rx_buff_len + p_this->xfer.tx_buff_len)-1))) )
			{
				RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
				SET_IC_DATA_CMD(p_this, (READ_CMD|(0x1<<10)) );  // send restart command to rx fifo : first but not last read cmd
			}
			else
			if ( (!(p_this->xfer.tx_len == (p_this->xfer.tx_buff_len))) &&
				(p_this->xfer.tx_len == ((p_this->xfer.rx_buff_len + p_this->xfer.tx_buff_len)-1)) )
			{
				RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
				SET_IC_DATA_CMD(p_this, (READ_CMD|(0x1<<9)) );  // send stop command to rx fifo  : not first but last read cmd
			}
			else
			{
				RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
				SET_IC_DATA_CMD(p_this, READ_CMD);  // send read command to rx fifo : not first also not last read cmd
			}
		}
	p_this->xfer.tx_len++;

		// RX Thread, incase rxfifo overflow and the datas are droped
		while(!RxComplete() && NOT_RXEMPTY(p_this))
		{
			RTK_DEBUG("[%s] %s  %d p_this->xfer.rx_len =%d \n", __FILE__,__FUNCTION__,__LINE__,p_this->xfer.rx_len);
			p_this->xfer.rx_buff[p_this->xfer.rx_len++] = (unsigned char)(GET_IC_DATA_CMD(p_this) & 0xFF);
		}
	}
	RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);

    // RX Thread
    while(!RxComplete() && NOT_RXEMPTY(p_this))
    {
        p_this->xfer.rx_buff[p_this->xfer.rx_len++] = (unsigned char)(GET_IC_DATA_CMD(p_this) & 0xFF);
    }

    if TxComplete()
    {
        SET_IC_INTR_MASK(p_this, GET_IC_INTR_MASK(p_this) & ~TX_EMPTY_BIT);
    }

    if (event & TX_ABRT_BIT)
    {
        p_this->xfer.ret = -ETXABORT;
        p_this->xfer.tx_abort_source = tx_abort_source;
    }
    else if ((event & STOP_DET_BIT) || RxComplete())
    {
        SET_IC_INTR_MASK(p_this, GET_IC_INTR_MASK(p_this) & ~RX_FULL_BIT);
        p_this->xfer.ret = RxComplete() ? p_this->xfer.rx_len : -ECMDSPLIT;
    }

    if (p_this->xfer.ret)
    {
        SET_IC_INTR_MASK(p_this, 0);
        SET_IC_ENABLE(p_this, 0);
        p_this->xfer.mode = I2C_IDEL;	// change to idle state
        wake_up(&p_this->wq);
    }

#undef TxComplete
#undef RxComplete
}

/*------------------------------------------------------------------
 * Func : venus_i2c_isr
 *
 * Desc : isr of venus i2c
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : 0
 *------------------------------------------------------------------*/
irqreturn_t venus_i2c_isr(int this_irq, void* dev_id){
    venus_i2c* p_this = (venus_i2c*) dev_id;
    unsigned long flags;
    unsigned int event = 0;
    unsigned int tx_abrt_source = 0;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    LOCK_VENUS_I2C(&p_this->lock, flags);

    if (!(GET_I2C_ISR(p_this) & p_this->reg_map.I2C_INT))    // interrupt belongs to I2C
    {
        UNLOCK_VENUS_I2C(&p_this->lock, flags);
	    return IRQ_NONE;
    }

    LOG_EVENT(EVENT_ENTER_ISR);

    event = GET_IC_INTR_STAT(p_this);
    tx_abrt_source = GET_IC_TX_ABRT_SOURCE(p_this);

	CLR_IC_INTR(p_this);	                    // clear interrupts of i2c_x

	if ((GET_IC_CON(p_this) & IC_SLAVE_DISABLE)==0)
    {
        while (NOT_RXEMPTY(p_this) && p_this->slave_rx_len < sizeof(p_this->slave_rx_buffer))
            p_this->slave_rx_buffer[p_this->slave_rx_len++] = (unsigned char)(GET_IC_DATA_CMD(p_this) & 0xFF);

	    //if (event & START_DET_BIT)
	    //    printk("start detect\n");

        if (event & STOP_DET_BIT && p_this->slave_rx_len)
        {
            if (p_this->slave_ops.handle_command)
                p_this->slave_ops.handle_command(
                    p_this->slave_id,
                    p_this->slave_rx_buffer,
                    p_this->slave_rx_len);

            p_this->slave_rx_len = 0;   // flush buffer
	    }

        if (event & RD_REQ_BIT)
        {
            if (p_this->slave_ops.read_data)
                SET_IC_DATA_CMD(p_this, p_this->slave_ops.read_data(p_this->slave_id));
            else
	            SET_IC_DATA_CMD(p_this, 0xFF);
	    }
	}
    else
    {
        switch (p_this->xfer.mode)
        {
        case I2C_MASTER_WRITE:
            venus_i2c_msater_write(p_this, event, tx_abrt_source);
            break;

        case I2C_MASTER_READ:
            venus_i2c_msater_read(p_this, event, tx_abrt_source);
            break;

        case I2C_MASTER_RANDOM_READ:
            venus_i2c_msater_random_read(p_this, event, tx_abrt_source);
            break;

        default:
            printk("Unexcepted Interrupt\n");
            SET_IC_ENABLE(p_this, 0);
        }
    }

    SET_I2C_ISR(p_this, p_this->reg_map.I2C_INT);   // clear I2C Interrupt Flag
    UNLOCK_VENUS_I2C(&p_this->lock, flags);
    return IRQ_HANDLED;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_set_tar
 *
 * Desc : set tar of venus i2c
 *
 * Parm : p_this : handle of venus i2c
 *        addr   : address of sar
 *        mode
  : mode of sar
 *
 * Retn : 0
 *------------------------------------------------------------------*/
int
venus_i2c_set_tar(
    venus_i2c*          p_this,
    unsigned short      addr,
    ADDR_MODE           mode
    )
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (mode==ADDR_MODE_10BITS)
    {
        if (addr > 0x3FF)
            return -EADDROVERRANGE;

        SET_IC_ENABLE(p_this, 0);
        SET_IC_TAR(p_this, addr & 0x3FF);
        SET_IC_CON(p_this, (GET_IC_CON(p_this) & (~IC_10BITADDR_MASTER)) | IC_10BITADDR_MASTER);
    }
    else
    {
        if (addr > 0x7F)
            return -EADDROVERRANGE;

        SET_IC_ENABLE(p_this, 0);
        SET_IC_TAR(p_this, addr & 0x7F);
        SET_IC_CON(p_this, GET_IC_CON(p_this) & (~IC_10BITADDR_MASTER));
    }

    p_this->tar      = addr;
    p_this->tar_mode = mode;

    return 0;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_slave_mode_enable
 *
 * Desc : enable/disable i2c slave mode
 *
 * Parm : p_this : handle of venus i2c
 *        on     : enable /disable
 *
 * Retn : 0
 *------------------------------------------------------------------*/
int venus_i2c_slave_mode_enable(
    venus_i2c*              p_this,
    unsigned char           on
    )
{
    unsigned long flags;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    LOCK_VENUS_I2C(&p_this->lock, flags);

    if (on)
    {
        printk("[I2C%d] i2c slave enabled, sar=%x\n", p_this->id, GET_IC_SAR(p_this));
        SET_IC_ENABLE(p_this, 0);
        p_this->set_sar(p_this, p_this->sar, p_this->sar_mode);
        SET_IC_CON(p_this, GET_IC_CON(p_this) & ~(IC_SLAVE_DISABLE));
        SET_IC_INTR_MASK(p_this, START_DET_BIT | STOP_DET_BIT | RD_REQ_BIT | RX_FULL_BIT);
        if (p_this->reg_map.I2C_ISR_EN)
            wr_reg(p_this->reg_map.I2C_ISR_EN, rd_reg(p_this->reg_map.I2C_ISR_EN) | p_this->reg_map.I2C_ISR_EN_MASK);
        SET_IC_ENABLE(p_this, 1);
        p_this->flags |= VENUS_I2C_SLAVE_ENABLE;
    }
    else
    {
        printk("[I2C%d] i2c slave disabled\n", p_this->id);
        SET_IC_ENABLE(p_this, 0);
        SET_IC_CON(p_this, GET_IC_CON(p_this) | IC_SLAVE_DISABLE);
        SET_IC_INTR_MASK(p_this, 0);
        p_this->flags &= ~VENUS_I2C_SLAVE_ENABLE;
    }

    UNLOCK_VENUS_I2C(&p_this->lock, flags);

    return 0;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_register_slave_ops
 *
 * Desc : register slave mode ops
 *
 * Parm : p_this : handle of venus i2c
 *        ops    : slave mode ops
 *
 * Retn : 0
 *------------------------------------------------------------------*/
int venus_i2c_register_slave_ops(
    venus_i2c*              p_this,
    venus_i2c_slave_ops*    ops,
    unsigned long           id
    )
{
    unsigned long flags;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    LOCK_VENUS_I2C(&p_this->lock, flags);

    if (ops==NULL)
    {
        p_this->slave_ops.handle_command = NULL;
        p_this->slave_ops.read_data = NULL;
        p_this->slave_id = 0;
        venus_i2c_slave_mode_enable(p_this, 0);
    }
    else
    {
        p_this->slave_ops.handle_command = ops->handle_command;
        p_this->slave_ops.read_data = ops->read_data;
        p_this->slave_id = id;
    }

    UNLOCK_VENUS_I2C(&p_this->lock, flags);
    return 0;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_set_port
 *
 * Desc : set port of venus i2c
 *
 * Parm : p_this  : handle of venus i2c
 *        port_id : output port selection
 *
 * Retn : 0
 *------------------------------------------------------------------*/
int
venus_i2c_set_port(
    venus_i2c*          p_this,
    unsigned char       port_id
    )
{
    venus_i2c_port* port = NULL;
    RTK_DEBUG("[%s] %s  %d  port_id = %d\n", __FILE__,__FUNCTION__,__LINE__, port_id);

    if (port_id >= p_this->n_port)
    {
        printk("[I2C%d] WARNING, zap to port %d failed, invalid port number\n", p_this->id, port_id);
        return -EFAULT;
    }

    port = &p_this->p_port[port_id];

    if (port->pin_mux[0].addr &&
        (rd_reg(port->pin_mux[0].addr) & port->pin_mux[0].mask)!= port->pin_mux[0].i2c_val)
    {
        printk("[I2C%d] WARNING, zap to port %d failed, port has been occupied by other application\n", p_this->id, port_id);
        return -EFAULT;
    }

    if (port->pin_mux[1].addr &&
        (rd_reg(port->pin_mux[1].addr) & port->pin_mux[1].mask)!= port->pin_mux[1].i2c_val)
    {
        printk("[I2C%d] WARNING, zap to port %d failed, port has been occupied by other application\n", p_this->id, port_id);
        return -EFAULT;
    }

    // set input mux
    if (port->input_mux[0].addr)
        wr_reg(port->input_mux[0].addr, (rd_reg(port->input_mux[0].addr) & ~port->input_mux[0].mask) | port->input_mux[0].val);

    if (port->input_mux[1].addr)
        wr_reg(port->input_mux[1].addr, (rd_reg(port->input_mux[1].addr) & ~port->input_mux[1].mask) | port->input_mux[1].val);

    p_this->current_port = port;

    return 0;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_set_sar
 *
 * Desc : set sar of venus i2c
 *
 * Parm : p_this : handle of venus i2c
 *        addr   : address of sar
 *        mode
  : mode of sar
 *
 * Retn : 0
 *------------------------------------------------------------------*/
int
venus_i2c_set_sar(
    venus_i2c*          p_this,
    unsigned short      addr,
    ADDR_MODE           mode
    )
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (mode==ADDR_MODE_10BITS)
    {
        SET_IC_ENABLE(p_this, 0);
        SET_IC_SAR(p_this, p_this->sar & 0x3FF);
        SET_IC_CON(p_this, GET_IC_CON(p_this) | IC_10BITADDR_SLAVE);
    }
    else
    {
        SET_IC_ENABLE(p_this, 0);
        SET_IC_SAR(p_this, p_this->sar & 0x7F);
        SET_IC_CON(p_this, GET_IC_CON(p_this) & (~IC_10BITADDR_SLAVE));
    }

    p_this->sar      = addr;
    p_this->sar_mode = mode;

    return 0;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_set_spd
 *
 * Desc : set speed of venus i2c
 *
 * Parm : p_this : handle of venus i2c
 *        KHz    : operation speed of i2c
 *
 * Retn : 0
 *------------------------------------------------------------------*/
int venus_i2c_set_spd(venus_i2c* p_this, int KHz)
{
    unsigned int scl_time;
//    unsigned int div_h = 0x89;
    unsigned int div_h = 127;
//    unsigned int div_l = 0xA1;
    unsigned int div_l = 134;
    unsigned long sda_del;
    unsigned long sda_del_sel;

    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);

    if (KHz < 10 || KHz > 800)
    {
        i2c_print("[I2C%d] warning, speed %d out of range, speed should between 10 ~ 800KHz\n", p_this->id, KHz);
        return -1;
    }

	scl_time = (1000000/KHz)/2;		//the time ns need for SCL high/low

	if(scl_time%37)
	{
		if((scl_time%37)>18)
			scl_time += (37 - (scl_time%37));
		else
			scl_time -= (scl_time%37);
	}

	//27MHz crystal generate one clock 37ns,
	//for synopsys design ware ip v1.14a, SCL_LCNT need -1, SCL_HCNT need -8,
	div_h = (scl_time/37)-8;
	div_l = (scl_time/37)-1;
/*
    if ((is_darwin_cpu() || is_macarthur_cpu()) && p_this->id > 0)
    {
        // the speed of darwin i2c1/2 clock is four times of others (27MHz).
        // so, the divider should be multiply by 4.
        div_h <<= 2;
        div_l <<= 2;
    }
*/
	//printk("[I2C%d] KHz = %d, div_h = %d, div_l = %d\n", p_this->id, KHz, div_h, div_l);

    if (div_h >= 0xFFFF || div_h==0 ||
        div_l >= 0xFFFF || div_l==0)
    {
        i2c_print("[I2C%d] fatal, set speed failed : divider divider out of range. div_h = %d, div_l = %d\n", p_this->id, div_h, div_l);
        return -1;
    }

    SET_IC_ENABLE(p_this, 0);
    SET_IC_CON(p_this, (GET_IC_CON(p_this) & (~IC_SPEED)) | SPEED_SS);
    SET_IC_SS_SCL_HCNT(p_this, div_h);
    SET_IC_SS_SCL_LCNT(p_this, div_l);
    p_this->spd  = KHz;
    p_this->tick = 1000 / KHz;

    if(1)//TODO : victor add 20140302 (is_saturn_cpu() || is_nike_cpu())                // add sda phase dealy
    {
        sda_del = GET_IC_SDA_DEL(p_this) & ~I2C_SDA_DEL_MASK;
		sda_del_sel = 1;//p_this->tick / 2;	//fix delay 512 ns for improving pmu/hdmi compatibility test by victor 20140911

        if (sda_del_sel)
            sda_del |= I2C_SDA_DEL_EN(1) | I2C_SDA_DEL_SEL(sda_del_sel);      // fix to delay 1ms

        SET_IC_SDA_DEL(p_this, sda_del);
    }
    else if (is_darwin_cpu() || is_macarthur_cpu())
    {
//        if (p_this->id > 0)
//            SET_IC_SDA_DEL(p_this, 0x00008004);
//        else
 //           SET_IC_SDA_DEL(p_this, 0x00008001);
    }

    return 0;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_set_guard_interval
 *
 * Desc : set guard_interval of venus i2c
 *
 * Parm : p_this : handle of venus i2c
 *        us     : operation speed of i2c
 *
 * Retn : 0
 *------------------------------------------------------------------*/
int venus_i2c_set_guard_interval(venus_i2c* p_this, unsigned long us)
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    p_this->guard_interval = us;
    return 0;
}

#define current_port_id(p_this)     ((p_this->current_port) ? (((unsigned long) p_this->current_port - (unsigned long) p_this->p_port)/sizeof(venus_i2c_port)) : -1)

/*------------------------------------------------------------------
 * Func : venus_i2c_dump
 *
 * Desc : dump staus of venus i2c
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : 0 for success
 *------------------------------------------------------------------*/
int venus_i2c_dump(venus_i2c* p_this)
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    i2c_print("=========================\n");
    i2c_print("= VER : %s               \n", VERSION);
    i2c_print("=========================\n");
    i2c_print("= PHY : %d               \n", p_this->id);
    i2c_print("= PORT: %ld               \n", current_port_id(p_this));
    i2c_print("= MODEL: %s              \n", p_this->model_name);
    i2c_print("= SPD : %d               \n", p_this->spd);
    i2c_print("= SAR : 0x%03x (%d bits) \n", p_this->sar, p_this->sar_mode);
    i2c_print("= TX FIFO DEPTH : %d     \n", p_this->tx_fifo_depth);
    i2c_print("= RX FIFO DEPTH : %d     \n", p_this->rx_fifo_depth);
    i2c_print("= FIFO THRESHOLD: %d     \n", FIFO_THRESHOLD);

    if (p_this->gpio_map.valid)
    {
        i2c_print("= SDA GPIO : %s_GPIO %d\n", gpio_type(gpio_group(p_this->gpio_map.sda)), gpio_idx(p_this->gpio_map.sda));
        i2c_print("= SCL GPIO : %s_GPIO %d\n", gpio_type(gpio_group(p_this->gpio_map.scl)), gpio_idx(p_this->gpio_map.scl));

#ifdef CONFIG_I2C_RTK_BUS_JAM_RECOVER
        i2c_print("= BUS JAM RECORVER 3: ON  \n");
#else
        i2c_print("= BUS JAM RECORVER 3: OFF  \n");
#endif

#ifdef CONFIG_I2C_VENUS_NON_STOP_WRITE_XFER
        i2c_print("= NON STOP WRITE : ON  \n");
#else
        i2c_print("= NON STOP WRITE : OFF  \n");
#endif

        i2c_print("= GPIO RW SUPPORT : ON \n");
    }
    i2c_print("=========================\n");
    return 0;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_find_current_port
 *
 * Desc : fi
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : 0
 *------------------------------------------------------------------*/
venus_i2c_port* venus_i2c_find_current_port(
    venus_i2c*              p_this
    )
{
    venus_i2c_port* p_port = p_this->p_port;
    int i;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (p_port==NULL)
        return NULL;

    for (i=0; i<p_this->n_port; i++)
    {
        /*
        i2c_print("port[%d] input_mux[0]={%08x, %08x, %08x}, input_mux[1]={%08x, %08x, %08x}, pin_mux[0]={%08x, %08x, %08x}, pin_mux[1]={%08x, %08x, %08x}\n",
            i,
            p_port[i].input_mux[0].addr, p_port[i].input_mux[0].mask, p_port[i].input_mux[0].val,
            p_port[i].input_mux[1].addr, p_port[i].input_mux[1].mask, p_port[i].input_mux[1].val,
            p_port[i].pin_mux[0].addr,   p_port[i].pin_mux[0].mask,   p_port[i].pin_mux[0].i2c_val,
            p_port[i].pin_mux[1].addr,   p_port[i].pin_mux[1].mask,   p_port[i].pin_mux[1].i2c_val);
        */
        if (p_port[i].input_mux[0].addr)
        {
            if ((rd_reg(p_port[i].input_mux[0].addr) & p_port[i].input_mux[0].mask)!=p_port[i].input_mux[0].val)
                continue;
        }

        if (p_port[i].input_mux[1].addr)
        {
            if ((rd_reg(p_port[i].input_mux[1].addr) & p_port[i].input_mux[1].mask)!=p_port[i].input_mux[1].val)
                continue;
        }

        if (p_port[i].pin_mux[0].addr)
        {
            if ((rd_reg(p_port[i].pin_mux[0].addr) & p_port[i].pin_mux[0].mask)!=p_port[i].pin_mux[0].i2c_val)
                continue;
        }

        if (p_port[i].pin_mux[1].addr)
        {
            if ((rd_reg(p_port[i].pin_mux[1].addr) & p_port[i].pin_mux[1].mask)!=p_port[i].pin_mux[1].i2c_val)
                continue;
        }

        return &p_port[i];
    }

    return NULL;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_probe
 *
 * Desc : probe venus i2c
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : 0
 *------------------------------------------------------------------*/
int venus_i2c_probe(venus_i2c* p_this)
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (p_this->id >=I2C_PHY_CNT)
        return -ENODEV;

    p_this->model_name = MODLE_NAME;
    p_this->reg_map    = *(i2c_phy[p_this->id].p_reg_map);
    p_this->n_port     = i2c_phy[p_this->id].n_port;
    p_this->p_port     = (venus_i2c_port *)i2c_phy[p_this->id].p_port;
//    p_this->current_port = venus_i2c_find_current_port(p_this);

    //if (p_this->current_port==NULL)
    //{
    //    i2c_print("Warning, check pinmux for i2c-%d failed\n",p_this->id);
    //}

    if (p_this->current_port && p_this->current_port->gpio_mapped)
    {
        p_this->gpio_map.muxpad      = p_this->current_port->pin_mux[0].addr;
        p_this->gpio_map.muxpad_mask = p_this->current_port->pin_mux[0].mask;
        p_this->gpio_map.muxpad_gpio = p_this->current_port->pin_mux[0].gpio_val;
        p_this->gpio_map.muxpad_i2c  = p_this->current_port->pin_mux[0].i2c_val;
        p_this->gpio_map.sda         = p_this->current_port->g2c_sda;
        p_this->gpio_map.scl         = p_this->current_port->g2c_scl;
        p_this->gpio_map.valid       = 1;
    }
    else
    {
        p_this->gpio_map.valid = 0;
    }

    return 0;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_phy_init
 *
 * Desc : init venus i2c phy
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : 0
 *------------------------------------------------------------------*/
int venus_i2c_phy_init(venus_i2c* p_this)
{
//	int i;
	RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    SET_IC_ENABLE(p_this, 0);
    SET_IC_INTR_MASK(p_this, 0);                // disable all interrupt
    SET_IC_CON(p_this, IC_SLAVE_DISABLE | IC_RESTART_EN | SPEED_SS | IC_MASTER_MODE);
    SET_IC_TX_TL(p_this, FIFO_THRESHOLD);
    SET_IC_RX_TL(p_this, p_this->rx_fifo_depth - FIFO_THRESHOLD);

    venus_i2c_set_spd(p_this, p_this->spd);
    //venus_i2c_set_sar(p_this, p_this->sar, p_this->sar_mode);
/*
#ifdef CONFIG_I2C_RTK_BUS_JAM_RECOVER
    if (venus_i2c_bus_jam_detect(p_this))
    {
        JAM_DEBUG("I2C%d Bus Status Check.... Error... Try to Recrver\n",p_this->id);
        venus_i2c_bus_jam_recover_proc(p_this);
    }
    else
        JAM_DEBUG("I2C%d Bus Status Check.... OK\n",p_this->id);
#endif
*/
//	for (i = 0 ; i < 3 ; i++){
//        venus_i2c_bus_jam_recover(p_this);
//        phoenix_i2c_mdelay(10);
//	}

#ifdef DEV_DEBUG
    venus_i2c_dump(p_this);
#endif
    return 0;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_init
 *
 * Desc : init venus i2c
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : 0
 *------------------------------------------------------------------*/
int venus_i2c_init(venus_i2c* p_this)
{
    int ret;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (p_this->flags & VENUS_I2C_IRQ_RDY)
        return 0;

    if (venus_i2c_probe(p_this)<0)
        return -ENODEV;

    if ((ret = request_irq(p_this->irq, venus_i2c_isr, SA_SHIRQ, "i2c", (void*) p_this)) < 0)
    {
        i2c_print("FATAL : Request irq%d failed(ret=%d)\n", p_this->irq, ret);
        return -ENODEV;
    }

    p_this->flags = VENUS_I2C_IRQ_RDY;
    p_this->rx_fifo_depth = ((GET_IC_COMP_PARAM_1(p_this) >>  8) & 0xFF)+1;
    p_this->tx_fifo_depth = ((GET_IC_COMP_PARAM_1(p_this) >> 16) & 0xFF)+1;

    init_waitqueue_head(&p_this->wq);

    spin_lock_init(&p_this->lock);

    return venus_i2c_phy_init(p_this);
}

/*------------------------------------------------------------------
 * Func : venus_i2c_uninit
 *
 * Desc : uninit venus i2c
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : 0
 *------------------------------------------------------------------*/
int venus_i2c_uninit(venus_i2c* p_this)
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    SET_IC_ENABLE(p_this, 0);
    SET_IC_INTR_MASK(p_this, 0);

    if ((p_this->flags & VENUS_I2C_IRQ_RDY))
    {
        free_irq(p_this->irq, p_this);
        p_this->flags = 0;
    }

    return 0;
}

enum {
    I2C_MODE    = 0,
    GPIO_MODE   = 1
};

/*------------------------------------------------------------------
 * Func : venus_i2c_gpio_selection
 *
 * Desc : select i2c/GPIO mode
 *
 * Parm : p_this : handle of venus i2c
 *        mode : 0      : SDA / SCL
 *               others : GPIO
 *
 * Retn : N/A
 *------------------------------------------------------------------*/
void venus_i2c_gpio_selection(venus_i2c* p_this, unsigned char mode)
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (p_this->gpio_map.muxpad)
    {
        unsigned long val = rd_reg(p_this->gpio_map.muxpad);

        val &= ~p_this->gpio_map.muxpad_mask;

        val |= (mode==GPIO_MODE) ? p_this->gpio_map.muxpad_gpio
                                 : p_this->gpio_map.muxpad_i2c;

        wr_reg(p_this->gpio_map.muxpad, val);

        //printk("GPIO Selection: [%08x] = %08x & %08x\n", p_this->gpio_map.muxpad, rd_reg(p_this->gpio_map.muxpad), p_this->gpio_map.muxpad_mask);
    }
}

/*------------------------------------------------------------------
 * Func : venus_i2c_suspend
 *
 * Desc : suspend venus i2c
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : 0 for success
 *------------------------------------------------------------------*/
int venus_i2c_suspend(venus_i2c* p_this)
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    i2c_print("[I2C%d] suspend\n", p_this->id);

#ifdef GPIO_MODE_SUSPEND

    VENUS_GPIO_ID sda = p_this->gpio_map.sda;
    VENUS_GPIO_ID scl = p_this->gpio_map.scl;

    while (p_this->xfer.mode!=I2C_IDEL)
        msleep(1);

    venus_gpio_set_dir(sda, 0);
    venus_gpio_set_dir(scl, 0);

    venus_gpio_set_irq_enable(sda, 0);
    venus_gpio_set_irq_enable(scl, 0);

    venus_i2c_gpio_selection(p_this, GPIO_MODE);
#endif

    return 0;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_resume
 *
 * Desc : resume venus i2c
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : 0 for success
 *------------------------------------------------------------------*/
int venus_i2c_resume(venus_i2c* p_this)
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    i2c_print("[I2C%d] resume\n", p_this->id);

#ifdef GPIO_MODE_SUSPEND
    venus_i2c_gpio_selection(p_this, I2C_MODE);
#endif

    venus_i2c_phy_init(p_this);

    return 0;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_reset_state
 *
 * Desc : reset internal state machine of i2c controller.
 *
 *        This is a hack that used to reset the internal state machine
 *        of venus i2c. In mars, there is no way to reset the internal
 *        state of venus I2C controller. However, we found out that we
 *        can use GPIO to generate a pseudo stop to reset it.
 *
 *        First, we need to set the i2c bus to CPIO mode and pull low
 *        SDA and pull high SCL, then changed the i2c bus to I2C mode.
 *        Because SDA has a pull high resistor, so the i2c controller
 *        will see SDA falling and rising when SCL is highw. It will be
 *        looked like start & stop and the state of i2c controller will
 *        be reset.
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : N/A
 *------------------------------------------------------------------*/
void venus_i2c_reset_state(venus_i2c* p_this)
{
    VENUS_GPIO_ID sda = p_this->gpio_map.sda;
    VENUS_GPIO_ID scl = p_this->gpio_map.scl;
    int d = p_this->tick / 2;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);

    if (!p_this->gpio_map.valid)
        return;

     // Disable GPIO Interrupt
    venus_gpio_set_irq_enable(sda, 0);
    venus_gpio_set_irq_enable(scl, 0);

    // pull high SCL & pull low SDA
    venus_gpio_output(sda, 0);
    venus_gpio_output(scl, 1);

    // mode : SCL : out, SDA : out
    venus_gpio_set_dir(sda, 1);
    venus_gpio_set_dir(scl, 1);

    venus_i2c_gpio_selection(p_this, GPIO_MODE);

    udelay(d);

    venus_i2c_gpio_selection(p_this, I2C_MODE);
    venus_gpio_set_dir(sda, 0);
    venus_gpio_set_dir(scl, 0);
}

#ifdef CONFIG_I2C_RTK_BUS_JAM_RECOVER

/*------------------------------------------------------------------
 * Func : venus_i2c_bus_jam_recover
 *
 * Desc : recover i2c bus jam status
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : N/A
 *------------------------------------------------------------------*/
void venus_i2c_bus_jam_recover(venus_i2c* p_this)
{
#if 0
    VENUS_GPIO_ID sda = p_this->gpio_map.sda;
    VENUS_GPIO_ID scl = p_this->gpio_map.scl;
    int i;
    int d = p_this->tick / 2;

    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (!p_this->gpio_map.valid)
        return;

    // Disable GPIO Interrupt
    venus_gpio_set_irq_enable(sda, 0);
    venus_gpio_set_irq_enable(scl, 0);

    // pull low SCL & SDA
    venus_gpio_output(sda, 0);
    venus_gpio_output(scl, 0);

    // mode : SCL : out, SDA : out
    venus_gpio_set_dir(sda, 1);
    venus_gpio_set_dir(scl, 1);

    venus_i2c_gpio_selection(p_this, GPIO_MODE);

    //Add Stop Condition
	udelay(10);
	venus_gpio_output(scl, 1);            // pull high SCL
	udelay(10);
	venus_gpio_output(sda, 1);            // pull high SDA
	udelay(10);

    venus_gpio_set_dir(sda, 0);          // mode SDA : in

    // Output Clock Modify Clock Output from 10 to 9
    for (i=0; i<9; i++)
    {
        venus_gpio_output(scl, 0);        // pull low SCL
        udelay(d);
        venus_gpio_output(scl, 1);        // pull high SCL
        udelay(d);
    }

    venus_gpio_set_dir(scl, 0);          // mode SCL : in

    venus_i2c_gpio_selection(p_this, I2C_MODE);
#else
    VENUS_GPIO_ID sda = p_this->gpio_map.sda;
    VENUS_GPIO_ID scl = p_this->gpio_map.scl;
    int i;
    int d = p_this->tick / 2;

    JAM_DEBUG("[%s] %s  %d start\n", __FILE__,__FUNCTION__,__LINE__);

    if (!p_this->gpio_map.valid)
        return;

    // Disable GPIO Interrupt
    phoenix_i2c_gpio_set_irq_enable(sda, 0);
    phoenix_i2c_gpio_set_irq_enable(scl, 0);

    // pull low SCL & SDA
    phoenix_i2c_gpio_output(sda, 0);
    phoenix_i2c_gpio_output(scl, 0);

    // mode : SCL : out, SDA : out
    phoenix_i2c_gpio_set_dir(sda, 1);
    phoenix_i2c_gpio_set_dir(scl, 1);

    venus_i2c_gpio_selection(p_this, GPIO_MODE);

    //Add Stop Condition
	udelay(10);
	phoenix_i2c_gpio_output(scl, 1);            // pull high SCL
	udelay(10);
	phoenix_i2c_gpio_output(sda, 1);            // pull high SDA
	udelay(10);

    phoenix_i2c_gpio_set_dir(sda, 0);          // mode SDA : in

    // Output Clock Modify Clock Output from 10 to 9
    for (i=0; i<9; i++)
    {
        phoenix_i2c_gpio_output(scl, 0);        // pull low SCL
        udelay(d);
        phoenix_i2c_gpio_output(scl, 1);        // pull high SCL
        udelay(d);
    }

    phoenix_i2c_gpio_set_dir(scl, 0);          // mode SCL : in

    venus_i2c_gpio_selection(p_this, I2C_MODE);
    JAM_DEBUG(KERN_EMERG"[%s] %s  %d end\n", __FILE__,__FUNCTION__,__LINE__);

#endif
}

/*------------------------------------------------------------------
 * Func : venus_i2c_bus_jam_detect
 *
 * Desc : check if bus jam occurs
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : 0 : bus not jammed, 1 : bus jammed
 *------------------------------------------------------------------*/
int venus_i2c_bus_jam_detect(venus_i2c* p_this)
{
    VENUS_GPIO_ID sda = p_this->gpio_map.sda;
    VENUS_GPIO_ID scl = p_this->gpio_map.scl;
    int ret = 1;
    int i;
    JAM_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (!p_this->gpio_map.valid)
        return 0;

    // GPIO Interrupt Disable
    phoenix_i2c_gpio_set_irq_enable(sda, 0);
    phoenix_i2c_gpio_set_irq_enable(scl, 0);

    // GPIO Dir=Input
    phoenix_i2c_gpio_set_dir(sda, 0);
    phoenix_i2c_gpio_set_dir(scl, 0);

    venus_i2c_gpio_selection(p_this, GPIO_MODE);

    for(i=0; i<30; i++)
    {
        if (phoenix_i2c_gpio_input(sda) &&  phoenix_i2c_gpio_input(scl))      // SDA && SCL == High
        {
            ret = 0;
            break;
        }
        phoenix_i2c_mdelay(1);
    }

    if (ret)
    {
        JAM_DEBUG("I2C %d Jamed, 0xFE01B124 =0x%x\n",
                p_this->id, (*(volatile unsigned char *)0xFE01B124 ));
        JAM_DEBUG("I2C %d Jamed, BUS Status: SDA=%d, SCL=%d\n",
                p_this->id, phoenix_i2c_gpio_input(sda), phoenix_i2c_gpio_input(scl));
    }

    venus_i2c_gpio_selection(p_this, I2C_MODE);

    return ret;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_bus_jam_recover
 *
 * Desc : recover i2c bus jam status
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : N/A
 *------------------------------------------------------------------*/
void venus_i2c_bus_jam_recover_proc(venus_i2c* p_this)
{
    int i = 0;

    JAM_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (!p_this->gpio_map.valid)
        return;

    do
    {
        JAM_DEBUG("Do I2C%d Bus Recover %d\n",p_this->id, i);

        venus_i2c_bus_jam_recover(p_this);

        phoenix_i2c_mdelay(200);

        if (venus_i2c_bus_jam_detect(p_this)==0)
        {
            JAM_DEBUG("I2C%d Bus Recover successed\n",p_this->id);

            return ;
        }

    }while(i++ < 3);

    JAM_DEBUG("I2C%d Bus Recover failed\n",p_this->id);
}
#endif

/*------------------------------------------------------------------
 * Func : venus_i2c_start_xfer
 *
 * Desc : start xfer message
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : 0 for success, others is failed
 *------------------------------------------------------------------*/
int venus_i2c_start_xfer(venus_i2c* p_this)
{
    unsigned long flags;
    int ret;
    int mode = p_this->xfer.mode;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    LOG_EVENT(EVENT_START_XFER);

    LOCK_VENUS_I2C(&p_this->lock, flags);

    if ((GET_IC_CON(p_this) & IC_SLAVE_DISABLE)==0)
    {
        SET_IC_ENABLE(p_this, 0);
        SET_IC_CON(p_this, GET_IC_CON(p_this) | IC_SLAVE_DISABLE);
    }

    switch (p_this->xfer.mode)
    {
    case I2C_MASTER_WRITE:
        SET_IC_INTR_MASK(p_this, TX_EMPTY_BIT | TX_ABRT_BIT | STOP_DET_BIT);
        break;

    case I2C_MASTER_READ:
	//printk(KERN_ERR "#############>>>> I2C_MASTER_READ\n");
    case I2C_MASTER_RANDOM_READ:
	//printk(KERN_ERR "#############>>>> I2C_MASTER_RANDOM_READ\n");
	//printk(KERN_ERR "p_this->reg_map.IC_RXFLR = %x\n", p_this->reg_map.IC_RXFLR);
	//printk(KERN_ERR "readl(p_this->reg_map.IC_RXFLR) = %x\n", readl(p_this->reg_map.IC_RXFLR));

	if (GET_IC_RXFLR(p_this))
        {
            printk("WARNING, RX FIFO NOT EMPRY\n");

            while(GET_IC_RXFLR(p_this))
                 GET_IC_DATA_CMD(p_this);
        }

        SET_IC_INTR_MASK(p_this, RX_FULL_BIT | TX_EMPTY_BIT | TX_ABRT_BIT | STOP_DET_BIT);
        break;

    default:
        UNLOCK_VENUS_I2C(&p_this->lock, flags);
        LOG_EVENT(EVENT_STOP_XFER);
        return -EILLEGALMSG;
    }

    if (p_this->reg_map.I2C_ISR_EN)
    {
        wr_reg(p_this->reg_map.I2C_ISR_EN, rd_reg(p_this->reg_map.I2C_ISR_EN) | p_this->reg_map.I2C_ISR_EN_MASK);
        //printk("Enable Interrupt Mask : reg(%08x)=%08x\n", p_this->reg_map.I2C_ISR_EN, rd_reg(p_this->reg_map.I2C_ISR_EN));
    }

#ifdef MINIMUM_DELAY_EN

    UNLOCK_VENUS_I2C(&p_this->lock, flags);

    if (jiffies <= p_this->time_stamp)
        //udelay(p_this->tick/2);   // wait 1/2 ticks...
        udelay(p_this->guard_interval);   // cfyeh found that delay 1/2 tick will cause long system booting time, so we revert the delay setting
                        // temporarily until we findout the root cause....

    LOCK_VENUS_I2C(&p_this->lock, flags);

#endif

    SET_IC_ENABLE(p_this, 1);                   // Start Xfer

    UNLOCK_VENUS_I2C(&p_this->lock, flags);

    if (p_this->xfer.except_time < 1000)            // less than 1 ms
        udelay(p_this->xfer.except_time + 20);      // extra 20 us for extra guard interval

    //printk(KERN_ERR "#############>>>> venus_i2c_start_xfer test 1\n");

    if (p_this->xfer.mode!=I2C_IDEL)
        wait_event_timeout(p_this->wq, p_this->xfer.mode == I2C_IDEL, 1 * HZ);

    //printk(KERN_ERR "#############>>>> venus_i2c_start_xfer test 2\n");
    LOCK_VENUS_I2C(&p_this->lock, flags);

    SET_IC_INTR_MASK(p_this, 0);
    SET_IC_ENABLE(p_this, 0);

    //printk(KERN_ERR "#############>>>> venus_i2c_start_xfer test 3\n");
    if (p_this->xfer.mode != I2C_IDEL)
    {
        p_this->xfer.ret  = -ETIMEOUT;

#ifdef CONFIG_I2C_RTK_BUS_JAM_RECOVER

        JAM_DEBUG("[I2C] WARNING, I2C ETIMEOUT\n");
        UNLOCK_VENUS_I2C(&p_this->lock, flags);

        // Bus Jammed Recovery Procedure
        if (venus_i2c_bus_jam_detect(p_this))
        {
            JAM_DEBUG("[I2C] WARNING, I2C Bus Jammed, Do Recorver\n");
            venus_i2c_bus_jam_recover_proc(p_this);
            msleep(50);
        }

        JAM_DEBUG("[I2C] Info, Reset I2C State\n");
        venus_i2c_reset_state(p_this);

        LOCK_VENUS_I2C(&p_this->lock, flags);
#endif
    }
    else if (p_this->xfer.ret==-ECMDSPLIT)
    {
        switch(mode)
        {
        case I2C_MASTER_WRITE:
            printk(KERN_ERR "WARNING, Write Cmd Split, tx : %d/%d\n",
                    p_this->xfer.tx_len, p_this->xfer.tx_buff_len);
            break;

        case I2C_MASTER_READ:
            printk(KERN_ERR "WARNING, Read Cmd Split, tx : %d/%d rx : %d/%d\n",
                    p_this->xfer.tx_len, p_this->xfer.tx_buff_len,
                    p_this->xfer.rx_len, p_this->xfer.rx_buff_len);
            break;

        case I2C_MASTER_RANDOM_READ:
            printk(KERN_ERR "WARNING, Read Cmd Split, tx : %d/%d rx : %d/%d\n",
                    p_this->xfer.tx_len, p_this->xfer.tx_buff_len + p_this->xfer.rx_buff_len,
                    p_this->xfer.rx_len, p_this->xfer.rx_buff_len);
            break;
        }
    }

#ifdef MINIMUM_DELAY_EN
    p_this->time_stamp = (unsigned long) jiffies;
#endif

    ret = p_this->xfer.ret;

    UNLOCK_VENUS_I2C(&p_this->lock, flags);

#ifndef MINIMUM_DELAY_EN
    udelay(p_this->guard_interval);
#endif

/*    if (ret==-ECMDSPLIT)
    {
        if (venus_i2c_probe(p_this)<0)
            printk("WARNING, I2C %d no longer exists\n", p_this->id);
    }*/ //Fix me

    LOG_EVENT(EVENT_STOP_XFER);

    if (p_this->flags & VENUS_I2C_SLAVE_ENABLE)
        p_this->slave_mode_enable(p_this, 1);

    return ret;
}

/*------------------------------------------------------------------
 * Func : venus_g2c_do_start
 *
 * Desc : gpio i2c xfer - start phase
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : N/A
 *------------------------------------------------------------------*/
void venus_g2c_do_start(venus_i2c* p_this)
{
    VENUS_GPIO_ID sda = p_this->gpio_map.sda;
    VENUS_GPIO_ID scl = p_this->gpio_map.scl;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);

    if (!p_this->gpio_map.valid)
        return;

    switch(p_this->xfer.gpio_xfer_sub_state)
    {
    case 0:
        venus_gpio_set_irq_enable(sda, 0);
        venus_gpio_set_irq_enable(scl, 0);
        venus_gpio_set_dir(sda, 0);          // SDA DIR = IN
        venus_gpio_set_dir(scl, 0);          // SCL DIR = IN
        venus_gpio_output(sda, 0);            // SDA = L
        venus_gpio_output(scl, 0);            // SCL = L
        venus_i2c_gpio_selection(p_this, GPIO_MODE);
        p_this->xfer.gpio_xfer_sub_state++;
        break;

    case 1:
        if (venus_gpio_input(scl) && venus_gpio_input(sda))       // Wait SDA = SCL = H
            p_this->xfer.gpio_xfer_sub_state++;

        break;

    case 2:
        venus_gpio_set_dir(sda, 1);             // SDA = L
        p_this->xfer.gpio_xfer_sub_state++;
        break;

    case 3:
        venus_gpio_set_dir(scl, 1);             // SCL = L
        p_this->xfer.gpio_xfer_state = G2C_ST_ADDR0;
        p_this->xfer.gpio_xfer_sub_state = 0;
        break;
    }
}

/*------------------------------------------------------------------
 * Func : venus_g2c_do_address
 *
 * Desc : gpio i2c xfer - address phase
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : N/A
 *------------------------------------------------------------------*/
void venus_g2c_do_address(venus_i2c* p_this)
{
    VENUS_GPIO_ID sda = p_this->gpio_map.sda;
    VENUS_GPIO_ID scl = p_this->gpio_map.scl;
    unsigned char state = G2C_MINOR_STATE(p_this->xfer.gpio_xfer_state);
    int bit_index = 0;
    unsigned char addr;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (!p_this->gpio_map.valid)
        return;

    if (state <= 7)
    {
        //--------------------------------------------------
        // ADDR Phase 0 ~ 7
        //--------------------------------------------------

        switch(p_this->xfer.gpio_xfer_sub_state)
        {
        case 0:
            venus_gpio_set_dir(scl, 1);             // SCL = L
            p_this->xfer.gpio_xfer_sub_state++;
            break;

        case 1:

            addr = p_this->tar << 1;

            if (p_this->xfer.mode == I2C_MASTER_READ)
                addr |= 1;

            bit_index = 7 - state;

            if ((addr>>bit_index) & 0x1)
                venus_gpio_set_dir(sda, 0);         // SDA = H
            else
                venus_gpio_set_dir(sda, 1);         // SDA = L

            p_this->xfer.gpio_xfer_sub_state++;
            break;

        case 2:

            addr = p_this->tar << 1;

            if (p_this->xfer.mode == I2C_MASTER_READ)
                addr |= 1;

            bit_index = 7 - state;

            if (((addr>>bit_index) & 0x1) && venus_gpio_input(sda)==0)
            {
                // lose of arbitraction
                p_this->xfer.ret = -ETXABORT;
                p_this->xfer.gpio_xfer_state = G2C_ST_DONE;
                p_this->xfer.gpio_xfer_sub_state = 0;
            }
            else
            {
                venus_gpio_set_dir(scl, 0);             // SCL = H
                p_this->xfer.gpio_xfer_sub_state++;
            }

            break;

        case 3:

            if (venus_gpio_input(scl))               // Wait SCL = H
            {
                p_this->xfer.gpio_xfer_state++;
                p_this->xfer.gpio_xfer_sub_state = 0;
            }
            break;
        }
    }
    else if (state==8)
    {
        //--------------------------------------------------
        // ADDR ACK & NACK
        //--------------------------------------------------
        switch(p_this->xfer.gpio_xfer_sub_state)
        {
        case 0:
            venus_gpio_set_dir(scl, 1);             // Pull low SCL
            p_this->xfer.gpio_xfer_sub_state++;
            break;

        case 1:
            venus_gpio_set_dir(sda, 0);             // SDA = H
            p_this->xfer.gpio_xfer_sub_state++;
            break;

        case 2:
            venus_gpio_set_dir(scl, 0);             // SCL = H
            p_this->xfer.gpio_xfer_sub_state++;
            break;

        case 3:
            if (venus_gpio_input(scl))               // Wait SCL = H
            {
                if (venus_gpio_input(sda))
                {
                    p_this->xfer.ret = -ETXABORT;
                    p_this->xfer.gpio_xfer_state = G2C_ST_STOP;     // NACK or no data to xfer
                }
                else
                {
                    p_this->xfer.gpio_xfer_state = G2C_ST_DATA0;    // ACK and still has data to xfer
                }

                p_this->xfer.gpio_xfer_sub_state = 0;
            }
            break;
        }
    }
}

/*------------------------------------------------------------------
 * Func : venus_g2c_do_read
 *
 * Desc : gpio i2c xfer - read data phase
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : N/A
 *------------------------------------------------------------------*/
void venus_g2c_do_read(venus_i2c* p_this)
{
    VENUS_GPIO_ID sda = p_this->gpio_map.sda;
    VENUS_GPIO_ID scl = p_this->gpio_map.scl;
    unsigned char state = G2C_MINOR_STATE(p_this->xfer.gpio_xfer_state);
    int bit_index = 0;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (!p_this->gpio_map.valid)
        return;

    if (state < 8)
    {
        //--------------------------------------------------
        // DATA Phase 0 ~ 7
        //--------------------------------------------------

        switch(p_this->xfer.gpio_xfer_sub_state)
        {
        case 0:
            venus_gpio_set_dir(scl, 1);             // SCL = L
            p_this->xfer.gpio_xfer_sub_state++;
            break;

        case 1:
            venus_gpio_set_dir(sda, 0);             // SDA = In
            p_this->xfer.gpio_xfer_sub_state++;
            break;

        case 2:
            venus_gpio_set_dir(scl, 0);             // SCL = H
            p_this->xfer.gpio_xfer_sub_state++;
            break;

        case 3:
            if (venus_gpio_input(scl))               // Wait SCL = H
            {
                if (venus_gpio_input(sda))
                {
                    bit_index = 7 - state;
                    p_this->xfer.rx_buff[p_this->xfer.rx_len] |= (1<<bit_index);
                }

                p_this->xfer.gpio_xfer_state++;     // Next State
                p_this->xfer.gpio_xfer_sub_state = 0;
            }
            break;
        }
    }
    else
    {
        //--------------------------------------------------
        // ACK & NACK
        //--------------------------------------------------

        switch(p_this->xfer.gpio_xfer_sub_state)
        {
        case 0:
            venus_gpio_set_dir(scl, 1);             // SCL = L
            p_this->xfer.gpio_xfer_sub_state++;
            p_this->xfer.rx_len++;
            break;

        case 1:
            if (p_this->xfer.rx_len < p_this->xfer.rx_buff_len)
            {
                venus_gpio_set_dir(sda, 1);             // SDA = L  ACK
                //printk(KERN_DEBUG "rx = %d/%d ACK\n", p_this->xfer.rx_len, p_this->xfer.rx_buff_len);
            }
            else
            {
                venus_gpio_set_dir(sda, 0);             // SDA = H  NACK
                //printk(KERN_DEBUG "rx = %d/%d NACK\n", p_this->xfer.rx_len, p_this->xfer.rx_buff_len);
            }

            p_this->xfer.gpio_xfer_sub_state++;
            break;

        case 2:
            venus_gpio_set_dir(scl, 0);             // SCL = H
            p_this->xfer.gpio_xfer_sub_state++;
            break;

        case 3:

            if (venus_gpio_input(scl))               // Wait SCL = H
            {
                if (p_this->xfer.rx_len < p_this->xfer.rx_buff_len)
                    p_this->xfer.gpio_xfer_state = G2C_ST_DATA0;
                else
                    p_this->xfer.gpio_xfer_state = G2C_ST_STOP;

                p_this->xfer.gpio_xfer_sub_state = 0;
            }
            break;
        }
    }
}

/*------------------------------------------------------------------
 * Func : venus_g2c_do_write
 *
 * Desc : gpio i2c xfer - write data phase
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : N/A
 *------------------------------------------------------------------*/
void venus_g2c_do_write(venus_i2c* p_this)
{
    VENUS_GPIO_ID sda = p_this->gpio_map.sda;
    VENUS_GPIO_ID scl = p_this->gpio_map.scl;
    unsigned char state = G2C_MINOR_STATE(p_this->xfer.gpio_xfer_state);
    int bit_index = 0;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (!p_this->gpio_map.valid)
        return;

    if (state < 8)
    {
        //--------------------------------------------------
        // DATA Phase 0 ~ 7
        //--------------------------------------------------

        switch(p_this->xfer.gpio_xfer_sub_state)
        {
        case 0:
            venus_gpio_set_dir(scl, 1);             // SCL = L
            p_this->xfer.gpio_xfer_sub_state++;
            break;

        case 1:
            bit_index = 7 - state;

            if ((p_this->xfer.tx_buff[p_this->xfer.tx_len]>>bit_index) & 0x1)
                venus_gpio_set_dir(sda, 0);         // SDA = H
            else
                venus_gpio_set_dir(sda, 1);         // SDA = L

            p_this->xfer.gpio_xfer_sub_state++;
            break;

        case 2:
            bit_index = 7 - state;
            if (((p_this->xfer.tx_buff[p_this->xfer.tx_len]>>bit_index) & 0x1) && venus_gpio_input(sda)==0)
            {
                // lose of arbitraction
                p_this->xfer.ret = -ETXABORT;
                p_this->xfer.gpio_xfer_state = G2C_ST_DONE;
                p_this->xfer.gpio_xfer_sub_state = 0;
            }
            else
            {
                venus_gpio_set_dir(scl, 0);             // SCL = H
                p_this->xfer.gpio_xfer_sub_state++;
            }

            break;

        case 3:
            if (venus_gpio_input(scl))               // Wait SCL = H
            {
                p_this->xfer.gpio_xfer_state++;     // Next State
                p_this->xfer.gpio_xfer_sub_state = 0;
            }
            break;
        }
    }
    else
    {
        //--------------------------------------------------
        // ACK & NACK
        //--------------------------------------------------

        switch(p_this->xfer.gpio_xfer_sub_state)
        {
        case 0:
            venus_gpio_set_dir(scl, 1);             // Pull low SCL
            p_this->xfer.gpio_xfer_sub_state++;
            break;

        case 1:
            venus_gpio_set_dir(sda, 0);             // SDA = H
            p_this->xfer.gpio_xfer_sub_state++;
            break;

        case 2:
            venus_gpio_set_dir(scl, 0);             // Release SCL
            p_this->xfer.gpio_xfer_sub_state++;
            break;

        case 3:
            if (venus_gpio_input(scl))               // Wait SCL = H
            {
                p_this->xfer.tx_len++;

                if (venus_gpio_input(sda) || (p_this->xfer.tx_len >= p_this->xfer.tx_buff_len))
                {
                    if (venus_gpio_input(sda))
                        p_this->xfer.ret = -ETXABORT;
                    p_this->xfer.gpio_xfer_state = G2C_ST_STOP;     // NACK or no data to xfer
                }
                else
                {
                    p_this->xfer.gpio_xfer_state = G2C_ST_DATA0;    // ACK and still has data to xfer
                }

                p_this->xfer.gpio_xfer_sub_state = 0;
            }
            break;
        }
    }
}

/*------------------------------------------------------------------
 * Func : venus_g2c_do_stop
 *
 * Desc : Do STOP or Restart
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : N/A
 *------------------------------------------------------------------*/
void venus_g2c_do_stop(venus_i2c* p_this)
{
    VENUS_GPIO_ID sda = p_this->gpio_map.sda;
    VENUS_GPIO_ID scl = p_this->gpio_map.scl;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (!p_this->gpio_map.valid)
        return;

    switch(p_this->xfer.gpio_xfer_sub_state)
    {
    case 0:
        venus_gpio_set_dir(scl, 1);             // SCL = L
        p_this->xfer.gpio_xfer_sub_state++;
        break;

    case 1:
        if ((p_this->xfer.flags & I2C_NO_STOP)==0 || p_this->xfer.ret < 0)
            venus_gpio_set_dir(sda, 1);         // SDA = L
        else
            venus_gpio_set_dir(sda, 0);         // SDA = H

        p_this->xfer.gpio_xfer_sub_state++;
        break;

    case 2:
        venus_gpio_set_dir(scl, 0);             // SCL = H
        p_this->xfer.gpio_xfer_sub_state++;
        break;

    case 3:
        if (venus_gpio_input(scl))               // wait SCL = H
        {
            venus_gpio_set_dir(sda, 0);         // SDA = H
            p_this->xfer.gpio_xfer_state = G2C_ST_DONE;
            p_this->xfer.gpio_xfer_sub_state = 0;
        }
    }
}

/*------------------------------------------------------------------
 * Func : venus_g2c_do_complete
 *
 * Desc : complete GPIO i2c transxfer
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : N/A
 *------------------------------------------------------------------*/
void venus_g2c_do_complete(venus_i2c* p_this)
{
    VENUS_GPIO_ID sda = p_this->gpio_map.sda;
    VENUS_GPIO_ID scl = p_this->gpio_map.scl;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (p_this->xfer.gpio_xfer_sub_state==0)
    {
        venus_gpio_set_dir(sda, 0);
        venus_gpio_set_dir(scl, 0);
        venus_i2c_gpio_selection(p_this, I2C_MODE);
        p_this->xfer.gpio_xfer_sub_state++;
        p_this->xfer.mode = I2C_IDEL;
    }
}

/*------------------------------------------------------------------
 * Func : venus_g2c_isr
 *
 * Desc : isr of venus gpio i2c
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : 0
 *------------------------------------------------------------------*/
static
irqreturn_t venus_g2c_isr(
    int                     this_irq,
    void*                   dev_id,
    struct pt_regs*         regs
    )
{
    venus_i2c* p_this = (venus_i2c*) dev_id;
    unsigned long flags;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);

#if 0
    printk(KERN_DEBUG "ST = %d-%d:%d\n",
        G2C_MAJOR_STATE(p_this->xfer.gpio_xfer_state),
        G2C_MINOR_STATE(p_this->xfer.gpio_xfer_state),
        p_this->xfer.gpio_xfer_sub_state);
#endif

    LOCK_VENUS_I2C(&p_this->lock, flags);

#if 0
    printk(KERN_DEBUG "p_this->xfer.mode=%d, jiffies = %lu,  timeout = %lu\n",
            p_this->xfer.mode,
            jiffies,
            p_this->xfer.timeout);
#endif

    if (p_this->xfer.mode != I2C_IDEL && time_after(jiffies,p_this->xfer.timeout))
    {
        p_this->xfer.ret = -ETIMEOUT;
        p_this->xfer.gpio_xfer_state = G2C_ST_DONE;
        p_this->xfer.gpio_xfer_sub_state = 0;
    }

    switch(G2C_MAJOR_STATE(p_this->xfer.gpio_xfer_state))
    {
    case G2C_STATE_START: venus_g2c_do_start(p_this);      break;
    case G2C_STATE_ADDR:  venus_g2c_do_address(p_this);    break;
    case G2C_STATE_STOP:  venus_g2c_do_stop(p_this);       break;
    case G2C_STATE_DONE:  venus_g2c_do_complete(p_this);   break;
    case G2C_STATE_DATA:
        if (p_this->xfer.mode==I2C_MASTER_WRITE)
            venus_g2c_do_write(p_this);
        else
            venus_g2c_do_read(p_this);
        break;
    }

    UNLOCK_VENUS_I2C(&p_this->lock, flags);

    return IRQ_HANDLED;
}

/*------------------------------------------------------------------
 * Func : venus_g2c_start_xfer
 *
 * Desc : venus_g2c_start_xfer
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : N/A
 *
 * Note : this file using GPIO4/5 to out I2C protocol. where GP4 is SCLK
 *        GP5 is SDA
 *------------------------------------------------------------------*/
int venus_g2c_start_xfer(
    venus_i2c*              p_this
    )
{
    int d = p_this->tick>>2;
    p_this->xfer.timeout = jiffies + (2 * HZ);
    p_this->xfer.gpio_wait_time = (G2C_WAIT_TIMEOUT * 1000);
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    while(1)
    {
        venus_g2c_isr(7, (void*) p_this, 0);

        if (p_this->xfer.mode == I2C_IDEL)
            break;

        if (p_this->xfer.gpio_wait_time <= d)
        {
            // maximum run time = 3 msec
            p_this->xfer.gpio_wait_time = G2C_WAIT_TIMEOUT * 1000;
            msleep(1);
        }
        else
        {
            p_this->xfer.gpio_wait_time -= d;
            udelay(d);
        }
    }

#ifdef CONFIG_I2C_RTK_BUS_JAM_RECOVER

    if (p_this->xfer.ret == -ETIMEOUT)
    {
        JAM_DEBUG("[I2C] WARNING, I2C ETIMEOUT\n");
        if (venus_i2c_bus_jam_detect(p_this))
        {
            JAM_DEBUG("[I2C] WARNING, I2C Bus Jammed, Do Recorver\n");
            venus_i2c_bus_jam_recover_proc(p_this);
            msleep(50);
        }

        JAM_DEBUG("[I2C] Info, Reset I2C State\n");
        venus_i2c_reset_state(p_this);
    }

#endif

    return p_this->xfer.ret;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_get_tx_abort_reason
 *
 * Desc : get reason of tx abort, this register will be clear when new message is loaded
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : tx about source
 *------------------------------------------------------------------*/
unsigned int venus_i2c_get_tx_abort_reason(venus_i2c* p_this)
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    return p_this->xfer.tx_abort_source;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_load_message
 *
 * Desc : load a i2c message (just add this message to the queue)
 *
 * Parm : p_this : handle of venus i2c
 *
 *
 * Retn : 0 for success, others is failed
 *------------------------------------------------------------------*/
int venus_i2c_load_message(
    venus_i2c*              p_this,
    unsigned char           mode,
    unsigned char*          tx_buf,
    unsigned short          tx_buf_len,
    unsigned char*          rx_buf,
    unsigned short          rx_buf_len,
    unsigned char           xfer_flags
    )
{
    unsigned long flags;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    LOCK_VENUS_I2C(&p_this->lock, flags);

    memset(&p_this->xfer, 0, sizeof(p_this->xfer));

    p_this->xfer.mode           = mode;
    p_this->xfer.flags          = xfer_flags;
    p_this->xfer.tx_buff        = tx_buf;
    p_this->xfer.tx_buff_len    = tx_buf_len;
    p_this->xfer.tx_len         = 0;
    p_this->xfer.rx_buff        = rx_buf;
    p_this->xfer.rx_buff_len    = rx_buf_len;
    p_this->xfer.rx_len         = 0;
    p_this->xfer.except_time    = ((tx_buf_len + rx_buf_len + 2) * 9 * p_this->tick);

    if (rx_buf && rx_buf_len)
        memset(rx_buf, 0, rx_buf_len);

    p_this->xfer.gpio_xfer_state   = G2C_ST_START;
    p_this->xfer.gpio_xfer_sub_state = 0;

    UNLOCK_VENUS_I2C(&p_this->lock, flags);

#ifdef DEV_DEBUG
	{
		int i;
		RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
		RTK_DEBUG("[%s] %s  %d  xfer.mode = %x\n", __FILE__,__FUNCTION__,__LINE__,p_this->xfer.mode);
		RTK_DEBUG("[%s] %s  %d  xfer.flags= 0x%x\n", __FILE__,__FUNCTION__,__LINE__,p_this->xfer.flags);

		if(p_this->xfer.tx_buff_len)
		{
			for(i=0;i<p_this->xfer.tx_buff_len;i++)
				RTK_DEBUG("[%s] %s  %d  xfer.tx_buff= 0x%x\n", __FILE__,__FUNCTION__,__LINE__,*p_this->xfer.tx_buff);
				RTK_DEBUG("[%s] %s  %d  xfer.tx_buff= 0x%x\n", __FILE__,__FUNCTION__,__LINE__,p_this->xfer.tx_buff[i]);
		}

		RTK_DEBUG("[%s] %s  %d  xfer.tx_buff_len= 0x%x\n", __FILE__,__FUNCTION__,__LINE__,p_this->xfer.tx_buff_len);
		RTK_DEBUG("[%s] %s  %d  xfer.tx_len= 0x%x\n", __FILE__,__FUNCTION__,__LINE__, p_this->xfer.tx_len);

		if(p_this->xfer.rx_buff_len)
		{
			for(i=0;i<p_this->xfer.rx_buff_len;i++)
				RTK_DEBUG("[%s] %s  %d  xfer.rx_buff= 0x%x\n", __FILE__,__FUNCTION__,__LINE__,*p_this->xfer.rx_buff);
				RTK_DEBUG("[%s] %s  %d  xfer.rx_buff= 0x%x\n", __FILE__,__FUNCTION__,__LINE__,p_this->xfer.rx_buff[i]);
		}

		RTK_DEBUG("[%s] %s  %d  xfer.rx_buff_len= 0x%x\n", __FILE__,__FUNCTION__,__LINE__, p_this->xfer.rx_buff_len);
		RTK_DEBUG("[%s] %s  %d  xfer.rx_len= 0x%x\n", __FILE__,__FUNCTION__,__LINE__, p_this->xfer.rx_len);
		RTK_DEBUG("[%s] %s  %d  xfer.except_time= 0x%lx\n", __FILE__,__FUNCTION__,__LINE__, p_this->xfer.except_time);
	}
#endif

    return 0;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_read
 *
 * Desc : read data from sar
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : 0 for success, others is failed
 *------------------------------------------------------------------*/
int venus_i2c_read(
    venus_i2c*              p_this,
    unsigned char*          tx_buf,
    unsigned short          tx_buf_len,
    unsigned char*          rx_buf,
    unsigned short          rx_buf_len
    )
{
    int retry = 2;
    int ret = 0;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    while(retry > 0)
    {
	//printk(KERN_ERR "venus_i2c_load_message\n");
	venus_i2c_load_message(p_this,
            (tx_buf_len) ? I2C_MASTER_RANDOM_READ : I2C_MASTER_READ,
            tx_buf, tx_buf_len, rx_buf, rx_buf_len, 0);
	//printk(KERN_ERR "venus_i2c_start_xfer\n");
        ret = venus_i2c_start_xfer(p_this);
        if (ret!=-ETIMEOUT)
            break;

        JAM_DEBUG("[I2C] read timeout detected, do retry\n");
        retry--;
    }

    return ret;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_write
 *
 * Desc : write data to sar
 *
 * Parm : p_this : handle of venus i2c
 *        tx_buf : data to write
 *        tx_buf_len : number of bytes to write
 *        wait_stop  : wait for stop of not (extension)
 *
 * Retn : 0 for success, others is failed
 *------------------------------------------------------------------*/
int venus_i2c_write(
    venus_i2c*              p_this,
    unsigned char*          tx_buf,
    unsigned short          tx_buf_len,
    unsigned char           wait_stop
    )
{
    int retry = 2;
    int ret = 0;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    while(retry > 0)
    {
        venus_i2c_load_message(p_this, I2C_MASTER_WRITE,
            tx_buf, tx_buf_len, NULL, 0, (wait_stop) ? 0 : I2C_NO_STOP);

#ifdef CONFIG_I2C_VENUS_NON_STOP_WRITE_XFER

        ret = (!wait_stop && p_this->gpio_map.valid) ? venus_g2c_start_xfer(p_this)   // normal i2c can not support this mode, so we use GPIO mode to instead
                           : venus_i2c_start_xfer(p_this);
#else
        ret = venus_i2c_start_xfer(p_this);
#endif

        if (ret!=-ETIMEOUT)
            break;

        JAM_DEBUG("[I2C] write timeout detected, do retry\n");
        retry--;
    }

    return ret;
}

int venus_g2c_read(
    venus_i2c*              p_this,
    unsigned char*          tx_buf,
    unsigned short          tx_buf_len,
    unsigned char*          rx_buf,
    unsigned short          rx_buf_len
    );

int venus_g2c_write(
    venus_i2c*              p_this,
    unsigned char*          tx_buf,
    unsigned short          tx_buf_len,
    unsigned char           wait_stop
    );

static unsigned char venus_i2c_flags = 0;
static venus_i2c* venus_i2c_phy_handle[I2C_PHY_CNT] = {NULL};

/*------------------------------------------------------------------
 * Func : get_venus_i2c_phy_count
 *
 * Desc : get number of venus i2c phy
 *
 * Parm : N/A
 *
 * Retn : number of venus i2c
 *
 *------------------------------------------------------------------*/
unsigned char get_venus_i2c_phy_count(void)
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    return I2C_PHY_CNT;
}

#ifdef EDID_4BLOCK_SUPPORT
/*
 * Block 0~1: Seg 0
 * Block 2: Seg 1, Offset 0
 * Block 3: Seg 1, Offset 128
 */
int venus_i2c_read_edid_seg (
        venus_i2c* p_this,
        unsigned char seg,/* Segment Pointer */
        unsigned char offset,/*Word Offset*/
        unsigned char *rx_buff,unsigned short rx_buf_len
        )
{
    int rx_len=0,tx_len=0,cnt;
#define RxComplete()		(rx_len >= rx_buf_len)
#define TxComplete()		(tx_len >= rx_buf_len)
    RTK_DEBUG("[%s] %s	%d	seg=0x%x offset=0x%02x len(%u)\n", __FILE__,__FUNCTION__,__LINE__,seg,offset,rx_buf_len);

    venus_i2c_set_tar(p_this,0x30,ADDR_MODE_7BITS);
    CLR_IC_INTR(p_this);
    SET_IC_ENABLE(p_this, 1);
    cnt=0;
    while( (GET_IC_STATUS(p_this) & ST_ACTIVITY_BIT) == 0 )
    {
        if(cnt++<5)
            udelay(50);
        else
            return -ETIMEOUT;
        RTK_DEBUG("[%s] %s	%d	IC_STATUS= 0x%x\n", __FILE__,__FUNCTION__,__LINE__,GET_IC_STATUS(p_this));
    }
    SET_IC_DATA_CMD(p_this, seg);//Segment Pointer
    udelay(50);
    CLR_IC_INTR(p_this);
    SET_IC_ENABLE(p_this, 0);

    venus_i2c_set_tar(p_this,0x50,ADDR_MODE_7BITS);
    CLR_IC_INTR(p_this);
    SET_IC_ENABLE(p_this, 1);
    cnt=0;
    while( (GET_IC_STATUS(p_this) & ST_ACTIVITY_BIT) == 0 )
    {
        if(cnt++<5)
            udelay(50);
        else
            return -ETIMEOUT;
    }
    SET_IC_DATA_CMD(p_this, offset|(0x1<<10));//Restart, Word Offset
    udelay(100);
    RTK_DEBUG("[%s] %s	%d	IC_STATUS= 0x%x\n", __FILE__,__FUNCTION__,__LINE__,GET_IC_STATUS(p_this));

    while(!TxComplete() && NOT_TXFULL(p_this))
    {
        if(tx_len==rx_buf_len-1)
        {
            SET_IC_DATA_CMD(p_this, (0x1<<8)|(0x1<<9));//Read,Stop
            //RTK_DEBUG("[%s] %s	%d	IC_STATUS= 0x%x\n", __FILE__,__FUNCTION__,__LINE__,GET_IC_STATUS(p_this));
        }
        else
        {
            SET_IC_DATA_CMD(p_this, (0x1<<8));//Read
            //RTK_DEBUG("[%s] %s	%d	IC_STATUS= 0x%x\n", __FILE__,__FUNCTION__,__LINE__,GET_IC_STATUS(p_this));
        }
        tx_len++;
        udelay(100);
        while(NOT_RXEMPTY(p_this))
        {
            rx_buff[rx_len] = (unsigned char)(GET_IC_DATA_CMD(p_this) & 0xFF);
            //RTK_DEBUG("+Data[%u]=0x%02x\n",rx_len,rx_buff[rx_len]);
            udelay(50);
            rx_len++;
        }
    }

    while(!RxComplete() && NOT_RXEMPTY(p_this))
    {
        rx_buff[rx_len] = (unsigned char)(GET_IC_DATA_CMD(p_this) & 0xFF);
        //RTK_DEBUG("++Data[%u]=0x%02x\n",rx_len,rx_buff[rx_len]);
        rx_len++;
        udelay(50);
    }
    CLR_IC_INTR(p_this);
    SET_IC_ENABLE(p_this, 0);

    return 0;
}

#endif

/*------------------------------------------------------------------
 * Func : create_venus_i2c_handle
 *
 * Desc : create handle of venus i2c
 *
 * Parm : N/A
 *
 * Retn : handle of venus i2c
 *
 *------------------------------------------------------------------*/
venus_i2c*
create_venus_i2c_handle(
    unsigned char       id,
    unsigned short      sar,
    ADDR_MODE           sar_mode,
    unsigned int        spd,
    unsigned int        irq
    )
{
    venus_i2c* hHandle;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (id >= I2C_PHY_CNT)
        return NULL;

    if (((venus_i2c_flags>>id) & 0x01))
    {
//        atomic_inc(&venus_i2c_phy_handle[id]->ref_cnt);  // reference count++
        return venus_i2c_phy_handle[id];
    }

    hHandle = kmalloc(sizeof(venus_i2c),GFP_KERNEL);

    if (hHandle!= NULL)
    {
        memset(hHandle, 0, sizeof(venus_i2c));
        hHandle->flags        = 0;
        hHandle->id           = id;
        hHandle->irq          = irq;
        hHandle->sar          = sar;
        hHandle->sar_mode     = sar_mode;
        hHandle->spd          = spd;
        hHandle->guard_interval = 1000;
        //hHandle->init         = venus_i2c_init;
        hHandle->uninit       = venus_i2c_uninit;
        hHandle->set_spd      = venus_i2c_set_spd;
        hHandle->set_guard_interval = venus_i2c_set_guard_interval;
        hHandle->set_tar      = venus_i2c_set_tar;
        //hHandle->set_port     = venus_i2c_set_port;
        hHandle->read         = venus_i2c_read;
        hHandle->write        = venus_i2c_write;
        hHandle->gpio_read    = venus_g2c_read;
        hHandle->gpio_write   = venus_g2c_write;
        hHandle->dump         = venus_i2c_dump;
        hHandle->suspend      = venus_i2c_suspend;
        hHandle->resume       = venus_i2c_resume;
        hHandle->get_tx_abort_reason = venus_i2c_get_tx_abort_reason;

        hHandle->set_sar      = venus_i2c_set_sar;
        hHandle->slave_mode_enable = venus_i2c_slave_mode_enable;
        hHandle->register_slave_ops = venus_i2c_register_slave_ops;

#ifdef EDID_4BLOCK_SUPPORT
		hHandle->read_edid_seg = venus_i2c_read_edid_seg;
#endif

        atomic_set(&hHandle->ref_cnt, 1);
        memset(&hHandle->xfer, 0, sizeof(venus_i2c_xfer));
        venus_i2c_phy_handle[id] = hHandle;
        venus_i2c_flags |= (0x01 << id);
    }

    return hHandle;
}
EXPORT_SYMBOL(create_venus_i2c_handle);

/*------------------------------------------------------------------
 * Func : destroy_venus_i2c_handle
 *
 * Desc : destroy handle of venus i2c
 *
 * Parm : N/A
 *
 * Retn : N/A
 *------------------------------------------------------------------*/
void destroy_venus_i2c_handle(venus_i2c* hHandle)
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (hHandle==NULL)
        return;

    if (atomic_dec_return(&hHandle->ref_cnt)>0) {
        printk("[I2C] destroy I2C%d successed, reference cnt=%d\n", hHandle->id, atomic_read(&hHandle->ref_cnt));
        return;
    }

    printk("[I2C] destroy venus i2c%d handle\n", hHandle->id);
    hHandle->uninit(hHandle);
    venus_i2c_flags &= ~(0x01<<hHandle->id);
    venus_i2c_phy_handle[hHandle->id] = NULL;
    kfree(hHandle);
}
EXPORT_SYMBOL(destroy_venus_i2c_handle);

/*------------------------------------------------------------------
 * Func : venus_g2c_null_function
 *
 * Desc : null function for gpio
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : 0 for success, others is failed
 *------------------------------------------------------------------*/
int venus_g2c_null_function(venus_i2c* p_this)
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    return 0;
}

/*------------------------------------------------------------------
 * Func : venus_g2c_null_function
 *
 * Desc : null function for gpio
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : 0 for success, others is failed
 *------------------------------------------------------------------*/
int venus_g2c_dump(venus_i2c* p_this)
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    i2c_print("=========================\n");
    i2c_print("= VER  : %s              \n", VERSION);
    i2c_print("=========================\n");
    i2c_print("= PHY  : %d              \n", p_this->id);
    i2c_print("= MODEL: G2C             \n");
    i2c_print("= SPD  : %d              \n", p_this->spd);
    i2c_print("= SDA  : %d              \n", gpio_idx(p_this->gpio_map.sda));
    i2c_print("= SCL  : %d              \n", gpio_idx(p_this->gpio_map.scl));
    i2c_print("= TX FIFO DEPTH : %d     \n", p_this->tx_fifo_depth);
    i2c_print("= RX FIFO DEPTH : %d     \n", p_this->rx_fifo_depth);
    i2c_print("=========================\n");
    return 0;
}

/*------------------------------------------------------------------
 * Func : venus_g2c_set_spd
 *
 * Desc : set speed of venus i2c
 *
 * Parm : p_this : handle of venus i2c
 *        KHz    : operation speed of i2c
 *
 * Retn : 0
 *------------------------------------------------------------------*/
int venus_g2c_set_spd(venus_i2c* p_this, int KHz)
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (KHz < 10 || KHz > 800)
    {
        i2c_print("[I2C%d] warning, speed %d out of range, speed should between 10 ~ 150KHz\n", p_this->id, KHz);
        return -1;
    }

    p_this->spd  = KHz;
    p_this->tick = 1000 / KHz;

    i2c_print("[I2C%d] i2c speed changed to %d KHz\n", p_this->id, p_this->spd);
    return 0;
}

/*------------------------------------------------------------------
 * Func : venus_i2c_set_tar
 *
 * Desc : set tar of venus i2c
 *
 * Parm : p_this : handle of venus i2c
 *        addr   : address of sar
 *        mode
  : mode of sar
 *
 * Retn : 0
 *------------------------------------------------------------------*/
int
venus_g2c_set_tar(
    venus_i2c*          p_this,
    unsigned short      addr,
    ADDR_MODE           mode
    )
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    p_this->tar      = addr;
    p_this->tar_mode = mode;
    return 0;
}

/*------------------------------------------------------------------
 * Func : venus_g2c_set_sar
 *
 * Desc : set sar of gpio i2c
 *
 * Parm : p_this : handle of venus i2c
 *        addr   : address of sar
 *        mode
  : mode of sar
 *
 * Retn : 0
 *------------------------------------------------------------------*/
int
venus_g2c_set_sar(
    venus_i2c*          p_this,
    unsigned short      addr,
    ADDR_MODE           mode
    )
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    p_this->sar      = addr;
    p_this->sar_mode = mode;
    return 0;
}

/*------------------------------------------------------------------
 * Func : venus_g2c_slave_mode_enable
 *
 * Desc : enable/disable i2c slave mode
 *
 * Parm : p_this : handle of venus i2c
 *        on     : enable /disable
 *
 * Retn : 0
 *------------------------------------------------------------------*/
int venus_g2c_slave_mode_enable(
    venus_i2c*              p_this,
    unsigned char           on
    )
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    return -1;
}

/*------------------------------------------------------------------
 * Func : venus_g2c_set_port
 *
 * Desc : set port of venus g2c
 *
 * Parm : p_this : handle of venus i2c
 *        port   : output port selection
 *
 * Retn : 0
 *------------------------------------------------------------------*/
int
venus_g2c_set_port(
    venus_i2c*          p_this,
    unsigned char       port
    )
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    return -EFAULT;
}

/*------------------------------------------------------------------
 * Func : venus_g2c_write
 *
 * Desc : write data to sar - GPIO mode
 *
 * Parm : p_this : handle of venus i2c
 *        tx_buf : data to write
 *        tx_buf_len : number of bytes to write
 *        wait_stop  : wait for stop of not (extension)
 *
 * Retn : 0 for success, others is failed
 *------------------------------------------------------------------*/
int venus_g2c_write(
    venus_i2c*              p_this,
    unsigned char*          tx_buf,
    unsigned short          tx_buf_len,
    unsigned char           wait_stop
    )
{
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (!p_this->gpio_map.valid && p_this->write == venus_i2c_write)
        return venus_i2c_write(p_this, tx_buf, tx_buf_len, wait_stop);

    venus_i2c_load_message(p_this, I2C_MASTER_WRITE,
                           tx_buf, tx_buf_len, NULL, 0, (wait_stop) ? 0 : I2C_NO_STOP);

    return venus_g2c_start_xfer(p_this);
}

/*------------------------------------------------------------------
 * Func : venus_g2c_read
 *
 * Desc : read data from sar - GPIO mode
 *
 * Parm : p_this : handle of venus i2c
 *
 * Retn : 0 for success, others is failed
 *------------------------------------------------------------------*/
int venus_g2c_read(
    venus_i2c*              p_this,
    unsigned char*          tx_buf,
    unsigned short          tx_buf_len,
    unsigned char*          rx_buf,
    unsigned short          rx_buf_len
    )
{
    int ret = 0;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (!p_this->gpio_map.valid && p_this->read == venus_i2c_read)
        return venus_i2c_read(p_this, tx_buf, tx_buf_len, rx_buf, rx_buf_len);

    if (tx_buf && tx_buf_len)
    {
        if ((ret = venus_g2c_write(p_this,  tx_buf, tx_buf_len, 0))<0)
            return ret;
    }

    venus_i2c_load_message(p_this, I2C_MASTER_READ,
            NULL, 0, rx_buf, rx_buf_len, 0);

    return venus_g2c_start_xfer(p_this);
}

#define venus_g2c_init                  venus_g2c_dump
#define venus_g2c_uninit                venus_g2c_null_function               // no nothing
#define venus_g2c_get_tx_abort_reason   venus_i2c_get_tx_abort_reason         // share the same function with venus i2c
#define venus_g2c_suspend               venus_g2c_null_function               // no nothing
#define venus_g2c_resume                venus_g2c_null_function               // no nothing

/*------------------------------------------------------------------
 * Func : create_venus_g2c_handle
 *
 * Desc : create handle of venus g2c
 *
 * Parm : gpio_sda : gpio for sda
 *        gpio_sda : gpio for scl
 *
 * Retn : handle of venus i2c
 *------------------------------------------------------------------*/
venus_i2c* create_venus_g2c_handle(
    unsigned char       id,
    unsigned char       gpio_sda,
    unsigned char       gpio_scl
    )
{
    venus_i2c* hHandle;
    RTK_DEBUG("[%s] %s  %d \n", __FILE__,__FUNCTION__,__LINE__);
    if (id >= 8 || (venus_i2c_flags>>id) & 0x01)
        return NULL;

    hHandle = kmalloc(sizeof(venus_i2c),GFP_KERNEL);

    if (hHandle!= NULL)
    {
        memset(hHandle, 0, sizeof(venus_i2c));

        hHandle->flags         = 0;
        hHandle->id            = id;
        hHandle->irq           = 0;
        hHandle->sar           = 0;
        hHandle->sar_mode      = ADDR_MODE_7BITS;
        hHandle->tar           = 0;
        hHandle->tar_mode      = ADDR_MODE_7BITS;
        hHandle->spd           = 100;
        hHandle->tick          = 1000/hHandle->spd;
        hHandle->guard_interval = 1000;
        hHandle->rx_fifo_depth = 16;
        hHandle->tx_fifo_depth = 16;
        hHandle->time_stamp    = 0;
        memset(&hHandle->xfer, 0, sizeof(venus_i2c_xfer));
        spin_lock_init(&hHandle->lock);

        // init gpio register map
        hHandle->gpio_map.valid       = 1;
        hHandle->gpio_map.scl         = venus_gpio_id(MIS_GPIO, gpio_scl);
        hHandle->gpio_map.sda         = venus_gpio_id(MIS_GPIO, gpio_sda);
        hHandle->gpio_map.muxpad      = 0;    // no muxpad supported
        hHandle->gpio_map.muxpad_mask = 0;
        hHandle->gpio_map.muxpad_gpio = 0;
        hHandle->gpio_map.muxpad_i2c  = 0;

        // init operations
        hHandle->init         = venus_g2c_init;
        hHandle->uninit       = venus_g2c_uninit;
        hHandle->set_spd      = venus_g2c_set_spd;
        hHandle->set_guard_interval = venus_i2c_set_guard_interval;
        hHandle->set_tar      = venus_g2c_set_tar;
        hHandle->set_port     = venus_g2c_set_port;
        hHandle->read         = venus_g2c_read;
        hHandle->write        = venus_g2c_write;
        hHandle->gpio_read    = venus_g2c_read;
        hHandle->gpio_write   = venus_g2c_write;
        hHandle->dump         = venus_g2c_dump;
        hHandle->suspend      = venus_g2c_suspend;
        hHandle->resume       = venus_g2c_resume;
        hHandle->get_tx_abort_reason = venus_g2c_get_tx_abort_reason;

        hHandle->set_sar      = venus_g2c_set_sar;
        hHandle->slave_mode_enable = venus_g2c_slave_mode_enable;
        hHandle->register_slave_ops = venus_i2c_register_slave_ops;

        venus_i2c_flags |= (0x01 << id);
    }

    return hHandle;
}
