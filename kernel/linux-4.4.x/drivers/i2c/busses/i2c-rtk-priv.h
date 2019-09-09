#ifndef __I2C_VENUS_PRIV_H__
#define __I2C_VENUS_PRIV_H__

#include <linux/i2c.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <soc/realtek/venus_gpio.h>
#include <asm/atomic.h>
#include "platform.h"

//#define DEV_DEBUG
#define DEV_JAM_DEBUG

#ifdef DEV_DEBUG
#define RTK_DEBUG(fmt, ...) printk(fmt, ##__VA_ARGS__)
#define DEV_JAM_DEBUG
#else
#define RTK_DEBUG(fmt, ...)
#endif

#ifdef DEV_JAM_DEBUG
#define JAM_DEBUG(fmt, ...) printk(fmt, ##__VA_ARGS__)
#else
#define JAM_DEBUG(fmt, ...)
#endif

#define EDID_4BLOCK_SUPPORT//For HDMI TX CTS 7-1

////////////////////////////////////////////////////////////////////
#define wr_reg(x,y)                     writel(y,(volatile unsigned int*)x)
#define rd_reg(x)                       readl((volatile unsigned int*)x)

// venus
//#define GET_MIS_PSELL()                 rd_reg(VENUS_IO_PORT_BASE + VENUS_MIS_PSELL)
//#define SET_MIS_PSELL(x)                wr_reg(VENUS_IO_PORT_BASE + VENUS_MIS_PSELL, x)

// mars
#define GET_MUX_PAD0()                  rd_reg(MARS_0_SYS_MUXPAD0)
#define SET_MUX_PAD0(x)                 wr_reg(MARS_0_SYS_MUXPAD0, x)
#define GET_MUX_PAD3()                  rd_reg(MARS_0_SYS_MUXPAD3)
#define SET_MUX_PAD3(x)                 wr_reg(MARS_0_SYS_MUXPAD3, x)
#define GET_MUX_PAD5()                  rd_reg(MARS_0_SYS_MUXPAD5)
#define SET_MUX_PAD5(x)                 wr_reg(MARS_0_SYS_MUXPAD5, x)

#define SET_I2C_ISR(adp,x)              wr_reg(adp->reg_map.I2C_ISR, x)
#define GET_I2C_ISR(adp)                rd_reg(adp->reg_map.I2C_ISR)
#define SET_IC_ENABLE(adp,x)            wr_reg(adp->reg_map.IC_ENABLE,x)
#define GET_IC_ENABLE(adp)              rd_reg(adp->reg_map.IC_ENABLE)
#define SET_IC_CON(adp,x)               wr_reg(adp->reg_map.IC_CON, x)
#define GET_IC_CON(adp)                 rd_reg(adp->reg_map.IC_CON)
#define SET_IC_SAR(adp,x)               wr_reg(adp->reg_map.IC_SAR, x)
#define GET_IC_SAR(adp)                 rd_reg(adp->reg_map.IC_SAR)
#define SET_IC_TAR(adp,x)               wr_reg(adp->reg_map.IC_TAR, x)
#define GET_IC_TAR(adp)                 rd_reg(adp->reg_map.IC_TAR)
#define SET_IC_DATA_CMD(adp, x)         wr_reg(adp->reg_map.IC_DATA_CMD, x)
#define GET_IC_DATA_CMD(adp)            rd_reg(adp->reg_map.IC_DATA_CMD)
#define SET_IC_SS_SCL_HCNT(adp,x)       wr_reg(adp->reg_map.IC_SS_SCL_HCNT, x)
#define SET_IC_SS_SCL_LCNT(adp,x)       wr_reg(adp->reg_map.IC_SS_SCL_LCNT, x)
#define GET_IC_STATUS(adp)              rd_reg(adp->reg_map.IC_STATUS)
#define SET_IC_INTR_MASK(adp,x)         wr_reg(adp->reg_map.IC_INTR_MASK, x)
#define GET_IC_INTR_MASK(adp)           rd_reg(adp->reg_map.IC_INTR_MASK)
#define GET_IC_INTR_STAT(adp)           rd_reg(adp->reg_map.IC_INTR_STAT)
#define GET_IC_RAW_INTR_STAT(adp)       rd_reg(adp->reg_map.IC_RAW_INTR_STAT)
#define CLR_IC_INTR(adp)                rd_reg(adp->reg_map.IC_CLR_INTR)
#define CLR_IC_RX_UNDER(adp)            rd_reg(adp->reg_map.IC_CLR_RX_UNDER)
#define CLR_IC_TX_OVER(adp)             rd_reg(adp->reg_map.IC_CLR_TX_OVER)
#define CLR_IC_RD_REQ(adp)              rd_reg(adp->reg_map.IC_CLR_RD_REQ)
#define CLR_IC_RX_DONE(adp)             rd_reg(adp->reg_map.IC_CLR_RX_DONE)
#define CLR_IC_ACTIVITY(adp)            rd_reg(adp->reg_map.IC_CLR_ACTIVITY)
#define CLR_IC_GEN_CALL(adp)            rd_reg(adp->reg_map.IC_CLR_GEN_CALL)
#define CLR_IC_TX_ABRT(adp)             rd_reg(adp->reg_map.IC_CLR_TX_ABRT)
#define CLR_IC_STOP_DET(adp)            rd_reg(adp->reg_map.IC_CLR_STOP_DET)
#define GET_IC_COMP_PARAM_1(adp)        rd_reg(adp->reg_map.IC_COMP_PARAM_1)
#define GET_IC_TXFLR(adp)               rd_reg(adp->reg_map.IC_TXFLR)
#define GET_IC_RXFLR(adp)               rd_reg(adp->reg_map.IC_RXFLR)
#define GET_IC_RX_TL(adp)               rd_reg(adp->reg_map.IC_RX_TL)
#define GET_IC_TX_TL(adp)               rd_reg(adp->reg_map.IC_TX_TL)
#define GET_IC_SDA_DEL(adp)             rd_reg(adp->reg_map.IC_SDA_DEL)
#define SET_IC_RX_TL(adp, x)            wr_reg(adp->reg_map.IC_RX_TL, x)
#define SET_IC_TX_TL(adp, x)            wr_reg(adp->reg_map.IC_TX_TL, x)
#define SET_IC_SDA_DEL(adp, x)          wr_reg(adp->reg_map.IC_SDA_DEL, x)
#define GET_IC_TX_ABRT_SOURCE(adp)      rd_reg(adp->reg_map.IC_TX_ABRT_SOURCE)
#define NOT_TXFULL(adp)                 (GET_IC_STATUS(adp) & ST_TFNF_BIT)
#define NOT_RXEMPTY(adp)                (GET_IC_STATUS(adp) & ST_RFNE_BIT)

////////////////////////////////////////////////////////////////////
#define MAX_I2C_CNT                 3

#define VERSION                "2.2"

#define MINIMUM_DELAY_EN
#define SPIN_LOCK_PROTECT_EN
#define FIFO_THRESHOLD         4
//#define I2C_PROFILEING_EN
//#define I2C_TIMEOUT_INTERVAL   20    // (unit : jiffies = 10ms)
#define I2C_TIMEOUT_INTERVAL   100    // (unit : jiffies = 10ms)

#define EVENT_START_XFER       4
#define EVENT_STOP_XFER        5
#define EVENT_ENTER_ISR        6
#define EVENT_EXIT_ISR         7
#define EVENT_EXIT_TIMEOUT     8

////////////////////////////////////////////////////////////////////

typedef enum {
    SPD_MODE_LS = 33,
    SPD_MODE_SS = 100,
    SPD_MODE_FS = 400,
    SPD_MODE_HS = 1000
}SPD_MODE;

typedef enum {
    ADDR_MODE_7BITS   = 7,
    ADDR_MODE_10BITS  = 10
}ADDR_MODE;

enum {
    ECMDSPLIT   = 40,       // stop detected during transfer
    ETXABORT    = 41,
    ETIMEOUT    = 42,
    EILLEGALMSG = 43,       // illegal message
    EADDROVERRANGE = 44,      // invalid Address
};

enum {
    NON_STOP    = 0,       // stop detected during transfer
    WAIT_STOP   = 1,
};

enum {
    G2C_STATE_START = 0,
    G2C_STATE_ADDR,
    G2C_STATE_DATA,
    G2C_STATE_STOP,
    G2C_STATE_DONE,
};

#define G2C_ST(major, minor)    (((major & 0x7) <<5) + (minor & 0x1F))
#define G2C_MAJOR_STATE(x)      ((x >>5) & 0x07)
#define G2C_MINOR_STATE(x)      (x & 0x1F)

enum {
    G2C_ST_START    = G2C_ST(G2C_STATE_START, 0),

    G2C_ST_ADDR0    = G2C_ST(G2C_STATE_ADDR, 0),
    G2C_ST_ADDR1    = G2C_ST(G2C_STATE_ADDR, 1),
    G2C_ST_ADDR2    = G2C_ST(G2C_STATE_ADDR, 2),
    G2C_ST_ADDR3    = G2C_ST(G2C_STATE_ADDR, 3),
    G2C_ST_ADDR4    = G2C_ST(G2C_STATE_ADDR, 4),
    G2C_ST_ADDR5    = G2C_ST(G2C_STATE_ADDR, 5),
    G2C_ST_ADDR6    = G2C_ST(G2C_STATE_ADDR, 6),
    G2C_ST_ADDR7    = G2C_ST(G2C_STATE_ADDR, 7),
    G2C_ST_ADDR_ACK = G2C_ST(G2C_STATE_ADDR, 8),

    G2C_ST_DATA0    = G2C_ST(G2C_STATE_DATA, 0),
    G2C_ST_DATA1    = G2C_ST(G2C_STATE_DATA, 1),
    G2C_ST_DATA2    = G2C_ST(G2C_STATE_DATA, 2),
    G2C_ST_DATA3    = G2C_ST(G2C_STATE_DATA, 3),
    G2C_ST_DATA4    = G2C_ST(G2C_STATE_DATA, 4),
    G2C_ST_DATA5    = G2C_ST(G2C_STATE_DATA, 5),
    G2C_ST_DATA6    = G2C_ST(G2C_STATE_DATA, 6),
    G2C_ST_DATA7    = G2C_ST(G2C_STATE_DATA, 7),
    G2C_ST_DATA_ACK = G2C_ST(G2C_STATE_DATA, 8),

    G2C_ST_STOP     = G2C_ST(G2C_STATE_STOP, 0),
    G2C_ST_DONE     = G2C_ST(G2C_STATE_DONE, 0)
};

typedef struct {
    unsigned char       mode;

    #define I2C_IDEL               0
    #define I2C_MASTER_READ        1
    #define I2C_MASTER_WRITE       2
    #define I2C_MASTER_RANDOM_READ 3

    unsigned char       flags;
    #define I2C_NO_STOP            0x01      // don't issue stop command, (for gpio xfer only)

    unsigned char*      tx_buff;
    unsigned short      tx_buff_len;
    unsigned short      tx_len;
    unsigned char*      rx_buff;
    unsigned short      rx_buff_len;
    unsigned short      rx_len;
    unsigned long       except_time;
    unsigned long       timeout;
    int                 ret;        // 0 : on going, >0 : success, <0 : err
    unsigned int        tx_abort_source;

    // for gpio mode
    unsigned int        gpio_wait_time;

    #define G2C_WAIT_TIMEOUT                   3 // max wait time : ms

    unsigned char       gpio_xfer_state;        // 0   : Start
                                                // 1~8 : Data Phase : send bit 0~7 (w)
                                                // 9   : ACK :        Wait ACK (w), Send ACK (r)
                                                // 10  : STOP / RESTART
                                                // 11  : IDEL

                                                //---------------------------------------------------------------------
                                                //     |  START    | DATA             | ACK/NACK         | STOP/RESTART
                                                //-----+-----------+------------------+------------------+-------------
    unsigned char       gpio_xfer_sub_state;    // 0   | Init      | SCL = L          | SCL = L          | SCL = L
                                                //-----+-----------+------------------+------------------+-------------
                                                // 1   | wait bus  | (W) SDA = H/L    | (W) N/A          | (St) SDA = L
                                                //     | free      | (R) N/A          | (R) SDA = L/H    | (Sr) SDA = H
                                                //-----+-----------+------------------+------------------+-------------
                                                // 2   | SDA = L   | SCL = H          | SCL = H          | SCL = H
                                                //-----+-----------+------------------+------------------+-------------
                                                // 3   | SCL = L   | (W) Wait SCL = H | (W) Wait SCL = H | (St) SDA = H
                                                //     |           | (R) Wait SCL = H |     then read SDA| (Sr) N/A
                                                //     |           |     then Read    | (R) N/A          |
                                                //---------------------------------------------------------------------

}venus_i2c_xfer;

typedef struct venus_i2c_reg_map_t    venus_i2c_reg_map;

struct venus_i2c_reg_map_t
{
    unsigned long I2C_ISR_EN;
    unsigned long I2C_ISR_EN_MASK;
    unsigned long I2C_ISR;
    unsigned long I2C_INT;
    unsigned long IC_CON;
    unsigned long IC_TAR;
    unsigned long IC_SAR;
    unsigned long IC_HS_MADDR;
    unsigned long IC_DATA_CMD;
    unsigned long IC_SS_SCL_HCNT;
    unsigned long IC_SS_SCL_LCNT;
    unsigned long IC_FS_SCL_HCNT;
    unsigned long IC_FS_SCL_LCNT;
    unsigned long IC_INTR_STAT;
    unsigned long IC_INTR_MASK;
    unsigned long IC_RAW_INTR_STAT;
    unsigned long IC_RX_TL;
    unsigned long IC_TX_TL;
    unsigned long IC_CLR_INTR;
    unsigned long IC_CLR_RX_UNDER;
    unsigned long IC_CLR_RX_OVER;
    unsigned long IC_CLR_TX_OVER;
    unsigned long IC_CLR_RD_REQ;
    unsigned long IC_CLR_TX_ABRT;
    unsigned long IC_CLR_RX_DONE;
    unsigned long IC_CLR_ACTIVITY;
    unsigned long IC_CLR_STOP_DET;
    unsigned long IC_CLR_START_DET;
    unsigned long IC_CLR_GEN_CALL;
    unsigned long IC_ENABLE;
    unsigned long IC_STATUS;
    unsigned long IC_TXFLR;
    unsigned long IC_RXFLR;
    unsigned long IC_SDA_HOLD;
    unsigned long IC_TX_ABRT_SOURCE;
    unsigned long IC_SLV_DATA_NACK_ONLY;
    unsigned long IC_DMA_CR;
    unsigned long IC_DMA_TDLR;
    unsigned long IC_DMA_RDLR;
    unsigned long IC_SDA_SETUP;
    unsigned long IC_ACK_GENERAL_CALL;
    unsigned long IC_ENABLE_STATUS;
    unsigned long IC_COMP_PARAM_1;
    unsigned long IC_COMP_VERSION;
    unsigned long IC_COMP_TYPE;
    unsigned long IC_SDA_DEL;
};

typedef struct venus_i2c_gpio_map_t    venus_i2c_gpio_map;

struct venus_i2c_gpio_map_t
{
    unsigned char  valid;
    // gpio index
    VENUS_GPIO_ID  scl;
    VENUS_GPIO_ID  sda;

    // mux pad for I2C/GPIO
    unsigned long  muxpad;
    unsigned long  muxpad_mask;
    unsigned long  muxpad_gpio;
    unsigned long  muxpad_i2c;
};

typedef struct venus_i2c_phy_t          venus_i2c_phy;
typedef struct venus_input_mux_reg_t    venus_input_mux_reg;
typedef struct venus_pin_mux_reg_t      venus_pin_mux_reg;
typedef struct venus_i2c_port_t         venus_i2c_port;

struct venus_input_mux_reg_t
{
   unsigned long    addr;
   unsigned long    mask;
   unsigned long    val;
};

struct venus_pin_mux_reg_t
{
   unsigned long    addr;
   unsigned long    mask;
   unsigned long    i2c_val;
   unsigned long    gpio_val;
};

struct venus_i2c_port_t
{
    unsigned char       gpio_mapped;
    VENUS_GPIO_ID       g2c_scl;
    VENUS_GPIO_ID       g2c_sda;
    venus_input_mux_reg input_mux[2];
    venus_pin_mux_reg   pin_mux[2];
};

struct venus_i2c_phy_t
{
    const venus_i2c_reg_map*  p_reg_map;
    const unsigned char       n_port;
    const venus_i2c_port*     p_port;
};

typedef struct
{
    int (*handle_command)(int id, unsigned char* cmd, unsigned char len);
    unsigned char (*read_data)(int id);   // read data form i2c slave
}venus_i2c_slave_ops;

typedef struct venus_i2c_t    venus_i2c;

struct venus_i2c_t
{
    unsigned int        flags;
    atomic_t            ref_cnt;
    #define VENUS_I2C_IRQ_RDY  0x01
    #define VENUS_I2C_SLAVE_ENABLE  0x80
    char*               model_name;

    unsigned int        irq;
    unsigned char       id;
    unsigned int        spd;
    unsigned int        tick;
    unsigned int        guard_interval;
    unsigned short      sar;
    ADDR_MODE           sar_mode;

    unsigned short      tar;
    ADDR_MODE           tar_mode;

    venus_i2c_reg_map   reg_map;

    unsigned char       n_port;

    venus_i2c_port*     p_port;

    venus_i2c_port*     current_port;

    venus_i2c_gpio_map  gpio_map;

    unsigned char       rx_fifo_depth;
    unsigned char       tx_fifo_depth;

    unsigned long       time_stamp;

    venus_i2c_xfer      xfer;

    unsigned char       slave_rx_buffer[64];
    unsigned int        slave_rx_len;
    venus_i2c_slave_ops slave_ops;
    unsigned long       slave_id;

    wait_queue_head_t   wq;

    spinlock_t          lock;

    int (*init)         (venus_i2c* p_this);
    int (*uninit)       (venus_i2c* p_this);
    int (*set_spd)      (venus_i2c* p_this, int KHz);
    int (*set_guard_interval) (venus_i2c* p_this, unsigned long us);
    int (*set_tar)      (venus_i2c* p_this, unsigned short, ADDR_MODE mode);
    int (*set_port)     (venus_i2c* p_this, unsigned char port_id);
    int (*read)         (venus_i2c* p_this, unsigned char* tx_buf, unsigned short tx_buf_len, unsigned char *rx_buff, unsigned short rx_buf_len);
    int (*write)        (venus_i2c* p_this, unsigned char* tx_buf, unsigned short tx_buf_len, unsigned char wait_stop);
    int (*gpio_read)    (venus_i2c* p_this, unsigned char* tx_buf, unsigned short tx_buf_len, unsigned char *rx_buff, unsigned short rx_buf_len);
    int (*gpio_write)   (venus_i2c* p_this, unsigned char* tx_buf, unsigned short tx_buf_len, unsigned char wait_stop);
    int (*dump)         (venus_i2c* p_this);        // for debug
    int (*suspend)      (venus_i2c* p_this);
    int (*resume)       (venus_i2c* p_this);
    unsigned int (*get_tx_abort_reason) (venus_i2c* p_this);

    int (*set_sar)                  (venus_i2c* p_this, unsigned short, ADDR_MODE mode);
    int (*register_slave_ops)       (venus_i2c* p_this, venus_i2c_slave_ops* ops, unsigned long id);
    int (*slave_mode_enable)        (venus_i2c* p_this, unsigned char on);
#ifdef EDID_4BLOCK_SUPPORT
	int (*read_edid_seg)	(venus_i2c* p_this, unsigned char seg, unsigned char offset, unsigned char *rx_buff, unsigned short rx_buf_len);
#endif

};

/*
const venus_i2c_port saturn_i2c0_port[] = {
    {
        // PHY1 SRC-0
        .gpio_mapped   = 0,
        .g2c_scl       = venus_gpio_id(MIS_GPIO, 61),
        .g2c_sda       = venus_gpio_id(MIS_GPIO, 62),
        .input_mux[0]  = {0},
        .input_mux[1]  = {0},
        .pin_mux[0]    = {0xFE007310, 0xF<<24, 0x5<<24, 0},
        .pin_mux[1]    = {0},
    },
};

const venus_i2c_port saturn_i2c1_port[] = {
    {
        // PHY1 SRC-0
        .gpio_mapped   = 1,
        .g2c_scl       = 51,//venus_gpio_id(MIS_GPIO, 61),
        .g2c_sda       = 52,//venus_gpio_id(MIS_GPIO, 62),
        .input_mux[0]  = {0},
        .input_mux[1]  = {0},
#ifdef CONFIG_MACH_RTK1192
        .pin_mux[0]    = {0xFE01A90C, 0xF<<0, 0x5<<0, 0},
#else
        .pin_mux[0]    = {0xFE00036c, 0xF<<0, 0x5<<0, 0},
#endif
        .pin_mux[1]    = {0},
    },
};

const venus_i2c_port saturn_i2c2_port[] = {
    {
        // PHY2 SRC-0
        .gpio_mapped   = 0,
        .g2c_scl       = venus_gpio_id(MIS_GPIO, 63),
        .g2c_sda       = venus_gpio_id(MIS_GPIO, 64),
        .input_mux[0]  = {0},
        .input_mux[1]  = {0},
#ifdef CONFIG_MACH_RTK1192
        .pin_mux[0]    = {0xFE01A908, 0x33<<18, 0x33<<18, 0x22<<18},
#else
        .pin_mux[0]    = {0xFE000368, 0x33<<18, 0x33<<18, 0x22<<18},
#endif
        .pin_mux[1]    = {0},
    },
};

const venus_i2c_port saturn_i2c3_port[] = {
    {
        // PHY3 SRC-0
        .gpio_mapped   = 1, //0,
        .g2c_scl       = 42, //venus_gpio_id(MIS_GPIO, 63),
        .g2c_sda       = 40, //venus_gpio_id(MIS_GPIO, 64),
        .input_mux[0]  = {0},
        .input_mux[1]  = {0},
#ifdef CONFIG_MACH_RTK1192
        .pin_mux[0]    = {0xFE01A908, 0x33<<16, 0x33<<16, 0x22<<16},
#else
        .pin_mux[0]    = {0xFE000368, 0x33<<16, 0x33<<16, 0x22<<16},
#endif
        .pin_mux[1]    = {0},
    },
};
*/

venus_i2c*  create_venus_i2c_handle     (unsigned char      id,
                                         unsigned short     sar,
                                         ADDR_MODE          sar_mode,
                                         SPD_MODE           spd,
                                         unsigned int       irq);

venus_i2c*  create_venus_g2c_handle     (unsigned char      id,
                                         unsigned char      gpio_sda,
                                         unsigned char      gpio_scl);

void        destroy_venus_i2c_handle    (venus_i2c*         hHandle);

unsigned char get_venus_i2c_phy_count(void);
int venus_i2c_phy_init(venus_i2c* p_this);
irqreturn_t venus_i2c_isr(int this_irq, void* dev_id);
venus_i2c_port* venus_i2c_find_current_port(venus_i2c* p_this);

#endif  // __I2C_VENUS_PRIV_H__
