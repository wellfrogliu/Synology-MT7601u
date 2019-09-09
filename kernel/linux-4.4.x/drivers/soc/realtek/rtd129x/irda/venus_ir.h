#ifndef __VENUS_IR_RTK__H__
#define __VENUS_IR_RTK__H__

#define IRCR_RESET							1<<31

#define SATURN_ISO_ISR_OFF					(0x00)
#define SATURN_ISO_IR_RSTN					(0x88)
#define SATURN_ISO_IR_CLKEN					(0x8C)

#define SATURN_ISO_IR_PSR_OFF				(0x00)
#define SATURN_ISO_IR_PER_OFF				(0x04)
#define SATURN_ISO_IR_SF_OFF				(0x08)
#define SATURN_ISO_IR_DPIR_OFF				(0x0c)
#define SATURN_ISO_IR_CR_OFF				(0x10)
#define SATURN_ISO_IR_RP_OFF				(0x14)
#define SATURN_ISO_IR_SR_OFF				(0x18)
#define SATURN_ISO_IR_RAW_CTRL_OFF			(0x1c)
#define SATURN_ISO_IR_RAW_FF_OFF			(0x20)
#define SATURN_ISO_IR_RAW_SAMPLE_TIME_OFF	(0x24)
#define SATURN_ISO_IR_RAW_WL_OFF			(0x28)
#define SATURN_ISO_IR_RAW_DEB_OFF			(0x2c)
#define SATURN_ISO_IR_PSR_UP_OFF			(0x30)
#define SATURN_ISO_IR_PER_UP_OFF			(0x34)
#define SATURN_ISO_IR_CTRL_RC6_OFF			(0x38)
#define SATURN_ISO_IR_RP2_OFF				(0x3C)
#define SATURN_ISO_IRTX_CFG_OFF				(0x40)
#define SATURN_ISO_IRTX_TIM_OFF				(0x44)
#define SATURN_ISO_IRTX_PWM_SETTING_OFF		(0x48)
#define SATURN_ISO_IRTX_INT_EN_OFF			(0x4c)
#define SATURN_ISO_IRTX_INT_ST_OFF			(0x50)
#define SATURN_ISO_IRTX_FIFO_ST_OFF			(0x54)
#define SATURN_ISO_IRTX_FIFO_OFF			(0x58)
#define SATURN_ISO_IRRCMM_TIMING_OFF		(0x60)
#define SATURN_ISO_IR_CR1_OFF				(0x64)
#define SATURN_ISO_IRRCMM_APKB_OFF			(0x68)
#define SATURN_ISO_IRRXRCLFIFO_OFF			(0x6C)

#define RTK_MK5_CUSTOMER_CODE		0x7F80

#define VENUS_IR_IOC_MAGIC			'r'
#define VENUS_IR_IOC_SET_IRIOTCDP		_IOW(VENUS_IR_IOC_MAGIC, 1, int)
#define VENUS_IR_IOC_FLUSH_IRRP			_IOW(VENUS_IR_IOC_MAGIC, 2, int)
#define VENUS_IR_IOC_SET_PROTOCOL		_IOW(VENUS_IR_IOC_MAGIC, 3, int)
#define VENUS_IR_IOC_SET_DEBOUNCE		_IOW(VENUS_IR_IOC_MAGIC, 4, int)
#define VENUS_IR_IOC_SET_IRPSR			_IOW(VENUS_IR_IOC_MAGIC, 5, int)
#define VENUS_IR_IOC_SET_IRPER			_IOW(VENUS_IR_IOC_MAGIC, 6, int)
#define VENUS_IR_IOC_SET_IRSF			_IOW(VENUS_IR_IOC_MAGIC, 7, int)
#define VENUS_IR_IOC_SET_IRCR			_IOW(VENUS_IR_IOC_MAGIC, 8, int)
#define VENUS_IR_IOC_SET_DRIVER_MODE	_IOW(VENUS_IR_IOC_MAGIC, 9, int)
#define VENUS_IR_IOC_SET_FIRST_REPEAT_DELAY		_IOW(VENUS_IR_IOC_MAGIC, 10, int)
//#define VENUS_IR_IOC_MAXNR			10

#define VENUS_IRTX_IOC_SET_TX_TABLE		_IOW(VENUS_IR_IOC_MAGIC, 11, int)
//#define VENUS_IRTX_IOC_MAXNR			1

#define LIBRA_MS_CUSTOMER_CODE			0x08F7
#define JAECS_T118_CUSTOMER_CODE		0xFC03
#define RTK_MK3_CUSTOMER_CODE			0xB649
#define YK_70LB_CUSTOMER_CODE			0x0E
#define RTK_MK4_CUSTOMER_CODE			0x6B86
#define RTK_MK5_CUSTOMER_CODE			0x7F80
#define NETG_MS_CUSTOMER_CODE			0x18
#define YK_54LU_CUSTOMER_CODE			0xf1f1
#define RTK_MK5_2_CUSTOMER_CODE			0xfb04
#define RTK_RC6_MODE_6_CUSTOMER_CODE	0x800F

#define IR_STR_IRRX_PROTOCOL		"irrx-protocol"
#define IR_STR_CUST_CODE			"cust-code"
#define IR_STR_SCANCODE_MSK			"scancode-msk"
#define IR_STR_CUSTCODE_MSK			"custcode-msk"
#define IR_STR_KEYMAP_SIZE			"keymap-size"
#define IR_STR_KEYMAP_TBL			"keymap-tbl"
#define IR_STR_RET_IR_DPIR			"reg-ir-dpir"

enum {
	NEC = 1,
	RC5 = 2,
	SHARP = 3,
	SONY = 4,
	C03 = 5,
	RC6 = 6,
	RAW_NEC = 7,
	RCA = 8,
	PANASONIC = 9,
	KONKA=10, //wangzhh add ,this value must same with the AP layer 20120927
	RAW_RC6 = 11,
	RC6_MODE_6 = 12, //add for RC6 mode 6
	TOSHIBA = 13, // add for Toshiba, is similar to NEC
	RAW_DIRECTTV = 14,
	RAW_COMCAST = 15,
};

enum {
	NEC_TX = 1,
	RC5_TX = 2,
	SHARP_TX = 3,
	SONY_TX = 4,
	C03_TX = 5,
	RC6_TX = 6,
	RCA_TX = 7,
	PANASONIC_TX = 8,
	KONKA_TX=9, //wangzhh add ,this value must same with the AP layer 20120927
};

enum {
	SINGLE_WORD_IF = 0,	// send IRRP only
	DOUBLE_WORD_IF = 1,	// send IRRP with IRSR together
};

struct venus_key {
	unsigned int scancode;
	unsigned int keycode;
};

struct venus_hw_param {
	union {
		unsigned int ir_psr;
		unsigned int ir_raw_deb;
	};
	union {
		unsigned int ir_per;
		unsigned int ir_raw_ctl;
	};
	unsigned int ir_sf;
};

struct venus_key_table {
	struct venus_key *keys;
	int size;
	unsigned int cust_code;
	unsigned int scancode_msk;
	unsigned int custcode_msk;
};

struct RTK119X_ir_wake_up_key {
	unsigned int protocol;
	unsigned int ir_scancode_mask;
	unsigned int ir_wakeup_scancode;
	unsigned int ir_cus_mask;
	unsigned int ir_cus_code;
};

struct RTK119X_ipc_shm_ir {
	unsigned int RTK119X_ipc_shm_ir_magic;
	unsigned int dev_count;
	struct RTK119X_ir_wake_up_key key_tbl[5];
};

struct Venus_IRTx_KeycodeTable {
	int irtx_protocol;
	unsigned int irtx_keycode_list_len;
	unsigned int irtx_keycode_list[2048];
};

#endif /* __VENUS_IR_RTK__H__ */
