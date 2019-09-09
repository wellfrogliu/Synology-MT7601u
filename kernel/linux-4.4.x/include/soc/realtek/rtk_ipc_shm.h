extern volatile void __iomem *rpc_common_base;
#define IPC_SHM_VIRT			(rpc_common_base+0x000000C4)

struct RTK119X_ipc_shm {
/*0C4*/	volatile uint32_t		sys_assign_serial;
/*0C8*/	volatile uint32_t		pov_boot_vd_std_ptr;
/*0CC*/	volatile uint32_t		pov_boot_av_info;
/*0D0*/	volatile uint32_t		audio_rpc_flag;
/*0D4*/	volatile uint32_t		suspend_mask;
/*0D8*/	volatile uint32_t		suspend_flag;
/*0DC*/ volatile uint32_t		vo_vsync_flag;
/*0E0*/	volatile uint32_t		audio_fw_entry_pt;
/*0E4*/	volatile uint32_t		power_saving_ptr;
/*0E8*/	volatile unsigned char	printk_buffer[24];
/*100*/	volatile uint32_t		ir_extended_tbl_pt;
/*104*/	volatile uint32_t		vo_int_sync;
/*108*/	volatile uint32_t		bt_wakeup_flag;//Bit31~24:magic key(0xEA), Bit23:high-active(1) low-active(0), Bit22~0:mask
/*10C*/	volatile uint32_t		ir_scancode_mask;
/*110*/	volatile uint32_t		ir_wakeup_scancode;
/*114*/	volatile uint32_t	    suspend_wakeup_flag;                /* [31-24] magic key(0xEA) [5] cec [4] timer [3] alarm [2] gpio [1] ir [0] lan , (0) disable (1) enable */
/*118*/	volatile uint32_t	    acpu_resume_state;                  /* [31-24] magic key(0xEA) [23-16] enum { NONE = 0, UNKNOW, IR, GPIO, LAN, ALARM, TIMER, CEC}  [15-0] ex GPIO Number */
/*11C*/	volatile uint32_t        gpio_wakeup_enable;                 /* [31-24] magic key(0xEA) [23-0] mapping to the number of iso gpio 0~23 */
/*120*/	volatile uint32_t        gpio_wakeup_activity;               /* [31-24] magic key(0xEA) [23-0] mapping to the number of iso gpio 0~23 , (0) low activity (1) high activity */
/*124*/	volatile uint32_t        gpio_output_change_enable;          /* [31-24] magic key(0xEA) [23-0] mapping to the number of iso gpio 0~23 */
/*128*/	volatile uint32_t        gpio_output_change_activity;        /* [31-24] magic key(0xEA) [23-0] mapping to the number of iso gpio 0~23 , (0) low activity (1) high activity AT SUSPEND TIME */
/*12C*/ volatile uint32_t        audio_reciprocal_timer_sec;         /* [31-24] magic key(0xEA) [23-0] audio reciprocal timer (sec) */
/*130*/ volatile uint32_t        u_boot_version_magic;
/*134*/ volatile uint32_t        u_boot_version_info;
/*138*/ volatile uint32_t        suspend_watchdog;                   /* [31-24] magic key(0xEA) [23] state (0) disable (1) enable [22] acpu response state [15-0] watch timeout (sec) */
/*13C*/ volatile uint32_t       xen_domu_boot_st;                    /* [31-24] magic key(0xEA) [23-20] version [19-16] Author (1) ACPU (2) SCPU [15-8] STATE [7-0] EXT */
/*140*/	volatile uint32_t		gpio_wakeup_enable2;				/* [31-24] magic key(0xEA) [10-0] mapping to the number of iso gpio 24~34 */
/*144*/	volatile uint32_t		gpio_wakeup_activity2;				/* [31-24] magic key(0xEA) [10-0] mapping to the number of iso gpio 24~34 , (0) low activity (1) high activity */
/*148*/	volatile uint32_t		gpio_output_change_enable2;			/* [31-24] magic key(0xEA) [10-0] mapping to the number of iso gpio 24~34 */
/*14C*/	volatile uint32_t		gpio_output_change_activity2;		/* [31-24] magic key(0xEA) [10-0] mapping to the number of iso gpio 24~34 , (0) low activity (1) high activity AT SUSPEND TIME */
};
