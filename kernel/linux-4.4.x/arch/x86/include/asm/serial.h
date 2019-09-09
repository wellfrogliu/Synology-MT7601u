#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifndef _ASM_X86_SERIAL_H
#define _ASM_X86_SERIAL_H

#define BASE_BAUD (1843200/16)

#ifdef CONFIG_SERIAL_8250_DETECT_IRQ
# define STD_COMX_FLAGS	(UPF_BOOT_AUTOCONF |	UPF_SKIP_TEST	| UPF_AUTO_IRQ)
# define STD_COM4_FLAGS	(UPF_BOOT_AUTOCONF |	0		| UPF_AUTO_IRQ)
#else
# define STD_COMX_FLAGS	(UPF_BOOT_AUTOCONF |	UPF_SKIP_TEST	| 0		)
# define STD_COM4_FLAGS	(UPF_BOOT_AUTOCONF |	0		| 0		)
#endif
#ifdef MY_ABC_HERE
	  \
#define SERIAL_PORT_DFNS								\
	 	\
	{ .uart = 0,	BASE_BAUD,	0xFFF,	4,	STD_COMX_FLAGS	},  	\
	{ .uart = 0,	BASE_BAUD,	0x2F8,	3,	STD_COMX_FLAGS	},  	\
	{ .uart = 0,	BASE_BAUD,	0x3E8,	4,	STD_COMX_FLAGS	},  	\
	{ .uart = 0,	BASE_BAUD,	0x2E8,	3,	STD_COM4_FLAGS	},  

#else  

#ifdef MY_DEF_HERE
#define SERIAL_PORT_DFNS								\
	 	\
	{ .uart = 0,	BASE_BAUD,	0x2F8,	3,	STD_COMX_FLAGS	},  	\
	{ .uart = 0,	BASE_BAUD,	0x3F8,	4,	STD_COMX_FLAGS	},  	\
	{ .uart = 0,	BASE_BAUD,	0x3E8,	4,	STD_COMX_FLAGS	},  	\
	{ .uart = 0,	BASE_BAUD,	0x2E8,	3,	STD_COM4_FLAGS	},  
#else  
#define SERIAL_PORT_DFNS								\
	 	\
	{ .uart = 0,	BASE_BAUD,	0x3F8,	4,	STD_COMX_FLAGS	},  	\
	{ .uart = 0,	BASE_BAUD,	0x2F8,	3,	STD_COMX_FLAGS	},  	\
	{ .uart = 0,	BASE_BAUD,	0x3E8,	4,	STD_COMX_FLAGS	},  	\
	{ .uart = 0,	BASE_BAUD,	0x2E8,	3,	STD_COM4_FLAGS	},  
#endif  

#endif  

#endif  
