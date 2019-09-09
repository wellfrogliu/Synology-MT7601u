#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef __SYNO_H_
#define __SYNO_H_

#ifdef	MY_ABC_HERE
#define IS_SYNO_USBBOOT_ID_VENDOR(VENDOR) (0xF400 == (VENDOR))
#define IS_SYNO_USBBOOT_ID_PRODUCT(PRODUCT) (0xF400 == (PRODUCT))
#endif  

#ifdef MY_ABC_HERE
#define SYNO_YOTAWIMAX_DESC          "SYNO CDC Ethernet Device for YotaKey"
#define SYNO_YOTAWIMAX_ETHERNET_NAME "wm"
#define SYNO_YOTAWIMAX_NET_NOLINK_EVENT (0xffffffff)
#endif

#ifdef CONFIG_SYNO_MPC85XX_COMMON
#define SYNO_NET_PHY_NOLINK_SPEED_INIT
#endif

#ifdef CONFIG_MACH_SYNOLOGY_6281
#define SYNO_6281_MTU_WA
#endif

#define SYNO_FIX_MD_RESIZE_BUSY_LOOP 5

#ifdef MY_ABC_HERE
#define SYNO_SMB_PSTRING_LEN 1024
#endif

#if defined(CONFIG_MV_XOR_MEMCOPY) && (defined(MY_DEF_HERE) || defined(MY_ABC_HERE))
#define SYNO_MV_PERF
#endif  

#ifdef CONFIG_SYNO_MV88F6281_USBSTATION
#define SYNO_SLOW_DOWN_UEVENT
#endif

#ifdef MY_ABC_HERE
#define MAX_CHANNEL_RETRY       2
#define CHANNEL_RETRY_INTERVAL  (3*HZ)

#endif

#include <uapi/linux/syno.h>

#ifdef MY_ABC_HERE
 
#define SYNO_ISCSI_DEVICE_INDEX    (26 + 25 * 26)     

#ifdef MY_DEF_HERE
 
#define SYNO_INTERNAL_MICROSD_NAME "4-4"
#endif  
#endif  

#endif  
