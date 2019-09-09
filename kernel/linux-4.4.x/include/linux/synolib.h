#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef __SYNOLIB_H_
#define __SYNOLIB_H_

#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/fs.h>

#ifdef  MY_ABC_HERE
extern int gSynoDebugFlag;
extern int gSynoAtaDebug;
extern int gSynoHibernationLogLevel;
extern struct mm_struct *syno_get_task_mm(struct task_struct *task);
void syno_do_hibernation_fd_log(const int fd);
void syno_do_hibernation_filename_log(const char __user *filename);
void syno_do_hibernation_inode_log(struct inode *inode);
void syno_do_hibernation_bio_log(const char *DeviceName);
void syno_do_hibernation_scsi_log(const char *DeviceName);
#endif  

#ifdef MY_ABC_HERE
int SynoSCSIGetDeviceIndex(struct block_device *bdev);
#endif

#ifdef MY_ABC_HERE
 
int syno_plugin_register(int plugin_magic, void *instance);
int syno_plugin_unregister(int plugin_magic);
 
int syno_plugin_handle_get(int plugin_magic, void **hnd);
void * syno_plugin_handle_instance(void *hnd);
void syno_plugin_handle_put(void *hnd);

#define EPIO_PLUGIN_MAGIC_NUMBER    0x20120815
#define RODSP_PLUGIN_MAGIC_NUMBER    0x20141111
#endif

#ifdef MY_ABC_HERE
 
#define SYNO_MAC_MAX_NUMBER 8
#endif  

#ifdef MY_ABC_HERE
#define SATA_REMAP_MAX  32
#define SATA_REMAP_NOT_INIT 0xff
extern int g_syno_sata_remap[SATA_REMAP_MAX];
extern int g_use_sata_remap;
int syno_get_remap_idx(int origin_idx);
extern int g_syno_mv14xx_remap[SATA_REMAP_MAX];
extern int g_use_mv14xx_remap;
int syno_get_mv_14xx_remap_idx(int origin_idx);
#endif  

#ifdef MY_ABC_HERE
#define PCI_ADDR_LEN_MAX 9
#define PCI_ADDR_NUM_MAX CONFIG_SYNO_MAX_PCI_SLOT
extern char gszPciAddrList[PCI_ADDR_NUM_MAX][PCI_ADDR_LEN_MAX];
extern int gPciAddrNum;
extern int syno_check_on_option_pci_slot(struct pci_dev *pdev);
#endif  

#ifdef MY_DEF_HERE
 
#define M2SATA_START_IDX 300
extern int g_nvc_map_index;
extern int g_syno_nvc_index_map[SATA_REMAP_MAX];
void syno_insert_sata_index_remap(unsigned int idx, unsigned int num, unsigned int id_start);
#endif  

#endif  
