#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifndef __SOUND_CORE_H
#define __SOUND_CORE_H

#include <linux/device.h>
#include <linux/sched.h>		 
#include <linux/mutex.h>		 
#include <linux/rwsem.h>		 
#include <linux/pm.h>			 
#include <linux/stringify.h>
#include <linux/printk.h>

#ifdef CONFIG_SND_DYNAMIC_MINORS
#define SNDRV_CARDS CONFIG_SND_MAX_CARDS
#else
#define SNDRV_CARDS 8		 
#endif

#define CONFIG_SND_MAJOR	116	 

struct pci_dev;
struct module;
struct completion;

enum snd_device_type {
	SNDRV_DEV_LOWLEVEL,
	SNDRV_DEV_CONTROL,
	SNDRV_DEV_INFO,
	SNDRV_DEV_BUS,
	SNDRV_DEV_CODEC,
	SNDRV_DEV_PCM,
	SNDRV_DEV_COMPRESS,
	SNDRV_DEV_RAWMIDI,
	SNDRV_DEV_TIMER,
	SNDRV_DEV_SEQUENCER,
	SNDRV_DEV_HWDEP,
	SNDRV_DEV_JACK,
};

enum snd_device_state {
	SNDRV_DEV_BUILD,
	SNDRV_DEV_REGISTERED,
	SNDRV_DEV_DISCONNECTED,
};

struct snd_device;

struct snd_device_ops {
	int (*dev_free)(struct snd_device *dev);
	int (*dev_register)(struct snd_device *dev);
	int (*dev_disconnect)(struct snd_device *dev);
};

struct snd_device {
	struct list_head list;		 
	struct snd_card *card;		 
	enum snd_device_state state;	 
	enum snd_device_type type;	 
	void *device_data;		 
	struct snd_device_ops *ops;	 
};

#define snd_device(n) list_entry(n, struct snd_device, list)

struct snd_card {
	int number;			 

	char id[16];			 
	char driver[16];		 
	char shortname[32];		 
	char longname[80];		 
	char mixername[80];		 
	char components[128];		 
	struct module *module;		 

	void *private_data;		 
	void (*private_free) (struct snd_card *card);  
	struct list_head devices;	 

	struct device ctl_dev;		 
	unsigned int last_numid;	 
	struct rw_semaphore controls_rwsem;	 
	rwlock_t ctl_files_rwlock;	 
	int controls_count;		 
	int user_ctl_count;		 
	struct list_head controls;	 
	struct list_head ctl_files;	 
	struct mutex user_ctl_lock;	 

	struct snd_info_entry *proc_root;	 
	struct snd_info_entry *proc_id;	 
	struct proc_dir_entry *proc_root_link;	 

	struct list_head files_list;	 
	struct snd_shutdown_f_ops *s_f_ops;  
	spinlock_t files_lock;		 
	int shutdown;			 
	struct completion *release_completion;
	struct device *dev;		 
	struct device card_dev;		 
	const struct attribute_group *dev_groups[4];  
	bool registered;		 

#ifdef CONFIG_PM
	unsigned int power_state;	 
	struct mutex power_lock;	 
	wait_queue_head_t power_sleep;
#endif

#if defined(CONFIG_SND_MIXER_OSS) || defined(CONFIG_SND_MIXER_OSS_MODULE)
	struct snd_mixer_oss *mixer_oss;
	int mixer_oss_change_count;
#endif
#if defined(MY_ABC_HERE)
	unsigned int low_level_dev_id;
#endif  
};

#define dev_to_snd_card(p)	container_of(p, struct snd_card, card_dev)

#ifdef CONFIG_PM
static inline void snd_power_lock(struct snd_card *card)
{
	mutex_lock(&card->power_lock);
}

static inline void snd_power_unlock(struct snd_card *card)
{
	mutex_unlock(&card->power_lock);
}

static inline unsigned int snd_power_get_state(struct snd_card *card)
{
	return card->power_state;
}

static inline void snd_power_change_state(struct snd_card *card, unsigned int state)
{
	card->power_state = state;
	wake_up(&card->power_sleep);
}

int snd_power_wait(struct snd_card *card, unsigned int power_state);

#else  

#define snd_power_lock(card)		do { (void)(card); } while (0)
#define snd_power_unlock(card)		do { (void)(card); } while (0)
static inline int snd_power_wait(struct snd_card *card, unsigned int state) { return 0; }
#define snd_power_get_state(card)	({ (void)(card); SNDRV_CTL_POWER_D0; })
#define snd_power_change_state(card, state)	do { (void)(card); } while (0)

#endif  

struct snd_minor {
	int type;			 
	int card;			 
	int device;			 
	const struct file_operations *f_ops;	 
	void *private_data;		 
	struct device *dev;		 
	struct snd_card *card_ptr;	 
};

static inline struct device *snd_card_get_device_link(struct snd_card *card)
{
	return card ? &card->card_dev : NULL;
}

extern int snd_major;
extern int snd_ecards_limit;
extern struct class *sound_class;

void snd_request_card(int card);

void snd_device_initialize(struct device *dev, struct snd_card *card);

int snd_register_device(int type, struct snd_card *card, int dev,
			const struct file_operations *f_ops,
			void *private_data, struct device *device);
int snd_unregister_device(struct device *dev);
void *snd_lookup_minor_data(unsigned int minor, int type);

#ifdef CONFIG_SND_OSSEMUL
int snd_register_oss_device(int type, struct snd_card *card, int dev,
			    const struct file_operations *f_ops, void *private_data);
int snd_unregister_oss_device(int type, struct snd_card *card, int dev);
void *snd_lookup_oss_minor_data(unsigned int minor, int type);
#endif

int snd_minor_info_init(void);

#ifdef CONFIG_SND_OSSEMUL
int snd_minor_info_oss_init(void);
#else
static inline int snd_minor_info_oss_init(void) { return 0; }
#endif

int copy_to_user_fromio(void __user *dst, const volatile void __iomem *src, size_t count);
int copy_from_user_toio(volatile void __iomem *dst, const void __user *src, size_t count);

extern struct snd_card *snd_cards[SNDRV_CARDS];
int snd_card_locked(int card);
#if defined(CONFIG_SND_MIXER_OSS) || defined(CONFIG_SND_MIXER_OSS_MODULE)
#define SND_MIXER_OSS_NOTIFY_REGISTER	0
#define SND_MIXER_OSS_NOTIFY_DISCONNECT	1
#define SND_MIXER_OSS_NOTIFY_FREE	2
extern int (*snd_mixer_oss_notify_callback)(struct snd_card *card, int cmd);
#endif

int snd_card_new(struct device *parent, int idx, const char *xid,
		 struct module *module, int extra_size,
		 struct snd_card **card_ret);

int snd_card_disconnect(struct snd_card *card);
int snd_card_free(struct snd_card *card);
int snd_card_free_when_closed(struct snd_card *card);
void snd_card_set_id(struct snd_card *card, const char *id);
int snd_card_register(struct snd_card *card);
int snd_card_info_init(void);
int snd_card_add_dev_attr(struct snd_card *card,
			  const struct attribute_group *group);
int snd_component_add(struct snd_card *card, const char *component);
int snd_card_file_add(struct snd_card *card, struct file *file);
int snd_card_file_remove(struct snd_card *card, struct file *file);
#define snd_card_unref(card)	put_device(&(card)->card_dev)

#define snd_card_set_dev(card, devptr) ((card)->dev = (devptr))

int snd_device_new(struct snd_card *card, enum snd_device_type type,
		   void *device_data, struct snd_device_ops *ops);
int snd_device_register(struct snd_card *card, void *device_data);
int snd_device_register_all(struct snd_card *card);
void snd_device_disconnect(struct snd_card *card, void *device_data);
void snd_device_disconnect_all(struct snd_card *card);
void snd_device_free(struct snd_card *card, void *device_data);
void snd_device_free_all(struct snd_card *card);

#ifdef CONFIG_ISA_DMA_API
#define DMA_MODE_NO_ENABLE	0x0100

void snd_dma_program(unsigned long dma, unsigned long addr, unsigned int size, unsigned short mode);
void snd_dma_disable(unsigned long dma);
unsigned int snd_dma_pointer(unsigned long dma, unsigned int size);
#endif

struct resource;
void release_and_free_resource(struct resource *res);

enum {
	SND_PR_ALWAYS,
	SND_PR_DEBUG,
	SND_PR_VERBOSE,
};

#if defined(CONFIG_SND_DEBUG) || defined(CONFIG_SND_VERBOSE_PRINTK)
__printf(4, 5)
void __snd_printk(unsigned int level, const char *file, int line,
		  const char *format, ...);
#else
#define __snd_printk(level, file, line, format, args...) \
	printk(format, ##args)
#endif

#define snd_printk(fmt, args...) \
	__snd_printk(0, __FILE__, __LINE__, fmt, ##args)

#ifdef CONFIG_SND_DEBUG
 
#define snd_printd(fmt, args...) \
	__snd_printk(1, __FILE__, __LINE__, fmt, ##args)
#define _snd_printd(level, fmt, args...) \
	__snd_printk(level, __FILE__, __LINE__, fmt, ##args)

#define snd_BUG()		WARN(1, "BUG?\n")

#define snd_printd_ratelimit() printk_ratelimit()

#define snd_BUG_ON(cond)	WARN_ON((cond))

#else  

__printf(1, 2)
static inline void snd_printd(const char *format, ...) {}
__printf(2, 3)
static inline void _snd_printd(int level, const char *format, ...) {}

#define snd_BUG()			do { } while (0)

#define snd_BUG_ON(condition) ({ \
	int __ret_warn_on = !!(condition); \
	unlikely(__ret_warn_on); \
})

static inline bool snd_printd_ratelimit(void) { return false; }

#endif  

#ifdef CONFIG_SND_DEBUG_VERBOSE
 
#define snd_printdd(format, args...) \
	__snd_printk(2, __FILE__, __LINE__, format, ##args)
#else
__printf(1, 2)
static inline void snd_printdd(const char *format, ...) {}
#endif

#define SNDRV_OSS_VERSION         ((3<<16)|(8<<8)|(1<<4)|(0))	 

#if defined(CONFIG_GAMEPORT) || defined(CONFIG_GAMEPORT_MODULE)
#define gameport_set_dev_parent(gp,xdev) ((gp)->dev.parent = (xdev))
#define gameport_set_port_data(gp,r) ((gp)->port_data = (r))
#define gameport_get_port_data(gp) (gp)->port_data
#endif

struct snd_pci_quirk {
	unsigned short subvendor;	 
	unsigned short subdevice;	 
	unsigned short subdevice_mask;	 
	int value;			 
#ifdef CONFIG_SND_DEBUG_VERBOSE
	const char *name;		 
#endif
};

#define _SND_PCI_QUIRK_ID_MASK(vend, mask, dev)	\
	.subvendor = (vend), .subdevice = (dev), .subdevice_mask = (mask)
#define _SND_PCI_QUIRK_ID(vend, dev) \
	_SND_PCI_QUIRK_ID_MASK(vend, 0xffff, dev)
#define SND_PCI_QUIRK_ID(vend,dev) {_SND_PCI_QUIRK_ID(vend, dev)}
#ifdef CONFIG_SND_DEBUG_VERBOSE
#define SND_PCI_QUIRK(vend,dev,xname,val) \
	{_SND_PCI_QUIRK_ID(vend, dev), .value = (val), .name = (xname)}
#define SND_PCI_QUIRK_VENDOR(vend, xname, val)			\
	{_SND_PCI_QUIRK_ID_MASK(vend, 0, 0), .value = (val), .name = (xname)}
#define SND_PCI_QUIRK_MASK(vend, mask, dev, xname, val)			\
	{_SND_PCI_QUIRK_ID_MASK(vend, mask, dev),			\
			.value = (val), .name = (xname)}
#define snd_pci_quirk_name(q)	((q)->name)
#else
#define SND_PCI_QUIRK(vend,dev,xname,val) \
	{_SND_PCI_QUIRK_ID(vend, dev), .value = (val)}
#define SND_PCI_QUIRK_MASK(vend, mask, dev, xname, val)			\
	{_SND_PCI_QUIRK_ID_MASK(vend, mask, dev), .value = (val)}
#define SND_PCI_QUIRK_VENDOR(vend, xname, val)			\
	{_SND_PCI_QUIRK_ID_MASK(vend, 0, 0), .value = (val)}
#define snd_pci_quirk_name(q)	""
#endif

#ifdef CONFIG_PCI
const struct snd_pci_quirk *
snd_pci_quirk_lookup(struct pci_dev *pci, const struct snd_pci_quirk *list);

const struct snd_pci_quirk *
snd_pci_quirk_lookup_id(u16 vendor, u16 device,
			const struct snd_pci_quirk *list);
#else
static inline const struct snd_pci_quirk *
snd_pci_quirk_lookup(struct pci_dev *pci, const struct snd_pci_quirk *list)
{
	return NULL;
}

static inline const struct snd_pci_quirk *
snd_pci_quirk_lookup_id(u16 vendor, u16 device,
			const struct snd_pci_quirk *list)
{
	return NULL;
}
#endif

#endif  
