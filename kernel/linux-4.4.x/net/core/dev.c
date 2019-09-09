#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <asm/uaccess.h>
#include <linux/bitops.h>
#include <linux/capability.h>
#include <linux/cpu.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/hash.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/notifier.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <linux/rtnetlink.h>
#include <linux/stat.h>
#include <net/dst.h>
#include <net/dst_metadata.h>
#include <net/pkt_sched.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netpoll.h>
#include <linux/rcupdate.h>
#include <linux/delay.h>
#include <net/iw_handler.h>
#include <asm/current.h>
#include <linux/audit.h>
#include <linux/dmaengine.h>
#include <linux/err.h>
#include <linux/ctype.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/mpls.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <trace/events/napi.h>
#include <trace/events/net.h>
#include <trace/events/skb.h>
#include <linux/pci.h>
#include <linux/inetdevice.h>
#include <linux/cpu_rmap.h>
#include <linux/static_key.h>
#include <linux/hashtable.h>
#include <linux/vmalloc.h>
#include <linux/if_macvlan.h>
#include <linux/errqueue.h>
#include <linux/hrtimer.h>
#include <linux/netfilter_ingress.h>
#if defined(MY_ABC_HERE)
#include <linux/synolib.h>
#endif  

#include "net-sysfs.h"

#define MAX_GRO_SKBS 8

#define GRO_MAX_HEAD (MAX_HEADER + 128)

static DEFINE_SPINLOCK(ptype_lock);
static DEFINE_SPINLOCK(offload_lock);
struct list_head ptype_base[PTYPE_HASH_SIZE] __read_mostly;
struct list_head ptype_all __read_mostly;	 
static struct list_head offload_base __read_mostly;

static int netif_rx_internal(struct sk_buff *skb);
static int call_netdevice_notifiers_info(unsigned long val,
					 struct net_device *dev,
					 struct netdev_notifier_info *info);

#if defined(MY_DEF_HERE)
void (*funcSynoNicLedCtrl)(int iEnable) = NULL;
EXPORT_SYMBOL(funcSynoNicLedCtrl);
#endif  

#ifdef MY_ABC_HERE
static unsigned int str_to_hex(char ch)
{
	if ((ch >= '0') && (ch <= '9'))
		return (ch - '0');

	if ((ch >= 'a') && (ch <= 'f'))
		return (ch - 'a' + 10);

	if ((ch >= 'A') && (ch <= 'F'))
		return (ch - 'A' + 10);

	return 0;
}

void convert_str_to_mac(char *source , char *dest)
{
	dest[0] = (str_to_hex(source[0]) << 4) + str_to_hex(source[1]);
	dest[1] = (str_to_hex(source[2]) << 4) + str_to_hex(source[3]);
	dest[2] = (str_to_hex(source[4]) << 4) + str_to_hex(source[5]);
	dest[3] = (str_to_hex(source[6]) << 4) + str_to_hex(source[7]);
	dest[4] = (str_to_hex(source[8]) << 4) + str_to_hex(source[9]);
	dest[5] = (str_to_hex(source[10]) << 4) + str_to_hex(source[11]);
}

static int syno_skip_bond_vender_mac(int iMacIndex)
{
	extern const char gszSkipVenderMacInterfaces[256];
	char szDupIfns[256] = {'\0'};
	char *token = NULL;
	char *ptr = NULL;
	long iSkipIndex = 0;
	int iMatch = 0;

	if (0 == strlen(gszSkipVenderMacInterfaces)) {
		goto END;
	}

	snprintf(szDupIfns, sizeof(szDupIfns), "%s", gszSkipVenderMacInterfaces);
	ptr = szDupIfns;
	 
	while (NULL != (token = strsep(&ptr, ","))) {
		if (0 != kstrtol(token, 10, &iSkipIndex)) {
			 
			iMatch = -1;
			goto END;
		}
		if ((long)iMacIndex == iSkipIndex) {
			iMatch = 1;
			goto END;
		}
		if (!ptr) {
			break;
		}
	}

END:
	return iMatch;
}

#define SYNO_VENDOR_MAC_SUCCESS     0
#define SYNO_VENDOR_MAC_EMPTY       1
#define SYNO_VENDOR_MAC_FAIL        2
int syno_get_dev_vendor_mac(const char *szDev, char *szMac)
{
	extern unsigned char grgbLanMac[SYNO_MAC_MAX_NUMBER][16];
#ifdef MY_ABC_HERE
	extern unsigned long g_internal_netif_num;
#endif  
	int err = SYNO_VENDOR_MAC_FAIL;
	char szIFPrefix[IFNAMSIZ] = "eth";
	int iMacIndex = 0;
	const char *pMacIndex = NULL;
	int iMatch = 0;

	if (!szMac || !szDev)
		goto ERR;

	if (!strncmp(szDev, szIFPrefix, strlen(szIFPrefix))) {
		pMacIndex = szDev + strlen(szIFPrefix);
		iMacIndex = simple_strtol(pMacIndex, NULL, 10);
#ifdef MY_ABC_HERE
		if (0 > iMacIndex || g_internal_netif_num <= iMacIndex) {
			err = SYNO_VENDOR_MAC_FAIL;
			goto ERR;
		}
#endif  
		if (1 == (iMatch = syno_skip_bond_vender_mac(iMacIndex))) {
			err = SYNO_VENDOR_MAC_EMPTY;
			goto ERR;
		} else if (-1 == iMatch) {
			printk(KERN_ERR "Error when match bond vender mac\n");
			err = SYNO_VENDOR_MAC_FAIL;
			goto ERR;
		}

		if (!strcmp(grgbLanMac[iMacIndex], "")) {
			err = SYNO_VENDOR_MAC_EMPTY;
			goto ERR;
		}
		convert_str_to_mac(grgbLanMac[iMacIndex], szMac);
	} else {
		goto ERR;
	}

	err = SYNO_VENDOR_MAC_SUCCESS;
ERR:
	return err;
}
EXPORT_SYMBOL(syno_get_dev_vendor_mac);
#endif  

DEFINE_RWLOCK(dev_base_lock);
EXPORT_SYMBOL(dev_base_lock);

static DEFINE_SPINLOCK(napi_hash_lock);

static unsigned int napi_gen_id;
static DEFINE_HASHTABLE(napi_hash, 8);

static seqcount_t devnet_rename_seq;

static inline void dev_base_seq_inc(struct net *net)
{
	while (++net->dev_base_seq == 0);
}

static inline struct hlist_head *dev_name_hash(struct net *net, const char *name)
{
	unsigned int hash = full_name_hash(name, strnlen(name, IFNAMSIZ));

	return &net->dev_name_head[hash_32(hash, NETDEV_HASHBITS)];
}

static inline struct hlist_head *dev_index_hash(struct net *net, int ifindex)
{
	return &net->dev_index_head[ifindex & (NETDEV_HASHENTRIES - 1)];
}

static inline void rps_lock(struct softnet_data *sd)
{
#ifdef CONFIG_RPS
	spin_lock(&sd->input_pkt_queue.lock);
#endif
}

static inline void rps_unlock(struct softnet_data *sd)
{
#ifdef CONFIG_RPS
	spin_unlock(&sd->input_pkt_queue.lock);
#endif
}

static void list_netdevice(struct net_device *dev)
{
	struct net *net = dev_net(dev);

	ASSERT_RTNL();

	write_lock_bh(&dev_base_lock);
	list_add_tail_rcu(&dev->dev_list, &net->dev_base_head);
	hlist_add_head_rcu(&dev->name_hlist, dev_name_hash(net, dev->name));
	hlist_add_head_rcu(&dev->index_hlist,
			   dev_index_hash(net, dev->ifindex));
	write_unlock_bh(&dev_base_lock);

	dev_base_seq_inc(net);
}

static void unlist_netdevice(struct net_device *dev)
{
	ASSERT_RTNL();

	write_lock_bh(&dev_base_lock);
	list_del_rcu(&dev->dev_list);
	hlist_del_rcu(&dev->name_hlist);
	hlist_del_rcu(&dev->index_hlist);
	write_unlock_bh(&dev_base_lock);

	dev_base_seq_inc(dev_net(dev));
}

static RAW_NOTIFIER_HEAD(netdev_chain);

DEFINE_PER_CPU_ALIGNED(struct softnet_data, softnet_data);
EXPORT_PER_CPU_SYMBOL(softnet_data);

#ifdef CONFIG_LOCKDEP
 
static const unsigned short netdev_lock_type[] =
	{ARPHRD_NETROM, ARPHRD_ETHER, ARPHRD_EETHER, ARPHRD_AX25,
	 ARPHRD_PRONET, ARPHRD_CHAOS, ARPHRD_IEEE802, ARPHRD_ARCNET,
	 ARPHRD_APPLETLK, ARPHRD_DLCI, ARPHRD_ATM, ARPHRD_METRICOM,
	 ARPHRD_IEEE1394, ARPHRD_EUI64, ARPHRD_INFINIBAND, ARPHRD_SLIP,
	 ARPHRD_CSLIP, ARPHRD_SLIP6, ARPHRD_CSLIP6, ARPHRD_RSRVD,
	 ARPHRD_ADAPT, ARPHRD_ROSE, ARPHRD_X25, ARPHRD_HWX25,
	 ARPHRD_PPP, ARPHRD_CISCO, ARPHRD_LAPB, ARPHRD_DDCMP,
	 ARPHRD_RAWHDLC, ARPHRD_TUNNEL, ARPHRD_TUNNEL6, ARPHRD_FRAD,
	 ARPHRD_SKIP, ARPHRD_LOOPBACK, ARPHRD_LOCALTLK, ARPHRD_FDDI,
	 ARPHRD_BIF, ARPHRD_SIT, ARPHRD_IPDDP, ARPHRD_IPGRE,
	 ARPHRD_PIMREG, ARPHRD_HIPPI, ARPHRD_ASH, ARPHRD_ECONET,
	 ARPHRD_IRDA, ARPHRD_FCPP, ARPHRD_FCAL, ARPHRD_FCPL,
	 ARPHRD_FCFABRIC, ARPHRD_IEEE80211, ARPHRD_IEEE80211_PRISM,
	 ARPHRD_IEEE80211_RADIOTAP, ARPHRD_PHONET, ARPHRD_PHONET_PIPE,
	 ARPHRD_IEEE802154, ARPHRD_VOID, ARPHRD_NONE};

static const char *const netdev_lock_name[] =
	{"_xmit_NETROM", "_xmit_ETHER", "_xmit_EETHER", "_xmit_AX25",
	 "_xmit_PRONET", "_xmit_CHAOS", "_xmit_IEEE802", "_xmit_ARCNET",
	 "_xmit_APPLETLK", "_xmit_DLCI", "_xmit_ATM", "_xmit_METRICOM",
	 "_xmit_IEEE1394", "_xmit_EUI64", "_xmit_INFINIBAND", "_xmit_SLIP",
	 "_xmit_CSLIP", "_xmit_SLIP6", "_xmit_CSLIP6", "_xmit_RSRVD",
	 "_xmit_ADAPT", "_xmit_ROSE", "_xmit_X25", "_xmit_HWX25",
	 "_xmit_PPP", "_xmit_CISCO", "_xmit_LAPB", "_xmit_DDCMP",
	 "_xmit_RAWHDLC", "_xmit_TUNNEL", "_xmit_TUNNEL6", "_xmit_FRAD",
	 "_xmit_SKIP", "_xmit_LOOPBACK", "_xmit_LOCALTLK", "_xmit_FDDI",
	 "_xmit_BIF", "_xmit_SIT", "_xmit_IPDDP", "_xmit_IPGRE",
	 "_xmit_PIMREG", "_xmit_HIPPI", "_xmit_ASH", "_xmit_ECONET",
	 "_xmit_IRDA", "_xmit_FCPP", "_xmit_FCAL", "_xmit_FCPL",
	 "_xmit_FCFABRIC", "_xmit_IEEE80211", "_xmit_IEEE80211_PRISM",
	 "_xmit_IEEE80211_RADIOTAP", "_xmit_PHONET", "_xmit_PHONET_PIPE",
	 "_xmit_IEEE802154", "_xmit_VOID", "_xmit_NONE"};

static struct lock_class_key netdev_xmit_lock_key[ARRAY_SIZE(netdev_lock_type)];
static struct lock_class_key netdev_addr_lock_key[ARRAY_SIZE(netdev_lock_type)];

static inline unsigned short netdev_lock_pos(unsigned short dev_type)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(netdev_lock_type); i++)
		if (netdev_lock_type[i] == dev_type)
			return i;
	 
	return ARRAY_SIZE(netdev_lock_type) - 1;
}

static inline void netdev_set_xmit_lockdep_class(spinlock_t *lock,
						 unsigned short dev_type)
{
	int i;

	i = netdev_lock_pos(dev_type);
	lockdep_set_class_and_name(lock, &netdev_xmit_lock_key[i],
				   netdev_lock_name[i]);
}

static inline void netdev_set_addr_lockdep_class(struct net_device *dev)
{
	int i;

	i = netdev_lock_pos(dev->type);
	lockdep_set_class_and_name(&dev->addr_list_lock,
				   &netdev_addr_lock_key[i],
				   netdev_lock_name[i]);
}
#else
static inline void netdev_set_xmit_lockdep_class(spinlock_t *lock,
						 unsigned short dev_type)
{
}
static inline void netdev_set_addr_lockdep_class(struct net_device *dev)
{
}
#endif

static inline struct list_head *ptype_head(const struct packet_type *pt)
{
	if (pt->type == htons(ETH_P_ALL))
		return pt->dev ? &pt->dev->ptype_all : &ptype_all;
	else
		return pt->dev ? &pt->dev->ptype_specific :
				 &ptype_base[ntohs(pt->type) & PTYPE_HASH_MASK];
}

void dev_add_pack(struct packet_type *pt)
{
	struct list_head *head = ptype_head(pt);

	spin_lock(&ptype_lock);
	list_add_rcu(&pt->list, head);
	spin_unlock(&ptype_lock);
}
EXPORT_SYMBOL(dev_add_pack);

void __dev_remove_pack(struct packet_type *pt)
{
	struct list_head *head = ptype_head(pt);
	struct packet_type *pt1;

	spin_lock(&ptype_lock);

	list_for_each_entry(pt1, head, list) {
		if (pt == pt1) {
			list_del_rcu(&pt->list);
			goto out;
		}
	}

	pr_warn("dev_remove_pack: %p not found\n", pt);
out:
	spin_unlock(&ptype_lock);
}
EXPORT_SYMBOL(__dev_remove_pack);

void dev_remove_pack(struct packet_type *pt)
{
	__dev_remove_pack(pt);

	synchronize_net();
}
EXPORT_SYMBOL(dev_remove_pack);

void dev_add_offload(struct packet_offload *po)
{
	struct packet_offload *elem;

	spin_lock(&offload_lock);
	list_for_each_entry(elem, &offload_base, list) {
		if (po->priority < elem->priority)
			break;
	}
	list_add_rcu(&po->list, elem->list.prev);
	spin_unlock(&offload_lock);
}
EXPORT_SYMBOL(dev_add_offload);

static void __dev_remove_offload(struct packet_offload *po)
{
	struct list_head *head = &offload_base;
	struct packet_offload *po1;

	spin_lock(&offload_lock);

	list_for_each_entry(po1, head, list) {
		if (po == po1) {
			list_del_rcu(&po->list);
			goto out;
		}
	}

	pr_warn("dev_remove_offload: %p not found\n", po);
out:
	spin_unlock(&offload_lock);
}

void dev_remove_offload(struct packet_offload *po)
{
	__dev_remove_offload(po);

	synchronize_net();
}
EXPORT_SYMBOL(dev_remove_offload);

static struct netdev_boot_setup dev_boot_setup[NETDEV_BOOT_SETUP_MAX];

static int netdev_boot_setup_add(char *name, struct ifmap *map)
{
	struct netdev_boot_setup *s;
	int i;

	s = dev_boot_setup;
	for (i = 0; i < NETDEV_BOOT_SETUP_MAX; i++) {
		if (s[i].name[0] == '\0' || s[i].name[0] == ' ') {
			memset(s[i].name, 0, sizeof(s[i].name));
			strlcpy(s[i].name, name, IFNAMSIZ);
			memcpy(&s[i].map, map, sizeof(s[i].map));
			break;
		}
	}

	return i >= NETDEV_BOOT_SETUP_MAX ? 0 : 1;
}

int netdev_boot_setup_check(struct net_device *dev)
{
	struct netdev_boot_setup *s = dev_boot_setup;
	int i;

	for (i = 0; i < NETDEV_BOOT_SETUP_MAX; i++) {
		if (s[i].name[0] != '\0' && s[i].name[0] != ' ' &&
		    !strcmp(dev->name, s[i].name)) {
			dev->irq 	= s[i].map.irq;
			dev->base_addr 	= s[i].map.base_addr;
			dev->mem_start 	= s[i].map.mem_start;
			dev->mem_end 	= s[i].map.mem_end;
			return 1;
		}
	}
	return 0;
}
EXPORT_SYMBOL(netdev_boot_setup_check);

unsigned long netdev_boot_base(const char *prefix, int unit)
{
	const struct netdev_boot_setup *s = dev_boot_setup;
	char name[IFNAMSIZ];
	int i;

	sprintf(name, "%s%d", prefix, unit);

	if (__dev_get_by_name(&init_net, name))
		return 1;

	for (i = 0; i < NETDEV_BOOT_SETUP_MAX; i++)
		if (!strcmp(name, s[i].name))
			return s[i].map.base_addr;
	return 0;
}

int __init netdev_boot_setup(char *str)
{
	int ints[5];
	struct ifmap map;

	str = get_options(str, ARRAY_SIZE(ints), ints);
	if (!str || !*str)
		return 0;

	memset(&map, 0, sizeof(map));
	if (ints[0] > 0)
		map.irq = ints[1];
	if (ints[0] > 1)
		map.base_addr = ints[2];
	if (ints[0] > 2)
		map.mem_start = ints[3];
	if (ints[0] > 3)
		map.mem_end = ints[4];

	return netdev_boot_setup_add(str, &map);
}

__setup("netdev=", netdev_boot_setup);

int dev_get_iflink(const struct net_device *dev)
{
	if (dev->netdev_ops && dev->netdev_ops->ndo_get_iflink)
		return dev->netdev_ops->ndo_get_iflink(dev);

	return dev->ifindex;
}
EXPORT_SYMBOL(dev_get_iflink);

int dev_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb)
{
	struct ip_tunnel_info *info;

	if (!dev->netdev_ops  || !dev->netdev_ops->ndo_fill_metadata_dst)
		return -EINVAL;

	info = skb_tunnel_info_unclone(skb);
	if (!info)
		return -ENOMEM;
	if (unlikely(!(info->mode & IP_TUNNEL_INFO_TX)))
		return -EINVAL;

	return dev->netdev_ops->ndo_fill_metadata_dst(dev, skb);
}
EXPORT_SYMBOL_GPL(dev_fill_metadata_dst);

struct net_device *__dev_get_by_name(struct net *net, const char *name)
{
	struct net_device *dev;
	struct hlist_head *head = dev_name_hash(net, name);

	hlist_for_each_entry(dev, head, name_hlist)
		if (!strncmp(dev->name, name, IFNAMSIZ))
			return dev;

	return NULL;
}
EXPORT_SYMBOL(__dev_get_by_name);

struct net_device *dev_get_by_name_rcu(struct net *net, const char *name)
{
	struct net_device *dev;
	struct hlist_head *head = dev_name_hash(net, name);

	hlist_for_each_entry_rcu(dev, head, name_hlist)
		if (!strncmp(dev->name, name, IFNAMSIZ))
			return dev;

	return NULL;
}
EXPORT_SYMBOL(dev_get_by_name_rcu);

struct net_device *dev_get_by_name(struct net *net, const char *name)
{
	struct net_device *dev;

	rcu_read_lock();
	dev = dev_get_by_name_rcu(net, name);
	if (dev)
		dev_hold(dev);
	rcu_read_unlock();
	return dev;
}
EXPORT_SYMBOL(dev_get_by_name);

struct net_device *__dev_get_by_index(struct net *net, int ifindex)
{
	struct net_device *dev;
	struct hlist_head *head = dev_index_hash(net, ifindex);

	hlist_for_each_entry(dev, head, index_hlist)
		if (dev->ifindex == ifindex)
			return dev;

	return NULL;
}
EXPORT_SYMBOL(__dev_get_by_index);

struct net_device *dev_get_by_index_rcu(struct net *net, int ifindex)
{
	struct net_device *dev;
	struct hlist_head *head = dev_index_hash(net, ifindex);

	hlist_for_each_entry_rcu(dev, head, index_hlist)
		if (dev->ifindex == ifindex)
			return dev;

	return NULL;
}
EXPORT_SYMBOL(dev_get_by_index_rcu);

struct net_device *dev_get_by_index(struct net *net, int ifindex)
{
	struct net_device *dev;

	rcu_read_lock();
	dev = dev_get_by_index_rcu(net, ifindex);
	if (dev)
		dev_hold(dev);
	rcu_read_unlock();
	return dev;
}
EXPORT_SYMBOL(dev_get_by_index);

int netdev_get_name(struct net *net, char *name, int ifindex)
{
	struct net_device *dev;
	unsigned int seq;

retry:
	seq = raw_seqcount_begin(&devnet_rename_seq);
	rcu_read_lock();
	dev = dev_get_by_index_rcu(net, ifindex);
	if (!dev) {
		rcu_read_unlock();
		return -ENODEV;
	}

	strcpy(name, dev->name);
	rcu_read_unlock();
	if (read_seqcount_retry(&devnet_rename_seq, seq)) {
		cond_resched();
		goto retry;
	}

	return 0;
}

struct net_device *dev_getbyhwaddr_rcu(struct net *net, unsigned short type,
				       const char *ha)
{
	struct net_device *dev;

	for_each_netdev_rcu(net, dev)
		if (dev->type == type &&
		    !memcmp(dev->dev_addr, ha, dev->addr_len))
			return dev;

	return NULL;
}
EXPORT_SYMBOL(dev_getbyhwaddr_rcu);

struct net_device *__dev_getfirstbyhwtype(struct net *net, unsigned short type)
{
	struct net_device *dev;

	ASSERT_RTNL();
	for_each_netdev(net, dev)
		if (dev->type == type)
			return dev;

	return NULL;
}
EXPORT_SYMBOL(__dev_getfirstbyhwtype);

struct net_device *dev_getfirstbyhwtype(struct net *net, unsigned short type)
{
	struct net_device *dev, *ret = NULL;

	rcu_read_lock();
	for_each_netdev_rcu(net, dev)
		if (dev->type == type) {
			dev_hold(dev);
			ret = dev;
			break;
		}
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(dev_getfirstbyhwtype);

struct net_device *__dev_get_by_flags(struct net *net, unsigned short if_flags,
				      unsigned short mask)
{
	struct net_device *dev, *ret;

	ASSERT_RTNL();

	ret = NULL;
	for_each_netdev(net, dev) {
		if (((dev->flags ^ if_flags) & mask) == 0) {
			ret = dev;
			break;
		}
	}
	return ret;
}
EXPORT_SYMBOL(__dev_get_by_flags);

bool dev_valid_name(const char *name)
{
	if (*name == '\0')
		return false;
	if (strlen(name) >= IFNAMSIZ)
		return false;
	if (!strcmp(name, ".") || !strcmp(name, ".."))
		return false;

	while (*name) {
		if (*name == '/' || *name == ':' || isspace(*name))
			return false;
		name++;
	}
	return true;
}
EXPORT_SYMBOL(dev_valid_name);

static int __dev_alloc_name(struct net *net, const char *name, char *buf)
{
	int i = 0;
	const char *p;
	const int max_netdevices = 8*PAGE_SIZE;
	unsigned long *inuse;
	struct net_device *d;

	p = strnchr(name, IFNAMSIZ-1, '%');
	if (p) {
		 
		if (p[1] != 'd' || strchr(p + 2, '%'))
			return -EINVAL;

		inuse = (unsigned long *) get_zeroed_page(GFP_ATOMIC);
		if (!inuse)
			return -ENOMEM;

		for_each_netdev(net, d) {
			if (!sscanf(d->name, name, &i))
				continue;
			if (i < 0 || i >= max_netdevices)
				continue;

			snprintf(buf, IFNAMSIZ, name, i);
			if (!strncmp(buf, d->name, IFNAMSIZ))
				set_bit(i, inuse);
		}

		i = find_first_zero_bit(inuse, max_netdevices);
		free_page((unsigned long) inuse);
	}

	if (buf != name)
		snprintf(buf, IFNAMSIZ, name, i);
	if (!__dev_get_by_name(net, buf))
		return i;

	return -ENFILE;
}

int dev_alloc_name(struct net_device *dev, const char *name)
{
	char buf[IFNAMSIZ];
	struct net *net;
	int ret;

	BUG_ON(!dev_net(dev));
	net = dev_net(dev);
	ret = __dev_alloc_name(net, name, buf);
	if (ret >= 0)
		strlcpy(dev->name, buf, IFNAMSIZ);
	return ret;
}
EXPORT_SYMBOL(dev_alloc_name);

static int dev_alloc_name_ns(struct net *net,
			     struct net_device *dev,
			     const char *name)
{
	char buf[IFNAMSIZ];
	int ret;

	ret = __dev_alloc_name(net, name, buf);
	if (ret >= 0)
		strlcpy(dev->name, buf, IFNAMSIZ);
	return ret;
}

static int dev_get_valid_name(struct net *net,
			      struct net_device *dev,
			      const char *name)
{
	BUG_ON(!net);

	if (!dev_valid_name(name))
		return -EINVAL;

	if (strchr(name, '%'))
		return dev_alloc_name_ns(net, dev, name);
	else if (__dev_get_by_name(net, name))
		return -EEXIST;
	else if (dev->name != name)
		strlcpy(dev->name, name, IFNAMSIZ);

	return 0;
}

int dev_change_name(struct net_device *dev, const char *newname)
{
	unsigned char old_assign_type;
	char oldname[IFNAMSIZ];
	int err = 0;
	int ret;
	struct net *net;

	ASSERT_RTNL();
	BUG_ON(!dev_net(dev));

	net = dev_net(dev);
	if (dev->flags & IFF_UP)
		return -EBUSY;

	write_seqcount_begin(&devnet_rename_seq);

	if (strncmp(newname, dev->name, IFNAMSIZ) == 0) {
		write_seqcount_end(&devnet_rename_seq);
		return 0;
	}

	memcpy(oldname, dev->name, IFNAMSIZ);

	err = dev_get_valid_name(net, dev, newname);
	if (err < 0) {
		write_seqcount_end(&devnet_rename_seq);
		return err;
	}

	if (oldname[0] && !strchr(oldname, '%'))
		netdev_info(dev, "renamed from %s\n", oldname);

	old_assign_type = dev->name_assign_type;
	dev->name_assign_type = NET_NAME_RENAMED;

rollback:
	ret = device_rename(&dev->dev, dev->name);
	if (ret) {
		memcpy(dev->name, oldname, IFNAMSIZ);
		dev->name_assign_type = old_assign_type;
		write_seqcount_end(&devnet_rename_seq);
		return ret;
	}

	write_seqcount_end(&devnet_rename_seq);

	netdev_adjacent_rename_links(dev, oldname);

	write_lock_bh(&dev_base_lock);
	hlist_del_rcu(&dev->name_hlist);
	write_unlock_bh(&dev_base_lock);

	synchronize_rcu();

	write_lock_bh(&dev_base_lock);
	hlist_add_head_rcu(&dev->name_hlist, dev_name_hash(net, dev->name));
	write_unlock_bh(&dev_base_lock);

	ret = call_netdevice_notifiers(NETDEV_CHANGENAME, dev);
	ret = notifier_to_errno(ret);

	if (ret) {
		 
		if (err >= 0) {
			err = ret;
			write_seqcount_begin(&devnet_rename_seq);
			memcpy(dev->name, oldname, IFNAMSIZ);
			memcpy(oldname, newname, IFNAMSIZ);
			dev->name_assign_type = old_assign_type;
			old_assign_type = NET_NAME_RENAMED;
			goto rollback;
		} else {
			pr_err("%s: name change rollback failed: %d\n",
			       dev->name, ret);
		}
	}

	return err;
}

int dev_set_alias(struct net_device *dev, const char *alias, size_t len)
{
	char *new_ifalias;

	ASSERT_RTNL();

	if (len >= IFALIASZ)
		return -EINVAL;

	if (!len) {
		kfree(dev->ifalias);
		dev->ifalias = NULL;
		return 0;
	}

	new_ifalias = krealloc(dev->ifalias, len + 1, GFP_KERNEL);
	if (!new_ifalias)
		return -ENOMEM;
	dev->ifalias = new_ifalias;

	strlcpy(dev->ifalias, alias, len+1);
	return len;
}

void netdev_features_change(struct net_device *dev)
{
	call_netdevice_notifiers(NETDEV_FEAT_CHANGE, dev);
}
EXPORT_SYMBOL(netdev_features_change);

void netdev_state_change(struct net_device *dev)
{
	if (dev->flags & IFF_UP) {
		struct netdev_notifier_change_info change_info;

		change_info.flags_changed = 0;
		call_netdevice_notifiers_info(NETDEV_CHANGE, dev,
					      &change_info.info);
		rtmsg_ifinfo(RTM_NEWLINK, dev, 0, GFP_KERNEL);
	}
}
EXPORT_SYMBOL(netdev_state_change);

void netdev_notify_peers(struct net_device *dev)
{
	rtnl_lock();
	call_netdevice_notifiers(NETDEV_NOTIFY_PEERS, dev);
	rtnl_unlock();
}
EXPORT_SYMBOL(netdev_notify_peers);

static int __dev_open(struct net_device *dev)
{
	const struct net_device_ops *ops = dev->netdev_ops;
	int ret;

	ASSERT_RTNL();

	if (!netif_device_present(dev))
		return -ENODEV;

	netpoll_poll_disable(dev);

	ret = call_netdevice_notifiers(NETDEV_PRE_UP, dev);
	ret = notifier_to_errno(ret);
	if (ret)
		return ret;

	set_bit(__LINK_STATE_START, &dev->state);

	if (ops->ndo_validate_addr)
		ret = ops->ndo_validate_addr(dev);

	if (!ret && ops->ndo_open)
		ret = ops->ndo_open(dev);

	netpoll_poll_enable(dev);

	if (ret)
		clear_bit(__LINK_STATE_START, &dev->state);
	else {
		dev->flags |= IFF_UP;
		dev_set_rx_mode(dev);
		dev_activate(dev);
		add_device_randomness(dev->dev_addr, dev->addr_len);
	}

	return ret;
}

int dev_open(struct net_device *dev)
{
	int ret;

	if (dev->flags & IFF_UP)
		return 0;

	ret = __dev_open(dev);
	if (ret < 0)
		return ret;

	rtmsg_ifinfo(RTM_NEWLINK, dev, IFF_UP|IFF_RUNNING, GFP_KERNEL);
	call_netdevice_notifiers(NETDEV_UP, dev);

	return ret;
}
EXPORT_SYMBOL(dev_open);

static int __dev_close_many(struct list_head *head)
{
	struct net_device *dev;

	ASSERT_RTNL();
	might_sleep();

	list_for_each_entry(dev, head, close_list) {
		 
		netpoll_poll_disable(dev);

		call_netdevice_notifiers(NETDEV_GOING_DOWN, dev);

		clear_bit(__LINK_STATE_START, &dev->state);

		smp_mb__after_atomic();  
	}

	dev_deactivate_many(head);

	list_for_each_entry(dev, head, close_list) {
		const struct net_device_ops *ops = dev->netdev_ops;

		if (ops->ndo_stop)
			ops->ndo_stop(dev);

		dev->flags &= ~IFF_UP;
		netpoll_poll_enable(dev);
	}

	return 0;
}

static int __dev_close(struct net_device *dev)
{
	int retval;
	LIST_HEAD(single);

	list_add(&dev->close_list, &single);
	retval = __dev_close_many(&single);
	list_del(&single);

	return retval;
}

int dev_close_many(struct list_head *head, bool unlink)
{
	struct net_device *dev, *tmp;

	list_for_each_entry_safe(dev, tmp, head, close_list)
		if (!(dev->flags & IFF_UP))
			list_del_init(&dev->close_list);

	__dev_close_many(head);

	list_for_each_entry_safe(dev, tmp, head, close_list) {
		rtmsg_ifinfo(RTM_NEWLINK, dev, IFF_UP|IFF_RUNNING, GFP_KERNEL);
		call_netdevice_notifiers(NETDEV_DOWN, dev);
		if (unlink)
			list_del_init(&dev->close_list);
	}

	return 0;
}
EXPORT_SYMBOL(dev_close_many);

int dev_close(struct net_device *dev)
{
	if (dev->flags & IFF_UP) {
		LIST_HEAD(single);

		list_add(&dev->close_list, &single);
		dev_close_many(&single, true);
		list_del(&single);
	}
	return 0;
}
EXPORT_SYMBOL(dev_close);

void dev_disable_lro(struct net_device *dev)
{
	struct net_device *lower_dev;
	struct list_head *iter;

	dev->wanted_features &= ~NETIF_F_LRO;
	netdev_update_features(dev);

	if (unlikely(dev->features & NETIF_F_LRO))
		netdev_WARN(dev, "failed to disable LRO!\n");

	netdev_for_each_lower_dev(dev, lower_dev, iter)
		dev_disable_lro(lower_dev);
}
EXPORT_SYMBOL(dev_disable_lro);

static int call_netdevice_notifier(struct notifier_block *nb, unsigned long val,
				   struct net_device *dev)
{
	struct netdev_notifier_info info;

	netdev_notifier_info_init(&info, dev);
	return nb->notifier_call(nb, val, &info);
}

static int dev_boot_phase = 1;

int register_netdevice_notifier(struct notifier_block *nb)
{
	struct net_device *dev;
	struct net_device *last;
	struct net *net;
	int err;

	rtnl_lock();
	err = raw_notifier_chain_register(&netdev_chain, nb);
	if (err)
		goto unlock;
	if (dev_boot_phase)
		goto unlock;
	for_each_net(net) {
		for_each_netdev(net, dev) {
			err = call_netdevice_notifier(nb, NETDEV_REGISTER, dev);
			err = notifier_to_errno(err);
			if (err)
				goto rollback;

			if (!(dev->flags & IFF_UP))
				continue;

			call_netdevice_notifier(nb, NETDEV_UP, dev);
		}
	}

unlock:
	rtnl_unlock();
	return err;

rollback:
	last = dev;
	for_each_net(net) {
		for_each_netdev(net, dev) {
			if (dev == last)
				goto outroll;

			if (dev->flags & IFF_UP) {
				call_netdevice_notifier(nb, NETDEV_GOING_DOWN,
							dev);
				call_netdevice_notifier(nb, NETDEV_DOWN, dev);
			}
			call_netdevice_notifier(nb, NETDEV_UNREGISTER, dev);
		}
	}

outroll:
	raw_notifier_chain_unregister(&netdev_chain, nb);
	goto unlock;
}
EXPORT_SYMBOL(register_netdevice_notifier);

int unregister_netdevice_notifier(struct notifier_block *nb)
{
	struct net_device *dev;
	struct net *net;
	int err;

	rtnl_lock();
	err = raw_notifier_chain_unregister(&netdev_chain, nb);
	if (err)
		goto unlock;

	for_each_net(net) {
		for_each_netdev(net, dev) {
			if (dev->flags & IFF_UP) {
				call_netdevice_notifier(nb, NETDEV_GOING_DOWN,
							dev);
				call_netdevice_notifier(nb, NETDEV_DOWN, dev);
			}
			call_netdevice_notifier(nb, NETDEV_UNREGISTER, dev);
		}
	}
unlock:
	rtnl_unlock();
	return err;
}
EXPORT_SYMBOL(unregister_netdevice_notifier);

static int call_netdevice_notifiers_info(unsigned long val,
					 struct net_device *dev,
					 struct netdev_notifier_info *info)
{
	ASSERT_RTNL();
	netdev_notifier_info_init(info, dev);
	return raw_notifier_call_chain(&netdev_chain, val, info);
}

int call_netdevice_notifiers(unsigned long val, struct net_device *dev)
{
	struct netdev_notifier_info info;

	return call_netdevice_notifiers_info(val, dev, &info);
}
EXPORT_SYMBOL(call_netdevice_notifiers);

#ifdef CONFIG_NET_INGRESS
static struct static_key ingress_needed __read_mostly;

void net_inc_ingress_queue(void)
{
	static_key_slow_inc(&ingress_needed);
}
EXPORT_SYMBOL_GPL(net_inc_ingress_queue);

void net_dec_ingress_queue(void)
{
	static_key_slow_dec(&ingress_needed);
}
EXPORT_SYMBOL_GPL(net_dec_ingress_queue);
#endif

static struct static_key netstamp_needed __read_mostly;
#ifdef HAVE_JUMP_LABEL
static atomic_t netstamp_needed_deferred;
static atomic_t netstamp_wanted;
static void netstamp_clear(struct work_struct *work)
{
	int deferred = atomic_xchg(&netstamp_needed_deferred, 0);
	int wanted;

	wanted = atomic_add_return(deferred, &netstamp_wanted);
	if (wanted > 0)
		static_key_enable(&netstamp_needed);
	else
		static_key_disable(&netstamp_needed);
}
static DECLARE_WORK(netstamp_work, netstamp_clear);
#endif

void net_enable_timestamp(void)
{
#ifdef HAVE_JUMP_LABEL
	int wanted;

	while (1) {
		wanted = atomic_read(&netstamp_wanted);
		if (wanted <= 0)
			break;
		if (atomic_cmpxchg(&netstamp_wanted, wanted, wanted + 1) == wanted)
			return;
	}
	atomic_inc(&netstamp_needed_deferred);
	schedule_work(&netstamp_work);
#else
	static_key_slow_inc(&netstamp_needed);
#endif
}
EXPORT_SYMBOL(net_enable_timestamp);

void net_disable_timestamp(void)
{
#ifdef HAVE_JUMP_LABEL
	int wanted;

	while (1) {
		wanted = atomic_read(&netstamp_wanted);
		if (wanted <= 1)
			break;
		if (atomic_cmpxchg(&netstamp_wanted, wanted, wanted - 1) == wanted)
			return;
	}
	atomic_dec(&netstamp_needed_deferred);
	schedule_work(&netstamp_work);
#else
	static_key_slow_dec(&netstamp_needed);
#endif
}
EXPORT_SYMBOL(net_disable_timestamp);

static inline void net_timestamp_set(struct sk_buff *skb)
{
	skb->tstamp.tv64 = 0;
	if (static_key_false(&netstamp_needed))
		__net_timestamp(skb);
}

#define net_timestamp_check(COND, SKB)			\
	if (static_key_false(&netstamp_needed)) {		\
		if ((COND) && !(SKB)->tstamp.tv64)	\
			__net_timestamp(SKB);		\
	}						\

bool is_skb_forwardable(struct net_device *dev, struct sk_buff *skb)
{
	unsigned int len;

	if (!(dev->flags & IFF_UP))
		return false;

	len = dev->mtu + dev->hard_header_len + VLAN_HLEN;
	if (skb->len <= len)
		return true;

	if (skb_is_gso(skb))
		return true;

	return false;
}
EXPORT_SYMBOL_GPL(is_skb_forwardable);

int __dev_forward_skb(struct net_device *dev, struct sk_buff *skb)
{
	if (skb_orphan_frags(skb, GFP_ATOMIC) ||
	    unlikely(!is_skb_forwardable(dev, skb))) {
		atomic_long_inc(&dev->rx_dropped);
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	skb_scrub_packet(skb, true);
	skb->priority = 0;
	skb->protocol = eth_type_trans(skb, dev);
	skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);

	return 0;
}
EXPORT_SYMBOL_GPL(__dev_forward_skb);

int dev_forward_skb(struct net_device *dev, struct sk_buff *skb)
{
	return __dev_forward_skb(dev, skb) ?: netif_rx_internal(skb);
}
EXPORT_SYMBOL_GPL(dev_forward_skb);

static inline int deliver_skb(struct sk_buff *skb,
			      struct packet_type *pt_prev,
			      struct net_device *orig_dev)
{
	if (unlikely(skb_orphan_frags(skb, GFP_ATOMIC)))
		return -ENOMEM;
	atomic_inc(&skb->users);
	return pt_prev->func(skb, skb->dev, pt_prev, orig_dev);
}

static inline void deliver_ptype_list_skb(struct sk_buff *skb,
					  struct packet_type **pt,
					  struct net_device *orig_dev,
					  __be16 type,
					  struct list_head *ptype_list)
{
	struct packet_type *ptype, *pt_prev = *pt;

	list_for_each_entry_rcu(ptype, ptype_list, list) {
		if (ptype->type != type)
			continue;
		if (pt_prev)
			deliver_skb(skb, pt_prev, orig_dev);
		pt_prev = ptype;
	}
	*pt = pt_prev;
}

static inline bool skb_loop_sk(struct packet_type *ptype, struct sk_buff *skb)
{
	if (!ptype->af_packet_priv || !skb->sk)
		return false;

	if (ptype->id_match)
		return ptype->id_match(ptype, skb->sk);
	else if ((struct sock *)ptype->af_packet_priv == skb->sk)
		return true;

	return false;
}

static void dev_queue_xmit_nit(struct sk_buff *skb, struct net_device *dev)
{
	struct packet_type *ptype;
	struct sk_buff *skb2 = NULL;
	struct packet_type *pt_prev = NULL;
	struct list_head *ptype_list = &ptype_all;

	rcu_read_lock();
again:
	list_for_each_entry_rcu(ptype, ptype_list, list) {
		 
		if (skb_loop_sk(ptype, skb))
			continue;

		if (pt_prev) {
			deliver_skb(skb2, pt_prev, skb->dev);
			pt_prev = ptype;
			continue;
		}

		skb2 = skb_clone(skb, GFP_ATOMIC);
		if (!skb2)
			goto out_unlock;

		net_timestamp_set(skb2);

		skb_reset_mac_header(skb2);

		if (skb_network_header(skb2) < skb2->data ||
		    skb_network_header(skb2) > skb_tail_pointer(skb2)) {
			net_crit_ratelimited("protocol %04x is buggy, dev %s\n",
					     ntohs(skb2->protocol),
					     dev->name);
			skb_reset_network_header(skb2);
		}

		skb2->transport_header = skb2->network_header;
		skb2->pkt_type = PACKET_OUTGOING;
		pt_prev = ptype;
	}

	if (ptype_list == &ptype_all) {
		ptype_list = &dev->ptype_all;
		goto again;
	}
out_unlock:
	if (pt_prev)
		pt_prev->func(skb2, skb->dev, pt_prev, skb->dev);
	rcu_read_unlock();
}

static void netif_setup_tc(struct net_device *dev, unsigned int txq)
{
	int i;
	struct netdev_tc_txq *tc = &dev->tc_to_txq[0];

	if (tc->offset + tc->count > txq) {
		pr_warn("Number of in use tx queues changed invalidating tc mappings. Priority traffic classification disabled!\n");
		dev->num_tc = 0;
		return;
	}

	for (i = 1; i < TC_BITMASK + 1; i++) {
		int q = netdev_get_prio_tc_map(dev, i);

		tc = &dev->tc_to_txq[q];
		if (tc->offset + tc->count > txq) {
			pr_warn("Number of in use tx queues changed. Priority %i to tc mapping %i is no longer valid. Setting map to 0\n",
				i, q);
			netdev_set_prio_tc_map(dev, i, 0);
		}
	}
}

#ifdef CONFIG_XPS
static DEFINE_MUTEX(xps_map_mutex);
#define xmap_dereference(P)		\
	rcu_dereference_protected((P), lockdep_is_held(&xps_map_mutex))

static struct xps_map *remove_xps_queue(struct xps_dev_maps *dev_maps,
					int cpu, u16 index)
{
	struct xps_map *map = NULL;
	int pos;

	if (dev_maps)
		map = xmap_dereference(dev_maps->cpu_map[cpu]);

	for (pos = 0; map && pos < map->len; pos++) {
		if (map->queues[pos] == index) {
			if (map->len > 1) {
				map->queues[pos] = map->queues[--map->len];
			} else {
				RCU_INIT_POINTER(dev_maps->cpu_map[cpu], NULL);
				kfree_rcu(map, rcu);
				map = NULL;
			}
			break;
		}
	}

	return map;
}

static void netif_reset_xps_queues_gt(struct net_device *dev, u16 index)
{
	struct xps_dev_maps *dev_maps;
	int cpu, i;
	bool active = false;

	mutex_lock(&xps_map_mutex);
	dev_maps = xmap_dereference(dev->xps_maps);

	if (!dev_maps)
		goto out_no_maps;

	for_each_possible_cpu(cpu) {
		for (i = index; i < dev->num_tx_queues; i++) {
			if (!remove_xps_queue(dev_maps, cpu, i))
				break;
		}
		if (i == dev->num_tx_queues)
			active = true;
	}

	if (!active) {
		RCU_INIT_POINTER(dev->xps_maps, NULL);
		kfree_rcu(dev_maps, rcu);
	}

	for (i = index; i < dev->num_tx_queues; i++)
		netdev_queue_numa_node_write(netdev_get_tx_queue(dev, i),
					     NUMA_NO_NODE);

out_no_maps:
	mutex_unlock(&xps_map_mutex);
}

static struct xps_map *expand_xps_map(struct xps_map *map,
				      int cpu, u16 index)
{
	struct xps_map *new_map;
	int alloc_len = XPS_MIN_MAP_ALLOC;
	int i, pos;

	for (pos = 0; map && pos < map->len; pos++) {
		if (map->queues[pos] != index)
			continue;
		return map;
	}

	if (map) {
		if (pos < map->alloc_len)
			return map;

		alloc_len = map->alloc_len * 2;
	}

	new_map = kzalloc_node(XPS_MAP_SIZE(alloc_len), GFP_KERNEL,
			       cpu_to_node(cpu));
	if (!new_map)
		return NULL;

	for (i = 0; i < pos; i++)
		new_map->queues[i] = map->queues[i];
	new_map->alloc_len = alloc_len;
	new_map->len = pos;

	return new_map;
}

int netif_set_xps_queue(struct net_device *dev, const struct cpumask *mask,
			u16 index)
{
	struct xps_dev_maps *dev_maps, *new_dev_maps = NULL;
	struct xps_map *map, *new_map;
	int maps_sz = max_t(unsigned int, XPS_DEV_MAPS_SIZE, L1_CACHE_BYTES);
	int cpu, numa_node_id = -2;
	bool active = false;

	mutex_lock(&xps_map_mutex);

	dev_maps = xmap_dereference(dev->xps_maps);

	for_each_online_cpu(cpu) {
		if (!cpumask_test_cpu(cpu, mask))
			continue;

		if (!new_dev_maps)
			new_dev_maps = kzalloc(maps_sz, GFP_KERNEL);
		if (!new_dev_maps) {
			mutex_unlock(&xps_map_mutex);
			return -ENOMEM;
		}

		map = dev_maps ? xmap_dereference(dev_maps->cpu_map[cpu]) :
				 NULL;

		map = expand_xps_map(map, cpu, index);
		if (!map)
			goto error;

		RCU_INIT_POINTER(new_dev_maps->cpu_map[cpu], map);
	}

	if (!new_dev_maps)
		goto out_no_new_maps;

	for_each_possible_cpu(cpu) {
		if (cpumask_test_cpu(cpu, mask) && cpu_online(cpu)) {
			 
			int pos = 0;

			map = xmap_dereference(new_dev_maps->cpu_map[cpu]);
			while ((pos < map->len) && (map->queues[pos] != index))
				pos++;

			if (pos == map->len)
				map->queues[map->len++] = index;
#ifdef CONFIG_NUMA
			if (numa_node_id == -2)
				numa_node_id = cpu_to_node(cpu);
			else if (numa_node_id != cpu_to_node(cpu))
				numa_node_id = -1;
#endif
		} else if (dev_maps) {
			 
			map = xmap_dereference(dev_maps->cpu_map[cpu]);
			RCU_INIT_POINTER(new_dev_maps->cpu_map[cpu], map);
		}

	}

	rcu_assign_pointer(dev->xps_maps, new_dev_maps);

	if (dev_maps) {
		for_each_possible_cpu(cpu) {
			new_map = xmap_dereference(new_dev_maps->cpu_map[cpu]);
			map = xmap_dereference(dev_maps->cpu_map[cpu]);
			if (map && map != new_map)
				kfree_rcu(map, rcu);
		}

		kfree_rcu(dev_maps, rcu);
	}

	dev_maps = new_dev_maps;
	active = true;

out_no_new_maps:
	 
	netdev_queue_numa_node_write(netdev_get_tx_queue(dev, index),
				     (numa_node_id >= 0) ? numa_node_id :
				     NUMA_NO_NODE);

	if (!dev_maps)
		goto out_no_maps;

	for_each_possible_cpu(cpu) {
		if (cpumask_test_cpu(cpu, mask) && cpu_online(cpu))
			continue;

		if (remove_xps_queue(dev_maps, cpu, index))
			active = true;
	}

	if (!active) {
		RCU_INIT_POINTER(dev->xps_maps, NULL);
		kfree_rcu(dev_maps, rcu);
	}

out_no_maps:
	mutex_unlock(&xps_map_mutex);

	return 0;
error:
	 
	for_each_possible_cpu(cpu) {
		new_map = xmap_dereference(new_dev_maps->cpu_map[cpu]);
		map = dev_maps ? xmap_dereference(dev_maps->cpu_map[cpu]) :
				 NULL;
		if (new_map && new_map != map)
			kfree(new_map);
	}

	mutex_unlock(&xps_map_mutex);

	kfree(new_dev_maps);
	return -ENOMEM;
}
EXPORT_SYMBOL(netif_set_xps_queue);

#endif
 
int netif_set_real_num_tx_queues(struct net_device *dev, unsigned int txq)
{
	int rc;

	if (txq < 1 || txq > dev->num_tx_queues)
		return -EINVAL;

	if (dev->reg_state == NETREG_REGISTERED ||
	    dev->reg_state == NETREG_UNREGISTERING) {
		ASSERT_RTNL();

		rc = netdev_queue_update_kobjects(dev, dev->real_num_tx_queues,
						  txq);
		if (rc)
			return rc;

		if (dev->num_tc)
			netif_setup_tc(dev, txq);

		if (txq < dev->real_num_tx_queues) {
			qdisc_reset_all_tx_gt(dev, txq);
#ifdef CONFIG_XPS
			netif_reset_xps_queues_gt(dev, txq);
#endif
		}
	}

	dev->real_num_tx_queues = txq;
	return 0;
}
EXPORT_SYMBOL(netif_set_real_num_tx_queues);

#ifdef CONFIG_SYSFS
 
int netif_set_real_num_rx_queues(struct net_device *dev, unsigned int rxq)
{
	int rc;

	if (rxq < 1 || rxq > dev->num_rx_queues)
		return -EINVAL;

	if (dev->reg_state == NETREG_REGISTERED) {
		ASSERT_RTNL();

		rc = net_rx_queue_update_kobjects(dev, dev->real_num_rx_queues,
						  rxq);
		if (rc)
			return rc;
	}

	dev->real_num_rx_queues = rxq;
	return 0;
}
EXPORT_SYMBOL(netif_set_real_num_rx_queues);
#endif

int netif_get_num_default_rss_queues(void)
{
	return min_t(int, DEFAULT_MAX_NUM_RSS_QUEUES, num_online_cpus());
}
EXPORT_SYMBOL(netif_get_num_default_rss_queues);

static inline void __netif_reschedule(struct Qdisc *q)
{
	struct softnet_data *sd;
	unsigned long flags;

	local_irq_save(flags);
	sd = this_cpu_ptr(&softnet_data);
	q->next_sched = NULL;
	*sd->output_queue_tailp = q;
	sd->output_queue_tailp = &q->next_sched;
	raise_softirq_irqoff(NET_TX_SOFTIRQ);
	local_irq_restore(flags);
}

void __netif_schedule(struct Qdisc *q)
{
	if (!test_and_set_bit(__QDISC_STATE_SCHED, &q->state))
		__netif_reschedule(q);
}
EXPORT_SYMBOL(__netif_schedule);

struct dev_kfree_skb_cb {
	enum skb_free_reason reason;
};

static struct dev_kfree_skb_cb *get_kfree_skb_cb(const struct sk_buff *skb)
{
	return (struct dev_kfree_skb_cb *)skb->cb;
}

void netif_schedule_queue(struct netdev_queue *txq)
{
	rcu_read_lock();
	if (!(txq->state & QUEUE_STATE_ANY_XOFF)) {
		struct Qdisc *q = rcu_dereference(txq->qdisc);

		__netif_schedule(q);
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL(netif_schedule_queue);

void netif_wake_subqueue(struct net_device *dev, u16 queue_index)
{
	struct netdev_queue *txq = netdev_get_tx_queue(dev, queue_index);

	if (test_and_clear_bit(__QUEUE_STATE_DRV_XOFF, &txq->state)) {
		struct Qdisc *q;

		rcu_read_lock();
		q = rcu_dereference(txq->qdisc);
		__netif_schedule(q);
		rcu_read_unlock();
	}
}
EXPORT_SYMBOL(netif_wake_subqueue);

void netif_tx_wake_queue(struct netdev_queue *dev_queue)
{
	if (test_and_clear_bit(__QUEUE_STATE_DRV_XOFF, &dev_queue->state)) {
		struct Qdisc *q;

		rcu_read_lock();
		q = rcu_dereference(dev_queue->qdisc);
		__netif_schedule(q);
		rcu_read_unlock();
	}
}
EXPORT_SYMBOL(netif_tx_wake_queue);

void __dev_kfree_skb_irq(struct sk_buff *skb, enum skb_free_reason reason)
{
	unsigned long flags;

	if (likely(atomic_read(&skb->users) == 1)) {
		smp_rmb();
		atomic_set(&skb->users, 0);
	} else if (likely(!atomic_dec_and_test(&skb->users))) {
		return;
	}
	get_kfree_skb_cb(skb)->reason = reason;
	local_irq_save(flags);
	skb->next = __this_cpu_read(softnet_data.completion_queue);
	__this_cpu_write(softnet_data.completion_queue, skb);
	raise_softirq_irqoff(NET_TX_SOFTIRQ);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(__dev_kfree_skb_irq);

void __dev_kfree_skb_any(struct sk_buff *skb, enum skb_free_reason reason)
{
	if (in_irq() || irqs_disabled())
		__dev_kfree_skb_irq(skb, reason);
	else
		dev_kfree_skb(skb);
}
EXPORT_SYMBOL(__dev_kfree_skb_any);

void netif_device_detach(struct net_device *dev)
{
	if (test_and_clear_bit(__LINK_STATE_PRESENT, &dev->state) &&
	    netif_running(dev)) {
		netif_tx_stop_all_queues(dev);
	}
}
EXPORT_SYMBOL(netif_device_detach);

void netif_device_attach(struct net_device *dev)
{
	if (!test_and_set_bit(__LINK_STATE_PRESENT, &dev->state) &&
	    netif_running(dev)) {
		netif_tx_wake_all_queues(dev);
		__netdev_watchdog_up(dev);
	}
}
EXPORT_SYMBOL(netif_device_attach);

u16 __skb_tx_hash(const struct net_device *dev, struct sk_buff *skb,
		  unsigned int num_tx_queues)
{
	u32 hash;
	u16 qoffset = 0;
	u16 qcount = num_tx_queues;

	if (skb_rx_queue_recorded(skb)) {
		hash = skb_get_rx_queue(skb);
		while (unlikely(hash >= num_tx_queues))
			hash -= num_tx_queues;
		return hash;
	}

	if (dev->num_tc) {
		u8 tc = netdev_get_prio_tc_map(dev, skb->priority);
		qoffset = dev->tc_to_txq[tc].offset;
		qcount = dev->tc_to_txq[tc].count;
	}

	return (u16) reciprocal_scale(skb_get_hash(skb), qcount) + qoffset;
}
EXPORT_SYMBOL(__skb_tx_hash);

static void skb_warn_bad_offload(const struct sk_buff *skb)
{
	static const netdev_features_t null_features = 0;
	struct net_device *dev = skb->dev;
	const char *name = "";

	if (!net_ratelimit())
		return;

	if (dev) {
		if (dev->dev.parent)
			name = dev_driver_string(dev->dev.parent);
		else
			name = netdev_name(dev);
	}
	WARN(1, "%s: caps=(%pNF, %pNF) len=%d data_len=%d gso_size=%d "
	     "gso_type=%d ip_summed=%d\n",
	     name, dev ? &dev->features : &null_features,
	     skb->sk ? &skb->sk->sk_route_caps : &null_features,
	     skb->len, skb->data_len, skb_shinfo(skb)->gso_size,
	     skb_shinfo(skb)->gso_type, skb->ip_summed);
}

int skb_checksum_help(struct sk_buff *skb)
{
	__wsum csum;
	int ret = 0, offset;

	if (skb->ip_summed == CHECKSUM_COMPLETE)
		goto out_set_summed;

	if (unlikely(skb_shinfo(skb)->gso_size)) {
		skb_warn_bad_offload(skb);
		return -EINVAL;
	}

	if (skb_has_shared_frag(skb)) {
		ret = __skb_linearize(skb);
		if (ret)
			goto out;
	}

	offset = skb_checksum_start_offset(skb);
	BUG_ON(offset >= skb_headlen(skb));
	csum = skb_checksum(skb, offset, skb->len - offset, 0);

	offset += skb->csum_offset;
	BUG_ON(offset + sizeof(__sum16) > skb_headlen(skb));

	if (skb_cloned(skb) &&
	    !skb_clone_writable(skb, offset + sizeof(__sum16))) {
		ret = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
		if (ret)
			goto out;
	}

	*(__sum16 *)(skb->data + offset) = csum_fold(csum) ?: CSUM_MANGLED_0;
out_set_summed:
	skb->ip_summed = CHECKSUM_NONE;
out:
	return ret;
}
EXPORT_SYMBOL(skb_checksum_help);

__be16 skb_network_protocol(struct sk_buff *skb, int *depth)
{
	__be16 type = skb->protocol;

	if (type == htons(ETH_P_TEB)) {
		struct ethhdr *eth;

		if (unlikely(!pskb_may_pull(skb, sizeof(struct ethhdr))))
			return 0;

		eth = (struct ethhdr *)skb_mac_header(skb);
		type = eth->h_proto;
	}

	return __vlan_get_protocol(skb, type, depth);
}

struct sk_buff *skb_mac_gso_segment(struct sk_buff *skb,
				    netdev_features_t features)
{
	struct sk_buff *segs = ERR_PTR(-EPROTONOSUPPORT);
	struct packet_offload *ptype;
	int vlan_depth = skb->mac_len;
	__be16 type = skb_network_protocol(skb, &vlan_depth);

	if (unlikely(!type))
		return ERR_PTR(-EINVAL);

	__skb_pull(skb, vlan_depth);

	rcu_read_lock();
	list_for_each_entry_rcu(ptype, &offload_base, list) {
		if (ptype->type == type && ptype->callbacks.gso_segment) {
			segs = ptype->callbacks.gso_segment(skb, features);
			break;
		}
	}
	rcu_read_unlock();

	__skb_push(skb, skb->data - skb_mac_header(skb));

	return segs;
}
EXPORT_SYMBOL(skb_mac_gso_segment);

static inline bool skb_needs_check(struct sk_buff *skb, bool tx_path)
{
	if (tx_path)
		return skb->ip_summed != CHECKSUM_PARTIAL;
	else
		return skb->ip_summed == CHECKSUM_NONE;
}

struct sk_buff *__skb_gso_segment(struct sk_buff *skb,
				  netdev_features_t features, bool tx_path)
{
	if (unlikely(skb_needs_check(skb, tx_path))) {
		int err;

		skb_warn_bad_offload(skb);

		err = skb_cow_head(skb, 0);
		if (err < 0)
			return ERR_PTR(err);
	}

	BUILD_BUG_ON(SKB_SGO_CB_OFFSET +
		     sizeof(*SKB_GSO_CB(skb)) > sizeof(skb->cb));

	SKB_GSO_CB(skb)->mac_offset = skb_headroom(skb);
	SKB_GSO_CB(skb)->encap_level = 0;

	skb_reset_mac_header(skb);
	skb_reset_mac_len(skb);

	return skb_mac_gso_segment(skb, features);
}
EXPORT_SYMBOL(__skb_gso_segment);

#ifdef CONFIG_BUG
void netdev_rx_csum_fault(struct net_device *dev)
{
	if (net_ratelimit()) {
		pr_err("%s: hw csum failure\n", dev ? dev->name : "<unknown>");
		dump_stack();
	}
}
EXPORT_SYMBOL(netdev_rx_csum_fault);
#endif

static int illegal_highdma(struct net_device *dev, struct sk_buff *skb)
{
#ifdef CONFIG_HIGHMEM
	int i;
	if (!(dev->features & NETIF_F_HIGHDMA)) {
		for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
			if (PageHighMem(skb_frag_page(frag)))
				return 1;
		}
	}

	if (PCI_DMA_BUS_IS_PHYS) {
		struct device *pdev = dev->dev.parent;

		if (!pdev)
			return 0;
		for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
			dma_addr_t addr = page_to_phys(skb_frag_page(frag));
			if (!pdev->dma_mask || addr + PAGE_SIZE - 1 > *pdev->dma_mask)
				return 1;
		}
	}
#endif
	return 0;
}

#if IS_ENABLED(CONFIG_NET_MPLS_GSO)
static netdev_features_t net_mpls_features(struct sk_buff *skb,
					   netdev_features_t features,
					   __be16 type)
{
	if (eth_p_mpls(type))
		features &= skb->dev->mpls_features;

	return features;
}
#else
static netdev_features_t net_mpls_features(struct sk_buff *skb,
					   netdev_features_t features,
					   __be16 type)
{
	return features;
}
#endif

static netdev_features_t harmonize_features(struct sk_buff *skb,
	netdev_features_t features)
{
	int tmp;
	__be16 type;

	type = skb_network_protocol(skb, &tmp);
	features = net_mpls_features(skb, features, type);

	if (skb->ip_summed != CHECKSUM_NONE &&
	    !can_checksum_protocol(features, type)) {
		features &= ~NETIF_F_ALL_CSUM;
	}
	if (illegal_highdma(skb->dev, skb))
		features &= ~NETIF_F_SG;

	return features;
}

netdev_features_t passthru_features_check(struct sk_buff *skb,
					  struct net_device *dev,
					  netdev_features_t features)
{
	return features;
}
EXPORT_SYMBOL(passthru_features_check);

static netdev_features_t dflt_features_check(const struct sk_buff *skb,
					     struct net_device *dev,
					     netdev_features_t features)
{
	return vlan_features_check(skb, features);
}

netdev_features_t netif_skb_features(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	netdev_features_t features = dev->features;
	u16 gso_segs = skb_shinfo(skb)->gso_segs;

	if (gso_segs > dev->gso_max_segs || gso_segs < dev->gso_min_segs)
		features &= ~NETIF_F_GSO_MASK;

	if (skb->encapsulation)
		features &= dev->hw_enc_features;

	if (skb_vlan_tagged(skb))
		features = netdev_intersect_features(features,
						     dev->vlan_features |
						     NETIF_F_HW_VLAN_CTAG_TX |
						     NETIF_F_HW_VLAN_STAG_TX);

	if (dev->netdev_ops->ndo_features_check)
		features &= dev->netdev_ops->ndo_features_check(skb, dev,
								features);
	else
		features &= dflt_features_check(skb, dev, features);

	return harmonize_features(skb, features);
}
EXPORT_SYMBOL(netif_skb_features);

static int xmit_one(struct sk_buff *skb, struct net_device *dev,
		    struct netdev_queue *txq, bool more)
{
	unsigned int len;
	int rc;

	if (!list_empty(&ptype_all) || !list_empty(&dev->ptype_all))
		dev_queue_xmit_nit(skb, dev);

	len = skb->len;
	trace_net_dev_start_xmit(skb, dev);
	rc = netdev_start_xmit(skb, dev, txq, more);
	trace_net_dev_xmit(skb, rc, dev, len);

	return rc;
}

struct sk_buff *dev_hard_start_xmit(struct sk_buff *first, struct net_device *dev,
				    struct netdev_queue *txq, int *ret)
{
	struct sk_buff *skb = first;
	int rc = NETDEV_TX_OK;

	while (skb) {
		struct sk_buff *next = skb->next;

		skb->next = NULL;
		rc = xmit_one(skb, dev, txq, next != NULL);
		if (unlikely(!dev_xmit_complete(rc))) {
			skb->next = next;
			goto out;
		}

		skb = next;
		if (netif_xmit_stopped(txq) && skb) {
			rc = NETDEV_TX_BUSY;
			break;
		}
	}

out:
	*ret = rc;
	return skb;
}

static struct sk_buff *validate_xmit_vlan(struct sk_buff *skb,
					  netdev_features_t features)
{
	if (skb_vlan_tag_present(skb) &&
	    !vlan_hw_offload_capable(features, skb->vlan_proto))
		skb = __vlan_hwaccel_push_inside(skb);
	return skb;
}

static struct sk_buff *validate_xmit_skb(struct sk_buff *skb, struct net_device *dev)
{
	netdev_features_t features;

	if (skb->next)
		return skb;

	features = netif_skb_features(skb);
	skb = validate_xmit_vlan(skb, features);
	if (unlikely(!skb))
		goto out_null;

	if (netif_needs_gso(skb, features)) {
		struct sk_buff *segs;

		segs = skb_gso_segment(skb, features);
		if (IS_ERR(segs)) {
			goto out_kfree_skb;
		} else if (segs) {
			consume_skb(skb);
			skb = segs;
		}
	} else {
		if (skb_needs_linearize(skb, features) &&
		    __skb_linearize(skb))
			goto out_kfree_skb;

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			if (skb->encapsulation)
				skb_set_inner_transport_header(skb,
							       skb_checksum_start_offset(skb));
			else
				skb_set_transport_header(skb,
							 skb_checksum_start_offset(skb));
			if (!(features & NETIF_F_ALL_CSUM) &&
			    skb_checksum_help(skb))
				goto out_kfree_skb;
		}
	}

	return skb;

out_kfree_skb:
	kfree_skb(skb);
out_null:
	return NULL;
}

struct sk_buff *validate_xmit_skb_list(struct sk_buff *skb, struct net_device *dev)
{
	struct sk_buff *next, *head = NULL, *tail;

	for (; skb != NULL; skb = next) {
		next = skb->next;
		skb->next = NULL;

		skb->prev = skb;

		skb = validate_xmit_skb(skb, dev);
		if (!skb)
			continue;

		if (!head)
			head = skb;
		else
			tail->next = skb;
		 
		tail = skb->prev;
	}
	return head;
}
EXPORT_SYMBOL_GPL(validate_xmit_skb_list);

static void qdisc_pkt_len_init(struct sk_buff *skb)
{
	const struct skb_shared_info *shinfo = skb_shinfo(skb);

	qdisc_skb_cb(skb)->pkt_len = skb->len;

	if (shinfo->gso_size)  {
		unsigned int hdr_len;
		u16 gso_segs = shinfo->gso_segs;

		hdr_len = skb_transport_header(skb) - skb_mac_header(skb);

		if (likely(shinfo->gso_type & (SKB_GSO_TCPV4 | SKB_GSO_TCPV6)))
			hdr_len += tcp_hdrlen(skb);
		else
			hdr_len += sizeof(struct udphdr);

		if (shinfo->gso_type & SKB_GSO_DODGY)
			gso_segs = DIV_ROUND_UP(skb->len - hdr_len,
						shinfo->gso_size);

		qdisc_skb_cb(skb)->pkt_len += (gso_segs - 1) * hdr_len;
	}
}

static inline int __dev_xmit_skb(struct sk_buff *skb, struct Qdisc *q,
				 struct net_device *dev,
				 struct netdev_queue *txq)
{
	spinlock_t *root_lock = qdisc_lock(q);
	bool contended;
	int rc;

	qdisc_pkt_len_init(skb);
	qdisc_calculate_pkt_len(skb, q);
	 
	contended = qdisc_is_running(q);
	if (unlikely(contended))
		spin_lock(&q->busylock);

	spin_lock(root_lock);
	if (unlikely(test_bit(__QDISC_STATE_DEACTIVATED, &q->state))) {
		kfree_skb(skb);
		rc = NET_XMIT_DROP;
	} else if ((q->flags & TCQ_F_CAN_BYPASS) && !qdisc_qlen(q) &&
		   qdisc_run_begin(q)) {
		 
		qdisc_bstats_update(q, skb);

		if (sch_direct_xmit(skb, q, dev, txq, root_lock, true)) {
			if (unlikely(contended)) {
				spin_unlock(&q->busylock);
				contended = false;
			}
			__qdisc_run(q);
		} else
			qdisc_run_end(q);

		rc = NET_XMIT_SUCCESS;
	} else {
		rc = q->enqueue(skb, q) & NET_XMIT_MASK;
		if (qdisc_run_begin(q)) {
			if (unlikely(contended)) {
				spin_unlock(&q->busylock);
				contended = false;
			}
			__qdisc_run(q);
		}
	}
	spin_unlock(root_lock);
	if (unlikely(contended))
		spin_unlock(&q->busylock);
	return rc;
}

#if IS_ENABLED(CONFIG_CGROUP_NET_PRIO)
static void skb_update_prio(struct sk_buff *skb)
{
	struct netprio_map *map = rcu_dereference_bh(skb->dev->priomap);

	if (!skb->priority && skb->sk && map) {
		unsigned int prioidx = skb->sk->sk_cgrp_prioidx;

		if (prioidx < map->priomap_len)
			skb->priority = map->priomap[prioidx];
	}
}
#else
#define skb_update_prio(skb)
#endif

DEFINE_PER_CPU(int, xmit_recursion);
EXPORT_SYMBOL(xmit_recursion);

#define RECURSION_LIMIT 10

int dev_loopback_xmit(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	skb_reset_mac_header(skb);
	__skb_pull(skb, skb_network_offset(skb));
	skb->pkt_type = PACKET_LOOPBACK;
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	WARN_ON(!skb_dst(skb));
	skb_dst_force(skb);
	netif_rx_ni(skb);
	return 0;
}
EXPORT_SYMBOL(dev_loopback_xmit);

static inline int get_xps_queue(struct net_device *dev, struct sk_buff *skb)
{
#ifdef CONFIG_XPS
	struct xps_dev_maps *dev_maps;
	struct xps_map *map;
	int queue_index = -1;

	rcu_read_lock();
	dev_maps = rcu_dereference(dev->xps_maps);
	if (dev_maps) {
		map = rcu_dereference(
		    dev_maps->cpu_map[skb->sender_cpu - 1]);
		if (map) {
			if (map->len == 1)
				queue_index = map->queues[0];
			else
				queue_index = map->queues[reciprocal_scale(skb_get_hash(skb),
									   map->len)];
			if (unlikely(queue_index >= dev->real_num_tx_queues))
				queue_index = -1;
		}
	}
	rcu_read_unlock();

	return queue_index;
#else
	return -1;
#endif
}

static u16 __netdev_pick_tx(struct net_device *dev, struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	int queue_index = sk_tx_queue_get(sk);

	if (queue_index < 0 || skb->ooo_okay ||
	    queue_index >= dev->real_num_tx_queues) {
		int new_index = get_xps_queue(dev, skb);
		if (new_index < 0)
			new_index = skb_tx_hash(dev, skb);

		if (queue_index != new_index && sk &&
		    sk_fullsock(sk) &&
		    rcu_access_pointer(sk->sk_dst_cache))
			sk_tx_queue_set(sk, new_index);

		queue_index = new_index;
	}

	return queue_index;
}

struct netdev_queue *netdev_pick_tx(struct net_device *dev,
				    struct sk_buff *skb,
				    void *accel_priv)
{
	int queue_index = 0;

#ifdef CONFIG_XPS
	if (skb->sender_cpu == 0)
		skb->sender_cpu = raw_smp_processor_id() + 1;
#endif

	if (dev->real_num_tx_queues != 1) {
		const struct net_device_ops *ops = dev->netdev_ops;
		if (ops->ndo_select_queue)
			queue_index = ops->ndo_select_queue(dev, skb, accel_priv,
							    __netdev_pick_tx);
		else
			queue_index = __netdev_pick_tx(dev, skb);

		if (!accel_priv)
			queue_index = netdev_cap_txqueue(dev, queue_index);
	}

	skb_set_queue_mapping(skb, queue_index);
	return netdev_get_tx_queue(dev, queue_index);
}

static int __dev_queue_xmit(struct sk_buff *skb, void *accel_priv)
{
	struct net_device *dev = skb->dev;
	struct netdev_queue *txq;
	struct Qdisc *q;
	int rc = -ENOMEM;

	skb_reset_mac_header(skb);

	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_SCHED_TSTAMP))
		__skb_tstamp_tx(skb, NULL, skb->sk, SCM_TSTAMP_SCHED);

	rcu_read_lock_bh();

	skb_update_prio(skb);

	if (dev->priv_flags & IFF_XMIT_DST_RELEASE)
		skb_dst_drop(skb);
	else
		skb_dst_force(skb);

#ifdef CONFIG_NET_SWITCHDEV
	 
	if (skb->offload_fwd_mark &&
	    skb->offload_fwd_mark == dev->offload_fwd_mark) {
		consume_skb(skb);
		rc = NET_XMIT_SUCCESS;
		goto out;
	}
#endif

	txq = netdev_pick_tx(dev, skb, accel_priv);
	q = rcu_dereference_bh(txq->qdisc);

#ifdef CONFIG_NET_CLS_ACT
	skb->tc_verd = SET_TC_AT(skb->tc_verd, AT_EGRESS);
#endif
	trace_net_dev_queue(skb);
	if (q->enqueue) {
		rc = __dev_xmit_skb(skb, q, dev, txq);
		goto out;
	}

	if (dev->flags & IFF_UP) {
		int cpu = smp_processor_id();  

		if (txq->xmit_lock_owner != cpu) {

			if (__this_cpu_read(xmit_recursion) > RECURSION_LIMIT)
				goto recursion_alert;

			skb = validate_xmit_skb(skb, dev);
			if (!skb)
				goto drop;

			HARD_TX_LOCK(dev, txq, cpu);

			if (!netif_xmit_stopped(txq)) {
				__this_cpu_inc(xmit_recursion);
				skb = dev_hard_start_xmit(skb, dev, txq, &rc);
				__this_cpu_dec(xmit_recursion);
				if (dev_xmit_complete(rc)) {
					HARD_TX_UNLOCK(dev, txq);
					goto out;
				}
			}
			HARD_TX_UNLOCK(dev, txq);
			net_crit_ratelimited("Virtual device %s asks to queue packet!\n",
					     dev->name);
		} else {
			 
recursion_alert:
			net_crit_ratelimited("Dead loop on virtual device %s, fix it urgently!\n",
					     dev->name);
		}
	}

	rc = -ENETDOWN;
drop:
	rcu_read_unlock_bh();

	atomic_long_inc(&dev->tx_dropped);
	kfree_skb_list(skb);
	return rc;
out:
	rcu_read_unlock_bh();
	return rc;
}

int dev_queue_xmit(struct sk_buff *skb)
{
	return __dev_queue_xmit(skb, NULL);
}
EXPORT_SYMBOL(dev_queue_xmit);

int dev_queue_xmit_accel(struct sk_buff *skb, void *accel_priv)
{
	return __dev_queue_xmit(skb, accel_priv);
}
EXPORT_SYMBOL(dev_queue_xmit_accel);

int netdev_max_backlog __read_mostly = 1000;
EXPORT_SYMBOL(netdev_max_backlog);

int netdev_tstamp_prequeue __read_mostly = 1;
int netdev_budget __read_mostly = 300;
int weight_p __read_mostly = 64;             

static inline void ____napi_schedule(struct softnet_data *sd,
				     struct napi_struct *napi)
{
	list_add_tail(&napi->poll_list, &sd->poll_list);
	__raise_softirq_irqoff(NET_RX_SOFTIRQ);
}

#ifdef CONFIG_RPS

struct rps_sock_flow_table __rcu *rps_sock_flow_table __read_mostly;
EXPORT_SYMBOL(rps_sock_flow_table);
u32 rps_cpu_mask __read_mostly;
EXPORT_SYMBOL(rps_cpu_mask);

struct static_key rps_needed __read_mostly;

static struct rps_dev_flow *
set_rps_cpu(struct net_device *dev, struct sk_buff *skb,
	    struct rps_dev_flow *rflow, u16 next_cpu)
{
	if (next_cpu < nr_cpu_ids) {
#ifdef CONFIG_RFS_ACCEL
		struct netdev_rx_queue *rxqueue;
		struct rps_dev_flow_table *flow_table;
		struct rps_dev_flow *old_rflow;
		u32 flow_id;
		u16 rxq_index;
		int rc;

		if (!skb_rx_queue_recorded(skb) || !dev->rx_cpu_rmap ||
		    !(dev->features & NETIF_F_NTUPLE))
			goto out;
		rxq_index = cpu_rmap_lookup_index(dev->rx_cpu_rmap, next_cpu);
		if (rxq_index == skb_get_rx_queue(skb))
			goto out;

		rxqueue = dev->_rx + rxq_index;
		flow_table = rcu_dereference(rxqueue->rps_flow_table);
		if (!flow_table)
			goto out;
		flow_id = skb_get_hash(skb) & flow_table->mask;
		rc = dev->netdev_ops->ndo_rx_flow_steer(dev, skb,
							rxq_index, flow_id);
		if (rc < 0)
			goto out;
		old_rflow = rflow;
		rflow = &flow_table->flows[flow_id];
		rflow->filter = rc;
		if (old_rflow->filter == rflow->filter)
			old_rflow->filter = RPS_NO_FILTER;
	out:
#endif
		rflow->last_qtail =
			per_cpu(softnet_data, next_cpu).input_queue_head;
	}

	rflow->cpu = next_cpu;
	return rflow;
}

static int get_rps_cpu(struct net_device *dev, struct sk_buff *skb,
		       struct rps_dev_flow **rflowp)
{
	const struct rps_sock_flow_table *sock_flow_table;
	struct netdev_rx_queue *rxqueue = dev->_rx;
	struct rps_dev_flow_table *flow_table;
	struct rps_map *map;
	int cpu = -1;
	u32 tcpu;
	u32 hash;

	if (skb_rx_queue_recorded(skb)) {
		u16 index = skb_get_rx_queue(skb);

		if (unlikely(index >= dev->real_num_rx_queues)) {
			WARN_ONCE(dev->real_num_rx_queues > 1,
				  "%s received packet on queue %u, but number "
				  "of RX queues is %u\n",
				  dev->name, index, dev->real_num_rx_queues);
			goto done;
		}
		rxqueue += index;
	}

	flow_table = rcu_dereference(rxqueue->rps_flow_table);
	map = rcu_dereference(rxqueue->rps_map);
	if (!flow_table && !map)
		goto done;

	skb_reset_network_header(skb);
	hash = skb_get_hash(skb);
	if (!hash)
		goto done;

	sock_flow_table = rcu_dereference(rps_sock_flow_table);
	if (flow_table && sock_flow_table) {
		struct rps_dev_flow *rflow;
		u32 next_cpu;
		u32 ident;

		ident = sock_flow_table->ents[hash & sock_flow_table->mask];
		if ((ident ^ hash) & ~rps_cpu_mask)
			goto try_rps;

		next_cpu = ident & rps_cpu_mask;

		rflow = &flow_table->flows[hash & flow_table->mask];
		tcpu = rflow->cpu;

		if (unlikely(tcpu != next_cpu) &&
		    (tcpu >= nr_cpu_ids || !cpu_online(tcpu) ||
		     ((int)(per_cpu(softnet_data, tcpu).input_queue_head -
		      rflow->last_qtail)) >= 0)) {
			tcpu = next_cpu;
			rflow = set_rps_cpu(dev, skb, rflow, next_cpu);
		}

		if (tcpu < nr_cpu_ids && cpu_online(tcpu)) {
			*rflowp = rflow;
			cpu = tcpu;
			goto done;
		}
	}

try_rps:

	if (map) {
		tcpu = map->cpus[reciprocal_scale(hash, map->len)];
		if (cpu_online(tcpu)) {
			cpu = tcpu;
			goto done;
		}
	}

done:
	return cpu;
}

#ifdef CONFIG_RFS_ACCEL

bool rps_may_expire_flow(struct net_device *dev, u16 rxq_index,
			 u32 flow_id, u16 filter_id)
{
	struct netdev_rx_queue *rxqueue = dev->_rx + rxq_index;
	struct rps_dev_flow_table *flow_table;
	struct rps_dev_flow *rflow;
	bool expire = true;
	unsigned int cpu;

	rcu_read_lock();
	flow_table = rcu_dereference(rxqueue->rps_flow_table);
	if (flow_table && flow_id <= flow_table->mask) {
		rflow = &flow_table->flows[flow_id];
		cpu = ACCESS_ONCE(rflow->cpu);
		if (rflow->filter == filter_id && cpu < nr_cpu_ids &&
		    ((int)(per_cpu(softnet_data, cpu).input_queue_head -
			   rflow->last_qtail) <
		     (int)(10 * flow_table->mask)))
			expire = false;
	}
	rcu_read_unlock();
	return expire;
}
EXPORT_SYMBOL(rps_may_expire_flow);

#endif  

static void rps_trigger_softirq(void *data)
{
	struct softnet_data *sd = data;

	____napi_schedule(sd, &sd->backlog);
	sd->received_rps++;
}

#endif  

static int rps_ipi_queued(struct softnet_data *sd)
{
#ifdef CONFIG_RPS
	struct softnet_data *mysd = this_cpu_ptr(&softnet_data);

	if (sd != mysd) {
		sd->rps_ipi_next = mysd->rps_ipi_list;
		mysd->rps_ipi_list = sd;

		__raise_softirq_irqoff(NET_RX_SOFTIRQ);
		return 1;
	}
#endif  
	return 0;
}

#ifdef CONFIG_NET_FLOW_LIMIT
int netdev_flow_limit_table_len __read_mostly = (1 << 12);
#endif

static bool skb_flow_limit(struct sk_buff *skb, unsigned int qlen)
{
#ifdef CONFIG_NET_FLOW_LIMIT
	struct sd_flow_limit *fl;
	struct softnet_data *sd;
	unsigned int old_flow, new_flow;

	if (qlen < (netdev_max_backlog >> 1))
		return false;

	sd = this_cpu_ptr(&softnet_data);

	rcu_read_lock();
	fl = rcu_dereference(sd->flow_limit);
	if (fl) {
		new_flow = skb_get_hash(skb) & (fl->num_buckets - 1);
		old_flow = fl->history[fl->history_head];
		fl->history[fl->history_head] = new_flow;

		fl->history_head++;
		fl->history_head &= FLOW_LIMIT_HISTORY - 1;

		if (likely(fl->buckets[old_flow]))
			fl->buckets[old_flow]--;

		if (++fl->buckets[new_flow] > (FLOW_LIMIT_HISTORY >> 1)) {
			fl->count++;
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
#endif
	return false;
}

static int enqueue_to_backlog(struct sk_buff *skb, int cpu,
			      unsigned int *qtail)
{
	struct softnet_data *sd;
	unsigned long flags;
	unsigned int qlen;

	sd = &per_cpu(softnet_data, cpu);

	local_irq_save(flags);

	rps_lock(sd);
	if (!netif_running(skb->dev))
		goto drop;
	qlen = skb_queue_len(&sd->input_pkt_queue);
	if (qlen <= netdev_max_backlog && !skb_flow_limit(skb, qlen)) {
		if (qlen) {
enqueue:
			__skb_queue_tail(&sd->input_pkt_queue, skb);
			input_queue_tail_incr_save(sd, qtail);
			rps_unlock(sd);
			local_irq_restore(flags);
			return NET_RX_SUCCESS;
		}

		if (!__test_and_set_bit(NAPI_STATE_SCHED, &sd->backlog.state)) {
			if (!rps_ipi_queued(sd))
				____napi_schedule(sd, &sd->backlog);
		}
		goto enqueue;
	}

drop:
	sd->dropped++;
	rps_unlock(sd);

	local_irq_restore(flags);

	atomic_long_inc(&skb->dev->rx_dropped);
	kfree_skb(skb);
	return NET_RX_DROP;
}

static int netif_rx_internal(struct sk_buff *skb)
{
	int ret;

	net_timestamp_check(netdev_tstamp_prequeue, skb);

	trace_netif_rx(skb);
#ifdef CONFIG_RPS
	if (static_key_false(&rps_needed)) {
		struct rps_dev_flow voidflow, *rflow = &voidflow;
		int cpu;

		preempt_disable();
		rcu_read_lock();

		cpu = get_rps_cpu(skb->dev, skb, &rflow);
		if (cpu < 0)
			cpu = smp_processor_id();

		ret = enqueue_to_backlog(skb, cpu, &rflow->last_qtail);

		rcu_read_unlock();
		preempt_enable();
	} else
#endif
	{
		unsigned int qtail;
		ret = enqueue_to_backlog(skb, get_cpu(), &qtail);
		put_cpu();
	}
	return ret;
}

int netif_rx(struct sk_buff *skb)
{
	trace_netif_rx_entry(skb);

	return netif_rx_internal(skb);
}
EXPORT_SYMBOL(netif_rx);

int netif_rx_ni(struct sk_buff *skb)
{
	int err;

	trace_netif_rx_ni_entry(skb);

	preempt_disable();
	err = netif_rx_internal(skb);
	if (local_softirq_pending())
		do_softirq();
	preempt_enable();

	return err;
}
EXPORT_SYMBOL(netif_rx_ni);

static void net_tx_action(struct softirq_action *h)
{
	struct softnet_data *sd = this_cpu_ptr(&softnet_data);

	if (sd->completion_queue) {
		struct sk_buff *clist;

		local_irq_disable();
		clist = sd->completion_queue;
		sd->completion_queue = NULL;
		local_irq_enable();

		while (clist) {
			struct sk_buff *skb = clist;
			clist = clist->next;

			WARN_ON(atomic_read(&skb->users));
			if (likely(get_kfree_skb_cb(skb)->reason == SKB_REASON_CONSUMED))
				trace_consume_skb(skb);
			else
				trace_kfree_skb(skb, net_tx_action);
			__kfree_skb(skb);
		}
	}

	if (sd->output_queue) {
		struct Qdisc *head;

		local_irq_disable();
		head = sd->output_queue;
		sd->output_queue = NULL;
		sd->output_queue_tailp = &sd->output_queue;
		local_irq_enable();

		while (head) {
			struct Qdisc *q = head;
			spinlock_t *root_lock;

			head = head->next_sched;

			root_lock = qdisc_lock(q);
			if (spin_trylock(root_lock)) {
				smp_mb__before_atomic();
				clear_bit(__QDISC_STATE_SCHED,
					  &q->state);
				qdisc_run(q);
				spin_unlock(root_lock);
			} else {
				if (!test_bit(__QDISC_STATE_DEACTIVATED,
					      &q->state)) {
					__netif_reschedule(q);
				} else {
					smp_mb__before_atomic();
					clear_bit(__QDISC_STATE_SCHED,
						  &q->state);
				}
			}
		}
	}
}

#if (defined(CONFIG_BRIDGE) || defined(CONFIG_BRIDGE_MODULE)) && \
    (defined(CONFIG_ATM_LANE) || defined(CONFIG_ATM_LANE_MODULE))
 
int (*br_fdb_test_addr_hook)(struct net_device *dev,
			     unsigned char *addr) __read_mostly;
EXPORT_SYMBOL_GPL(br_fdb_test_addr_hook);
#endif

static inline struct sk_buff *handle_ing(struct sk_buff *skb,
					 struct packet_type **pt_prev,
					 int *ret, struct net_device *orig_dev)
{
#ifdef CONFIG_NET_CLS_ACT
	struct tcf_proto *cl = rcu_dereference_bh(skb->dev->ingress_cl_list);
	struct tcf_result cl_res;

	if (!cl)
		return skb;
	if (*pt_prev) {
		*ret = deliver_skb(skb, *pt_prev, orig_dev);
		*pt_prev = NULL;
	}

	qdisc_skb_cb(skb)->pkt_len = skb->len;
	skb->tc_verd = SET_TC_AT(skb->tc_verd, AT_INGRESS);
	qdisc_bstats_cpu_update(cl->q, skb);

	switch (tc_classify(skb, cl, &cl_res, false)) {
	case TC_ACT_OK:
	case TC_ACT_RECLASSIFY:
		skb->tc_index = TC_H_MIN(cl_res.classid);
		break;
	case TC_ACT_SHOT:
		qdisc_qstats_cpu_drop(cl->q);
	case TC_ACT_STOLEN:
	case TC_ACT_QUEUED:
		kfree_skb(skb);
		return NULL;
	case TC_ACT_REDIRECT:
		 
		__skb_push(skb, skb->mac_len);
		skb_do_redirect(skb);
		return NULL;
	default:
		break;
	}
#endif  
	return skb;
}

bool netdev_is_rx_handler_busy(struct net_device *dev)
{
	ASSERT_RTNL();
	return dev && rtnl_dereference(dev->rx_handler);
}
EXPORT_SYMBOL_GPL(netdev_is_rx_handler_busy);

int netdev_rx_handler_register(struct net_device *dev,
			       rx_handler_func_t *rx_handler,
			       void *rx_handler_data)
{
	ASSERT_RTNL();

	if (dev->rx_handler)
		return -EBUSY;

	rcu_assign_pointer(dev->rx_handler_data, rx_handler_data);
	rcu_assign_pointer(dev->rx_handler, rx_handler);

	return 0;
}
EXPORT_SYMBOL_GPL(netdev_rx_handler_register);

void netdev_rx_handler_unregister(struct net_device *dev)
{

	ASSERT_RTNL();
	RCU_INIT_POINTER(dev->rx_handler, NULL);
	 
	synchronize_net();
	RCU_INIT_POINTER(dev->rx_handler_data, NULL);
}
EXPORT_SYMBOL_GPL(netdev_rx_handler_unregister);

static bool skb_pfmemalloc_protocol(struct sk_buff *skb)
{
	switch (skb->protocol) {
	case htons(ETH_P_ARP):
	case htons(ETH_P_IP):
	case htons(ETH_P_IPV6):
	case htons(ETH_P_8021Q):
	case htons(ETH_P_8021AD):
		return true;
	default:
		return false;
	}
}

static inline int nf_ingress(struct sk_buff *skb, struct packet_type **pt_prev,
			     int *ret, struct net_device *orig_dev)
{
#ifdef CONFIG_NETFILTER_INGRESS
	if (nf_hook_ingress_active(skb)) {
		if (*pt_prev) {
			*ret = deliver_skb(skb, *pt_prev, orig_dev);
			*pt_prev = NULL;
		}

		return nf_hook_ingress(skb);
	}
#endif  
	return 0;
}

static int __netif_receive_skb_core(struct sk_buff *skb, bool pfmemalloc)
{
	struct packet_type *ptype, *pt_prev;
	rx_handler_func_t *rx_handler;
	struct net_device *orig_dev;
	bool deliver_exact = false;
	int ret = NET_RX_DROP;
	__be16 type;

	net_timestamp_check(!netdev_tstamp_prequeue, skb);

	trace_netif_receive_skb(skb);

	orig_dev = skb->dev;

	skb_reset_network_header(skb);
	if (!skb_transport_header_was_set(skb))
		skb_reset_transport_header(skb);
	skb_reset_mac_len(skb);

	pt_prev = NULL;

another_round:
	skb->skb_iif = skb->dev->ifindex;

	__this_cpu_inc(softnet_data.processed);

	if (skb->protocol == cpu_to_be16(ETH_P_8021Q) ||
	    skb->protocol == cpu_to_be16(ETH_P_8021AD)) {
		skb = skb_vlan_untag(skb);
		if (unlikely(!skb))
			goto out;
	}

#ifdef CONFIG_NET_CLS_ACT
	if (skb->tc_verd & TC_NCLS) {
		skb->tc_verd = CLR_TC_NCLS(skb->tc_verd);
		goto ncls;
	}
#endif

	if (pfmemalloc)
		goto skip_taps;

	list_for_each_entry_rcu(ptype, &ptype_all, list) {
		if (pt_prev)
			ret = deliver_skb(skb, pt_prev, orig_dev);
		pt_prev = ptype;
	}

	list_for_each_entry_rcu(ptype, &skb->dev->ptype_all, list) {
		if (pt_prev)
			ret = deliver_skb(skb, pt_prev, orig_dev);
		pt_prev = ptype;
	}

skip_taps:
#ifdef CONFIG_NET_INGRESS
	if (static_key_false(&ingress_needed)) {
		skb = handle_ing(skb, &pt_prev, &ret, orig_dev);
		if (!skb)
			goto out;

		if (nf_ingress(skb, &pt_prev, &ret, orig_dev) < 0)
			goto out;
	}
#endif
#ifdef CONFIG_NET_CLS_ACT
	skb->tc_verd = 0;
ncls:
#endif
	if (pfmemalloc && !skb_pfmemalloc_protocol(skb))
		goto drop;

	if (skb_vlan_tag_present(skb)) {
		if (pt_prev) {
			ret = deliver_skb(skb, pt_prev, orig_dev);
			pt_prev = NULL;
		}
		if (vlan_do_receive(&skb))
			goto another_round;
		else if (unlikely(!skb))
			goto out;
	}

	rx_handler = rcu_dereference(skb->dev->rx_handler);
	if (rx_handler) {
		if (pt_prev) {
			ret = deliver_skb(skb, pt_prev, orig_dev);
			pt_prev = NULL;
		}
		switch (rx_handler(&skb)) {
		case RX_HANDLER_CONSUMED:
			ret = NET_RX_SUCCESS;
			goto out;
		case RX_HANDLER_ANOTHER:
			goto another_round;
		case RX_HANDLER_EXACT:
			deliver_exact = true;
		case RX_HANDLER_PASS:
			break;
		default:
			BUG();
		}
	}

	if (unlikely(skb_vlan_tag_present(skb))) {
		if (skb_vlan_tag_get_id(skb))
			skb->pkt_type = PACKET_OTHERHOST;
		 
		skb->vlan_tci = 0;
	}

	type = skb->protocol;

	if (likely(!deliver_exact)) {
		deliver_ptype_list_skb(skb, &pt_prev, orig_dev, type,
				       &ptype_base[ntohs(type) &
						   PTYPE_HASH_MASK]);
	}

	deliver_ptype_list_skb(skb, &pt_prev, orig_dev, type,
			       &orig_dev->ptype_specific);

	if (unlikely(skb->dev != orig_dev)) {
		deliver_ptype_list_skb(skb, &pt_prev, orig_dev, type,
				       &skb->dev->ptype_specific);
	}

	if (pt_prev) {
		if (unlikely(skb_orphan_frags(skb, GFP_ATOMIC)))
			goto drop;
		else
			ret = pt_prev->func(skb, skb->dev, pt_prev, orig_dev);
	} else {
drop:
		atomic_long_inc(&skb->dev->rx_dropped);
		kfree_skb(skb);
		 
		ret = NET_RX_DROP;
	}

out:
	return ret;
}

static int __netif_receive_skb(struct sk_buff *skb)
{
	int ret;

	if (sk_memalloc_socks() && skb_pfmemalloc(skb)) {
		unsigned long pflags = current->flags;

		current->flags |= PF_MEMALLOC;
		ret = __netif_receive_skb_core(skb, true);
		tsk_restore_flags(current, pflags, PF_MEMALLOC);
	} else
		ret = __netif_receive_skb_core(skb, false);

	return ret;
}

static int netif_receive_skb_internal(struct sk_buff *skb)
{
	int ret;

	net_timestamp_check(netdev_tstamp_prequeue, skb);

	if (skb_defer_rx_timestamp(skb))
		return NET_RX_SUCCESS;

	rcu_read_lock();

#ifdef CONFIG_RPS
	if (static_key_false(&rps_needed)) {
		struct rps_dev_flow voidflow, *rflow = &voidflow;
		int cpu = get_rps_cpu(skb->dev, skb, &rflow);

		if (cpu >= 0) {
			ret = enqueue_to_backlog(skb, cpu, &rflow->last_qtail);
			rcu_read_unlock();
			return ret;
		}
	}
#endif
	ret = __netif_receive_skb(skb);
	rcu_read_unlock();
	return ret;
}

int netif_receive_skb(struct sk_buff *skb)
{
	trace_netif_receive_skb_entry(skb);

	return netif_receive_skb_internal(skb);
}
EXPORT_SYMBOL(netif_receive_skb);

static void flush_backlog(void *arg)
{
	struct net_device *dev = arg;
	struct softnet_data *sd = this_cpu_ptr(&softnet_data);
	struct sk_buff *skb, *tmp;

	rps_lock(sd);
	skb_queue_walk_safe(&sd->input_pkt_queue, skb, tmp) {
		if (skb->dev == dev) {
			__skb_unlink(skb, &sd->input_pkt_queue);
			kfree_skb(skb);
			input_queue_head_incr(sd);
		}
	}
	rps_unlock(sd);

	skb_queue_walk_safe(&sd->process_queue, skb, tmp) {
		if (skb->dev == dev) {
			__skb_unlink(skb, &sd->process_queue);
			kfree_skb(skb);
			input_queue_head_incr(sd);
		}
	}
}

static int napi_gro_complete(struct sk_buff *skb)
{
	struct packet_offload *ptype;
	__be16 type = skb->protocol;
	struct list_head *head = &offload_base;
	int err = -ENOENT;

	BUILD_BUG_ON(sizeof(struct napi_gro_cb) > sizeof(skb->cb));

	if (NAPI_GRO_CB(skb)->count == 1) {
		skb_shinfo(skb)->gso_size = 0;
		goto out;
	}

	rcu_read_lock();
	list_for_each_entry_rcu(ptype, head, list) {
		if (ptype->type != type || !ptype->callbacks.gro_complete)
			continue;

		err = ptype->callbacks.gro_complete(skb, 0);
		break;
	}
	rcu_read_unlock();

	if (err) {
		WARN_ON(&ptype->list == head);
		kfree_skb(skb);
		return NET_RX_SUCCESS;
	}

out:
	return netif_receive_skb_internal(skb);
}

void napi_gro_flush(struct napi_struct *napi, bool flush_old)
{
	struct sk_buff *skb, *prev = NULL;

	for (skb = napi->gro_list; skb != NULL; skb = skb->next) {
		skb->prev = prev;
		prev = skb;
	}

	for (skb = prev; skb; skb = prev) {
		skb->next = NULL;

		if (flush_old && NAPI_GRO_CB(skb)->age == jiffies)
			return;

		prev = skb->prev;
		napi_gro_complete(skb);
		napi->gro_count--;
	}

	napi->gro_list = NULL;
}
EXPORT_SYMBOL(napi_gro_flush);

static void gro_list_prepare(struct napi_struct *napi, struct sk_buff *skb)
{
	struct sk_buff *p;
	unsigned int maclen = skb->dev->hard_header_len;
	u32 hash = skb_get_hash_raw(skb);

	for (p = napi->gro_list; p; p = p->next) {
		unsigned long diffs;

		NAPI_GRO_CB(p)->flush = 0;

		if (hash != skb_get_hash_raw(p)) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		diffs = (unsigned long)p->dev ^ (unsigned long)skb->dev;
		diffs |= p->vlan_tci ^ skb->vlan_tci;
		diffs |= skb_metadata_dst_cmp(p, skb);
		if (maclen == ETH_HLEN)
			diffs |= compare_ether_header(skb_mac_header(p),
						      skb_mac_header(skb));
		else if (!diffs)
			diffs = memcmp(skb_mac_header(p),
				       skb_mac_header(skb),
				       maclen);
		NAPI_GRO_CB(p)->same_flow = !diffs;
	}
}

static void skb_gro_reset_offset(struct sk_buff *skb)
{
	const struct skb_shared_info *pinfo = skb_shinfo(skb);
	const skb_frag_t *frag0 = &pinfo->frags[0];

	NAPI_GRO_CB(skb)->data_offset = 0;
	NAPI_GRO_CB(skb)->frag0 = NULL;
	NAPI_GRO_CB(skb)->frag0_len = 0;

	if (skb_mac_header(skb) == skb_tail_pointer(skb) &&
	    pinfo->nr_frags &&
	    !PageHighMem(skb_frag_page(frag0))) {
		NAPI_GRO_CB(skb)->frag0 = skb_frag_address(frag0);
		NAPI_GRO_CB(skb)->frag0_len = min_t(unsigned int,
						    skb_frag_size(frag0),
						    skb->end - skb->tail);
	}
}

static void gro_pull_from_frag0(struct sk_buff *skb, int grow)
{
	struct skb_shared_info *pinfo = skb_shinfo(skb);

	BUG_ON(skb->end - skb->tail < grow);

	memcpy(skb_tail_pointer(skb), NAPI_GRO_CB(skb)->frag0, grow);

	skb->data_len -= grow;
	skb->tail += grow;

	pinfo->frags[0].page_offset += grow;
	skb_frag_size_sub(&pinfo->frags[0], grow);

	if (unlikely(!skb_frag_size(&pinfo->frags[0]))) {
		skb_frag_unref(skb, 0);
		memmove(pinfo->frags, pinfo->frags + 1,
			--pinfo->nr_frags * sizeof(pinfo->frags[0]));
	}
}

static enum gro_result dev_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
{
	struct sk_buff **pp = NULL;
	struct packet_offload *ptype;
	__be16 type = skb->protocol;
	struct list_head *head = &offload_base;
	int same_flow;
	enum gro_result ret;
	int grow;

	if (!(skb->dev->features & NETIF_F_GRO))
		goto normal;

	if (skb_is_gso(skb) || skb_has_frag_list(skb) || skb->csum_bad)
		goto normal;

	gro_list_prepare(napi, skb);

	rcu_read_lock();
	list_for_each_entry_rcu(ptype, head, list) {
		if (ptype->type != type || !ptype->callbacks.gro_receive)
			continue;

		skb_set_network_header(skb, skb_gro_offset(skb));
		skb_reset_mac_len(skb);
		NAPI_GRO_CB(skb)->same_flow = 0;
		NAPI_GRO_CB(skb)->flush = 0;
		NAPI_GRO_CB(skb)->free = 0;
		NAPI_GRO_CB(skb)->encap_mark = 0;
		NAPI_GRO_CB(skb)->recursion_counter = 0;
		NAPI_GRO_CB(skb)->gro_remcsum_start = 0;

		switch (skb->ip_summed) {
		case CHECKSUM_COMPLETE:
			NAPI_GRO_CB(skb)->csum = skb->csum;
			NAPI_GRO_CB(skb)->csum_valid = 1;
			NAPI_GRO_CB(skb)->csum_cnt = 0;
			break;
		case CHECKSUM_UNNECESSARY:
			NAPI_GRO_CB(skb)->csum_cnt = skb->csum_level + 1;
			NAPI_GRO_CB(skb)->csum_valid = 0;
			break;
		default:
			NAPI_GRO_CB(skb)->csum_cnt = 0;
			NAPI_GRO_CB(skb)->csum_valid = 0;
		}

		pp = ptype->callbacks.gro_receive(&napi->gro_list, skb);
		break;
	}
	rcu_read_unlock();

	if (&ptype->list == head)
		goto normal;

	same_flow = NAPI_GRO_CB(skb)->same_flow;
	ret = NAPI_GRO_CB(skb)->free ? GRO_MERGED_FREE : GRO_MERGED;

	if (pp) {
		struct sk_buff *nskb = *pp;

		*pp = nskb->next;
		nskb->next = NULL;
		napi_gro_complete(nskb);
		napi->gro_count--;
	}

	if (same_flow)
		goto ok;

	if (NAPI_GRO_CB(skb)->flush)
		goto normal;

	if (unlikely(napi->gro_count >= MAX_GRO_SKBS)) {
		struct sk_buff *nskb = napi->gro_list;

		while (nskb->next) {
			pp = &nskb->next;
			nskb = *pp;
		}
		*pp = NULL;
		nskb->next = NULL;
		napi_gro_complete(nskb);
	} else {
		napi->gro_count++;
	}
	NAPI_GRO_CB(skb)->count = 1;
	NAPI_GRO_CB(skb)->age = jiffies;
	NAPI_GRO_CB(skb)->last = skb;
	skb_shinfo(skb)->gso_size = skb_gro_len(skb);
	skb->next = napi->gro_list;
	napi->gro_list = skb;
	ret = GRO_HELD;

pull:
	grow = skb_gro_offset(skb) - skb_headlen(skb);
	if (grow > 0)
		gro_pull_from_frag0(skb, grow);
ok:
	return ret;

normal:
	ret = GRO_NORMAL;
	goto pull;
}

struct packet_offload *gro_find_receive_by_type(__be16 type)
{
	struct list_head *offload_head = &offload_base;
	struct packet_offload *ptype;

	list_for_each_entry_rcu(ptype, offload_head, list) {
		if (ptype->type != type || !ptype->callbacks.gro_receive)
			continue;
		return ptype;
	}
	return NULL;
}
EXPORT_SYMBOL(gro_find_receive_by_type);

struct packet_offload *gro_find_complete_by_type(__be16 type)
{
	struct list_head *offload_head = &offload_base;
	struct packet_offload *ptype;

	list_for_each_entry_rcu(ptype, offload_head, list) {
		if (ptype->type != type || !ptype->callbacks.gro_complete)
			continue;
		return ptype;
	}
	return NULL;
}
EXPORT_SYMBOL(gro_find_complete_by_type);

static gro_result_t napi_skb_finish(gro_result_t ret, struct sk_buff *skb)
{
	switch (ret) {
	case GRO_NORMAL:
		if (netif_receive_skb_internal(skb))
			ret = GRO_DROP;
		break;

	case GRO_DROP:
		kfree_skb(skb);
		break;

	case GRO_MERGED_FREE:
		if (NAPI_GRO_CB(skb)->free == NAPI_GRO_FREE_STOLEN_HEAD) {
			skb_dst_drop(skb);
			kmem_cache_free(skbuff_head_cache, skb);
		} else {
			__kfree_skb(skb);
		}
		break;

	case GRO_HELD:
	case GRO_MERGED:
		break;
	}

	return ret;
}

gro_result_t napi_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
{
	trace_napi_gro_receive_entry(skb);

	skb_gro_reset_offset(skb);

	return napi_skb_finish(dev_gro_receive(napi, skb), skb);
}
EXPORT_SYMBOL(napi_gro_receive);

static void napi_reuse_skb(struct napi_struct *napi, struct sk_buff *skb)
{
	if (unlikely(skb->pfmemalloc)) {
		consume_skb(skb);
		return;
	}
	__skb_pull(skb, skb_headlen(skb));
	 
	skb_reserve(skb, NET_SKB_PAD + NET_IP_ALIGN - skb_headroom(skb));
	skb->vlan_tci = 0;
	skb->dev = napi->dev;
	skb->skb_iif = 0;
	skb->encapsulation = 0;
	skb_shinfo(skb)->gso_type = 0;
	skb->truesize = SKB_TRUESIZE(skb_end_offset(skb));

	napi->skb = skb;
}

struct sk_buff *napi_get_frags(struct napi_struct *napi)
{
	struct sk_buff *skb = napi->skb;

	if (!skb) {
		skb = napi_alloc_skb(napi, GRO_MAX_HEAD);
		napi->skb = skb;
	}
	return skb;
}
EXPORT_SYMBOL(napi_get_frags);

static gro_result_t napi_frags_finish(struct napi_struct *napi,
				      struct sk_buff *skb,
				      gro_result_t ret)
{
	switch (ret) {
	case GRO_NORMAL:
	case GRO_HELD:
		__skb_push(skb, ETH_HLEN);
		skb->protocol = eth_type_trans(skb, skb->dev);
		if (ret == GRO_NORMAL && netif_receive_skb_internal(skb))
			ret = GRO_DROP;
		break;

	case GRO_DROP:
	case GRO_MERGED_FREE:
		napi_reuse_skb(napi, skb);
		break;

	case GRO_MERGED:
		break;
	}

	return ret;
}

static struct sk_buff *napi_frags_skb(struct napi_struct *napi)
{
	struct sk_buff *skb = napi->skb;
	const struct ethhdr *eth;
	unsigned int hlen = sizeof(*eth);

	napi->skb = NULL;

	skb_reset_mac_header(skb);
	skb_gro_reset_offset(skb);

	eth = skb_gro_header_fast(skb, 0);
	if (unlikely(skb_gro_header_hard(skb, hlen))) {
		eth = skb_gro_header_slow(skb, hlen, 0);
		if (unlikely(!eth)) {
			napi_reuse_skb(napi, skb);
			return NULL;
		}
	} else {
		gro_pull_from_frag0(skb, hlen);
		NAPI_GRO_CB(skb)->frag0 += hlen;
		NAPI_GRO_CB(skb)->frag0_len -= hlen;
	}
	__skb_pull(skb, hlen);

	skb->protocol = eth->h_proto;

	return skb;
}

gro_result_t napi_gro_frags(struct napi_struct *napi)
{
	struct sk_buff *skb = napi_frags_skb(napi);

	if (!skb)
		return GRO_DROP;

	trace_napi_gro_frags_entry(skb);

	return napi_frags_finish(napi, skb, dev_gro_receive(napi, skb));
}
EXPORT_SYMBOL(napi_gro_frags);

__sum16 __skb_gro_checksum_complete(struct sk_buff *skb)
{
	__wsum wsum;
	__sum16 sum;

	wsum = skb_checksum(skb, skb_gro_offset(skb), skb_gro_len(skb), 0);

	sum = csum_fold(csum_add(NAPI_GRO_CB(skb)->csum, wsum));
	if (likely(!sum)) {
		if (unlikely(skb->ip_summed == CHECKSUM_COMPLETE) &&
		    !skb->csum_complete_sw)
			netdev_rx_csum_fault(skb->dev);
	}

	NAPI_GRO_CB(skb)->csum = wsum;
	NAPI_GRO_CB(skb)->csum_valid = 1;

	return sum;
}
EXPORT_SYMBOL(__skb_gro_checksum_complete);

static void net_rps_action_and_irq_enable(struct softnet_data *sd)
{
#ifdef CONFIG_RPS
	struct softnet_data *remsd = sd->rps_ipi_list;

	if (remsd) {
		sd->rps_ipi_list = NULL;

		local_irq_enable();

		while (remsd) {
			struct softnet_data *next = remsd->rps_ipi_next;

			if (cpu_online(remsd->cpu))
				smp_call_function_single_async(remsd->cpu,
							   &remsd->csd);
			remsd = next;
		}
	} else
#endif
		local_irq_enable();
}

static bool sd_has_rps_ipi_waiting(struct softnet_data *sd)
{
#ifdef CONFIG_RPS
	return sd->rps_ipi_list != NULL;
#else
	return false;
#endif
}

static int process_backlog(struct napi_struct *napi, int quota)
{
	int work = 0;
	struct softnet_data *sd = container_of(napi, struct softnet_data, backlog);

	if (sd_has_rps_ipi_waiting(sd)) {
		local_irq_disable();
		net_rps_action_and_irq_enable(sd);
	}

	napi->weight = weight_p;
	local_irq_disable();
	while (1) {
		struct sk_buff *skb;

		while ((skb = __skb_dequeue(&sd->process_queue))) {
			rcu_read_lock();
			local_irq_enable();
			__netif_receive_skb(skb);
			rcu_read_unlock();
			local_irq_disable();
			input_queue_head_incr(sd);
			if (++work >= quota) {
				local_irq_enable();
				return work;
			}
		}

		rps_lock(sd);
		if (skb_queue_empty(&sd->input_pkt_queue)) {
			 
			napi->state = 0;
			rps_unlock(sd);

			break;
		}

		skb_queue_splice_tail_init(&sd->input_pkt_queue,
					   &sd->process_queue);
		rps_unlock(sd);
	}
	local_irq_enable();

	return work;
}

void __napi_schedule(struct napi_struct *n)
{
	unsigned long flags;

	local_irq_save(flags);
	____napi_schedule(this_cpu_ptr(&softnet_data), n);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(__napi_schedule);

void __napi_schedule_irqoff(struct napi_struct *n)
{
	____napi_schedule(this_cpu_ptr(&softnet_data), n);
}
EXPORT_SYMBOL(__napi_schedule_irqoff);

void __napi_complete(struct napi_struct *n)
{
	BUG_ON(!test_bit(NAPI_STATE_SCHED, &n->state));

	list_del_init(&n->poll_list);
	smp_mb__before_atomic();
	clear_bit(NAPI_STATE_SCHED, &n->state);
}
EXPORT_SYMBOL(__napi_complete);

void napi_complete_done(struct napi_struct *n, int work_done)
{
	unsigned long flags;

	if (unlikely(test_bit(NAPI_STATE_NPSVC, &n->state)))
		return;

	if (n->gro_list) {
		unsigned long timeout = 0;

		if (work_done)
			timeout = n->dev->gro_flush_timeout;

		if (timeout)
			hrtimer_start(&n->timer, ns_to_ktime(timeout),
				      HRTIMER_MODE_REL_PINNED);
		else
			napi_gro_flush(n, false);
	}
	if (likely(list_empty(&n->poll_list))) {
		WARN_ON_ONCE(!test_and_clear_bit(NAPI_STATE_SCHED, &n->state));
	} else {
		 
		local_irq_save(flags);
		__napi_complete(n);
		local_irq_restore(flags);
	}
}
EXPORT_SYMBOL(napi_complete_done);

struct napi_struct *napi_by_id(unsigned int napi_id)
{
	unsigned int hash = napi_id % HASH_SIZE(napi_hash);
	struct napi_struct *napi;

	hlist_for_each_entry_rcu(napi, &napi_hash[hash], napi_hash_node)
		if (napi->napi_id == napi_id)
			return napi;

	return NULL;
}
EXPORT_SYMBOL_GPL(napi_by_id);

void napi_hash_add(struct napi_struct *napi)
{
	if (!test_and_set_bit(NAPI_STATE_HASHED, &napi->state)) {

		spin_lock(&napi_hash_lock);

		napi->napi_id = 0;
		while (!napi->napi_id) {
			napi->napi_id = ++napi_gen_id;
			if (napi_by_id(napi->napi_id))
				napi->napi_id = 0;
		}

		hlist_add_head_rcu(&napi->napi_hash_node,
			&napi_hash[napi->napi_id % HASH_SIZE(napi_hash)]);

		spin_unlock(&napi_hash_lock);
	}
}
EXPORT_SYMBOL_GPL(napi_hash_add);

void napi_hash_del(struct napi_struct *napi)
{
	spin_lock(&napi_hash_lock);

	if (test_and_clear_bit(NAPI_STATE_HASHED, &napi->state))
		hlist_del_rcu(&napi->napi_hash_node);

	spin_unlock(&napi_hash_lock);
}
EXPORT_SYMBOL_GPL(napi_hash_del);

static enum hrtimer_restart napi_watchdog(struct hrtimer *timer)
{
	struct napi_struct *napi;

	napi = container_of(timer, struct napi_struct, timer);
	if (napi->gro_list)
		napi_schedule(napi);

	return HRTIMER_NORESTART;
}

void netif_napi_add(struct net_device *dev, struct napi_struct *napi,
		    int (*poll)(struct napi_struct *, int), int weight)
{
	INIT_LIST_HEAD(&napi->poll_list);
	hrtimer_init(&napi->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED);
	napi->timer.function = napi_watchdog;
	napi->gro_count = 0;
	napi->gro_list = NULL;
	napi->skb = NULL;
	napi->poll = poll;
	if (weight > NAPI_POLL_WEIGHT)
		pr_err_once("netif_napi_add() called with weight %d on device %s\n",
			    weight, dev->name);
	napi->weight = weight;
	list_add(&napi->dev_list, &dev->napi_list);
	napi->dev = dev;
#ifdef CONFIG_NETPOLL
	spin_lock_init(&napi->poll_lock);
	napi->poll_owner = -1;
#endif
	set_bit(NAPI_STATE_SCHED, &napi->state);
}
EXPORT_SYMBOL(netif_napi_add);

void napi_disable(struct napi_struct *n)
{
	might_sleep();
	set_bit(NAPI_STATE_DISABLE, &n->state);

	while (test_and_set_bit(NAPI_STATE_SCHED, &n->state))
		msleep(1);
	while (test_and_set_bit(NAPI_STATE_NPSVC, &n->state))
		msleep(1);

	hrtimer_cancel(&n->timer);

	clear_bit(NAPI_STATE_DISABLE, &n->state);
}
EXPORT_SYMBOL(napi_disable);

void netif_napi_del(struct napi_struct *napi)
{
	list_del_init(&napi->dev_list);
	napi_free_frags(napi);

	kfree_skb_list(napi->gro_list);
	napi->gro_list = NULL;
	napi->gro_count = 0;
}
EXPORT_SYMBOL(netif_napi_del);

static int napi_poll(struct napi_struct *n, struct list_head *repoll)
{
	void *have;
	int work, weight;

	list_del_init(&n->poll_list);

	have = netpoll_poll_lock(n);

	weight = n->weight;

	work = 0;
	if (test_bit(NAPI_STATE_SCHED, &n->state)) {
		work = n->poll(n, weight);
		trace_napi_poll(n);
	}

	WARN_ON_ONCE(work > weight);

	if (likely(work < weight))
		goto out_unlock;

	if (unlikely(napi_disable_pending(n))) {
		napi_complete(n);
		goto out_unlock;
	}

	if (n->gro_list) {
		 
		napi_gro_flush(n, HZ >= 1000);
	}

	if (unlikely(!list_empty(&n->poll_list))) {
		pr_warn_once("%s: Budget exhausted after napi rescheduled\n",
			     n->dev ? n->dev->name : "backlog");
		goto out_unlock;
	}

	list_add_tail(&n->poll_list, repoll);

out_unlock:
	netpoll_poll_unlock(have);

	return work;
}

static void net_rx_action(struct softirq_action *h)
{
	struct softnet_data *sd = this_cpu_ptr(&softnet_data);
	unsigned long time_limit = jiffies + 2;
	int budget = netdev_budget;
	LIST_HEAD(list);
	LIST_HEAD(repoll);

	local_irq_disable();
	list_splice_init(&sd->poll_list, &list);
	local_irq_enable();

	for (;;) {
		struct napi_struct *n;

		if (list_empty(&list)) {
			if (!sd_has_rps_ipi_waiting(sd) && list_empty(&repoll))
				return;
			break;
		}

		n = list_first_entry(&list, struct napi_struct, poll_list);
		budget -= napi_poll(n, &repoll);

		if (unlikely(budget <= 0 ||
			     time_after_eq(jiffies, time_limit))) {
			sd->time_squeeze++;
			break;
		}
	}

	local_irq_disable();

	list_splice_tail_init(&sd->poll_list, &list);
	list_splice_tail(&repoll, &list);
	list_splice(&list, &sd->poll_list);
	if (!list_empty(&sd->poll_list))
		__raise_softirq_irqoff(NET_RX_SOFTIRQ);

	net_rps_action_and_irq_enable(sd);
}

struct netdev_adjacent {
	struct net_device *dev;

	bool master;

	u16 ref_nr;

	void *private;

	struct list_head list;
	struct rcu_head rcu;
};

static struct netdev_adjacent *__netdev_find_adj(struct net_device *adj_dev,
						 struct list_head *adj_list)
{
	struct netdev_adjacent *adj;

	list_for_each_entry(adj, adj_list, list) {
		if (adj->dev == adj_dev)
			return adj;
	}
	return NULL;
}

bool netdev_has_upper_dev(struct net_device *dev,
			  struct net_device *upper_dev)
{
	ASSERT_RTNL();

	return __netdev_find_adj(upper_dev, &dev->all_adj_list.upper);
}
EXPORT_SYMBOL(netdev_has_upper_dev);

static bool netdev_has_any_upper_dev(struct net_device *dev)
{
	ASSERT_RTNL();

	return !list_empty(&dev->all_adj_list.upper);
}

struct net_device *netdev_master_upper_dev_get(struct net_device *dev)
{
	struct netdev_adjacent *upper;

	ASSERT_RTNL();

	if (list_empty(&dev->adj_list.upper))
		return NULL;

	upper = list_first_entry(&dev->adj_list.upper,
				 struct netdev_adjacent, list);
	if (likely(upper->master))
		return upper->dev;
	return NULL;
}
EXPORT_SYMBOL(netdev_master_upper_dev_get);

void *netdev_adjacent_get_private(struct list_head *adj_list)
{
	struct netdev_adjacent *adj;

	adj = list_entry(adj_list, struct netdev_adjacent, list);

	return adj->private;
}
EXPORT_SYMBOL(netdev_adjacent_get_private);

struct net_device *netdev_upper_get_next_dev_rcu(struct net_device *dev,
						 struct list_head **iter)
{
	struct netdev_adjacent *upper;

	WARN_ON_ONCE(!rcu_read_lock_held() && !lockdep_rtnl_is_held());

	upper = list_entry_rcu((*iter)->next, struct netdev_adjacent, list);

	if (&upper->list == &dev->adj_list.upper)
		return NULL;

	*iter = &upper->list;

	return upper->dev;
}
EXPORT_SYMBOL(netdev_upper_get_next_dev_rcu);

struct net_device *netdev_all_upper_get_next_dev_rcu(struct net_device *dev,
						     struct list_head **iter)
{
	struct netdev_adjacent *upper;

	WARN_ON_ONCE(!rcu_read_lock_held() && !lockdep_rtnl_is_held());

	upper = list_entry_rcu((*iter)->next, struct netdev_adjacent, list);

	if (&upper->list == &dev->all_adj_list.upper)
		return NULL;

	*iter = &upper->list;

	return upper->dev;
}
EXPORT_SYMBOL(netdev_all_upper_get_next_dev_rcu);

void *netdev_lower_get_next_private(struct net_device *dev,
				    struct list_head **iter)
{
	struct netdev_adjacent *lower;

	lower = list_entry(*iter, struct netdev_adjacent, list);

	if (&lower->list == &dev->adj_list.lower)
		return NULL;

	*iter = lower->list.next;

	return lower->private;
}
EXPORT_SYMBOL(netdev_lower_get_next_private);

void *netdev_lower_get_next_private_rcu(struct net_device *dev,
					struct list_head **iter)
{
	struct netdev_adjacent *lower;

	WARN_ON_ONCE(!rcu_read_lock_held());

	lower = list_entry_rcu((*iter)->next, struct netdev_adjacent, list);

	if (&lower->list == &dev->adj_list.lower)
		return NULL;

	*iter = &lower->list;

	return lower->private;
}
EXPORT_SYMBOL(netdev_lower_get_next_private_rcu);

void *netdev_lower_get_next(struct net_device *dev, struct list_head **iter)
{
	struct netdev_adjacent *lower;

	lower = list_entry((*iter)->next, struct netdev_adjacent, list);

	if (&lower->list == &dev->adj_list.lower)
		return NULL;

	*iter = &lower->list;

	return lower->dev;
}
EXPORT_SYMBOL(netdev_lower_get_next);

void *netdev_lower_get_first_private_rcu(struct net_device *dev)
{
	struct netdev_adjacent *lower;

	lower = list_first_or_null_rcu(&dev->adj_list.lower,
			struct netdev_adjacent, list);
	if (lower)
		return lower->private;
	return NULL;
}
EXPORT_SYMBOL(netdev_lower_get_first_private_rcu);

struct net_device *netdev_master_upper_dev_get_rcu(struct net_device *dev)
{
	struct netdev_adjacent *upper;

	upper = list_first_or_null_rcu(&dev->adj_list.upper,
				       struct netdev_adjacent, list);
	if (upper && likely(upper->master))
		return upper->dev;
	return NULL;
}
EXPORT_SYMBOL(netdev_master_upper_dev_get_rcu);

static int netdev_adjacent_sysfs_add(struct net_device *dev,
			      struct net_device *adj_dev,
			      struct list_head *dev_list)
{
	char linkname[IFNAMSIZ+7];
	sprintf(linkname, dev_list == &dev->adj_list.upper ?
		"upper_%s" : "lower_%s", adj_dev->name);
	return sysfs_create_link(&(dev->dev.kobj), &(adj_dev->dev.kobj),
				 linkname);
}
static void netdev_adjacent_sysfs_del(struct net_device *dev,
			       char *name,
			       struct list_head *dev_list)
{
	char linkname[IFNAMSIZ+7];
	sprintf(linkname, dev_list == &dev->adj_list.upper ?
		"upper_%s" : "lower_%s", name);
	sysfs_remove_link(&(dev->dev.kobj), linkname);
}

static inline bool netdev_adjacent_is_neigh_list(struct net_device *dev,
						 struct net_device *adj_dev,
						 struct list_head *dev_list)
{
	return (dev_list == &dev->adj_list.upper ||
		dev_list == &dev->adj_list.lower) &&
		net_eq(dev_net(dev), dev_net(adj_dev));
}

static int __netdev_adjacent_dev_insert(struct net_device *dev,
					struct net_device *adj_dev,
					u16 ref_nr,
					struct list_head *dev_list,
					void *private, bool master)
{
	struct netdev_adjacent *adj;
	int ret;

	adj = __netdev_find_adj(adj_dev, dev_list);

	if (adj) {
		adj->ref_nr += ref_nr;
		return 0;
	}

	adj = kmalloc(sizeof(*adj), GFP_KERNEL);
	if (!adj)
		return -ENOMEM;

	adj->dev = adj_dev;
	adj->master = master;
	adj->ref_nr = ref_nr;
	adj->private = private;
	dev_hold(adj_dev);

	pr_debug("dev_hold for %s, because of link added from %s to %s\n",
		 adj_dev->name, dev->name, adj_dev->name);

	if (netdev_adjacent_is_neigh_list(dev, adj_dev, dev_list)) {
		ret = netdev_adjacent_sysfs_add(dev, adj_dev, dev_list);
		if (ret)
			goto free_adj;
	}

	if (master) {
		ret = sysfs_create_link(&(dev->dev.kobj),
					&(adj_dev->dev.kobj), "master");
		if (ret)
			goto remove_symlinks;

		list_add_rcu(&adj->list, dev_list);
	} else {
		list_add_tail_rcu(&adj->list, dev_list);
	}

	return 0;

remove_symlinks:
	if (netdev_adjacent_is_neigh_list(dev, adj_dev, dev_list))
		netdev_adjacent_sysfs_del(dev, adj_dev->name, dev_list);
free_adj:
	kfree(adj);
	dev_put(adj_dev);

	return ret;
}

static void __netdev_adjacent_dev_remove(struct net_device *dev,
					 struct net_device *adj_dev,
					 u16 ref_nr,
					 struct list_head *dev_list)
{
	struct netdev_adjacent *adj;

	adj = __netdev_find_adj(adj_dev, dev_list);

	if (!adj) {
		pr_err("tried to remove device %s from %s\n",
		       dev->name, adj_dev->name);
		BUG();
	}

	if (adj->ref_nr > ref_nr) {
		pr_debug("%s to %s ref_nr-%d = %d\n", dev->name, adj_dev->name,
			 ref_nr, adj->ref_nr-ref_nr);
		adj->ref_nr -= ref_nr;
		return;
	}

	if (adj->master)
		sysfs_remove_link(&(dev->dev.kobj), "master");

	if (netdev_adjacent_is_neigh_list(dev, adj_dev, dev_list))
		netdev_adjacent_sysfs_del(dev, adj_dev->name, dev_list);

	list_del_rcu(&adj->list);
	pr_debug("dev_put for %s, because link removed from %s to %s\n",
		 adj_dev->name, dev->name, adj_dev->name);
	dev_put(adj_dev);
	kfree_rcu(adj, rcu);
}

static int __netdev_adjacent_dev_link_lists(struct net_device *dev,
					    struct net_device *upper_dev,
					    u16 ref_nr,
					    struct list_head *up_list,
					    struct list_head *down_list,
					    void *private, bool master)
{
	int ret;

	ret = __netdev_adjacent_dev_insert(dev, upper_dev, ref_nr, up_list,
					   private, master);
	if (ret)
		return ret;

	ret = __netdev_adjacent_dev_insert(upper_dev, dev, ref_nr, down_list,
					   private, false);
	if (ret) {
		__netdev_adjacent_dev_remove(dev, upper_dev, ref_nr, up_list);
		return ret;
	}

	return 0;
}

static int __netdev_adjacent_dev_link(struct net_device *dev,
				      struct net_device *upper_dev,
				      u16 ref_nr)
{
	return __netdev_adjacent_dev_link_lists(dev, upper_dev, ref_nr,
						&dev->all_adj_list.upper,
						&upper_dev->all_adj_list.lower,
						NULL, false);
}

static void __netdev_adjacent_dev_unlink_lists(struct net_device *dev,
					       struct net_device *upper_dev,
					       u16 ref_nr,
					       struct list_head *up_list,
					       struct list_head *down_list)
{
	__netdev_adjacent_dev_remove(dev, upper_dev, ref_nr, up_list);
	__netdev_adjacent_dev_remove(upper_dev, dev, ref_nr, down_list);
}

static void __netdev_adjacent_dev_unlink(struct net_device *dev,
					 struct net_device *upper_dev,
					 u16 ref_nr)
{
	__netdev_adjacent_dev_unlink_lists(dev, upper_dev, ref_nr,
					   &dev->all_adj_list.upper,
					   &upper_dev->all_adj_list.lower);
}

static int __netdev_adjacent_dev_link_neighbour(struct net_device *dev,
						struct net_device *upper_dev,
						void *private, bool master)
{
	int ret = __netdev_adjacent_dev_link(dev, upper_dev, 1);

	if (ret)
		return ret;

	ret = __netdev_adjacent_dev_link_lists(dev, upper_dev, 1,
					       &dev->adj_list.upper,
					       &upper_dev->adj_list.lower,
					       private, master);
	if (ret) {
		__netdev_adjacent_dev_unlink(dev, upper_dev, 1);
		return ret;
	}

	return 0;
}

static void __netdev_adjacent_dev_unlink_neighbour(struct net_device *dev,
						   struct net_device *upper_dev)
{
	__netdev_adjacent_dev_unlink(dev, upper_dev, 1);
	__netdev_adjacent_dev_unlink_lists(dev, upper_dev, 1,
					   &dev->adj_list.upper,
					   &upper_dev->adj_list.lower);
}

static int __netdev_upper_dev_link(struct net_device *dev,
				   struct net_device *upper_dev, bool master,
				   void *private)
{
	struct netdev_notifier_changeupper_info changeupper_info;
	struct netdev_adjacent *i, *j, *to_i, *to_j;
	int ret = 0;

	ASSERT_RTNL();

	if (dev == upper_dev)
		return -EBUSY;

	if (__netdev_find_adj(dev, &upper_dev->all_adj_list.upper))
		return -EBUSY;

	if (__netdev_find_adj(upper_dev, &dev->adj_list.upper))
		return -EEXIST;

	if (master && netdev_master_upper_dev_get(dev))
		return -EBUSY;

	changeupper_info.upper_dev = upper_dev;
	changeupper_info.master = master;
	changeupper_info.linking = true;

	ret = call_netdevice_notifiers_info(NETDEV_PRECHANGEUPPER, dev,
					    &changeupper_info.info);
	ret = notifier_to_errno(ret);
	if (ret)
		return ret;

	ret = __netdev_adjacent_dev_link_neighbour(dev, upper_dev, private,
						   master);
	if (ret)
		return ret;

	list_for_each_entry(i, &dev->all_adj_list.lower, list) {
		list_for_each_entry(j, &upper_dev->all_adj_list.upper, list) {
			pr_debug("Interlinking %s with %s, non-neighbour\n",
				 i->dev->name, j->dev->name);
			ret = __netdev_adjacent_dev_link(i->dev, j->dev, i->ref_nr);
			if (ret)
				goto rollback_mesh;
		}
	}

	list_for_each_entry(i, &upper_dev->all_adj_list.upper, list) {
		pr_debug("linking %s's upper device %s with %s\n",
			 upper_dev->name, i->dev->name, dev->name);
		ret = __netdev_adjacent_dev_link(dev, i->dev, i->ref_nr);
		if (ret)
			goto rollback_upper_mesh;
	}

	list_for_each_entry(i, &dev->all_adj_list.lower, list) {
		pr_debug("linking %s's lower device %s with %s\n", dev->name,
			 i->dev->name, upper_dev->name);
		ret = __netdev_adjacent_dev_link(i->dev, upper_dev, i->ref_nr);
		if (ret)
			goto rollback_lower_mesh;
	}

	call_netdevice_notifiers_info(NETDEV_CHANGEUPPER, dev,
				      &changeupper_info.info);
	return 0;

rollback_lower_mesh:
	to_i = i;
	list_for_each_entry(i, &dev->all_adj_list.lower, list) {
		if (i == to_i)
			break;
		__netdev_adjacent_dev_unlink(i->dev, upper_dev, i->ref_nr);
	}

	i = NULL;

rollback_upper_mesh:
	to_i = i;
	list_for_each_entry(i, &upper_dev->all_adj_list.upper, list) {
		if (i == to_i)
			break;
		__netdev_adjacent_dev_unlink(dev, i->dev, i->ref_nr);
	}

	i = j = NULL;

rollback_mesh:
	to_i = i;
	to_j = j;
	list_for_each_entry(i, &dev->all_adj_list.lower, list) {
		list_for_each_entry(j, &upper_dev->all_adj_list.upper, list) {
			if (i == to_i && j == to_j)
				break;
			__netdev_adjacent_dev_unlink(i->dev, j->dev, i->ref_nr);
		}
		if (i == to_i)
			break;
	}

	__netdev_adjacent_dev_unlink_neighbour(dev, upper_dev);

	return ret;
}

int netdev_upper_dev_link(struct net_device *dev,
			  struct net_device *upper_dev)
{
	return __netdev_upper_dev_link(dev, upper_dev, false, NULL);
}
EXPORT_SYMBOL(netdev_upper_dev_link);

int netdev_master_upper_dev_link(struct net_device *dev,
				 struct net_device *upper_dev)
{
	return __netdev_upper_dev_link(dev, upper_dev, true, NULL);
}
EXPORT_SYMBOL(netdev_master_upper_dev_link);

int netdev_master_upper_dev_link_private(struct net_device *dev,
					 struct net_device *upper_dev,
					 void *private)
{
	return __netdev_upper_dev_link(dev, upper_dev, true, private);
}
EXPORT_SYMBOL(netdev_master_upper_dev_link_private);

void netdev_upper_dev_unlink(struct net_device *dev,
			     struct net_device *upper_dev)
{
	struct netdev_notifier_changeupper_info changeupper_info;
	struct netdev_adjacent *i, *j;
	ASSERT_RTNL();

	changeupper_info.upper_dev = upper_dev;
	changeupper_info.master = netdev_master_upper_dev_get(dev) == upper_dev;
	changeupper_info.linking = false;

	call_netdevice_notifiers_info(NETDEV_PRECHANGEUPPER, dev,
				      &changeupper_info.info);

	__netdev_adjacent_dev_unlink_neighbour(dev, upper_dev);

	list_for_each_entry(i, &dev->all_adj_list.lower, list)
		list_for_each_entry(j, &upper_dev->all_adj_list.upper, list)
			__netdev_adjacent_dev_unlink(i->dev, j->dev, i->ref_nr);

	list_for_each_entry(i, &dev->all_adj_list.lower, list)
		__netdev_adjacent_dev_unlink(i->dev, upper_dev, i->ref_nr);

	list_for_each_entry(i, &upper_dev->all_adj_list.upper, list)
		__netdev_adjacent_dev_unlink(dev, i->dev, i->ref_nr);

	call_netdevice_notifiers_info(NETDEV_CHANGEUPPER, dev,
				      &changeupper_info.info);
}
EXPORT_SYMBOL(netdev_upper_dev_unlink);

void netdev_bonding_info_change(struct net_device *dev,
				struct netdev_bonding_info *bonding_info)
{
	struct netdev_notifier_bonding_info	info;

	memcpy(&info.bonding_info, bonding_info,
	       sizeof(struct netdev_bonding_info));
	call_netdevice_notifiers_info(NETDEV_BONDING_INFO, dev,
				      &info.info);
}
EXPORT_SYMBOL(netdev_bonding_info_change);

static void netdev_adjacent_add_links(struct net_device *dev)
{
	struct netdev_adjacent *iter;

	struct net *net = dev_net(dev);

	list_for_each_entry(iter, &dev->adj_list.upper, list) {
		if (!net_eq(net,dev_net(iter->dev)))
			continue;
		netdev_adjacent_sysfs_add(iter->dev, dev,
					  &iter->dev->adj_list.lower);
		netdev_adjacent_sysfs_add(dev, iter->dev,
					  &dev->adj_list.upper);
	}

	list_for_each_entry(iter, &dev->adj_list.lower, list) {
		if (!net_eq(net,dev_net(iter->dev)))
			continue;
		netdev_adjacent_sysfs_add(iter->dev, dev,
					  &iter->dev->adj_list.upper);
		netdev_adjacent_sysfs_add(dev, iter->dev,
					  &dev->adj_list.lower);
	}
}

static void netdev_adjacent_del_links(struct net_device *dev)
{
	struct netdev_adjacent *iter;

	struct net *net = dev_net(dev);

	list_for_each_entry(iter, &dev->adj_list.upper, list) {
		if (!net_eq(net,dev_net(iter->dev)))
			continue;
		netdev_adjacent_sysfs_del(iter->dev, dev->name,
					  &iter->dev->adj_list.lower);
		netdev_adjacent_sysfs_del(dev, iter->dev->name,
					  &dev->adj_list.upper);
	}

	list_for_each_entry(iter, &dev->adj_list.lower, list) {
		if (!net_eq(net,dev_net(iter->dev)))
			continue;
		netdev_adjacent_sysfs_del(iter->dev, dev->name,
					  &iter->dev->adj_list.upper);
		netdev_adjacent_sysfs_del(dev, iter->dev->name,
					  &dev->adj_list.lower);
	}
}

void netdev_adjacent_rename_links(struct net_device *dev, char *oldname)
{
	struct netdev_adjacent *iter;

	struct net *net = dev_net(dev);

	list_for_each_entry(iter, &dev->adj_list.upper, list) {
		if (!net_eq(net,dev_net(iter->dev)))
			continue;
		netdev_adjacent_sysfs_del(iter->dev, oldname,
					  &iter->dev->adj_list.lower);
		netdev_adjacent_sysfs_add(iter->dev, dev,
					  &iter->dev->adj_list.lower);
	}

	list_for_each_entry(iter, &dev->adj_list.lower, list) {
		if (!net_eq(net,dev_net(iter->dev)))
			continue;
		netdev_adjacent_sysfs_del(iter->dev, oldname,
					  &iter->dev->adj_list.upper);
		netdev_adjacent_sysfs_add(iter->dev, dev,
					  &iter->dev->adj_list.upper);
	}
}

void *netdev_lower_dev_get_private(struct net_device *dev,
				   struct net_device *lower_dev)
{
	struct netdev_adjacent *lower;

	if (!lower_dev)
		return NULL;
	lower = __netdev_find_adj(lower_dev, &dev->adj_list.lower);
	if (!lower)
		return NULL;

	return lower->private;
}
EXPORT_SYMBOL(netdev_lower_dev_get_private);

int dev_get_nest_level(struct net_device *dev,
		       bool (*type_check)(struct net_device *dev))
{
	struct net_device *lower = NULL;
	struct list_head *iter;
	int max_nest = -1;
	int nest;

	ASSERT_RTNL();

	netdev_for_each_lower_dev(dev, lower, iter) {
		nest = dev_get_nest_level(lower, type_check);
		if (max_nest < nest)
			max_nest = nest;
	}

	if (type_check(dev))
		max_nest++;

	return max_nest;
}
EXPORT_SYMBOL(dev_get_nest_level);

static void dev_change_rx_flags(struct net_device *dev, int flags)
{
	const struct net_device_ops *ops = dev->netdev_ops;

	if (ops->ndo_change_rx_flags)
		ops->ndo_change_rx_flags(dev, flags);
}

static int __dev_set_promiscuity(struct net_device *dev, int inc, bool notify)
{
	unsigned int old_flags = dev->flags;
	kuid_t uid;
	kgid_t gid;

	ASSERT_RTNL();

	dev->flags |= IFF_PROMISC;
	dev->promiscuity += inc;
	if (dev->promiscuity == 0) {
		 
		if (inc < 0)
			dev->flags &= ~IFF_PROMISC;
		else {
			dev->promiscuity -= inc;
			pr_warn("%s: promiscuity touches roof, set promiscuity failed. promiscuity feature of device might be broken.\n",
				dev->name);
			return -EOVERFLOW;
		}
	}
	if (dev->flags != old_flags) {
		pr_info("device %s %s promiscuous mode\n",
			dev->name,
			dev->flags & IFF_PROMISC ? "entered" : "left");
		if (audit_enabled) {
			current_uid_gid(&uid, &gid);
			audit_log(current->audit_context, GFP_ATOMIC,
				AUDIT_ANOM_PROMISCUOUS,
				"dev=%s prom=%d old_prom=%d auid=%u uid=%u gid=%u ses=%u",
				dev->name, (dev->flags & IFF_PROMISC),
				(old_flags & IFF_PROMISC),
				from_kuid(&init_user_ns, audit_get_loginuid(current)),
				from_kuid(&init_user_ns, uid),
				from_kgid(&init_user_ns, gid),
				audit_get_sessionid(current));
		}

		dev_change_rx_flags(dev, IFF_PROMISC);
	}
	if (notify)
		__dev_notify_flags(dev, old_flags, IFF_PROMISC);
	return 0;
}

int dev_set_promiscuity(struct net_device *dev, int inc)
{
	unsigned int old_flags = dev->flags;
	int err;

	err = __dev_set_promiscuity(dev, inc, true);
	if (err < 0)
		return err;
	if (dev->flags != old_flags)
		dev_set_rx_mode(dev);
	return err;
}
EXPORT_SYMBOL(dev_set_promiscuity);

static int __dev_set_allmulti(struct net_device *dev, int inc, bool notify)
{
	unsigned int old_flags = dev->flags, old_gflags = dev->gflags;

	ASSERT_RTNL();

	dev->flags |= IFF_ALLMULTI;
	dev->allmulti += inc;
	if (dev->allmulti == 0) {
		 
		if (inc < 0)
			dev->flags &= ~IFF_ALLMULTI;
		else {
			dev->allmulti -= inc;
			pr_warn("%s: allmulti touches roof, set allmulti failed. allmulti feature of device might be broken.\n",
				dev->name);
			return -EOVERFLOW;
		}
	}
	if (dev->flags ^ old_flags) {
		dev_change_rx_flags(dev, IFF_ALLMULTI);
		dev_set_rx_mode(dev);
		if (notify)
			__dev_notify_flags(dev, old_flags,
					   dev->gflags ^ old_gflags);
	}
	return 0;
}

int dev_set_allmulti(struct net_device *dev, int inc)
{
	return __dev_set_allmulti(dev, inc, true);
}
EXPORT_SYMBOL(dev_set_allmulti);

void __dev_set_rx_mode(struct net_device *dev)
{
	const struct net_device_ops *ops = dev->netdev_ops;

	if (!(dev->flags&IFF_UP))
		return;

	if (!netif_device_present(dev))
		return;

	if (!(dev->priv_flags & IFF_UNICAST_FLT)) {
		 
		if (!netdev_uc_empty(dev) && !dev->uc_promisc) {
			__dev_set_promiscuity(dev, 1, false);
			dev->uc_promisc = true;
		} else if (netdev_uc_empty(dev) && dev->uc_promisc) {
			__dev_set_promiscuity(dev, -1, false);
			dev->uc_promisc = false;
		}
	}

	if (ops->ndo_set_rx_mode)
		ops->ndo_set_rx_mode(dev);
}

void dev_set_rx_mode(struct net_device *dev)
{
	netif_addr_lock_bh(dev);
	__dev_set_rx_mode(dev);
	netif_addr_unlock_bh(dev);
}

unsigned int dev_get_flags(const struct net_device *dev)
{
	unsigned int flags;

	flags = (dev->flags & ~(IFF_PROMISC |
				IFF_ALLMULTI |
				IFF_RUNNING |
				IFF_LOWER_UP |
				IFF_DORMANT)) |
		(dev->gflags & (IFF_PROMISC |
				IFF_ALLMULTI));

	if (netif_running(dev)) {
		if (netif_oper_up(dev))
			flags |= IFF_RUNNING;
		if (netif_carrier_ok(dev))
			flags |= IFF_LOWER_UP;
		if (netif_dormant(dev))
			flags |= IFF_DORMANT;
	}

	return flags;
}
EXPORT_SYMBOL(dev_get_flags);

int __dev_change_flags(struct net_device *dev, unsigned int flags)
{
	unsigned int old_flags = dev->flags;
	int ret;

	ASSERT_RTNL();

	dev->flags = (flags & (IFF_DEBUG | IFF_NOTRAILERS | IFF_NOARP |
			       IFF_DYNAMIC | IFF_MULTICAST | IFF_PORTSEL |
			       IFF_AUTOMEDIA)) |
		     (dev->flags & (IFF_UP | IFF_VOLATILE | IFF_PROMISC |
				    IFF_ALLMULTI));

	if ((old_flags ^ flags) & IFF_MULTICAST)
		dev_change_rx_flags(dev, IFF_MULTICAST);

	dev_set_rx_mode(dev);

	ret = 0;
	if ((old_flags ^ flags) & IFF_UP)
		ret = ((old_flags & IFF_UP) ? __dev_close : __dev_open)(dev);

	if ((flags ^ dev->gflags) & IFF_PROMISC) {
		int inc = (flags & IFF_PROMISC) ? 1 : -1;
		unsigned int old_flags = dev->flags;

		dev->gflags ^= IFF_PROMISC;

		if (__dev_set_promiscuity(dev, inc, false) >= 0)
			if (dev->flags != old_flags)
				dev_set_rx_mode(dev);
	}

	if ((flags ^ dev->gflags) & IFF_ALLMULTI) {
		int inc = (flags & IFF_ALLMULTI) ? 1 : -1;

		dev->gflags ^= IFF_ALLMULTI;
		__dev_set_allmulti(dev, inc, false);
	}

	return ret;
}

void __dev_notify_flags(struct net_device *dev, unsigned int old_flags,
			unsigned int gchanges)
{
	unsigned int changes = dev->flags ^ old_flags;

	if (gchanges)
		rtmsg_ifinfo(RTM_NEWLINK, dev, gchanges, GFP_ATOMIC);

	if (changes & IFF_UP) {
		if (dev->flags & IFF_UP)
			call_netdevice_notifiers(NETDEV_UP, dev);
		else
			call_netdevice_notifiers(NETDEV_DOWN, dev);
	}

	if (dev->flags & IFF_UP &&
	    (changes & ~(IFF_UP | IFF_PROMISC | IFF_ALLMULTI | IFF_VOLATILE))) {
		struct netdev_notifier_change_info change_info;

		change_info.flags_changed = changes;
		call_netdevice_notifiers_info(NETDEV_CHANGE, dev,
					      &change_info.info);
	}
}

int dev_change_flags(struct net_device *dev, unsigned int flags)
{
	int ret;
	unsigned int changes, old_flags = dev->flags, old_gflags = dev->gflags;

	ret = __dev_change_flags(dev, flags);
	if (ret < 0)
		return ret;

	changes = (old_flags ^ dev->flags) | (old_gflags ^ dev->gflags);
	__dev_notify_flags(dev, old_flags, changes);
	return ret;
}
EXPORT_SYMBOL(dev_change_flags);

static int __dev_set_mtu(struct net_device *dev, int new_mtu)
{
	const struct net_device_ops *ops = dev->netdev_ops;

	if (ops->ndo_change_mtu)
		return ops->ndo_change_mtu(dev, new_mtu);

	dev->mtu = new_mtu;
	return 0;
}

int dev_set_mtu(struct net_device *dev, int new_mtu)
{
	int err, orig_mtu;

	if (new_mtu == dev->mtu)
		return 0;

	if (new_mtu < 0)
		return -EINVAL;

	if (!netif_device_present(dev))
		return -ENODEV;

	err = call_netdevice_notifiers(NETDEV_PRECHANGEMTU, dev);
	err = notifier_to_errno(err);
	if (err)
		return err;

	orig_mtu = dev->mtu;
	err = __dev_set_mtu(dev, new_mtu);

	if (!err) {
		err = call_netdevice_notifiers(NETDEV_CHANGEMTU, dev);
		err = notifier_to_errno(err);
		if (err) {
			 
			__dev_set_mtu(dev, orig_mtu);
			call_netdevice_notifiers(NETDEV_CHANGEMTU, dev);
		}
	}
	return err;
}
EXPORT_SYMBOL(dev_set_mtu);

void dev_set_group(struct net_device *dev, int new_group)
{
	dev->group = new_group;
}
EXPORT_SYMBOL(dev_set_group);

int dev_set_mac_address(struct net_device *dev, struct sockaddr *sa)
{
	const struct net_device_ops *ops = dev->netdev_ops;
	int err;

	if (!ops->ndo_set_mac_address)
		return -EOPNOTSUPP;
	if (sa->sa_family != dev->type)
		return -EINVAL;
	if (!netif_device_present(dev))
		return -ENODEV;
	err = ops->ndo_set_mac_address(dev, sa);
	if (err)
		return err;
	dev->addr_assign_type = NET_ADDR_SET;
	call_netdevice_notifiers(NETDEV_CHANGEADDR, dev);
	add_device_randomness(dev->dev_addr, dev->addr_len);
	return 0;
}
EXPORT_SYMBOL(dev_set_mac_address);

int dev_change_carrier(struct net_device *dev, bool new_carrier)
{
	const struct net_device_ops *ops = dev->netdev_ops;

	if (!ops->ndo_change_carrier)
		return -EOPNOTSUPP;
	if (!netif_device_present(dev))
		return -ENODEV;
	return ops->ndo_change_carrier(dev, new_carrier);
}
EXPORT_SYMBOL(dev_change_carrier);

int dev_get_phys_port_id(struct net_device *dev,
			 struct netdev_phys_item_id *ppid)
{
	const struct net_device_ops *ops = dev->netdev_ops;

	if (!ops->ndo_get_phys_port_id)
		return -EOPNOTSUPP;
	return ops->ndo_get_phys_port_id(dev, ppid);
}
EXPORT_SYMBOL(dev_get_phys_port_id);

int dev_get_phys_port_name(struct net_device *dev,
			   char *name, size_t len)
{
	const struct net_device_ops *ops = dev->netdev_ops;

	if (!ops->ndo_get_phys_port_name)
		return -EOPNOTSUPP;
	return ops->ndo_get_phys_port_name(dev, name, len);
}
EXPORT_SYMBOL(dev_get_phys_port_name);

int dev_change_proto_down(struct net_device *dev, bool proto_down)
{
	const struct net_device_ops *ops = dev->netdev_ops;

	if (!ops->ndo_change_proto_down)
		return -EOPNOTSUPP;
	if (!netif_device_present(dev))
		return -ENODEV;
	return ops->ndo_change_proto_down(dev, proto_down);
}
EXPORT_SYMBOL(dev_change_proto_down);

static int dev_new_index(struct net *net)
{
	int ifindex = net->ifindex;
	for (;;) {
		if (++ifindex <= 0)
			ifindex = 1;
		if (!__dev_get_by_index(net, ifindex))
			return net->ifindex = ifindex;
	}
}

static LIST_HEAD(net_todo_list);
DECLARE_WAIT_QUEUE_HEAD(netdev_unregistering_wq);

static void net_set_todo(struct net_device *dev)
{
	list_add_tail(&dev->todo_list, &net_todo_list);
	dev_net(dev)->dev_unreg_count++;
}

static void rollback_registered_many(struct list_head *head)
{
	struct net_device *dev, *tmp;
	LIST_HEAD(close_head);

	BUG_ON(dev_boot_phase);
	ASSERT_RTNL();

	list_for_each_entry_safe(dev, tmp, head, unreg_list) {
		 
		if (dev->reg_state == NETREG_UNINITIALIZED) {
			pr_debug("unregister_netdevice: device %s/%p never was registered\n",
				 dev->name, dev);

			WARN_ON(1);
			list_del(&dev->unreg_list);
			continue;
		}
		dev->dismantle = true;
		BUG_ON(dev->reg_state != NETREG_REGISTERED);
	}

	list_for_each_entry(dev, head, unreg_list)
		list_add_tail(&dev->close_list, &close_head);
	dev_close_many(&close_head, true);

	list_for_each_entry(dev, head, unreg_list) {
		 
		unlist_netdevice(dev);

		dev->reg_state = NETREG_UNREGISTERING;
		on_each_cpu(flush_backlog, dev, 1);
	}

	synchronize_net();

	list_for_each_entry(dev, head, unreg_list) {
		struct sk_buff *skb = NULL;

		dev_shutdown(dev);

		call_netdevice_notifiers(NETDEV_UNREGISTER, dev);

		if (!dev->rtnl_link_ops ||
		    dev->rtnl_link_state == RTNL_LINK_INITIALIZED)
			skb = rtmsg_ifinfo_build_skb(RTM_DELLINK, dev, ~0U,
						     GFP_KERNEL);

		dev_uc_flush(dev);
		dev_mc_flush(dev);

		if (dev->netdev_ops->ndo_uninit)
			dev->netdev_ops->ndo_uninit(dev);

		if (skb)
			rtmsg_ifinfo_send(skb, dev, GFP_KERNEL);

		WARN_ON(netdev_has_any_upper_dev(dev));

		netdev_unregister_kobject(dev);
#ifdef CONFIG_XPS
		 
		netif_reset_xps_queues_gt(dev, 0);
#endif
	}

	synchronize_net();

	list_for_each_entry(dev, head, unreg_list)
		dev_put(dev);
}

static void rollback_registered(struct net_device *dev)
{
	LIST_HEAD(single);

	list_add(&dev->unreg_list, &single);
	rollback_registered_many(&single);
	list_del(&single);
}

static netdev_features_t netdev_sync_upper_features(struct net_device *lower,
	struct net_device *upper, netdev_features_t features)
{
	netdev_features_t upper_disables = NETIF_F_UPPER_DISABLES;
	netdev_features_t feature;
	int feature_bit;

	for_each_netdev_feature(&upper_disables, feature_bit) {
		feature = __NETIF_F_BIT(feature_bit);
		if (!(upper->wanted_features & feature)
		    && (features & feature)) {
			netdev_dbg(lower, "Dropping feature %pNF, upper dev %s has it off.\n",
				   &feature, upper->name);
			features &= ~feature;
		}
	}

	return features;
}

static void netdev_sync_lower_features(struct net_device *upper,
	struct net_device *lower, netdev_features_t features)
{
	netdev_features_t upper_disables = NETIF_F_UPPER_DISABLES;
	netdev_features_t feature;
	int feature_bit;

	for_each_netdev_feature(&upper_disables, feature_bit) {
		feature = __NETIF_F_BIT(feature_bit);
		if (!(features & feature) && (lower->features & feature)) {
			netdev_dbg(upper, "Disabling feature %pNF on lower dev %s.\n",
				   &feature, lower->name);
			lower->wanted_features &= ~feature;
			netdev_update_features(lower);

			if (unlikely(lower->features & feature))
				netdev_WARN(upper, "failed to disable %pNF on %s!\n",
					    &feature, lower->name);
		}
	}
}

static netdev_features_t netdev_fix_features(struct net_device *dev,
	netdev_features_t features)
{
	 
	if ((features & NETIF_F_HW_CSUM) &&
	    (features & (NETIF_F_IP_CSUM|NETIF_F_IPV6_CSUM))) {
		netdev_warn(dev, "mixed HW and IP checksum settings.\n");
		features &= ~(NETIF_F_IP_CSUM|NETIF_F_IPV6_CSUM);
	}

	if ((features & NETIF_F_ALL_TSO) && !(features & NETIF_F_SG)) {
		netdev_dbg(dev, "Dropping TSO features since no SG feature.\n");
		features &= ~NETIF_F_ALL_TSO;
	}

	if ((features & NETIF_F_TSO) && !(features & NETIF_F_HW_CSUM) &&
					!(features & NETIF_F_IP_CSUM)) {
		netdev_dbg(dev, "Dropping TSO features since no CSUM feature.\n");
		features &= ~NETIF_F_TSO;
		features &= ~NETIF_F_TSO_ECN;
	}

	if ((features & NETIF_F_TSO6) && !(features & NETIF_F_HW_CSUM) &&
					 !(features & NETIF_F_IPV6_CSUM)) {
		netdev_dbg(dev, "Dropping TSO6 features since no CSUM feature.\n");
		features &= ~NETIF_F_TSO6;
	}

	if ((features & NETIF_F_ALL_TSO) == NETIF_F_TSO_ECN)
		features &= ~NETIF_F_TSO_ECN;

	if ((features & NETIF_F_GSO) && !(features & NETIF_F_SG)) {
		netdev_dbg(dev, "Dropping NETIF_F_GSO since no SG feature.\n");
		features &= ~NETIF_F_GSO;
	}

	if (features & NETIF_F_UFO) {
		 
		if (!((features & NETIF_F_GEN_CSUM) ||
		    (features & (NETIF_F_IP_CSUM|NETIF_F_IPV6_CSUM))
			    == (NETIF_F_IP_CSUM|NETIF_F_IPV6_CSUM))) {
			netdev_dbg(dev,
				"Dropping NETIF_F_UFO since no checksum offload features.\n");
			features &= ~NETIF_F_UFO;
		}

		if (!(features & NETIF_F_SG)) {
			netdev_dbg(dev,
				"Dropping NETIF_F_UFO since no NETIF_F_SG feature.\n");
			features &= ~NETIF_F_UFO;
		}
	}

#ifdef CONFIG_NET_RX_BUSY_POLL
	if (dev->netdev_ops->ndo_busy_poll)
		features |= NETIF_F_BUSY_POLL;
	else
#endif
		features &= ~NETIF_F_BUSY_POLL;

	return features;
}

int __netdev_update_features(struct net_device *dev)
{
	struct net_device *upper, *lower;
	netdev_features_t features;
	struct list_head *iter;
	int err = -1;

	ASSERT_RTNL();

	features = netdev_get_wanted_features(dev);

	if (dev->netdev_ops->ndo_fix_features)
		features = dev->netdev_ops->ndo_fix_features(dev, features);

	features = netdev_fix_features(dev, features);

	netdev_for_each_upper_dev_rcu(dev, upper, iter)
		features = netdev_sync_upper_features(dev, upper, features);

	if (dev->features == features)
		goto sync_lower;

	netdev_dbg(dev, "Features changed: %pNF -> %pNF\n",
		&dev->features, &features);

	if (dev->netdev_ops->ndo_set_features)
		err = dev->netdev_ops->ndo_set_features(dev, features);
	else
		err = 0;

	if (unlikely(err < 0)) {
		netdev_err(dev,
			"set_features() failed (%d); wanted %pNF, left %pNF\n",
			err, &features, &dev->features);
		 
		return -1;
	}

sync_lower:
	 
	netdev_for_each_lower_dev(dev, lower, iter)
		netdev_sync_lower_features(dev, lower, features);

	if (!err)
		dev->features = features;

	return err < 0 ? 0 : 1;
}

void netdev_update_features(struct net_device *dev)
{
	if (__netdev_update_features(dev))
		netdev_features_change(dev);
}
EXPORT_SYMBOL(netdev_update_features);

void netdev_change_features(struct net_device *dev)
{
	__netdev_update_features(dev);
	netdev_features_change(dev);
}
EXPORT_SYMBOL(netdev_change_features);

void netif_stacked_transfer_operstate(const struct net_device *rootdev,
					struct net_device *dev)
{
	if (rootdev->operstate == IF_OPER_DORMANT)
		netif_dormant_on(dev);
	else
		netif_dormant_off(dev);

	if (netif_carrier_ok(rootdev)) {
		if (!netif_carrier_ok(dev))
			netif_carrier_on(dev);
	} else {
		if (netif_carrier_ok(dev))
			netif_carrier_off(dev);
	}
}
EXPORT_SYMBOL(netif_stacked_transfer_operstate);

#ifdef CONFIG_SYSFS
static int netif_alloc_rx_queues(struct net_device *dev)
{
	unsigned int i, count = dev->num_rx_queues;
	struct netdev_rx_queue *rx;
	size_t sz = count * sizeof(*rx);

	BUG_ON(count < 1);

	rx = kzalloc(sz, GFP_KERNEL | __GFP_NOWARN | __GFP_REPEAT);
	if (!rx) {
		rx = vzalloc(sz);
		if (!rx)
			return -ENOMEM;
	}
	dev->_rx = rx;

	for (i = 0; i < count; i++)
		rx[i].dev = dev;
	return 0;
}
#endif

static void netdev_init_one_queue(struct net_device *dev,
				  struct netdev_queue *queue, void *_unused)
{
	 
	spin_lock_init(&queue->_xmit_lock);
	netdev_set_xmit_lockdep_class(&queue->_xmit_lock, dev->type);
	queue->xmit_lock_owner = -1;
	netdev_queue_numa_node_write(queue, NUMA_NO_NODE);
	queue->dev = dev;
#ifdef CONFIG_BQL
	dql_init(&queue->dql, HZ);
#endif
}

static void netif_free_tx_queues(struct net_device *dev)
{
	kvfree(dev->_tx);
}

static int netif_alloc_netdev_queues(struct net_device *dev)
{
	unsigned int count = dev->num_tx_queues;
	struct netdev_queue *tx;
	size_t sz = count * sizeof(*tx);

	if (count < 1 || count > 0xffff)
		return -EINVAL;

	tx = kzalloc(sz, GFP_KERNEL | __GFP_NOWARN | __GFP_REPEAT);
	if (!tx) {
		tx = vzalloc(sz);
		if (!tx)
			return -ENOMEM;
	}
	dev->_tx = tx;

	netdev_for_each_tx_queue(dev, netdev_init_one_queue, NULL);
	spin_lock_init(&dev->tx_global_lock);

	return 0;
}

void netif_tx_stop_all_queues(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		netif_tx_stop_queue(txq);
	}
}
EXPORT_SYMBOL(netif_tx_stop_all_queues);

int register_netdevice(struct net_device *dev)
{
	int ret;
	struct net *net = dev_net(dev);

	BUG_ON(dev_boot_phase);
	ASSERT_RTNL();

	might_sleep();

	BUG_ON(dev->reg_state != NETREG_UNINITIALIZED);
	BUG_ON(!net);

	spin_lock_init(&dev->addr_list_lock);
	netdev_set_addr_lockdep_class(dev);

	ret = dev_get_valid_name(net, dev, dev->name);
	if (ret < 0)
		goto out;

	if (dev->netdev_ops->ndo_init) {
		ret = dev->netdev_ops->ndo_init(dev);
		if (ret) {
			if (ret > 0)
				ret = -EIO;
			goto out;
		}
	}

	if (((dev->hw_features | dev->features) &
	     NETIF_F_HW_VLAN_CTAG_FILTER) &&
	    (!dev->netdev_ops->ndo_vlan_rx_add_vid ||
	     !dev->netdev_ops->ndo_vlan_rx_kill_vid)) {
		netdev_WARN(dev, "Buggy VLAN acceleration in driver!\n");
		ret = -EINVAL;
		goto err_uninit;
	}

	ret = -EBUSY;
	if (!dev->ifindex)
		dev->ifindex = dev_new_index(net);
	else if (__dev_get_by_index(net, dev->ifindex))
		goto err_uninit;

	dev->hw_features |= NETIF_F_SOFT_FEATURES;
	dev->features |= NETIF_F_SOFT_FEATURES;
	dev->wanted_features = dev->features & dev->hw_features;

	if (!(dev->flags & IFF_LOOPBACK)) {
		dev->hw_features |= NETIF_F_NOCACHE_COPY;
	}

	dev->vlan_features |= NETIF_F_HIGHDMA;

	dev->hw_enc_features |= NETIF_F_SG;

	dev->mpls_features |= NETIF_F_SG;

	ret = call_netdevice_notifiers(NETDEV_POST_INIT, dev);
	ret = notifier_to_errno(ret);
	if (ret)
		goto err_uninit;

	ret = netdev_register_kobject(dev);
	if (ret)
		goto err_uninit;
	dev->reg_state = NETREG_REGISTERED;

	__netdev_update_features(dev);

	set_bit(__LINK_STATE_PRESENT, &dev->state);

	linkwatch_init_dev(dev);

	dev_init_scheduler(dev);
	dev_hold(dev);
	list_netdevice(dev);
	add_device_randomness(dev->dev_addr, dev->addr_len);

	if (dev->addr_assign_type == NET_ADDR_PERM)
		memcpy(dev->perm_addr, dev->dev_addr, dev->addr_len);

	ret = call_netdevice_notifiers(NETDEV_REGISTER, dev);
	ret = notifier_to_errno(ret);
	if (ret) {
		rollback_registered(dev);
		dev->reg_state = NETREG_UNREGISTERED;
	}
	 
	if (!dev->rtnl_link_ops ||
	    dev->rtnl_link_state == RTNL_LINK_INITIALIZED)
		rtmsg_ifinfo(RTM_NEWLINK, dev, ~0U, GFP_KERNEL);

out:
	return ret;

err_uninit:
	if (dev->netdev_ops->ndo_uninit)
		dev->netdev_ops->ndo_uninit(dev);
	goto out;
}
EXPORT_SYMBOL(register_netdevice);

int init_dummy_netdev(struct net_device *dev)
{
	 
	memset(dev, 0, sizeof(struct net_device));

	dev->reg_state = NETREG_DUMMY;

	INIT_LIST_HEAD(&dev->napi_list);

	set_bit(__LINK_STATE_PRESENT, &dev->state);
	set_bit(__LINK_STATE_START, &dev->state);

	return 0;
}
EXPORT_SYMBOL_GPL(init_dummy_netdev);

int register_netdev(struct net_device *dev)
{
	int err;

	rtnl_lock();
	err = register_netdevice(dev);
	rtnl_unlock();
	return err;
}
EXPORT_SYMBOL(register_netdev);

int netdev_refcnt_read(const struct net_device *dev)
{
	int i, refcnt = 0;

	for_each_possible_cpu(i)
		refcnt += *per_cpu_ptr(dev->pcpu_refcnt, i);
	return refcnt;
}
EXPORT_SYMBOL(netdev_refcnt_read);

static void netdev_wait_allrefs(struct net_device *dev)
{
	unsigned long rebroadcast_time, warning_time;
	int refcnt;

	linkwatch_forget_dev(dev);

	rebroadcast_time = warning_time = jiffies;
	refcnt = netdev_refcnt_read(dev);

	while (refcnt != 0) {
		if (time_after(jiffies, rebroadcast_time + 1 * HZ)) {
			rtnl_lock();

			call_netdevice_notifiers(NETDEV_UNREGISTER, dev);

			__rtnl_unlock();
			rcu_barrier();
			rtnl_lock();

			call_netdevice_notifiers(NETDEV_UNREGISTER_FINAL, dev);
			if (test_bit(__LINK_STATE_LINKWATCH_PENDING,
				     &dev->state)) {
				 
				linkwatch_run_queue();
			}

			__rtnl_unlock();

			rebroadcast_time = jiffies;
		}

		msleep(250);

		refcnt = netdev_refcnt_read(dev);

		if (time_after(jiffies, warning_time + 10 * HZ)) {
			pr_emerg("unregister_netdevice: waiting for %s to become free. Usage count = %d\n",
				 dev->name, refcnt);
			warning_time = jiffies;
		}
	}
}

void netdev_run_todo(void)
{
	struct list_head list;

	list_replace_init(&net_todo_list, &list);

	__rtnl_unlock();

	if (!list_empty(&list))
		rcu_barrier();

	while (!list_empty(&list)) {
		struct net_device *dev
			= list_first_entry(&list, struct net_device, todo_list);
		list_del(&dev->todo_list);

		rtnl_lock();
		call_netdevice_notifiers(NETDEV_UNREGISTER_FINAL, dev);
		__rtnl_unlock();

		if (unlikely(dev->reg_state != NETREG_UNREGISTERING)) {
			pr_err("network todo '%s' but state %d\n",
			       dev->name, dev->reg_state);
			dump_stack();
			continue;
		}

		dev->reg_state = NETREG_UNREGISTERED;

		netdev_wait_allrefs(dev);

		BUG_ON(netdev_refcnt_read(dev));
		BUG_ON(!list_empty(&dev->ptype_all));
		BUG_ON(!list_empty(&dev->ptype_specific));
		WARN_ON(rcu_access_pointer(dev->ip_ptr));
		WARN_ON(rcu_access_pointer(dev->ip6_ptr));
		WARN_ON(dev->dn_ptr);

		if (dev->destructor)
			dev->destructor(dev);

		rtnl_lock();
		dev_net(dev)->dev_unreg_count--;
		__rtnl_unlock();
		wake_up(&netdev_unregistering_wq);

		kobject_put(&dev->dev.kobj);
	}
}

void netdev_stats_to_stats64(struct rtnl_link_stats64 *stats64,
			     const struct net_device_stats *netdev_stats)
{
#if BITS_PER_LONG == 64
	BUILD_BUG_ON(sizeof(*stats64) != sizeof(*netdev_stats));
	memcpy(stats64, netdev_stats, sizeof(*stats64));
#else
	size_t i, n = sizeof(*stats64) / sizeof(u64);
	const unsigned long *src = (const unsigned long *)netdev_stats;
	u64 *dst = (u64 *)stats64;

	BUILD_BUG_ON(sizeof(*netdev_stats) / sizeof(unsigned long) !=
		     sizeof(*stats64) / sizeof(u64));
	for (i = 0; i < n; i++)
		dst[i] = src[i];
#endif
}
EXPORT_SYMBOL(netdev_stats_to_stats64);

struct rtnl_link_stats64 *dev_get_stats(struct net_device *dev,
					struct rtnl_link_stats64 *storage)
{
	const struct net_device_ops *ops = dev->netdev_ops;

	if (ops->ndo_get_stats64) {
		memset(storage, 0, sizeof(*storage));
		ops->ndo_get_stats64(dev, storage);
	} else if (ops->ndo_get_stats) {
		netdev_stats_to_stats64(storage, ops->ndo_get_stats(dev));
	} else {
		netdev_stats_to_stats64(storage, &dev->stats);
	}
#if defined(MY_ABC_HERE)
	 
#else
	storage->rx_dropped += atomic_long_read(&dev->rx_dropped);
#endif  
	storage->tx_dropped += atomic_long_read(&dev->tx_dropped);
	return storage;
}
EXPORT_SYMBOL(dev_get_stats);

struct netdev_queue *dev_ingress_queue_create(struct net_device *dev)
{
	struct netdev_queue *queue = dev_ingress_queue(dev);

#ifdef CONFIG_NET_CLS_ACT
	if (queue)
		return queue;
	queue = kzalloc(sizeof(*queue), GFP_KERNEL);
	if (!queue)
		return NULL;
	netdev_init_one_queue(dev, queue, NULL);
	RCU_INIT_POINTER(queue->qdisc, &noop_qdisc);
	queue->qdisc_sleeping = &noop_qdisc;
	rcu_assign_pointer(dev->ingress_queue, queue);
#endif
	return queue;
}

static const struct ethtool_ops default_ethtool_ops;

void netdev_set_default_ethtool_ops(struct net_device *dev,
				    const struct ethtool_ops *ops)
{
	if (dev->ethtool_ops == &default_ethtool_ops)
		dev->ethtool_ops = ops;
}
EXPORT_SYMBOL_GPL(netdev_set_default_ethtool_ops);

void netdev_freemem(struct net_device *dev)
{
	char *addr = (char *)dev - dev->padded;

	kvfree(addr);
}

struct net_device *alloc_netdev_mqs(int sizeof_priv, const char *name,
		unsigned char name_assign_type,
		void (*setup)(struct net_device *),
		unsigned int txqs, unsigned int rxqs)
{
	struct net_device *dev;
	size_t alloc_size;
	struct net_device *p;

	BUG_ON(strlen(name) >= sizeof(dev->name));

	if (txqs < 1) {
		pr_err("alloc_netdev: Unable to allocate device with zero queues\n");
		return NULL;
	}

#ifdef CONFIG_SYSFS
	if (rxqs < 1) {
		pr_err("alloc_netdev: Unable to allocate device with zero RX queues\n");
		return NULL;
	}
#endif

	alloc_size = sizeof(struct net_device);
	if (sizeof_priv) {
		 
		alloc_size = ALIGN(alloc_size, NETDEV_ALIGN);
		alloc_size += sizeof_priv;
	}
	 
	alloc_size += NETDEV_ALIGN - 1;

	p = kzalloc(alloc_size, GFP_KERNEL | __GFP_NOWARN | __GFP_REPEAT);
	if (!p)
		p = vzalloc(alloc_size);
	if (!p)
		return NULL;

	dev = PTR_ALIGN(p, NETDEV_ALIGN);
	dev->padded = (char *)dev - (char *)p;

	dev->pcpu_refcnt = alloc_percpu(int);
	if (!dev->pcpu_refcnt)
		goto free_dev;

	if (dev_addr_init(dev))
		goto free_pcpu;

	dev_mc_init(dev);
	dev_uc_init(dev);

	dev_net_set(dev, &init_net);

	dev->gso_max_size = GSO_MAX_SIZE;
	dev->gso_max_segs = GSO_MAX_SEGS;
	dev->gso_min_segs = 0;

	INIT_LIST_HEAD(&dev->napi_list);
	INIT_LIST_HEAD(&dev->unreg_list);
	INIT_LIST_HEAD(&dev->close_list);
	INIT_LIST_HEAD(&dev->link_watch_list);
	INIT_LIST_HEAD(&dev->adj_list.upper);
	INIT_LIST_HEAD(&dev->adj_list.lower);
	INIT_LIST_HEAD(&dev->all_adj_list.upper);
	INIT_LIST_HEAD(&dev->all_adj_list.lower);
	INIT_LIST_HEAD(&dev->ptype_all);
	INIT_LIST_HEAD(&dev->ptype_specific);
	dev->priv_flags = IFF_XMIT_DST_RELEASE | IFF_XMIT_DST_RELEASE_PERM;
	setup(dev);

	if (!dev->tx_queue_len) {
		dev->priv_flags |= IFF_NO_QUEUE;
		dev->tx_queue_len = 1;
	}

	dev->num_tx_queues = txqs;
	dev->real_num_tx_queues = txqs;
	if (netif_alloc_netdev_queues(dev))
		goto free_all;

#ifdef CONFIG_SYSFS
	dev->num_rx_queues = rxqs;
	dev->real_num_rx_queues = rxqs;
	if (netif_alloc_rx_queues(dev))
		goto free_all;
#endif

	strcpy(dev->name, name);
	dev->name_assign_type = name_assign_type;
	dev->group = INIT_NETDEV_GROUP;
	if (!dev->ethtool_ops)
		dev->ethtool_ops = &default_ethtool_ops;

	nf_hook_ingress_init(dev);

	return dev;

free_all:
	free_netdev(dev);
	return NULL;

free_pcpu:
	free_percpu(dev->pcpu_refcnt);
free_dev:
	netdev_freemem(dev);
	return NULL;
}
EXPORT_SYMBOL(alloc_netdev_mqs);

void free_netdev(struct net_device *dev)
{
	struct napi_struct *p, *n;

	netif_free_tx_queues(dev);
#ifdef CONFIG_SYSFS
	kvfree(dev->_rx);
#endif

	kfree(rcu_dereference_protected(dev->ingress_queue, 1));

	dev_addr_flush(dev);

	list_for_each_entry_safe(p, n, &dev->napi_list, dev_list)
		netif_napi_del(p);

	free_percpu(dev->pcpu_refcnt);
	dev->pcpu_refcnt = NULL;

	if (dev->reg_state == NETREG_UNINITIALIZED) {
		netdev_freemem(dev);
		return;
	}

	BUG_ON(dev->reg_state != NETREG_UNREGISTERED);
	dev->reg_state = NETREG_RELEASED;

	put_device(&dev->dev);
}
EXPORT_SYMBOL(free_netdev);

void synchronize_net(void)
{
	might_sleep();
	if (rtnl_is_locked())
		synchronize_rcu_expedited();
	else
		synchronize_rcu();
}
EXPORT_SYMBOL(synchronize_net);

void unregister_netdevice_queue(struct net_device *dev, struct list_head *head)
{
	ASSERT_RTNL();

	if (head) {
		list_move_tail(&dev->unreg_list, head);
	} else {
		rollback_registered(dev);
		 
		net_set_todo(dev);
	}
}
EXPORT_SYMBOL(unregister_netdevice_queue);

void unregister_netdevice_many(struct list_head *head)
{
	struct net_device *dev;

	if (!list_empty(head)) {
		rollback_registered_many(head);
		list_for_each_entry(dev, head, unreg_list)
			net_set_todo(dev);
		list_del(head);
	}
}
EXPORT_SYMBOL(unregister_netdevice_many);

void unregister_netdev(struct net_device *dev)
{
	rtnl_lock();
	unregister_netdevice(dev);
	rtnl_unlock();
}
EXPORT_SYMBOL(unregister_netdev);

int dev_change_net_namespace(struct net_device *dev, struct net *net, const char *pat)
{
	int err;

	ASSERT_RTNL();

	err = -EINVAL;
	if (dev->features & NETIF_F_NETNS_LOCAL)
		goto out;

	if (dev->reg_state != NETREG_REGISTERED)
		goto out;

	err = 0;
	if (net_eq(dev_net(dev), net))
		goto out;

	err = -EEXIST;
	if (__dev_get_by_name(net, dev->name)) {
		 
		if (!pat)
			goto out;
		if (dev_get_valid_name(net, dev, pat) < 0)
			goto out;
	}

	dev_close(dev);

	err = -ENODEV;
	unlist_netdevice(dev);

	synchronize_net();

	dev_shutdown(dev);

	call_netdevice_notifiers(NETDEV_UNREGISTER, dev);
	rcu_barrier();
	call_netdevice_notifiers(NETDEV_UNREGISTER_FINAL, dev);
	rtmsg_ifinfo(RTM_DELLINK, dev, ~0U, GFP_KERNEL);

	dev_uc_flush(dev);
	dev_mc_flush(dev);

	kobject_uevent(&dev->dev.kobj, KOBJ_REMOVE);
	netdev_adjacent_del_links(dev);

	dev_net_set(dev, net);

	if (__dev_get_by_index(net, dev->ifindex))
		dev->ifindex = dev_new_index(net);

	kobject_uevent(&dev->dev.kobj, KOBJ_ADD);
	netdev_adjacent_add_links(dev);

	err = device_rename(&dev->dev, dev->name);
	WARN_ON(err);

	list_netdevice(dev);

	call_netdevice_notifiers(NETDEV_REGISTER, dev);

	rtmsg_ifinfo(RTM_NEWLINK, dev, ~0U, GFP_KERNEL);

	synchronize_net();
	err = 0;
out:
	return err;
}
EXPORT_SYMBOL_GPL(dev_change_net_namespace);

static int dev_cpu_callback(struct notifier_block *nfb,
			    unsigned long action,
			    void *ocpu)
{
	struct sk_buff **list_skb;
	struct sk_buff *skb;
	unsigned int cpu, oldcpu = (unsigned long)ocpu;
	struct softnet_data *sd, *oldsd;

	if (action != CPU_DEAD && action != CPU_DEAD_FROZEN)
		return NOTIFY_OK;

	local_irq_disable();
	cpu = smp_processor_id();
	sd = &per_cpu(softnet_data, cpu);
	oldsd = &per_cpu(softnet_data, oldcpu);

	list_skb = &sd->completion_queue;
	while (*list_skb)
		list_skb = &(*list_skb)->next;
	 
	*list_skb = oldsd->completion_queue;
	oldsd->completion_queue = NULL;

	if (oldsd->output_queue) {
		*sd->output_queue_tailp = oldsd->output_queue;
		sd->output_queue_tailp = oldsd->output_queue_tailp;
		oldsd->output_queue = NULL;
		oldsd->output_queue_tailp = &oldsd->output_queue;
	}
	 
	while (!list_empty(&oldsd->poll_list)) {
		struct napi_struct *napi = list_first_entry(&oldsd->poll_list,
							    struct napi_struct,
							    poll_list);

		list_del_init(&napi->poll_list);
		if (napi->poll == process_backlog)
			napi->state = 0;
		else
			____napi_schedule(sd, napi);
	}

	raise_softirq_irqoff(NET_TX_SOFTIRQ);
	local_irq_enable();

	while ((skb = __skb_dequeue(&oldsd->process_queue))) {
		netif_rx_ni(skb);
		input_queue_head_incr(oldsd);
	}
	while ((skb = skb_dequeue(&oldsd->input_pkt_queue))) {
		netif_rx_ni(skb);
		input_queue_head_incr(oldsd);
	}

	return NOTIFY_OK;
}

netdev_features_t netdev_increment_features(netdev_features_t all,
	netdev_features_t one, netdev_features_t mask)
{
	if (mask & NETIF_F_GEN_CSUM)
		mask |= NETIF_F_ALL_CSUM;
	mask |= NETIF_F_VLAN_CHALLENGED;

	all |= one & (NETIF_F_ONE_FOR_ALL|NETIF_F_ALL_CSUM) & mask;
	all &= one | ~NETIF_F_ALL_FOR_ALL;

	if (all & NETIF_F_GEN_CSUM)
		all &= ~(NETIF_F_ALL_CSUM & ~NETIF_F_GEN_CSUM);

	return all;
}
EXPORT_SYMBOL(netdev_increment_features);

static struct hlist_head * __net_init netdev_create_hash(void)
{
	int i;
	struct hlist_head *hash;

	hash = kmalloc(sizeof(*hash) * NETDEV_HASHENTRIES, GFP_KERNEL);
	if (hash != NULL)
		for (i = 0; i < NETDEV_HASHENTRIES; i++)
			INIT_HLIST_HEAD(&hash[i]);

	return hash;
}

static int __net_init netdev_init(struct net *net)
{
	if (net != &init_net)
		INIT_LIST_HEAD(&net->dev_base_head);

	net->dev_name_head = netdev_create_hash();
	if (net->dev_name_head == NULL)
		goto err_name;

	net->dev_index_head = netdev_create_hash();
	if (net->dev_index_head == NULL)
		goto err_idx;

	return 0;

err_idx:
	kfree(net->dev_name_head);
err_name:
	return -ENOMEM;
}

const char *netdev_drivername(const struct net_device *dev)
{
	const struct device_driver *driver;
	const struct device *parent;
	const char *empty = "";

	parent = dev->dev.parent;
	if (!parent)
		return empty;

	driver = parent->driver;
	if (driver && driver->name)
		return driver->name;
	return empty;
}

static void __netdev_printk(const char *level, const struct net_device *dev,
			    struct va_format *vaf)
{
	if (dev && dev->dev.parent) {
		dev_printk_emit(level[1] - '0',
				dev->dev.parent,
				"%s %s %s%s: %pV",
				dev_driver_string(dev->dev.parent),
				dev_name(dev->dev.parent),
				netdev_name(dev), netdev_reg_state(dev),
				vaf);
	} else if (dev) {
		printk("%s%s%s: %pV",
		       level, netdev_name(dev), netdev_reg_state(dev), vaf);
	} else {
		printk("%s(NULL net_device): %pV", level, vaf);
	}
}

void netdev_printk(const char *level, const struct net_device *dev,
		   const char *format, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, format);

	vaf.fmt = format;
	vaf.va = &args;

	__netdev_printk(level, dev, &vaf);

	va_end(args);
}
EXPORT_SYMBOL(netdev_printk);

#define define_netdev_printk_level(func, level)			\
void func(const struct net_device *dev, const char *fmt, ...)	\
{								\
	struct va_format vaf;					\
	va_list args;						\
								\
	va_start(args, fmt);					\
								\
	vaf.fmt = fmt;						\
	vaf.va = &args;						\
								\
	__netdev_printk(level, dev, &vaf);			\
								\
	va_end(args);						\
}								\
EXPORT_SYMBOL(func);

define_netdev_printk_level(netdev_emerg, KERN_EMERG);
define_netdev_printk_level(netdev_alert, KERN_ALERT);
define_netdev_printk_level(netdev_crit, KERN_CRIT);
define_netdev_printk_level(netdev_err, KERN_ERR);
define_netdev_printk_level(netdev_warn, KERN_WARNING);
define_netdev_printk_level(netdev_notice, KERN_NOTICE);
define_netdev_printk_level(netdev_info, KERN_INFO);

static void __net_exit netdev_exit(struct net *net)
{
	kfree(net->dev_name_head);
	kfree(net->dev_index_head);
}

static struct pernet_operations __net_initdata netdev_net_ops = {
	.init = netdev_init,
	.exit = netdev_exit,
};

static void __net_exit default_device_exit(struct net *net)
{
	struct net_device *dev, *aux;
	 
	rtnl_lock();
	for_each_netdev_safe(net, dev, aux) {
		int err;
		char fb_name[IFNAMSIZ];

		if (dev->features & NETIF_F_NETNS_LOCAL)
			continue;

		if (dev->rtnl_link_ops)
			continue;

		snprintf(fb_name, IFNAMSIZ, "dev%d", dev->ifindex);
		err = dev_change_net_namespace(dev, &init_net, fb_name);
		if (err) {
			pr_emerg("%s: failed to move %s to init_net: %d\n",
				 __func__, dev->name, err);
			BUG();
		}
	}
	rtnl_unlock();
}

static void __net_exit rtnl_lock_unregistering(struct list_head *net_list)
{
	 
	struct net *net;
	bool unregistering;
	DEFINE_WAIT_FUNC(wait, woken_wake_function);

	add_wait_queue(&netdev_unregistering_wq, &wait);
	for (;;) {
		unregistering = false;
		rtnl_lock();
		list_for_each_entry(net, net_list, exit_list) {
			if (net->dev_unreg_count > 0) {
				unregistering = true;
				break;
			}
		}
		if (!unregistering)
			break;
		__rtnl_unlock();

		wait_woken(&wait, TASK_UNINTERRUPTIBLE, MAX_SCHEDULE_TIMEOUT);
	}
	remove_wait_queue(&netdev_unregistering_wq, &wait);
}

static void __net_exit default_device_exit_batch(struct list_head *net_list)
{
	 
	struct net_device *dev;
	struct net *net;
	LIST_HEAD(dev_kill_list);

	rtnl_lock_unregistering(net_list);
	list_for_each_entry(net, net_list, exit_list) {
		for_each_netdev_reverse(net, dev) {
			if (dev->rtnl_link_ops && dev->rtnl_link_ops->dellink)
				dev->rtnl_link_ops->dellink(dev, &dev_kill_list);
			else
				unregister_netdevice_queue(dev, &dev_kill_list);
		}
	}
	unregister_netdevice_many(&dev_kill_list);
	rtnl_unlock();
}

static struct pernet_operations __net_initdata default_device_ops = {
	.exit = default_device_exit,
	.exit_batch = default_device_exit_batch,
};

static int __init net_dev_init(void)
{
	int i, rc = -ENOMEM;

	BUG_ON(!dev_boot_phase);

	if (dev_proc_init())
		goto out;

	if (netdev_kobject_init())
		goto out;

	INIT_LIST_HEAD(&ptype_all);
	for (i = 0; i < PTYPE_HASH_SIZE; i++)
		INIT_LIST_HEAD(&ptype_base[i]);

	INIT_LIST_HEAD(&offload_base);

	if (register_pernet_subsys(&netdev_net_ops))
		goto out;

	for_each_possible_cpu(i) {
		struct softnet_data *sd = &per_cpu(softnet_data, i);

		skb_queue_head_init(&sd->input_pkt_queue);
		skb_queue_head_init(&sd->process_queue);
		INIT_LIST_HEAD(&sd->poll_list);
		sd->output_queue_tailp = &sd->output_queue;
#ifdef CONFIG_RPS
		sd->csd.func = rps_trigger_softirq;
		sd->csd.info = sd;
		sd->cpu = i;
#endif

		sd->backlog.poll = process_backlog;
		sd->backlog.weight = weight_p;
	}

	dev_boot_phase = 0;

	if (register_pernet_device(&loopback_net_ops))
		goto out;

	if (register_pernet_device(&default_device_ops))
		goto out;

	open_softirq(NET_TX_SOFTIRQ, net_tx_action);
	open_softirq(NET_RX_SOFTIRQ, net_rx_action);

	hotcpu_notifier(dev_cpu_callback, 0);
	dst_subsys_init();
	rc = 0;
out:
	return rc;
}

subsys_initcall(net_dev_init);
