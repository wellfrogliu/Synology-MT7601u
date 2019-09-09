#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef _LINUX_NETDEVICE_H
#define _LINUX_NETDEVICE_H

#include <linux/timer.h>
#include <linux/bug.h>
#include <linux/delay.h>
#include <linux/atomic.h>
#include <linux/prefetch.h>
#include <asm/cache.h>
#include <asm/byteorder.h>

#include <linux/percpu.h>
#include <linux/rculist.h>
#include <linux/dmaengine.h>
#include <linux/workqueue.h>
#include <linux/dynamic_queue_limits.h>

#include <linux/ethtool.h>
#include <net/net_namespace.h>
#include <net/dsa.h>
#ifdef CONFIG_DCB
#include <net/dcbnl.h>
#endif
#include <net/netprio_cgroup.h>

#include <linux/netdev_features.h>
#include <linux/neighbour.h>
#include <uapi/linux/netdevice.h>
#include <uapi/linux/if_bonding.h>

struct netpoll_info;
struct device;
struct phy_device;
 
struct wireless_dev;
 
struct wpan_dev;
struct mpls_dev;

void netdev_set_default_ethtool_ops(struct net_device *dev,
				    const struct ethtool_ops *ops);

#define NET_RX_SUCCESS		0	 
#define NET_RX_DROP		1	 

#define NET_XMIT_SUCCESS	0x00
#define NET_XMIT_DROP		0x01	 
#define NET_XMIT_CN		0x02	 
#define NET_XMIT_POLICED	0x03	 
#define NET_XMIT_MASK		0x0f	 

#define net_xmit_eval(e)	((e) == NET_XMIT_CN ? 0 : (e))
#define net_xmit_errno(e)	((e) != NET_XMIT_CN ? -ENOBUFS : 0)

#define NETDEV_TX_MASK		0xf0

enum netdev_tx {
	__NETDEV_TX_MIN	 = INT_MIN,	 
	NETDEV_TX_OK	 = 0x00,	 
	NETDEV_TX_BUSY	 = 0x10,	 
	NETDEV_TX_LOCKED = 0x20,	 
};
typedef enum netdev_tx netdev_tx_t;

static inline bool dev_xmit_complete(int rc)
{
	 
	if (likely(rc < NET_XMIT_MASK))
		return true;

	return false;
}

#if defined(CONFIG_WLAN) || IS_ENABLED(CONFIG_AX25)
# if defined(CONFIG_MAC80211_MESH)
#  define LL_MAX_HEADER 128
# else
#  define LL_MAX_HEADER 96
# endif
#else
# define LL_MAX_HEADER 32
#endif

#if !IS_ENABLED(CONFIG_NET_IPIP) && !IS_ENABLED(CONFIG_NET_IPGRE) && \
    !IS_ENABLED(CONFIG_IPV6_SIT) && !IS_ENABLED(CONFIG_IPV6_TUNNEL)
#define MAX_HEADER LL_MAX_HEADER
#else
#define MAX_HEADER (LL_MAX_HEADER + 48)
#endif

struct net_device_stats {
	unsigned long	rx_packets;
	unsigned long	tx_packets;
	unsigned long	rx_bytes;
	unsigned long	tx_bytes;
	unsigned long	rx_errors;
	unsigned long	tx_errors;
	unsigned long	rx_dropped;
	unsigned long	tx_dropped;
	unsigned long	multicast;
	unsigned long	collisions;
	unsigned long	rx_length_errors;
	unsigned long	rx_over_errors;
	unsigned long	rx_crc_errors;
	unsigned long	rx_frame_errors;
	unsigned long	rx_fifo_errors;
	unsigned long	rx_missed_errors;
	unsigned long	tx_aborted_errors;
	unsigned long	tx_carrier_errors;
	unsigned long	tx_fifo_errors;
	unsigned long	tx_heartbeat_errors;
	unsigned long	tx_window_errors;
	unsigned long	rx_compressed;
	unsigned long	tx_compressed;
};

#include <linux/cache.h>
#include <linux/skbuff.h>

#ifdef CONFIG_RPS
#include <linux/static_key.h>
extern struct static_key rps_needed;
#endif

struct neighbour;
struct neigh_parms;
struct sk_buff;

struct netdev_hw_addr {
	struct list_head	list;
	unsigned char		addr[MAX_ADDR_LEN];
	unsigned char		type;
#define NETDEV_HW_ADDR_T_LAN		1
#define NETDEV_HW_ADDR_T_SAN		2
#define NETDEV_HW_ADDR_T_SLAVE		3
#define NETDEV_HW_ADDR_T_UNICAST	4
#define NETDEV_HW_ADDR_T_MULTICAST	5
	bool			global_use;
	int			sync_cnt;
	int			refcount;
	int			synced;
	struct rcu_head		rcu_head;
};

struct netdev_hw_addr_list {
	struct list_head	list;
	int			count;
};

#define netdev_hw_addr_list_count(l) ((l)->count)
#define netdev_hw_addr_list_empty(l) (netdev_hw_addr_list_count(l) == 0)
#define netdev_hw_addr_list_for_each(ha, l) \
	list_for_each_entry(ha, &(l)->list, list)

#define netdev_uc_count(dev) netdev_hw_addr_list_count(&(dev)->uc)
#define netdev_uc_empty(dev) netdev_hw_addr_list_empty(&(dev)->uc)
#define netdev_for_each_uc_addr(ha, dev) \
	netdev_hw_addr_list_for_each(ha, &(dev)->uc)

#define netdev_mc_count(dev) netdev_hw_addr_list_count(&(dev)->mc)
#define netdev_mc_empty(dev) netdev_hw_addr_list_empty(&(dev)->mc)
#define netdev_for_each_mc_addr(ha, dev) \
	netdev_hw_addr_list_for_each(ha, &(dev)->mc)

struct hh_cache {
	u16		hh_len;
	u16		__pad;
	seqlock_t	hh_lock;

#define HH_DATA_MOD	16
#define HH_DATA_OFF(__len) \
	(HH_DATA_MOD - (((__len - 1) & (HH_DATA_MOD - 1)) + 1))
#define HH_DATA_ALIGN(__len) \
	(((__len)+(HH_DATA_MOD-1))&~(HH_DATA_MOD - 1))
	unsigned long	hh_data[HH_DATA_ALIGN(LL_MAX_HEADER) / sizeof(long)];
};

#define LL_RESERVED_SPACE(dev) \
	((((dev)->hard_header_len+(dev)->needed_headroom)&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)
#define LL_RESERVED_SPACE_EXTRA(dev,extra) \
	((((dev)->hard_header_len+(dev)->needed_headroom+(extra))&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)

struct header_ops {
	int	(*create) (struct sk_buff *skb, struct net_device *dev,
			   unsigned short type, const void *daddr,
			   const void *saddr, unsigned int len);
	int	(*parse)(const struct sk_buff *skb, unsigned char *haddr);
	int	(*cache)(const struct neighbour *neigh, struct hh_cache *hh, __be16 type);
	void	(*cache_update)(struct hh_cache *hh,
				const struct net_device *dev,
				const unsigned char *haddr);
	bool	(*validate)(const char *ll_header, unsigned int len);
};

enum netdev_state_t {
	__LINK_STATE_START,
	__LINK_STATE_PRESENT,
	__LINK_STATE_NOCARRIER,
	__LINK_STATE_LINKWATCH_PENDING,
	__LINK_STATE_DORMANT,
};

struct netdev_boot_setup {
	char name[IFNAMSIZ];
	struct ifmap map;
};
#define NETDEV_BOOT_SETUP_MAX 8

int __init netdev_boot_setup(char *str);

struct napi_struct {
	 
	struct list_head	poll_list;

	unsigned long		state;
	int			weight;
	unsigned int		gro_count;
	int			(*poll)(struct napi_struct *, int);
#ifdef CONFIG_NETPOLL
	spinlock_t		poll_lock;
	int			poll_owner;
#endif
	struct net_device	*dev;
	struct sk_buff		*gro_list;
	struct sk_buff		*skb;
	struct hrtimer		timer;
	struct list_head	dev_list;
	struct hlist_node	napi_hash_node;
	unsigned int		napi_id;
};

enum {
	NAPI_STATE_SCHED,	 
	NAPI_STATE_DISABLE,	 
	NAPI_STATE_NPSVC,	 
	NAPI_STATE_HASHED,	 
};

enum gro_result {
	GRO_MERGED,
	GRO_MERGED_FREE,
	GRO_HELD,
	GRO_NORMAL,
	GRO_DROP,
};
typedef enum gro_result gro_result_t;

enum rx_handler_result {
	RX_HANDLER_CONSUMED,
	RX_HANDLER_ANOTHER,
	RX_HANDLER_EXACT,
	RX_HANDLER_PASS,
};
typedef enum rx_handler_result rx_handler_result_t;
typedef rx_handler_result_t rx_handler_func_t(struct sk_buff **pskb);

void __napi_schedule(struct napi_struct *n);
void __napi_schedule_irqoff(struct napi_struct *n);

static inline bool napi_disable_pending(struct napi_struct *n)
{
	return test_bit(NAPI_STATE_DISABLE, &n->state);
}

static inline bool napi_schedule_prep(struct napi_struct *n)
{
	return !napi_disable_pending(n) &&
		!test_and_set_bit(NAPI_STATE_SCHED, &n->state);
}

static inline void napi_schedule(struct napi_struct *n)
{
	if (napi_schedule_prep(n))
		__napi_schedule(n);
}

static inline void napi_schedule_irqoff(struct napi_struct *n)
{
	if (napi_schedule_prep(n))
		__napi_schedule_irqoff(n);
}

static inline bool napi_reschedule(struct napi_struct *napi)
{
	if (napi_schedule_prep(napi)) {
		__napi_schedule(napi);
		return true;
	}
	return false;
}

void __napi_complete(struct napi_struct *n);
void napi_complete_done(struct napi_struct *n, int work_done);
 
static inline void napi_complete(struct napi_struct *n)
{
	return napi_complete_done(n, 0);
}

struct napi_struct *napi_by_id(unsigned int napi_id);

void napi_hash_add(struct napi_struct *napi);

void napi_hash_del(struct napi_struct *napi);

void napi_disable(struct napi_struct *n);

static inline void napi_enable(struct napi_struct *n)
{
	BUG_ON(!test_bit(NAPI_STATE_SCHED, &n->state));
	smp_mb__before_atomic();
	clear_bit(NAPI_STATE_SCHED, &n->state);
	clear_bit(NAPI_STATE_NPSVC, &n->state);
}

static inline void napi_synchronize(const struct napi_struct *n)
{
	if (IS_ENABLED(CONFIG_SMP))
		while (test_bit(NAPI_STATE_SCHED, &n->state))
			msleep(1);
	else
		barrier();
}

enum netdev_queue_state_t {
	__QUEUE_STATE_DRV_XOFF,
	__QUEUE_STATE_STACK_XOFF,
	__QUEUE_STATE_FROZEN,
};

#define QUEUE_STATE_DRV_XOFF	(1 << __QUEUE_STATE_DRV_XOFF)
#define QUEUE_STATE_STACK_XOFF	(1 << __QUEUE_STATE_STACK_XOFF)
#define QUEUE_STATE_FROZEN	(1 << __QUEUE_STATE_FROZEN)

#define QUEUE_STATE_ANY_XOFF	(QUEUE_STATE_DRV_XOFF | QUEUE_STATE_STACK_XOFF)
#define QUEUE_STATE_ANY_XOFF_OR_FROZEN (QUEUE_STATE_ANY_XOFF | \
					QUEUE_STATE_FROZEN)
#define QUEUE_STATE_DRV_XOFF_OR_FROZEN (QUEUE_STATE_DRV_XOFF | \
					QUEUE_STATE_FROZEN)

struct netdev_queue {
 
	struct net_device	*dev;
	struct Qdisc __rcu	*qdisc;
	struct Qdisc		*qdisc_sleeping;
#ifdef CONFIG_SYSFS
	struct kobject		kobj;
#endif
#if defined(CONFIG_XPS) && defined(CONFIG_NUMA)
	int			numa_node;
#endif
 
	spinlock_t		_xmit_lock ____cacheline_aligned_in_smp;
	int			xmit_lock_owner;
	 
	unsigned long		trans_start;

	unsigned long		trans_timeout;

	unsigned long		state;

#ifdef CONFIG_BQL
	struct dql		dql;
#endif
	unsigned long		tx_maxrate;
} ____cacheline_aligned_in_smp;

static inline int netdev_queue_numa_node_read(const struct netdev_queue *q)
{
#if defined(CONFIG_XPS) && defined(CONFIG_NUMA)
	return q->numa_node;
#else
	return NUMA_NO_NODE;
#endif
}

static inline void netdev_queue_numa_node_write(struct netdev_queue *q, int node)
{
#if defined(CONFIG_XPS) && defined(CONFIG_NUMA)
	q->numa_node = node;
#endif
}

#ifdef CONFIG_RPS
 
struct rps_map {
	unsigned int len;
	struct rcu_head rcu;
	u16 cpus[0];
};
#define RPS_MAP_SIZE(_num) (sizeof(struct rps_map) + ((_num) * sizeof(u16)))

struct rps_dev_flow {
	u16 cpu;
	u16 filter;
	unsigned int last_qtail;
};
#define RPS_NO_FILTER 0xffff

struct rps_dev_flow_table {
	unsigned int mask;
	struct rcu_head rcu;
	struct rps_dev_flow flows[0];
};
#define RPS_DEV_FLOW_TABLE_SIZE(_num) (sizeof(struct rps_dev_flow_table) + \
    ((_num) * sizeof(struct rps_dev_flow)))

struct rps_sock_flow_table {
	u32	mask;

	u32	ents[0] ____cacheline_aligned_in_smp;
};
#define	RPS_SOCK_FLOW_TABLE_SIZE(_num) (offsetof(struct rps_sock_flow_table, ents[_num]))

#define RPS_NO_CPU 0xffff

extern u32 rps_cpu_mask;
extern struct rps_sock_flow_table __rcu *rps_sock_flow_table;

static inline void rps_record_sock_flow(struct rps_sock_flow_table *table,
					u32 hash)
{
	if (table && hash) {
		unsigned int index = hash & table->mask;
		u32 val = hash & ~rps_cpu_mask;

		val |= raw_smp_processor_id();

		if (table->ents[index] != val)
			table->ents[index] = val;
	}
}

#ifdef CONFIG_RFS_ACCEL
bool rps_may_expire_flow(struct net_device *dev, u16 rxq_index, u32 flow_id,
			 u16 filter_id);
#endif
#endif  

struct netdev_rx_queue {
#ifdef CONFIG_RPS
	struct rps_map __rcu		*rps_map;
	struct rps_dev_flow_table __rcu	*rps_flow_table;
#endif
	struct kobject			kobj;
	struct net_device		*dev;
} ____cacheline_aligned_in_smp;

struct rx_queue_attribute {
	struct attribute attr;
	ssize_t (*show)(struct netdev_rx_queue *queue,
	    struct rx_queue_attribute *attr, char *buf);
	ssize_t (*store)(struct netdev_rx_queue *queue,
	    struct rx_queue_attribute *attr, const char *buf, size_t len);
};

#ifdef CONFIG_XPS
 
struct xps_map {
	unsigned int len;
	unsigned int alloc_len;
	struct rcu_head rcu;
	u16 queues[0];
};
#define XPS_MAP_SIZE(_num) (sizeof(struct xps_map) + ((_num) * sizeof(u16)))
#define XPS_MIN_MAP_ALLOC ((L1_CACHE_ALIGN(offsetof(struct xps_map, queues[1])) \
       - sizeof(struct xps_map)) / sizeof(u16))

struct xps_dev_maps {
	struct rcu_head rcu;
	struct xps_map __rcu *cpu_map[0];
};
#define XPS_DEV_MAPS_SIZE (sizeof(struct xps_dev_maps) +		\
    (nr_cpu_ids * sizeof(struct xps_map *)))
#endif  

#define TC_MAX_QUEUE	16
#define TC_BITMASK	15
 
struct netdev_tc_txq {
	u16 count;
	u16 offset;
};

#if defined(CONFIG_FCOE) || defined(CONFIG_FCOE_MODULE)
 
struct netdev_fcoe_hbainfo {
	char	manufacturer[64];
	char	serial_number[64];
	char	hardware_version[64];
	char	driver_version[64];
	char	optionrom_version[64];
	char	firmware_version[64];
	char	model[256];
	char	model_description[256];
};
#endif

#define MAX_PHYS_ITEM_ID_LEN 32

struct netdev_phys_item_id {
	unsigned char id[MAX_PHYS_ITEM_ID_LEN];
	unsigned char id_len;
};

static inline bool netdev_phys_item_id_same(struct netdev_phys_item_id *a,
					    struct netdev_phys_item_id *b)
{
	return a->id_len == b->id_len &&
	       memcmp(a->id, b->id, a->id_len) == 0;
}

typedef u16 (*select_queue_fallback_t)(struct net_device *dev,
				       struct sk_buff *skb);

struct net_device_ops {
	int			(*ndo_init)(struct net_device *dev);
	void			(*ndo_uninit)(struct net_device *dev);
	int			(*ndo_open)(struct net_device *dev);
	int			(*ndo_stop)(struct net_device *dev);
	netdev_tx_t		(*ndo_start_xmit) (struct sk_buff *skb,
						   struct net_device *dev);
	u16			(*ndo_select_queue)(struct net_device *dev,
						    struct sk_buff *skb,
						    void *accel_priv,
						    select_queue_fallback_t fallback);
	void			(*ndo_change_rx_flags)(struct net_device *dev,
						       int flags);
	void			(*ndo_set_rx_mode)(struct net_device *dev);
	int			(*ndo_set_mac_address)(struct net_device *dev,
						       void *addr);
	int			(*ndo_validate_addr)(struct net_device *dev);
	int			(*ndo_do_ioctl)(struct net_device *dev,
					        struct ifreq *ifr, int cmd);
	int			(*ndo_set_config)(struct net_device *dev,
					          struct ifmap *map);
	int			(*ndo_change_mtu)(struct net_device *dev,
						  int new_mtu);
	int			(*ndo_neigh_setup)(struct net_device *dev,
						   struct neigh_parms *);
	void			(*ndo_tx_timeout) (struct net_device *dev);

	struct rtnl_link_stats64* (*ndo_get_stats64)(struct net_device *dev,
						     struct rtnl_link_stats64 *storage);
	struct net_device_stats* (*ndo_get_stats)(struct net_device *dev);

	int			(*ndo_vlan_rx_add_vid)(struct net_device *dev,
						       __be16 proto, u16 vid);
	int			(*ndo_vlan_rx_kill_vid)(struct net_device *dev,
						        __be16 proto, u16 vid);
#ifdef CONFIG_NET_POLL_CONTROLLER
	void                    (*ndo_poll_controller)(struct net_device *dev);
	int			(*ndo_netpoll_setup)(struct net_device *dev,
						     struct netpoll_info *info);
	void			(*ndo_netpoll_cleanup)(struct net_device *dev);
#endif
#ifdef CONFIG_NET_RX_BUSY_POLL
	int			(*ndo_busy_poll)(struct napi_struct *dev);
#endif
	int			(*ndo_set_vf_mac)(struct net_device *dev,
						  int queue, u8 *mac);
	int			(*ndo_set_vf_vlan)(struct net_device *dev,
						   int queue, u16 vlan, u8 qos);
	int			(*ndo_set_vf_rate)(struct net_device *dev,
						   int vf, int min_tx_rate,
						   int max_tx_rate);
	int			(*ndo_set_vf_spoofchk)(struct net_device *dev,
						       int vf, bool setting);
	int			(*ndo_set_vf_trust)(struct net_device *dev,
						    int vf, bool setting);
	int			(*ndo_get_vf_config)(struct net_device *dev,
						     int vf,
						     struct ifla_vf_info *ivf);
	int			(*ndo_set_vf_link_state)(struct net_device *dev,
							 int vf, int link_state);
	int			(*ndo_get_vf_stats)(struct net_device *dev,
						    int vf,
						    struct ifla_vf_stats
						    *vf_stats);
	int			(*ndo_set_vf_port)(struct net_device *dev,
						   int vf,
						   struct nlattr *port[]);
	int			(*ndo_get_vf_port)(struct net_device *dev,
						   int vf, struct sk_buff *skb);
	int			(*ndo_set_vf_rss_query_en)(
						   struct net_device *dev,
						   int vf, bool setting);
	int			(*ndo_setup_tc)(struct net_device *dev, u8 tc);
#if IS_ENABLED(CONFIG_FCOE)
	int			(*ndo_fcoe_enable)(struct net_device *dev);
	int			(*ndo_fcoe_disable)(struct net_device *dev);
	int			(*ndo_fcoe_ddp_setup)(struct net_device *dev,
						      u16 xid,
						      struct scatterlist *sgl,
						      unsigned int sgc);
	int			(*ndo_fcoe_ddp_done)(struct net_device *dev,
						     u16 xid);
	int			(*ndo_fcoe_ddp_target)(struct net_device *dev,
						       u16 xid,
						       struct scatterlist *sgl,
						       unsigned int sgc);
	int			(*ndo_fcoe_get_hbainfo)(struct net_device *dev,
							struct netdev_fcoe_hbainfo *hbainfo);
#endif

#if IS_ENABLED(CONFIG_LIBFCOE)
#define NETDEV_FCOE_WWNN 0
#define NETDEV_FCOE_WWPN 1
	int			(*ndo_fcoe_get_wwn)(struct net_device *dev,
						    u64 *wwn, int type);
#endif

#ifdef CONFIG_RFS_ACCEL
	int			(*ndo_rx_flow_steer)(struct net_device *dev,
						     const struct sk_buff *skb,
						     u16 rxq_index,
						     u32 flow_id);
#endif
	int			(*ndo_add_slave)(struct net_device *dev,
						 struct net_device *slave_dev);
	int			(*ndo_del_slave)(struct net_device *dev,
						 struct net_device *slave_dev);
	netdev_features_t	(*ndo_fix_features)(struct net_device *dev,
						    netdev_features_t features);
	int			(*ndo_set_features)(struct net_device *dev,
						    netdev_features_t features);
	int			(*ndo_neigh_construct)(struct neighbour *n);
	void			(*ndo_neigh_destroy)(struct neighbour *n);

	int			(*ndo_fdb_add)(struct ndmsg *ndm,
					       struct nlattr *tb[],
					       struct net_device *dev,
					       const unsigned char *addr,
					       u16 vid,
					       u16 flags);
	int			(*ndo_fdb_del)(struct ndmsg *ndm,
					       struct nlattr *tb[],
					       struct net_device *dev,
					       const unsigned char *addr,
					       u16 vid);
	int			(*ndo_fdb_dump)(struct sk_buff *skb,
						struct netlink_callback *cb,
						struct net_device *dev,
						struct net_device *filter_dev,
						int idx);

	int			(*ndo_bridge_setlink)(struct net_device *dev,
						      struct nlmsghdr *nlh,
						      u16 flags);
	int			(*ndo_bridge_getlink)(struct sk_buff *skb,
						      u32 pid, u32 seq,
						      struct net_device *dev,
						      u32 filter_mask,
						      int nlflags);
	int			(*ndo_bridge_dellink)(struct net_device *dev,
						      struct nlmsghdr *nlh,
						      u16 flags);
	int			(*ndo_change_carrier)(struct net_device *dev,
						      bool new_carrier);
	int			(*ndo_get_phys_port_id)(struct net_device *dev,
							struct netdev_phys_item_id *ppid);
	int			(*ndo_get_phys_port_name)(struct net_device *dev,
							  char *name, size_t len);
	void			(*ndo_add_vxlan_port)(struct  net_device *dev,
						      sa_family_t sa_family,
						      __be16 port);
	void			(*ndo_del_vxlan_port)(struct  net_device *dev,
						      sa_family_t sa_family,
						      __be16 port);

	void*			(*ndo_dfwd_add_station)(struct net_device *pdev,
							struct net_device *dev);
	void			(*ndo_dfwd_del_station)(struct net_device *pdev,
							void *priv);

	netdev_tx_t		(*ndo_dfwd_start_xmit) (struct sk_buff *skb,
							struct net_device *dev,
							void *priv);
	int			(*ndo_get_lock_subclass)(struct net_device *dev);
	netdev_features_t	(*ndo_features_check) (struct sk_buff *skb,
						       struct net_device *dev,
						       netdev_features_t features);
	int			(*ndo_set_tx_maxrate)(struct net_device *dev,
						      int queue_index,
						      u32 maxrate);
	int			(*ndo_get_iflink)(const struct net_device *dev);
	int			(*ndo_change_proto_down)(struct net_device *dev,
							 bool proto_down);
	int			(*ndo_fill_metadata_dst)(struct net_device *dev,
						       struct sk_buff *skb);
#if defined(MY_DEF_HERE)
	void		(*ndo_lan_led_control)(struct net_device *dev,
							int status);
#endif  
};

enum netdev_priv_flags {
	IFF_802_1Q_VLAN			= 1<<0,
	IFF_EBRIDGE			= 1<<1,
	IFF_BONDING			= 1<<2,
	IFF_ISATAP			= 1<<3,
	IFF_WAN_HDLC			= 1<<4,
	IFF_XMIT_DST_RELEASE		= 1<<5,
	IFF_DONT_BRIDGE			= 1<<6,
	IFF_DISABLE_NETPOLL		= 1<<7,
	IFF_MACVLAN_PORT		= 1<<8,
	IFF_BRIDGE_PORT			= 1<<9,
	IFF_OVS_DATAPATH		= 1<<10,
	IFF_TX_SKB_SHARING		= 1<<11,
	IFF_UNICAST_FLT			= 1<<12,
	IFF_TEAM_PORT			= 1<<13,
	IFF_SUPP_NOFCS			= 1<<14,
	IFF_LIVE_ADDR_CHANGE		= 1<<15,
	IFF_MACVLAN			= 1<<16,
	IFF_XMIT_DST_RELEASE_PERM	= 1<<17,
	IFF_IPVLAN_MASTER		= 1<<18,
	IFF_IPVLAN_SLAVE		= 1<<19,
	IFF_L3MDEV_MASTER		= 1<<20,
	IFF_NO_QUEUE			= 1<<21,
	IFF_OPENVSWITCH			= 1<<22,
	IFF_L3MDEV_SLAVE		= 1<<23,
};

#define IFF_802_1Q_VLAN			IFF_802_1Q_VLAN
#define IFF_EBRIDGE			IFF_EBRIDGE
#define IFF_BONDING			IFF_BONDING
#define IFF_ISATAP			IFF_ISATAP
#define IFF_WAN_HDLC			IFF_WAN_HDLC
#define IFF_XMIT_DST_RELEASE		IFF_XMIT_DST_RELEASE
#define IFF_DONT_BRIDGE			IFF_DONT_BRIDGE
#define IFF_DISABLE_NETPOLL		IFF_DISABLE_NETPOLL
#define IFF_MACVLAN_PORT		IFF_MACVLAN_PORT
#define IFF_BRIDGE_PORT			IFF_BRIDGE_PORT
#define IFF_OVS_DATAPATH		IFF_OVS_DATAPATH
#define IFF_TX_SKB_SHARING		IFF_TX_SKB_SHARING
#define IFF_UNICAST_FLT			IFF_UNICAST_FLT
#define IFF_TEAM_PORT			IFF_TEAM_PORT
#define IFF_SUPP_NOFCS			IFF_SUPP_NOFCS
#define IFF_LIVE_ADDR_CHANGE		IFF_LIVE_ADDR_CHANGE
#define IFF_MACVLAN			IFF_MACVLAN
#define IFF_XMIT_DST_RELEASE_PERM	IFF_XMIT_DST_RELEASE_PERM
#define IFF_IPVLAN_MASTER		IFF_IPVLAN_MASTER
#define IFF_IPVLAN_SLAVE		IFF_IPVLAN_SLAVE
#define IFF_L3MDEV_MASTER		IFF_L3MDEV_MASTER
#define IFF_NO_QUEUE			IFF_NO_QUEUE
#define IFF_OPENVSWITCH			IFF_OPENVSWITCH
#define IFF_L3MDEV_SLAVE		IFF_L3MDEV_SLAVE

struct net_device {
	char			name[IFNAMSIZ];
	struct hlist_node	name_hlist;
	char 			*ifalias;
	 
	unsigned long		mem_end;
	unsigned long		mem_start;
	unsigned long		base_addr;
	int			irq;

	atomic_t		carrier_changes;

	unsigned long		state;

	struct list_head	dev_list;
	struct list_head	napi_list;
	struct list_head	unreg_list;
	struct list_head	close_list;
	struct list_head	ptype_all;
	struct list_head	ptype_specific;

	struct {
		struct list_head upper;
		struct list_head lower;
	} adj_list;

	struct {
		struct list_head upper;
		struct list_head lower;
	} all_adj_list;

	netdev_features_t	features;
	netdev_features_t	hw_features;
	netdev_features_t	wanted_features;
	netdev_features_t	vlan_features;
	netdev_features_t	hw_enc_features;
	netdev_features_t	mpls_features;

	int			ifindex;
	int			group;

	struct net_device_stats	stats;

	atomic_long_t		rx_dropped;
	atomic_long_t		tx_dropped;

#ifdef CONFIG_WIRELESS_EXT
	const struct iw_handler_def *	wireless_handlers;
	struct iw_public_data *	wireless_data;
#endif
	const struct net_device_ops *netdev_ops;
	const struct ethtool_ops *ethtool_ops;
#ifdef CONFIG_NET_SWITCHDEV
	const struct switchdev_ops *switchdev_ops;
#endif
#ifdef CONFIG_NET_L3_MASTER_DEV
	const struct l3mdev_ops	*l3mdev_ops;
#endif

	const struct header_ops *header_ops;

	unsigned int		flags;
	unsigned int		priv_flags;

	unsigned short		gflags;
	unsigned short		padded;

	unsigned char		operstate;
	unsigned char		link_mode;

	unsigned char		if_port;
	unsigned char		dma;

	unsigned int		mtu;
	unsigned short		type;
	unsigned short		hard_header_len;
	unsigned short		min_header_len;

	unsigned short		needed_headroom;
	unsigned short		needed_tailroom;

	unsigned char		perm_addr[MAX_ADDR_LEN];
	unsigned char		addr_assign_type;
	unsigned char		addr_len;
	unsigned short		neigh_priv_len;
	unsigned short          dev_id;
	unsigned short          dev_port;
	spinlock_t		addr_list_lock;
	unsigned char		name_assign_type;
	bool			uc_promisc;
	struct netdev_hw_addr_list	uc;
	struct netdev_hw_addr_list	mc;
	struct netdev_hw_addr_list	dev_addrs;

#ifdef CONFIG_SYSFS
	struct kset		*queues_kset;
#endif
	unsigned int		promiscuity;
	unsigned int		allmulti;

#if IS_ENABLED(CONFIG_VLAN_8021Q)
	struct vlan_info __rcu	*vlan_info;
#endif
#if IS_ENABLED(CONFIG_NET_DSA)
	struct dsa_switch_tree	*dsa_ptr;
#endif
#if IS_ENABLED(CONFIG_TIPC)
	struct tipc_bearer __rcu *tipc_ptr;
#endif
	void 			*atalk_ptr;
	struct in_device __rcu	*ip_ptr;
	struct dn_dev __rcu     *dn_ptr;
	struct inet6_dev __rcu	*ip6_ptr;
	void			*ax25_ptr;
	struct wireless_dev	*ieee80211_ptr;
	struct wpan_dev		*ieee802154_ptr;
#if IS_ENABLED(CONFIG_MPLS_ROUTING)
	struct mpls_dev __rcu	*mpls_ptr;
#endif

	unsigned long		last_rx;

	unsigned char		*dev_addr;

#ifdef CONFIG_SYSFS
	struct netdev_rx_queue	*_rx;

	unsigned int		num_rx_queues;
	unsigned int		real_num_rx_queues;

#endif

	unsigned long		gro_flush_timeout;
	rx_handler_func_t __rcu	*rx_handler;
	void __rcu		*rx_handler_data;

#ifdef CONFIG_NET_CLS_ACT
	struct tcf_proto __rcu  *ingress_cl_list;
#endif
	struct netdev_queue __rcu *ingress_queue;
#ifdef CONFIG_NETFILTER_INGRESS
	struct list_head	nf_hooks_ingress;
#endif

	unsigned char		broadcast[MAX_ADDR_LEN];
#ifdef CONFIG_RFS_ACCEL
	struct cpu_rmap		*rx_cpu_rmap;
#endif
	struct hlist_node	index_hlist;

	struct netdev_queue	*_tx ____cacheline_aligned_in_smp;
	unsigned int		num_tx_queues;
	unsigned int		real_num_tx_queues;
	struct Qdisc		*qdisc;
	unsigned long		tx_queue_len;
	spinlock_t		tx_global_lock;
	int			watchdog_timeo;

#ifdef CONFIG_XPS
	struct xps_dev_maps __rcu *xps_maps;
#endif

#ifdef CONFIG_NET_SWITCHDEV
	u32			offload_fwd_mark;
#endif

	unsigned long		trans_start;

	struct timer_list	watchdog_timer;

	int __percpu		*pcpu_refcnt;
	struct list_head	todo_list;

	struct list_head	link_watch_list;

	enum { NETREG_UNINITIALIZED=0,
	       NETREG_REGISTERED,	 
	       NETREG_UNREGISTERING,	 
	       NETREG_UNREGISTERED,	 
	       NETREG_RELEASED,		 
	       NETREG_DUMMY,		 
	} reg_state:8;

	bool dismantle;

	enum {
		RTNL_LINK_INITIALIZED,
		RTNL_LINK_INITIALIZING,
	} rtnl_link_state:16;

	void (*destructor)(struct net_device *dev);

#ifdef CONFIG_NETPOLL
	struct netpoll_info __rcu	*npinfo;
#endif

	possible_net_t			nd_net;

	union {
		void					*ml_priv;
		struct pcpu_lstats __percpu		*lstats;
		struct pcpu_sw_netstats __percpu	*tstats;
		struct pcpu_dstats __percpu		*dstats;
		struct pcpu_vstats __percpu		*vstats;
	};

	struct garp_port __rcu	*garp_port;
	struct mrp_port __rcu	*mrp_port;

	struct device	dev;
	const struct attribute_group *sysfs_groups[4];
	const struct attribute_group *sysfs_rx_queue_group;

	const struct rtnl_link_ops *rtnl_link_ops;

#define GSO_MAX_SIZE		65536
	unsigned int		gso_max_size;
#define GSO_MAX_SEGS		65535
	u16			gso_max_segs;
	u16			gso_min_segs;
#ifdef CONFIG_DCB
	const struct dcbnl_rtnl_ops *dcbnl_ops;
#endif
	u8 num_tc;
	struct netdev_tc_txq tc_to_txq[TC_MAX_QUEUE];
	u8 prio_tc_map[TC_BITMASK + 1];

#if IS_ENABLED(CONFIG_FCOE)
	unsigned int		fcoe_ddp_xid;
#endif
#if IS_ENABLED(CONFIG_CGROUP_NET_PRIO)
	struct netprio_map __rcu *priomap;
#endif
	struct phy_device *phydev;
	struct lock_class_key *qdisc_tx_busylock;
	bool proto_down;
};
#define to_net_dev(d) container_of(d, struct net_device, dev)

#define	NETDEV_ALIGN		32

static inline
int netdev_get_prio_tc_map(const struct net_device *dev, u32 prio)
{
	return dev->prio_tc_map[prio & TC_BITMASK];
}

static inline
int netdev_set_prio_tc_map(struct net_device *dev, u8 prio, u8 tc)
{
	if (tc >= dev->num_tc)
		return -EINVAL;

	dev->prio_tc_map[prio & TC_BITMASK] = tc & TC_BITMASK;
	return 0;
}

static inline
void netdev_reset_tc(struct net_device *dev)
{
	dev->num_tc = 0;
	memset(dev->tc_to_txq, 0, sizeof(dev->tc_to_txq));
	memset(dev->prio_tc_map, 0, sizeof(dev->prio_tc_map));
}

static inline
int netdev_set_tc_queue(struct net_device *dev, u8 tc, u16 count, u16 offset)
{
	if (tc >= dev->num_tc)
		return -EINVAL;

	dev->tc_to_txq[tc].count = count;
	dev->tc_to_txq[tc].offset = offset;
	return 0;
}

static inline
int netdev_set_num_tc(struct net_device *dev, u8 num_tc)
{
	if (num_tc > TC_MAX_QUEUE)
		return -EINVAL;

	dev->num_tc = num_tc;
	return 0;
}

static inline
int netdev_get_num_tc(struct net_device *dev)
{
	return dev->num_tc;
}

static inline
struct netdev_queue *netdev_get_tx_queue(const struct net_device *dev,
					 unsigned int index)
{
	return &dev->_tx[index];
}

static inline struct netdev_queue *skb_get_tx_queue(const struct net_device *dev,
						    const struct sk_buff *skb)
{
	return netdev_get_tx_queue(dev, skb_get_queue_mapping(skb));
}

static inline void netdev_for_each_tx_queue(struct net_device *dev,
					    void (*f)(struct net_device *,
						      struct netdev_queue *,
						      void *),
					    void *arg)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++)
		f(dev, &dev->_tx[i], arg);
}

struct netdev_queue *netdev_pick_tx(struct net_device *dev,
				    struct sk_buff *skb,
				    void *accel_priv);

static inline
struct net *dev_net(const struct net_device *dev)
{
	return read_pnet(&dev->nd_net);
}

static inline
void dev_net_set(struct net_device *dev, struct net *net)
{
	write_pnet(&dev->nd_net, net);
}

static inline bool netdev_uses_dsa(struct net_device *dev)
{
#if IS_ENABLED(CONFIG_NET_DSA)
	if (dev->dsa_ptr != NULL)
		return dsa_uses_tagged_protocol(dev->dsa_ptr);
#endif
	return false;
}

static inline void *netdev_priv(const struct net_device *dev)
{
	return (char *)dev + ALIGN(sizeof(struct net_device), NETDEV_ALIGN);
}

#define SET_NETDEV_DEV(net, pdev)	((net)->dev.parent = (pdev))

#define SET_NETDEV_DEVTYPE(net, devtype)	((net)->dev.type = (devtype))

#define NAPI_POLL_WEIGHT 64

void netif_napi_add(struct net_device *dev, struct napi_struct *napi,
		    int (*poll)(struct napi_struct *, int), int weight);

void netif_napi_del(struct napi_struct *napi);

struct napi_gro_cb {
	 
	void *frag0;

	unsigned int frag0_len;

	int data_offset;

	u16	flush;

	u16	flush_id;

	u16	count;

	u16	gro_remcsum_start;

	unsigned long age;

	u16	proto;

	u8	same_flow:1;

	u8	encap_mark:1;

	u8	csum_valid:1;

	u8	csum_cnt:3;

	u8	free:2;
#define NAPI_GRO_FREE		  1
#define NAPI_GRO_FREE_STOLEN_HEAD 2

	u8	is_ipv6:1;

	u8 recursion_counter:4;

	__wsum	csum;

	struct sk_buff *last;
};

#define NAPI_GRO_CB(skb) ((struct napi_gro_cb *)(skb)->cb)

#define GRO_RECURSION_LIMIT 15
static inline int gro_recursion_inc_test(struct sk_buff *skb)
{
	return ++NAPI_GRO_CB(skb)->recursion_counter == GRO_RECURSION_LIMIT;
}

typedef struct sk_buff **(*gro_receive_t)(struct sk_buff **, struct sk_buff *);
static inline struct sk_buff **call_gro_receive(gro_receive_t cb,
						struct sk_buff **head,
						struct sk_buff *skb)
{
	if (unlikely(gro_recursion_inc_test(skb))) {
		NAPI_GRO_CB(skb)->flush |= 1;
		return NULL;
	}

	return cb(head, skb);
}

struct packet_type {
	__be16			type;	 
	struct net_device	*dev;	 
	int			(*func) (struct sk_buff *,
					 struct net_device *,
					 struct packet_type *,
					 struct net_device *);
	bool			(*id_match)(struct packet_type *ptype,
					    struct sock *sk);
	void			*af_packet_priv;
	struct list_head	list;
};

struct offload_callbacks {
	struct sk_buff		*(*gso_segment)(struct sk_buff *skb,
						netdev_features_t features);
	struct sk_buff		**(*gro_receive)(struct sk_buff **head,
						 struct sk_buff *skb);
	int			(*gro_complete)(struct sk_buff *skb, int nhoff);
};

struct packet_offload {
	__be16			 type;	 
	u16			 priority;
	struct offload_callbacks callbacks;
	struct list_head	 list;
};

struct udp_offload;

struct udp_offload_callbacks {
	struct sk_buff		**(*gro_receive)(struct sk_buff **head,
						 struct sk_buff *skb,
						 struct udp_offload *uoff);
	int			(*gro_complete)(struct sk_buff *skb,
						int nhoff,
						struct udp_offload *uoff);
};

struct udp_offload {
	__be16			 port;
	u8			 ipproto;
	struct udp_offload_callbacks callbacks;
};

typedef struct sk_buff **(*gro_receive_udp_t)(struct sk_buff **,
					      struct sk_buff *,
					      struct udp_offload *);
static inline struct sk_buff **call_gro_receive_udp(gro_receive_udp_t cb,
						    struct sk_buff **head,
						    struct sk_buff *skb,
						    struct udp_offload *uoff)
{
	if (unlikely(gro_recursion_inc_test(skb))) {
		NAPI_GRO_CB(skb)->flush |= 1;
		return NULL;
	}

	return cb(head, skb, uoff);
}

struct pcpu_sw_netstats {
	u64     rx_packets;
	u64     rx_bytes;
	u64     tx_packets;
	u64     tx_bytes;
	struct u64_stats_sync   syncp;
};

#define __netdev_alloc_pcpu_stats(type, gfp)				\
({									\
	typeof(type) __percpu *pcpu_stats = alloc_percpu_gfp(type, gfp);\
	if (pcpu_stats)	{						\
		int __cpu;						\
		for_each_possible_cpu(__cpu) {				\
			typeof(type) *stat;				\
			stat = per_cpu_ptr(pcpu_stats, __cpu);		\
			u64_stats_init(&stat->syncp);			\
		}							\
	}								\
	pcpu_stats;							\
})

#define netdev_alloc_pcpu_stats(type)					\
	__netdev_alloc_pcpu_stats(type, GFP_KERNEL)

#include <linux/notifier.h>

#define NETDEV_UP	0x0001	 
#define NETDEV_DOWN	0x0002
#define NETDEV_REBOOT	0x0003	 
#define NETDEV_CHANGE	0x0004	 
#define NETDEV_REGISTER 0x0005
#define NETDEV_UNREGISTER	0x0006
#define NETDEV_CHANGEMTU	0x0007  
#define NETDEV_CHANGEADDR	0x0008
#define NETDEV_GOING_DOWN	0x0009
#define NETDEV_CHANGENAME	0x000A
#define NETDEV_FEAT_CHANGE	0x000B
#define NETDEV_BONDING_FAILOVER 0x000C
#define NETDEV_PRE_UP		0x000D
#define NETDEV_PRE_TYPE_CHANGE	0x000E
#define NETDEV_POST_TYPE_CHANGE	0x000F
#define NETDEV_POST_INIT	0x0010
#define NETDEV_UNREGISTER_FINAL 0x0011
#define NETDEV_RELEASE		0x0012
#define NETDEV_NOTIFY_PEERS	0x0013
#define NETDEV_JOIN		0x0014
#define NETDEV_CHANGEUPPER	0x0015
#define NETDEV_RESEND_IGMP	0x0016
#define NETDEV_PRECHANGEMTU	0x0017  
#define NETDEV_CHANGEINFODATA	0x0018
#define NETDEV_BONDING_INFO	0x0019
#define NETDEV_PRECHANGEUPPER	0x001A

int register_netdevice_notifier(struct notifier_block *nb);
int unregister_netdevice_notifier(struct notifier_block *nb);

struct netdev_notifier_info {
	struct net_device *dev;
};

struct netdev_notifier_change_info {
	struct netdev_notifier_info info;  
	unsigned int flags_changed;
};

struct netdev_notifier_changeupper_info {
	struct netdev_notifier_info info;  
	struct net_device *upper_dev;  
	bool master;  
	bool linking;  
};

static inline void netdev_notifier_info_init(struct netdev_notifier_info *info,
					     struct net_device *dev)
{
	info->dev = dev;
}

static inline struct net_device *
netdev_notifier_info_to_dev(const struct netdev_notifier_info *info)
{
	return info->dev;
}

int call_netdevice_notifiers(unsigned long val, struct net_device *dev);

extern rwlock_t				dev_base_lock;		 

#define for_each_netdev(net, d)		\
		list_for_each_entry(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_reverse(net, d)	\
		list_for_each_entry_reverse(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_rcu(net, d)		\
		list_for_each_entry_rcu(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_safe(net, d, n)	\
		list_for_each_entry_safe(d, n, &(net)->dev_base_head, dev_list)
#define for_each_netdev_continue(net, d)		\
		list_for_each_entry_continue(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_continue_rcu(net, d)		\
	list_for_each_entry_continue_rcu(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_in_bond_rcu(bond, slave)	\
		for_each_netdev_rcu(&init_net, slave)	\
			if (netdev_master_upper_dev_get_rcu(slave) == (bond))
#define net_device_entry(lh)	list_entry(lh, struct net_device, dev_list)

static inline struct net_device *next_net_device(struct net_device *dev)
{
	struct list_head *lh;
	struct net *net;

	net = dev_net(dev);
	lh = dev->dev_list.next;
	return lh == &net->dev_base_head ? NULL : net_device_entry(lh);
}

static inline struct net_device *next_net_device_rcu(struct net_device *dev)
{
	struct list_head *lh;
	struct net *net;

	net = dev_net(dev);
	lh = rcu_dereference(list_next_rcu(&dev->dev_list));
	return lh == &net->dev_base_head ? NULL : net_device_entry(lh);
}

static inline struct net_device *first_net_device(struct net *net)
{
	return list_empty(&net->dev_base_head) ? NULL :
		net_device_entry(net->dev_base_head.next);
}

static inline struct net_device *first_net_device_rcu(struct net *net)
{
	struct list_head *lh = rcu_dereference(list_next_rcu(&net->dev_base_head));

	return lh == &net->dev_base_head ? NULL : net_device_entry(lh);
}

int netdev_boot_setup_check(struct net_device *dev);
unsigned long netdev_boot_base(const char *prefix, int unit);
struct net_device *dev_getbyhwaddr_rcu(struct net *net, unsigned short type,
				       const char *hwaddr);
struct net_device *dev_getfirstbyhwtype(struct net *net, unsigned short type);
struct net_device *__dev_getfirstbyhwtype(struct net *net, unsigned short type);
void dev_add_pack(struct packet_type *pt);
void dev_remove_pack(struct packet_type *pt);
void __dev_remove_pack(struct packet_type *pt);
void dev_add_offload(struct packet_offload *po);
void dev_remove_offload(struct packet_offload *po);

int dev_get_iflink(const struct net_device *dev);
int dev_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb);
struct net_device *__dev_get_by_flags(struct net *net, unsigned short flags,
				      unsigned short mask);
struct net_device *dev_get_by_name(struct net *net, const char *name);
struct net_device *dev_get_by_name_rcu(struct net *net, const char *name);
struct net_device *__dev_get_by_name(struct net *net, const char *name);
int dev_alloc_name(struct net_device *dev, const char *name);
int dev_open(struct net_device *dev);
int dev_close(struct net_device *dev);
int dev_close_many(struct list_head *head, bool unlink);
void dev_disable_lro(struct net_device *dev);
int dev_loopback_xmit(struct net *net, struct sock *sk, struct sk_buff *newskb);
int dev_queue_xmit(struct sk_buff *skb);
int dev_queue_xmit_accel(struct sk_buff *skb, void *accel_priv);
int register_netdevice(struct net_device *dev);
void unregister_netdevice_queue(struct net_device *dev, struct list_head *head);
void unregister_netdevice_many(struct list_head *head);
static inline void unregister_netdevice(struct net_device *dev)
{
	unregister_netdevice_queue(dev, NULL);
}

int netdev_refcnt_read(const struct net_device *dev);
void free_netdev(struct net_device *dev);
void netdev_freemem(struct net_device *dev);
void synchronize_net(void);
int init_dummy_netdev(struct net_device *dev);

DECLARE_PER_CPU(int, xmit_recursion);
static inline int dev_recursion_level(void)
{
	return this_cpu_read(xmit_recursion);
}

struct net_device *dev_get_by_index(struct net *net, int ifindex);
struct net_device *__dev_get_by_index(struct net *net, int ifindex);
struct net_device *dev_get_by_index_rcu(struct net *net, int ifindex);
int netdev_get_name(struct net *net, char *name, int ifindex);
int dev_restart(struct net_device *dev);
int skb_gro_receive(struct sk_buff **head, struct sk_buff *skb);

static inline unsigned int skb_gro_offset(const struct sk_buff *skb)
{
	return NAPI_GRO_CB(skb)->data_offset;
}

static inline unsigned int skb_gro_len(const struct sk_buff *skb)
{
	return skb->len - NAPI_GRO_CB(skb)->data_offset;
}

static inline void skb_gro_pull(struct sk_buff *skb, unsigned int len)
{
	NAPI_GRO_CB(skb)->data_offset += len;
}

static inline void *skb_gro_header_fast(struct sk_buff *skb,
					unsigned int offset)
{
	return NAPI_GRO_CB(skb)->frag0 + offset;
}

static inline int skb_gro_header_hard(struct sk_buff *skb, unsigned int hlen)
{
	return NAPI_GRO_CB(skb)->frag0_len < hlen;
}

static inline void skb_gro_frag0_invalidate(struct sk_buff *skb)
{
	NAPI_GRO_CB(skb)->frag0 = NULL;
	NAPI_GRO_CB(skb)->frag0_len = 0;
}

static inline void *skb_gro_header_slow(struct sk_buff *skb, unsigned int hlen,
					unsigned int offset)
{
	if (!pskb_may_pull(skb, hlen))
		return NULL;

	skb_gro_frag0_invalidate(skb);
	return skb->data + offset;
}

static inline void *skb_gro_network_header(struct sk_buff *skb)
{
	return (NAPI_GRO_CB(skb)->frag0 ?: skb->data) +
	       skb_network_offset(skb);
}

static inline void skb_gro_postpull_rcsum(struct sk_buff *skb,
					const void *start, unsigned int len)
{
	if (NAPI_GRO_CB(skb)->csum_valid)
		NAPI_GRO_CB(skb)->csum = csum_sub(NAPI_GRO_CB(skb)->csum,
						  csum_partial(start, len, 0));
}

__sum16 __skb_gro_checksum_complete(struct sk_buff *skb);

static inline bool skb_at_gro_remcsum_start(struct sk_buff *skb)
{
	return (NAPI_GRO_CB(skb)->gro_remcsum_start == skb_gro_offset(skb));
}

static inline bool __skb_gro_checksum_validate_needed(struct sk_buff *skb,
						      bool zero_okay,
						      __sum16 check)
{
	return ((skb->ip_summed != CHECKSUM_PARTIAL ||
		skb_checksum_start_offset(skb) <
		 skb_gro_offset(skb)) &&
		!skb_at_gro_remcsum_start(skb) &&
		NAPI_GRO_CB(skb)->csum_cnt == 0 &&
		(!zero_okay || check));
}

static inline __sum16 __skb_gro_checksum_validate_complete(struct sk_buff *skb,
							   __wsum psum)
{
	if (NAPI_GRO_CB(skb)->csum_valid &&
	    !csum_fold(csum_add(psum, NAPI_GRO_CB(skb)->csum)))
		return 0;

	NAPI_GRO_CB(skb)->csum = psum;

	return __skb_gro_checksum_complete(skb);
}

static inline void skb_gro_incr_csum_unnecessary(struct sk_buff *skb)
{
	if (NAPI_GRO_CB(skb)->csum_cnt > 0) {
		 
		NAPI_GRO_CB(skb)->csum_cnt--;
	} else {
		 
		__skb_incr_checksum_unnecessary(skb);
	}
}

#define __skb_gro_checksum_validate(skb, proto, zero_okay, check,	\
				    compute_pseudo)			\
({									\
	__sum16 __ret = 0;						\
	if (__skb_gro_checksum_validate_needed(skb, zero_okay, check))	\
		__ret = __skb_gro_checksum_validate_complete(skb,	\
				compute_pseudo(skb, proto));		\
	if (__ret)							\
		__skb_mark_checksum_bad(skb);				\
	else								\
		skb_gro_incr_csum_unnecessary(skb);			\
	__ret;								\
})

#define skb_gro_checksum_validate(skb, proto, compute_pseudo)		\
	__skb_gro_checksum_validate(skb, proto, false, 0, compute_pseudo)

#define skb_gro_checksum_validate_zero_check(skb, proto, check,		\
					     compute_pseudo)		\
	__skb_gro_checksum_validate(skb, proto, true, check, compute_pseudo)

#define skb_gro_checksum_simple_validate(skb)				\
	__skb_gro_checksum_validate(skb, 0, false, 0, null_compute_pseudo)

static inline bool __skb_gro_checksum_convert_check(struct sk_buff *skb)
{
	return (NAPI_GRO_CB(skb)->csum_cnt == 0 &&
		!NAPI_GRO_CB(skb)->csum_valid);
}

static inline void __skb_gro_checksum_convert(struct sk_buff *skb,
					      __sum16 check, __wsum pseudo)
{
	NAPI_GRO_CB(skb)->csum = ~pseudo;
	NAPI_GRO_CB(skb)->csum_valid = 1;
}

#define skb_gro_checksum_try_convert(skb, proto, check, compute_pseudo)	\
do {									\
	if (__skb_gro_checksum_convert_check(skb))			\
		__skb_gro_checksum_convert(skb, check,			\
					   compute_pseudo(skb, proto));	\
} while (0)

struct gro_remcsum {
	int offset;
	__wsum delta;
};

static inline void skb_gro_remcsum_init(struct gro_remcsum *grc)
{
	grc->offset = 0;
	grc->delta = 0;
}

static inline void *skb_gro_remcsum_process(struct sk_buff *skb, void *ptr,
					    unsigned int off, size_t hdrlen,
					    int start, int offset,
					    struct gro_remcsum *grc,
					    bool nopartial)
{
	__wsum delta;
	size_t plen = hdrlen + max_t(size_t, offset + sizeof(u16), start);

	BUG_ON(!NAPI_GRO_CB(skb)->csum_valid);

	if (!nopartial) {
		NAPI_GRO_CB(skb)->gro_remcsum_start = off + hdrlen + start;
		return ptr;
	}

	ptr = skb_gro_header_fast(skb, off);
	if (skb_gro_header_hard(skb, off + plen)) {
		ptr = skb_gro_header_slow(skb, off + plen, off);
		if (!ptr)
			return NULL;
	}

	delta = remcsum_adjust(ptr + hdrlen, NAPI_GRO_CB(skb)->csum,
			       start, offset);

	NAPI_GRO_CB(skb)->csum = csum_add(NAPI_GRO_CB(skb)->csum, delta);

	grc->offset = off + hdrlen + offset;
	grc->delta = delta;

	return ptr;
}

static inline void skb_gro_remcsum_cleanup(struct sk_buff *skb,
					   struct gro_remcsum *grc)
{
	void *ptr;
	size_t plen = grc->offset + sizeof(u16);

	if (!grc->delta)
		return;

	ptr = skb_gro_header_fast(skb, grc->offset);
	if (skb_gro_header_hard(skb, grc->offset + sizeof(u16))) {
		ptr = skb_gro_header_slow(skb, plen, grc->offset);
		if (!ptr)
			return;
	}

	remcsum_unadjust((__sum16 *)ptr, grc->delta);
}

static inline int dev_hard_header(struct sk_buff *skb, struct net_device *dev,
				  unsigned short type,
				  const void *daddr, const void *saddr,
				  unsigned int len)
{
	if (!dev->header_ops || !dev->header_ops->create)
		return 0;

	return dev->header_ops->create(skb, dev, type, daddr, saddr, len);
}

static inline int dev_parse_header(const struct sk_buff *skb,
				   unsigned char *haddr)
{
	const struct net_device *dev = skb->dev;

	if (!dev->header_ops || !dev->header_ops->parse)
		return 0;
	return dev->header_ops->parse(skb, haddr);
}

static inline bool dev_validate_header(const struct net_device *dev,
				       char *ll_header, int len)
{
	if (likely(len >= dev->hard_header_len))
		return true;
	if (len < dev->min_header_len)
		return false;

	if (capable(CAP_SYS_RAWIO)) {
		memset(ll_header + len, 0, dev->hard_header_len - len);
		return true;
	}

	if (dev->header_ops && dev->header_ops->validate)
		return dev->header_ops->validate(ll_header, len);

	return false;
}

typedef int gifconf_func_t(struct net_device * dev, char __user * bufptr, int len);
int register_gifconf(unsigned int family, gifconf_func_t *gifconf);
static inline int unregister_gifconf(unsigned int family)
{
	return register_gifconf(family, NULL);
}

#ifdef CONFIG_NET_FLOW_LIMIT
#define FLOW_LIMIT_HISTORY	(1 << 7)   
struct sd_flow_limit {
	u64			count;
	unsigned int		num_buckets;
	unsigned int		history_head;
	u16			history[FLOW_LIMIT_HISTORY];
	u8			buckets[];
};

extern int netdev_flow_limit_table_len;
#endif  

struct softnet_data {
	struct list_head	poll_list;
	struct sk_buff_head	process_queue;

	unsigned int		processed;
	unsigned int		time_squeeze;
	unsigned int		cpu_collision;
	unsigned int		received_rps;
#ifdef CONFIG_RPS
	struct softnet_data	*rps_ipi_list;
#endif
#ifdef CONFIG_NET_FLOW_LIMIT
	struct sd_flow_limit __rcu *flow_limit;
#endif
	struct Qdisc		*output_queue;
	struct Qdisc		**output_queue_tailp;
	struct sk_buff		*completion_queue;

#ifdef CONFIG_RPS
	 
	struct call_single_data	csd ____cacheline_aligned_in_smp;
	struct softnet_data	*rps_ipi_next;
	unsigned int		cpu;
	unsigned int		input_queue_head;
	unsigned int		input_queue_tail;
#endif
	unsigned int		dropped;
	struct sk_buff_head	input_pkt_queue;
	struct napi_struct	backlog;

};

static inline void input_queue_head_incr(struct softnet_data *sd)
{
#ifdef CONFIG_RPS
	sd->input_queue_head++;
#endif
}

static inline void input_queue_tail_incr_save(struct softnet_data *sd,
					      unsigned int *qtail)
{
#ifdef CONFIG_RPS
	*qtail = ++sd->input_queue_tail;
#endif
}

DECLARE_PER_CPU_ALIGNED(struct softnet_data, softnet_data);

void __netif_schedule(struct Qdisc *q);
void netif_schedule_queue(struct netdev_queue *txq);

static inline void netif_tx_schedule_all(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++)
		netif_schedule_queue(netdev_get_tx_queue(dev, i));
}

static inline void netif_tx_start_queue(struct netdev_queue *dev_queue)
{
	clear_bit(__QUEUE_STATE_DRV_XOFF, &dev_queue->state);
}

static inline void netif_start_queue(struct net_device *dev)
{
	netif_tx_start_queue(netdev_get_tx_queue(dev, 0));
}

static inline void netif_tx_start_all_queues(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		netif_tx_start_queue(txq);
	}
}

void netif_tx_wake_queue(struct netdev_queue *dev_queue);

static inline void netif_wake_queue(struct net_device *dev)
{
	netif_tx_wake_queue(netdev_get_tx_queue(dev, 0));
}

static inline void netif_tx_wake_all_queues(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		netif_tx_wake_queue(txq);
	}
}

static inline void netif_tx_stop_queue(struct netdev_queue *dev_queue)
{
	set_bit(__QUEUE_STATE_DRV_XOFF, &dev_queue->state);
}

static inline void netif_stop_queue(struct net_device *dev)
{
	netif_tx_stop_queue(netdev_get_tx_queue(dev, 0));
}

void netif_tx_stop_all_queues(struct net_device *dev);

static inline bool netif_tx_queue_stopped(const struct netdev_queue *dev_queue)
{
	return test_bit(__QUEUE_STATE_DRV_XOFF, &dev_queue->state);
}

static inline bool netif_queue_stopped(const struct net_device *dev)
{
	return netif_tx_queue_stopped(netdev_get_tx_queue(dev, 0));
}

static inline bool netif_xmit_stopped(const struct netdev_queue *dev_queue)
{
	return dev_queue->state & QUEUE_STATE_ANY_XOFF;
}

static inline bool
netif_xmit_frozen_or_stopped(const struct netdev_queue *dev_queue)
{
	return dev_queue->state & QUEUE_STATE_ANY_XOFF_OR_FROZEN;
}

static inline bool
netif_xmit_frozen_or_drv_stopped(const struct netdev_queue *dev_queue)
{
	return dev_queue->state & QUEUE_STATE_DRV_XOFF_OR_FROZEN;
}

static inline void netdev_txq_bql_enqueue_prefetchw(struct netdev_queue *dev_queue)
{
#ifdef CONFIG_BQL
	prefetchw(&dev_queue->dql.num_queued);
#endif
}

static inline void netdev_txq_bql_complete_prefetchw(struct netdev_queue *dev_queue)
{
#ifdef CONFIG_BQL
	prefetchw(&dev_queue->dql.limit);
#endif
}

static inline void netdev_tx_sent_queue(struct netdev_queue *dev_queue,
					unsigned int bytes)
{
#ifdef CONFIG_BQL
	dql_queued(&dev_queue->dql, bytes);

	if (likely(dql_avail(&dev_queue->dql) >= 0))
		return;

	set_bit(__QUEUE_STATE_STACK_XOFF, &dev_queue->state);

	smp_mb();

	if (unlikely(dql_avail(&dev_queue->dql) >= 0))
		clear_bit(__QUEUE_STATE_STACK_XOFF, &dev_queue->state);
#endif
}

static inline void netdev_sent_queue(struct net_device *dev, unsigned int bytes)
{
	netdev_tx_sent_queue(netdev_get_tx_queue(dev, 0), bytes);
}

static inline void netdev_tx_completed_queue(struct netdev_queue *dev_queue,
					     unsigned int pkts, unsigned int bytes)
{
#ifdef CONFIG_BQL
	if (unlikely(!bytes))
		return;

	dql_completed(&dev_queue->dql, bytes);

	smp_mb();

	if (dql_avail(&dev_queue->dql) < 0)
		return;

	if (test_and_clear_bit(__QUEUE_STATE_STACK_XOFF, &dev_queue->state))
		netif_schedule_queue(dev_queue);
#endif
}

static inline void netdev_completed_queue(struct net_device *dev,
					  unsigned int pkts, unsigned int bytes)
{
	netdev_tx_completed_queue(netdev_get_tx_queue(dev, 0), pkts, bytes);
}

static inline void netdev_tx_reset_queue(struct netdev_queue *q)
{
#ifdef CONFIG_BQL
	clear_bit(__QUEUE_STATE_STACK_XOFF, &q->state);
	dql_reset(&q->dql);
#endif
}

static inline void netdev_reset_queue(struct net_device *dev_queue)
{
	netdev_tx_reset_queue(netdev_get_tx_queue(dev_queue, 0));
}

static inline u16 netdev_cap_txqueue(struct net_device *dev, u16 queue_index)
{
	if (unlikely(queue_index >= dev->real_num_tx_queues)) {
		net_warn_ratelimited("%s selects TX queue %d, but real number of TX queues is %d\n",
				     dev->name, queue_index,
				     dev->real_num_tx_queues);
		return 0;
	}

	return queue_index;
}

static inline bool netif_running(const struct net_device *dev)
{
	return test_bit(__LINK_STATE_START, &dev->state);
}

static inline void netif_start_subqueue(struct net_device *dev, u16 queue_index)
{
	struct netdev_queue *txq = netdev_get_tx_queue(dev, queue_index);

	netif_tx_start_queue(txq);
}

static inline void netif_stop_subqueue(struct net_device *dev, u16 queue_index)
{
	struct netdev_queue *txq = netdev_get_tx_queue(dev, queue_index);
	netif_tx_stop_queue(txq);
}

static inline bool __netif_subqueue_stopped(const struct net_device *dev,
					    u16 queue_index)
{
	struct netdev_queue *txq = netdev_get_tx_queue(dev, queue_index);

	return netif_tx_queue_stopped(txq);
}

static inline bool netif_subqueue_stopped(const struct net_device *dev,
					  struct sk_buff *skb)
{
	return __netif_subqueue_stopped(dev, skb_get_queue_mapping(skb));
}

void netif_wake_subqueue(struct net_device *dev, u16 queue_index);

#ifdef CONFIG_XPS
int netif_set_xps_queue(struct net_device *dev, const struct cpumask *mask,
			u16 index);
#else
static inline int netif_set_xps_queue(struct net_device *dev,
				      const struct cpumask *mask,
				      u16 index)
{
	return 0;
}
#endif

u16 __skb_tx_hash(const struct net_device *dev, struct sk_buff *skb,
		  unsigned int num_tx_queues);

static inline u16 skb_tx_hash(const struct net_device *dev,
			      struct sk_buff *skb)
{
	return __skb_tx_hash(dev, skb, dev->real_num_tx_queues);
}

static inline bool netif_is_multiqueue(const struct net_device *dev)
{
	return dev->num_tx_queues > 1;
}

int netif_set_real_num_tx_queues(struct net_device *dev, unsigned int txq);

#ifdef CONFIG_SYSFS
int netif_set_real_num_rx_queues(struct net_device *dev, unsigned int rxq);
#else
static inline int netif_set_real_num_rx_queues(struct net_device *dev,
						unsigned int rxq)
{
	return 0;
}
#endif

#ifdef CONFIG_SYSFS
static inline unsigned int get_netdev_rx_queue_index(
		struct netdev_rx_queue *queue)
{
	struct net_device *dev = queue->dev;
	int index = queue - dev->_rx;

	BUG_ON(index >= dev->num_rx_queues);
	return index;
}
#endif

#define DEFAULT_MAX_NUM_RSS_QUEUES	(8)
int netif_get_num_default_rss_queues(void);

enum skb_free_reason {
	SKB_REASON_CONSUMED,
	SKB_REASON_DROPPED,
};

void __dev_kfree_skb_irq(struct sk_buff *skb, enum skb_free_reason reason);
void __dev_kfree_skb_any(struct sk_buff *skb, enum skb_free_reason reason);

static inline void dev_kfree_skb_irq(struct sk_buff *skb)
{
	__dev_kfree_skb_irq(skb, SKB_REASON_DROPPED);
}

static inline void dev_consume_skb_irq(struct sk_buff *skb)
{
	__dev_kfree_skb_irq(skb, SKB_REASON_CONSUMED);
}

static inline void dev_kfree_skb_any(struct sk_buff *skb)
{
	__dev_kfree_skb_any(skb, SKB_REASON_DROPPED);
}

static inline void dev_consume_skb_any(struct sk_buff *skb)
{
	__dev_kfree_skb_any(skb, SKB_REASON_CONSUMED);
}

int netif_rx(struct sk_buff *skb);
int netif_rx_ni(struct sk_buff *skb);
int netif_receive_skb(struct sk_buff *skb);
gro_result_t napi_gro_receive(struct napi_struct *napi, struct sk_buff *skb);
void napi_gro_flush(struct napi_struct *napi, bool flush_old);
struct sk_buff *napi_get_frags(struct napi_struct *napi);
gro_result_t napi_gro_frags(struct napi_struct *napi);
struct packet_offload *gro_find_receive_by_type(__be16 type);
struct packet_offload *gro_find_complete_by_type(__be16 type);

static inline void napi_free_frags(struct napi_struct *napi)
{
	kfree_skb(napi->skb);
	napi->skb = NULL;
}

bool netdev_is_rx_handler_busy(struct net_device *dev);
int netdev_rx_handler_register(struct net_device *dev,
			       rx_handler_func_t *rx_handler,
			       void *rx_handler_data);
void netdev_rx_handler_unregister(struct net_device *dev);

bool dev_valid_name(const char *name);
int dev_ioctl(struct net *net, unsigned int cmd, void __user *);
int dev_ethtool(struct net *net, struct ifreq *);
unsigned int dev_get_flags(const struct net_device *);
int __dev_change_flags(struct net_device *, unsigned int flags);
int dev_change_flags(struct net_device *, unsigned int);
void __dev_notify_flags(struct net_device *, unsigned int old_flags,
			unsigned int gchanges);
int dev_change_name(struct net_device *, const char *);
int dev_set_alias(struct net_device *, const char *, size_t);
int dev_change_net_namespace(struct net_device *, struct net *, const char *);
int dev_set_mtu(struct net_device *, int);
void dev_set_group(struct net_device *, int);
int dev_set_mac_address(struct net_device *, struct sockaddr *);
int dev_change_carrier(struct net_device *, bool new_carrier);
int dev_get_phys_port_id(struct net_device *dev,
			 struct netdev_phys_item_id *ppid);
int dev_get_phys_port_name(struct net_device *dev,
			   char *name, size_t len);
int dev_change_proto_down(struct net_device *dev, bool proto_down);
struct sk_buff *validate_xmit_skb_list(struct sk_buff *skb, struct net_device *dev);
struct sk_buff *dev_hard_start_xmit(struct sk_buff *skb, struct net_device *dev,
				    struct netdev_queue *txq, int *ret);
int __dev_forward_skb(struct net_device *dev, struct sk_buff *skb);
int dev_forward_skb(struct net_device *dev, struct sk_buff *skb);
bool is_skb_forwardable(struct net_device *dev, struct sk_buff *skb);

extern int		netdev_budget;

void netdev_run_todo(void);

static inline void dev_put(struct net_device *dev)
{
	this_cpu_dec(*dev->pcpu_refcnt);
}

static inline void dev_hold(struct net_device *dev)
{
	this_cpu_inc(*dev->pcpu_refcnt);
}

void linkwatch_init_dev(struct net_device *dev);
void linkwatch_fire_event(struct net_device *dev);
void linkwatch_forget_dev(struct net_device *dev);

static inline bool netif_carrier_ok(const struct net_device *dev)
{
	return !test_bit(__LINK_STATE_NOCARRIER, &dev->state);
}

unsigned long dev_trans_start(struct net_device *dev);

void __netdev_watchdog_up(struct net_device *dev);

void netif_carrier_on(struct net_device *dev);

void netif_carrier_off(struct net_device *dev);

static inline void netif_dormant_on(struct net_device *dev)
{
	if (!test_and_set_bit(__LINK_STATE_DORMANT, &dev->state))
		linkwatch_fire_event(dev);
}

static inline void netif_dormant_off(struct net_device *dev)
{
	if (test_and_clear_bit(__LINK_STATE_DORMANT, &dev->state))
		linkwatch_fire_event(dev);
}

static inline bool netif_dormant(const struct net_device *dev)
{
	return test_bit(__LINK_STATE_DORMANT, &dev->state);
}

static inline bool netif_oper_up(const struct net_device *dev)
{
	return (dev->operstate == IF_OPER_UP ||
		dev->operstate == IF_OPER_UNKNOWN  );
}

static inline bool netif_device_present(struct net_device *dev)
{
	return test_bit(__LINK_STATE_PRESENT, &dev->state);
}

void netif_device_detach(struct net_device *dev);

void netif_device_attach(struct net_device *dev);

enum {
	NETIF_MSG_DRV		= 0x0001,
	NETIF_MSG_PROBE		= 0x0002,
	NETIF_MSG_LINK		= 0x0004,
	NETIF_MSG_TIMER		= 0x0008,
	NETIF_MSG_IFDOWN	= 0x0010,
	NETIF_MSG_IFUP		= 0x0020,
	NETIF_MSG_RX_ERR	= 0x0040,
	NETIF_MSG_TX_ERR	= 0x0080,
	NETIF_MSG_TX_QUEUED	= 0x0100,
	NETIF_MSG_INTR		= 0x0200,
	NETIF_MSG_TX_DONE	= 0x0400,
	NETIF_MSG_RX_STATUS	= 0x0800,
	NETIF_MSG_PKTDATA	= 0x1000,
	NETIF_MSG_HW		= 0x2000,
	NETIF_MSG_WOL		= 0x4000,
};

#define netif_msg_drv(p)	((p)->msg_enable & NETIF_MSG_DRV)
#define netif_msg_probe(p)	((p)->msg_enable & NETIF_MSG_PROBE)
#define netif_msg_link(p)	((p)->msg_enable & NETIF_MSG_LINK)
#define netif_msg_timer(p)	((p)->msg_enable & NETIF_MSG_TIMER)
#define netif_msg_ifdown(p)	((p)->msg_enable & NETIF_MSG_IFDOWN)
#define netif_msg_ifup(p)	((p)->msg_enable & NETIF_MSG_IFUP)
#define netif_msg_rx_err(p)	((p)->msg_enable & NETIF_MSG_RX_ERR)
#define netif_msg_tx_err(p)	((p)->msg_enable & NETIF_MSG_TX_ERR)
#define netif_msg_tx_queued(p)	((p)->msg_enable & NETIF_MSG_TX_QUEUED)
#define netif_msg_intr(p)	((p)->msg_enable & NETIF_MSG_INTR)
#define netif_msg_tx_done(p)	((p)->msg_enable & NETIF_MSG_TX_DONE)
#define netif_msg_rx_status(p)	((p)->msg_enable & NETIF_MSG_RX_STATUS)
#define netif_msg_pktdata(p)	((p)->msg_enable & NETIF_MSG_PKTDATA)
#define netif_msg_hw(p)		((p)->msg_enable & NETIF_MSG_HW)
#define netif_msg_wol(p)	((p)->msg_enable & NETIF_MSG_WOL)

static inline u32 netif_msg_init(int debug_value, int default_msg_enable_bits)
{
	 
	if (debug_value < 0 || debug_value >= (sizeof(u32) * 8))
		return default_msg_enable_bits;
	if (debug_value == 0)	 
		return 0;
	 
	return (1 << debug_value) - 1;
}

static inline void __netif_tx_lock(struct netdev_queue *txq, int cpu)
{
	spin_lock(&txq->_xmit_lock);
	txq->xmit_lock_owner = cpu;
}

static inline void __netif_tx_lock_bh(struct netdev_queue *txq)
{
	spin_lock_bh(&txq->_xmit_lock);
	txq->xmit_lock_owner = smp_processor_id();
}

static inline bool __netif_tx_trylock(struct netdev_queue *txq)
{
	bool ok = spin_trylock(&txq->_xmit_lock);
	if (likely(ok))
		txq->xmit_lock_owner = smp_processor_id();
	return ok;
}

static inline void __netif_tx_unlock(struct netdev_queue *txq)
{
	txq->xmit_lock_owner = -1;
	spin_unlock(&txq->_xmit_lock);
}

static inline void __netif_tx_unlock_bh(struct netdev_queue *txq)
{
	txq->xmit_lock_owner = -1;
	spin_unlock_bh(&txq->_xmit_lock);
}

static inline void txq_trans_update(struct netdev_queue *txq)
{
	if (txq->xmit_lock_owner != -1)
		txq->trans_start = jiffies;
}

static inline void netif_tx_lock(struct net_device *dev)
{
	unsigned int i;
	int cpu;

	spin_lock(&dev->tx_global_lock);
	cpu = smp_processor_id();
	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);

		__netif_tx_lock(txq, cpu);
		set_bit(__QUEUE_STATE_FROZEN, &txq->state);
		__netif_tx_unlock(txq);
	}
}

static inline void netif_tx_lock_bh(struct net_device *dev)
{
	local_bh_disable();
	netif_tx_lock(dev);
}

static inline void netif_tx_unlock(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);

		clear_bit(__QUEUE_STATE_FROZEN, &txq->state);
		netif_schedule_queue(txq);
	}
	spin_unlock(&dev->tx_global_lock);
}

static inline void netif_tx_unlock_bh(struct net_device *dev)
{
	netif_tx_unlock(dev);
	local_bh_enable();
}

#define HARD_TX_LOCK(dev, txq, cpu) {			\
	if ((dev->features & NETIF_F_LLTX) == 0) {	\
		__netif_tx_lock(txq, cpu);		\
	}						\
}

#define HARD_TX_TRYLOCK(dev, txq)			\
	(((dev->features & NETIF_F_LLTX) == 0) ?	\
		__netif_tx_trylock(txq) :		\
		true )

#define HARD_TX_UNLOCK(dev, txq) {			\
	if ((dev->features & NETIF_F_LLTX) == 0) {	\
		__netif_tx_unlock(txq);			\
	}						\
}

static inline void netif_tx_disable(struct net_device *dev)
{
	unsigned int i;
	int cpu;

	local_bh_disable();
	cpu = smp_processor_id();
	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);

		__netif_tx_lock(txq, cpu);
		netif_tx_stop_queue(txq);
		__netif_tx_unlock(txq);
	}
	local_bh_enable();
}

static inline void netif_addr_lock(struct net_device *dev)
{
	spin_lock(&dev->addr_list_lock);
}

static inline void netif_addr_lock_nested(struct net_device *dev)
{
	int subclass = SINGLE_DEPTH_NESTING;

	if (dev->netdev_ops->ndo_get_lock_subclass)
		subclass = dev->netdev_ops->ndo_get_lock_subclass(dev);

	spin_lock_nested(&dev->addr_list_lock, subclass);
}

static inline void netif_addr_lock_bh(struct net_device *dev)
{
	spin_lock_bh(&dev->addr_list_lock);
}

static inline void netif_addr_unlock(struct net_device *dev)
{
	spin_unlock(&dev->addr_list_lock);
}

static inline void netif_addr_unlock_bh(struct net_device *dev)
{
	spin_unlock_bh(&dev->addr_list_lock);
}

#define for_each_dev_addr(dev, ha) \
		list_for_each_entry_rcu(ha, &dev->dev_addrs.list, list)

void ether_setup(struct net_device *dev);

struct net_device *alloc_netdev_mqs(int sizeof_priv, const char *name,
				    unsigned char name_assign_type,
				    void (*setup)(struct net_device *),
				    unsigned int txqs, unsigned int rxqs);
#define alloc_netdev(sizeof_priv, name, name_assign_type, setup) \
	alloc_netdev_mqs(sizeof_priv, name, name_assign_type, setup, 1, 1)

#define alloc_netdev_mq(sizeof_priv, name, name_assign_type, setup, count) \
	alloc_netdev_mqs(sizeof_priv, name, name_assign_type, setup, count, \
			 count)

int register_netdev(struct net_device *dev);
void unregister_netdev(struct net_device *dev);

int __hw_addr_sync(struct netdev_hw_addr_list *to_list,
		   struct netdev_hw_addr_list *from_list, int addr_len);
void __hw_addr_unsync(struct netdev_hw_addr_list *to_list,
		      struct netdev_hw_addr_list *from_list, int addr_len);
int __hw_addr_sync_dev(struct netdev_hw_addr_list *list,
		       struct net_device *dev,
		       int (*sync)(struct net_device *, const unsigned char *),
		       int (*unsync)(struct net_device *,
				     const unsigned char *));
void __hw_addr_unsync_dev(struct netdev_hw_addr_list *list,
			  struct net_device *dev,
			  int (*unsync)(struct net_device *,
					const unsigned char *));
void __hw_addr_init(struct netdev_hw_addr_list *list);

int dev_addr_add(struct net_device *dev, const unsigned char *addr,
		 unsigned char addr_type);
int dev_addr_del(struct net_device *dev, const unsigned char *addr,
		 unsigned char addr_type);
void dev_addr_flush(struct net_device *dev);
int dev_addr_init(struct net_device *dev);

int dev_uc_add(struct net_device *dev, const unsigned char *addr);
int dev_uc_add_excl(struct net_device *dev, const unsigned char *addr);
int dev_uc_del(struct net_device *dev, const unsigned char *addr);
int dev_uc_sync(struct net_device *to, struct net_device *from);
int dev_uc_sync_multiple(struct net_device *to, struct net_device *from);
void dev_uc_unsync(struct net_device *to, struct net_device *from);
void dev_uc_flush(struct net_device *dev);
void dev_uc_init(struct net_device *dev);

static inline int __dev_uc_sync(struct net_device *dev,
				int (*sync)(struct net_device *,
					    const unsigned char *),
				int (*unsync)(struct net_device *,
					      const unsigned char *))
{
	return __hw_addr_sync_dev(&dev->uc, dev, sync, unsync);
}

static inline void __dev_uc_unsync(struct net_device *dev,
				   int (*unsync)(struct net_device *,
						 const unsigned char *))
{
	__hw_addr_unsync_dev(&dev->uc, dev, unsync);
}

int dev_mc_add(struct net_device *dev, const unsigned char *addr);
int dev_mc_add_global(struct net_device *dev, const unsigned char *addr);
int dev_mc_add_excl(struct net_device *dev, const unsigned char *addr);
int dev_mc_del(struct net_device *dev, const unsigned char *addr);
int dev_mc_del_global(struct net_device *dev, const unsigned char *addr);
int dev_mc_sync(struct net_device *to, struct net_device *from);
int dev_mc_sync_multiple(struct net_device *to, struct net_device *from);
void dev_mc_unsync(struct net_device *to, struct net_device *from);
void dev_mc_flush(struct net_device *dev);
void dev_mc_init(struct net_device *dev);

static inline int __dev_mc_sync(struct net_device *dev,
				int (*sync)(struct net_device *,
					    const unsigned char *),
				int (*unsync)(struct net_device *,
					      const unsigned char *))
{
	return __hw_addr_sync_dev(&dev->mc, dev, sync, unsync);
}

static inline void __dev_mc_unsync(struct net_device *dev,
				   int (*unsync)(struct net_device *,
						 const unsigned char *))
{
	__hw_addr_unsync_dev(&dev->mc, dev, unsync);
}

void dev_set_rx_mode(struct net_device *dev);
void __dev_set_rx_mode(struct net_device *dev);
int dev_set_promiscuity(struct net_device *dev, int inc);
int dev_set_allmulti(struct net_device *dev, int inc);
void netdev_state_change(struct net_device *dev);
void netdev_notify_peers(struct net_device *dev);
void netdev_features_change(struct net_device *dev);
 
void dev_load(struct net *net, const char *name);
struct rtnl_link_stats64 *dev_get_stats(struct net_device *dev,
					struct rtnl_link_stats64 *storage);
void netdev_stats_to_stats64(struct rtnl_link_stats64 *stats64,
			     const struct net_device_stats *netdev_stats);

extern int		netdev_max_backlog;
extern int		netdev_tstamp_prequeue;
extern int		weight_p;
extern int		bpf_jit_enable;

bool netdev_has_upper_dev(struct net_device *dev, struct net_device *upper_dev);
struct net_device *netdev_upper_get_next_dev_rcu(struct net_device *dev,
						     struct list_head **iter);
struct net_device *netdev_all_upper_get_next_dev_rcu(struct net_device *dev,
						     struct list_head **iter);

#define netdev_for_each_upper_dev_rcu(dev, updev, iter) \
	for (iter = &(dev)->adj_list.upper, \
	     updev = netdev_upper_get_next_dev_rcu(dev, &(iter)); \
	     updev; \
	     updev = netdev_upper_get_next_dev_rcu(dev, &(iter)))

#define netdev_for_each_all_upper_dev_rcu(dev, updev, iter) \
	for (iter = &(dev)->all_adj_list.upper, \
	     updev = netdev_all_upper_get_next_dev_rcu(dev, &(iter)); \
	     updev; \
	     updev = netdev_all_upper_get_next_dev_rcu(dev, &(iter)))

void *netdev_lower_get_next_private(struct net_device *dev,
				    struct list_head **iter);
void *netdev_lower_get_next_private_rcu(struct net_device *dev,
					struct list_head **iter);

#define netdev_for_each_lower_private(dev, priv, iter) \
	for (iter = (dev)->adj_list.lower.next, \
	     priv = netdev_lower_get_next_private(dev, &(iter)); \
	     priv; \
	     priv = netdev_lower_get_next_private(dev, &(iter)))

#define netdev_for_each_lower_private_rcu(dev, priv, iter) \
	for (iter = &(dev)->adj_list.lower, \
	     priv = netdev_lower_get_next_private_rcu(dev, &(iter)); \
	     priv; \
	     priv = netdev_lower_get_next_private_rcu(dev, &(iter)))

void *netdev_lower_get_next(struct net_device *dev,
				struct list_head **iter);
#define netdev_for_each_lower_dev(dev, ldev, iter) \
	for (iter = &(dev)->adj_list.lower, \
	     ldev = netdev_lower_get_next(dev, &(iter)); \
	     ldev; \
	     ldev = netdev_lower_get_next(dev, &(iter)))

void *netdev_adjacent_get_private(struct list_head *adj_list);
void *netdev_lower_get_first_private_rcu(struct net_device *dev);
struct net_device *netdev_master_upper_dev_get(struct net_device *dev);
struct net_device *netdev_master_upper_dev_get_rcu(struct net_device *dev);
int netdev_upper_dev_link(struct net_device *dev, struct net_device *upper_dev);
int netdev_master_upper_dev_link(struct net_device *dev,
				 struct net_device *upper_dev);
int netdev_master_upper_dev_link_private(struct net_device *dev,
					 struct net_device *upper_dev,
					 void *private);
void netdev_upper_dev_unlink(struct net_device *dev,
			     struct net_device *upper_dev);
void netdev_adjacent_rename_links(struct net_device *dev, char *oldname);
void *netdev_lower_dev_get_private(struct net_device *dev,
				   struct net_device *lower_dev);

#define NETDEV_RSS_KEY_LEN 52
extern u8 netdev_rss_key[NETDEV_RSS_KEY_LEN];
void netdev_rss_key_fill(void *buffer, size_t len);

int dev_get_nest_level(struct net_device *dev,
		       bool (*type_check)(struct net_device *dev));
int skb_checksum_help(struct sk_buff *skb);
struct sk_buff *__skb_gso_segment(struct sk_buff *skb,
				  netdev_features_t features, bool tx_path);
struct sk_buff *skb_mac_gso_segment(struct sk_buff *skb,
				    netdev_features_t features);

struct netdev_bonding_info {
	ifslave	slave;
	ifbond	master;
};

struct netdev_notifier_bonding_info {
	struct netdev_notifier_info info;  
	struct netdev_bonding_info  bonding_info;
};

void netdev_bonding_info_change(struct net_device *dev,
				struct netdev_bonding_info *bonding_info);

static inline
struct sk_buff *skb_gso_segment(struct sk_buff *skb, netdev_features_t features)
{
	return __skb_gso_segment(skb, features, true);
}
__be16 skb_network_protocol(struct sk_buff *skb, int *depth);

static inline bool can_checksum_protocol(netdev_features_t features,
					 __be16 protocol)
{
	return ((features & NETIF_F_GEN_CSUM) ||
		((features & NETIF_F_V4_CSUM) &&
		 protocol == htons(ETH_P_IP)) ||
		((features & NETIF_F_V6_CSUM) &&
		 protocol == htons(ETH_P_IPV6)) ||
		((features & NETIF_F_FCOE_CRC) &&
		 protocol == htons(ETH_P_FCOE)));
}

#ifdef CONFIG_BUG
void netdev_rx_csum_fault(struct net_device *dev);
#else
static inline void netdev_rx_csum_fault(struct net_device *dev)
{
}
#endif
 
void net_enable_timestamp(void);
void net_disable_timestamp(void);

#ifdef CONFIG_PROC_FS
int __init dev_proc_init(void);
#else
#define dev_proc_init() 0
#endif

static inline netdev_tx_t __netdev_start_xmit(const struct net_device_ops *ops,
					      struct sk_buff *skb, struct net_device *dev,
					      bool more)
{
	skb->xmit_more = more ? 1 : 0;
	return ops->ndo_start_xmit(skb, dev);
}

static inline netdev_tx_t netdev_start_xmit(struct sk_buff *skb, struct net_device *dev,
					    struct netdev_queue *txq, bool more)
{
	const struct net_device_ops *ops = dev->netdev_ops;
	int rc;

	rc = __netdev_start_xmit(ops, skb, dev, more);
	if (rc == NETDEV_TX_OK)
		txq_trans_update(txq);

	return rc;
}

int netdev_class_create_file_ns(struct class_attribute *class_attr,
				const void *ns);
void netdev_class_remove_file_ns(struct class_attribute *class_attr,
				 const void *ns);

static inline int netdev_class_create_file(struct class_attribute *class_attr)
{
	return netdev_class_create_file_ns(class_attr, NULL);
}

static inline void netdev_class_remove_file(struct class_attribute *class_attr)
{
	netdev_class_remove_file_ns(class_attr, NULL);
}

extern struct kobj_ns_type_operations net_ns_type_operations;

const char *netdev_drivername(const struct net_device *dev);

void linkwatch_run_queue(void);

static inline netdev_features_t netdev_intersect_features(netdev_features_t f1,
							  netdev_features_t f2)
{
	if (f1 & NETIF_F_GEN_CSUM)
		f1 |= (NETIF_F_ALL_CSUM & ~NETIF_F_GEN_CSUM);
	if (f2 & NETIF_F_GEN_CSUM)
		f2 |= (NETIF_F_ALL_CSUM & ~NETIF_F_GEN_CSUM);
	f1 &= f2;
	if (f1 & NETIF_F_GEN_CSUM)
		f1 &= ~(NETIF_F_ALL_CSUM & ~NETIF_F_GEN_CSUM);

	return f1;
}

static inline netdev_features_t netdev_get_wanted_features(
	struct net_device *dev)
{
	return (dev->features & ~dev->hw_features) | dev->wanted_features;
}
netdev_features_t netdev_increment_features(netdev_features_t all,
	netdev_features_t one, netdev_features_t mask);

static inline netdev_features_t netdev_add_tso_features(netdev_features_t features,
							netdev_features_t mask)
{
	return netdev_increment_features(features, NETIF_F_ALL_TSO, mask);
}

int __netdev_update_features(struct net_device *dev);
void netdev_update_features(struct net_device *dev);
void netdev_change_features(struct net_device *dev);

void netif_stacked_transfer_operstate(const struct net_device *rootdev,
					struct net_device *dev);

netdev_features_t passthru_features_check(struct sk_buff *skb,
					  struct net_device *dev,
					  netdev_features_t features);
netdev_features_t netif_skb_features(struct sk_buff *skb);

static inline bool net_gso_ok(netdev_features_t features, int gso_type)
{
	netdev_features_t feature = gso_type << NETIF_F_GSO_SHIFT;

	BUILD_BUG_ON(SKB_GSO_TCPV4   != (NETIF_F_TSO >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_UDP     != (NETIF_F_UFO >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_DODGY   != (NETIF_F_GSO_ROBUST >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_TCP_ECN != (NETIF_F_TSO_ECN >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_TCPV6   != (NETIF_F_TSO6 >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_FCOE    != (NETIF_F_FSO >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_GRE     != (NETIF_F_GSO_GRE >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_GRE_CSUM != (NETIF_F_GSO_GRE_CSUM >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_IPIP    != (NETIF_F_GSO_IPIP >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_SIT     != (NETIF_F_GSO_SIT >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_UDP_TUNNEL != (NETIF_F_GSO_UDP_TUNNEL >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_UDP_TUNNEL_CSUM != (NETIF_F_GSO_UDP_TUNNEL_CSUM >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_TUNNEL_REMCSUM != (NETIF_F_GSO_TUNNEL_REMCSUM >> NETIF_F_GSO_SHIFT));

	return (features & feature) == feature;
}

static inline bool skb_gso_ok(struct sk_buff *skb, netdev_features_t features)
{
	return net_gso_ok(features, skb_shinfo(skb)->gso_type) &&
	       (!skb_has_frag_list(skb) || (features & NETIF_F_FRAGLIST));
}

static inline bool netif_needs_gso(struct sk_buff *skb,
				   netdev_features_t features)
{
	return skb_is_gso(skb) && (!skb_gso_ok(skb, features) ||
		unlikely((skb->ip_summed != CHECKSUM_PARTIAL) &&
			 (skb->ip_summed != CHECKSUM_UNNECESSARY)));
}

static inline void netif_set_gso_max_size(struct net_device *dev,
					  unsigned int size)
{
	dev->gso_max_size = size;
}

static inline void skb_gso_error_unwind(struct sk_buff *skb, __be16 protocol,
					int pulled_hlen, u16 mac_offset,
					int mac_len)
{
	skb->protocol = protocol;
	skb->encapsulation = 1;
	skb_push(skb, pulled_hlen);
	skb_reset_transport_header(skb);
	skb->mac_header = mac_offset;
	skb->network_header = skb->mac_header + mac_len;
	skb->mac_len = mac_len;
}

static inline bool netif_is_macvlan(struct net_device *dev)
{
	return dev->priv_flags & IFF_MACVLAN;
}

static inline bool netif_is_macvlan_port(struct net_device *dev)
{
	return dev->priv_flags & IFF_MACVLAN_PORT;
}

static inline bool netif_is_ipvlan(struct net_device *dev)
{
	return dev->priv_flags & IFF_IPVLAN_SLAVE;
}

static inline bool netif_is_ipvlan_port(struct net_device *dev)
{
	return dev->priv_flags & IFF_IPVLAN_MASTER;
}

static inline bool netif_is_bond_master(struct net_device *dev)
{
	return dev->flags & IFF_MASTER && dev->priv_flags & IFF_BONDING;
}

static inline bool netif_is_bond_slave(struct net_device *dev)
{
	return dev->flags & IFF_SLAVE && dev->priv_flags & IFF_BONDING;
}

static inline bool netif_supports_nofcs(struct net_device *dev)
{
	return dev->priv_flags & IFF_SUPP_NOFCS;
}

static inline bool netif_is_l3_master(const struct net_device *dev)
{
	return dev->priv_flags & IFF_L3MDEV_MASTER;
}

static inline bool netif_is_l3_slave(const struct net_device *dev)
{
	return dev->priv_flags & IFF_L3MDEV_SLAVE;
}

static inline bool netif_is_bridge_master(const struct net_device *dev)
{
	return dev->priv_flags & IFF_EBRIDGE;
}

static inline bool netif_is_bridge_port(const struct net_device *dev)
{
	return dev->priv_flags & IFF_BRIDGE_PORT;
}

static inline bool netif_is_ovs_master(const struct net_device *dev)
{
	return dev->priv_flags & IFF_OPENVSWITCH;
}

static inline void netif_keep_dst(struct net_device *dev)
{
	dev->priv_flags &= ~(IFF_XMIT_DST_RELEASE | IFF_XMIT_DST_RELEASE_PERM);
}

extern struct pernet_operations __net_initdata loopback_net_ops;

#ifdef MY_ABC_HERE
extern int syno_get_dev_vendor_mac(const char *szDev, char *szMac);
#endif  

static inline const char *netdev_name(const struct net_device *dev)
{
	if (!dev->name[0] || strchr(dev->name, '%'))
		return "(unnamed net_device)";
	return dev->name;
}

static inline const char *netdev_reg_state(const struct net_device *dev)
{
	switch (dev->reg_state) {
	case NETREG_UNINITIALIZED: return " (uninitialized)";
	case NETREG_REGISTERED: return "";
	case NETREG_UNREGISTERING: return " (unregistering)";
	case NETREG_UNREGISTERED: return " (unregistered)";
	case NETREG_RELEASED: return " (released)";
	case NETREG_DUMMY: return " (dummy)";
	}

	WARN_ONCE(1, "%s: unknown reg_state %d\n", dev->name, dev->reg_state);
	return " (unknown)";
}

__printf(3, 4)
void netdev_printk(const char *level, const struct net_device *dev,
		   const char *format, ...);
__printf(2, 3)
void netdev_emerg(const struct net_device *dev, const char *format, ...);
__printf(2, 3)
void netdev_alert(const struct net_device *dev, const char *format, ...);
__printf(2, 3)
void netdev_crit(const struct net_device *dev, const char *format, ...);
__printf(2, 3)
void netdev_err(const struct net_device *dev, const char *format, ...);
__printf(2, 3)
void netdev_warn(const struct net_device *dev, const char *format, ...);
__printf(2, 3)
void netdev_notice(const struct net_device *dev, const char *format, ...);
__printf(2, 3)
void netdev_info(const struct net_device *dev, const char *format, ...);

#define MODULE_ALIAS_NETDEV(device) \
	MODULE_ALIAS("netdev-" device)

#if defined(CONFIG_DYNAMIC_DEBUG)
#define netdev_dbg(__dev, format, args...)			\
do {								\
	dynamic_netdev_dbg(__dev, format, ##args);		\
} while (0)
#elif defined(DEBUG)
#define netdev_dbg(__dev, format, args...)			\
	netdev_printk(KERN_DEBUG, __dev, format, ##args)
#else
#define netdev_dbg(__dev, format, args...)			\
({								\
	if (0)							\
		netdev_printk(KERN_DEBUG, __dev, format, ##args); \
})
#endif

#if defined(VERBOSE_DEBUG)
#define netdev_vdbg	netdev_dbg
#else

#define netdev_vdbg(dev, format, args...)			\
({								\
	if (0)							\
		netdev_printk(KERN_DEBUG, dev, format, ##args);	\
	0;							\
})
#endif

#define netdev_WARN(dev, format, args...)			\
	WARN(1, "netdevice: %s%s\n" format, netdev_name(dev),	\
	     netdev_reg_state(dev), ##args)

#define netif_printk(priv, type, level, dev, fmt, args...)	\
do {					  			\
	if (netif_msg_##type(priv))				\
		netdev_printk(level, (dev), fmt, ##args);	\
} while (0)

#define netif_level(level, priv, type, dev, fmt, args...)	\
do {								\
	if (netif_msg_##type(priv))				\
		netdev_##level(dev, fmt, ##args);		\
} while (0)

#define netif_emerg(priv, type, dev, fmt, args...)		\
	netif_level(emerg, priv, type, dev, fmt, ##args)
#define netif_alert(priv, type, dev, fmt, args...)		\
	netif_level(alert, priv, type, dev, fmt, ##args)
#define netif_crit(priv, type, dev, fmt, args...)		\
	netif_level(crit, priv, type, dev, fmt, ##args)
#define netif_err(priv, type, dev, fmt, args...)		\
	netif_level(err, priv, type, dev, fmt, ##args)
#define netif_warn(priv, type, dev, fmt, args...)		\
	netif_level(warn, priv, type, dev, fmt, ##args)
#define netif_notice(priv, type, dev, fmt, args...)		\
	netif_level(notice, priv, type, dev, fmt, ##args)
#define netif_info(priv, type, dev, fmt, args...)		\
	netif_level(info, priv, type, dev, fmt, ##args)

#if defined(CONFIG_DYNAMIC_DEBUG)
#define netif_dbg(priv, type, netdev, format, args...)		\
do {								\
	if (netif_msg_##type(priv))				\
		dynamic_netdev_dbg(netdev, format, ##args);	\
} while (0)
#elif defined(DEBUG)
#define netif_dbg(priv, type, dev, format, args...)		\
	netif_printk(priv, type, KERN_DEBUG, dev, format, ##args)
#else
#define netif_dbg(priv, type, dev, format, args...)			\
({									\
	if (0)								\
		netif_printk(priv, type, KERN_DEBUG, dev, format, ##args); \
	0;								\
})
#endif

#if defined(VERBOSE_DEBUG)
#define netif_vdbg	netif_dbg
#else
#define netif_vdbg(priv, type, dev, format, args...)		\
({								\
	if (0)							\
		netif_printk(priv, type, KERN_DEBUG, dev, format, ##args); \
	0;							\
})
#endif

#define PTYPE_HASH_SIZE	(16)
#define PTYPE_HASH_MASK	(PTYPE_HASH_SIZE - 1)

#endif	 
