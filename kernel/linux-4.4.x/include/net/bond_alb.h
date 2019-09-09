#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef _NET_BOND_ALB_H
#define _NET_BOND_ALB_H

#include <linux/if_ether.h>

struct bonding;
struct slave;

#define BOND_ALB_INFO(bond)   ((bond)->alb_info)
#define SLAVE_TLB_INFO(slave) ((slave)->tlb_info)

#define ALB_TIMER_TICKS_PER_SEC	    10	 
#define BOND_TLB_REBALANCE_INTERVAL 10	 
#define BOND_ALB_DEFAULT_LP_INTERVAL 1
#define BOND_ALB_LP_INTERVAL(bond) (bond->params.lp_interval)	 

#define BOND_TLB_REBALANCE_TICKS (BOND_TLB_REBALANCE_INTERVAL \
				  * ALB_TIMER_TICKS_PER_SEC)

#define BOND_ALB_LP_TICKS(bond) (BOND_ALB_LP_INTERVAL(bond) \
			   * ALB_TIMER_TICKS_PER_SEC)

#define TLB_HASH_TABLE_SIZE 256	 

#define TLB_NULL_INDEX		0xffffffff

#define RLB_HASH_TABLE_SIZE	256
#define RLB_NULL_INDEX		0xffffffff
#define RLB_UPDATE_DELAY	(2*ALB_TIMER_TICKS_PER_SEC)  
#define RLB_ARP_BURST_SIZE	2
#define RLB_UPDATE_RETRY	3  
 
#define RLB_PROMISC_TIMEOUT	(10*ALB_TIMER_TICKS_PER_SEC)

struct tlb_client_info {
	struct slave *tx_slave;	 
	u32 tx_bytes;		 
	u32 load_history;	 
	u32 next;		 
	u32 prev;		 
};

struct rlb_client_info {
	__be32 ip_src;		 
	__be32 ip_dst;		 
	u8  mac_src[ETH_ALEN];	 
	u8  mac_dst[ETH_ALEN];	 

	u32 used_next;
	u32 used_prev;

	u32 src_next;	 
	u32 src_prev;	 
	u32 src_first;	 

	u8  assigned;		 
	u8  ntt;		 
	struct slave *slave;	 
	unsigned short vlan_id;	 
};

struct tlb_slave_info {
	u32 head;	 
	u32 load;	 
};

struct alb_bond_info {
	struct tlb_client_info	*tx_hashtbl;  
	u32			unbalanced_load;
	int			tx_rebalance_counter;
	int			lp_counter;
	 
	int rlb_enabled;
	struct rlb_client_info	*rx_hashtbl;	 
	u32			rx_hashtbl_used_head;
	u8			rx_ntt;	 
	struct slave		*rx_slave; 
	u8			primary_is_promisc;	    
	u32			rlb_promisc_timeout_counter; 
	u32			rlb_update_delay_counter;
	u32			rlb_update_retry_counter; 
	u8			rlb_rebalance;	 
};

int bond_alb_initialize(struct bonding *bond, int rlb_enabled);
void bond_alb_deinitialize(struct bonding *bond);
int bond_alb_init_slave(struct bonding *bond, struct slave *slave);
void bond_alb_deinit_slave(struct bonding *bond, struct slave *slave);
void bond_alb_handle_link_change(struct bonding *bond, struct slave *slave, char link);
void bond_alb_handle_active_change(struct bonding *bond, struct slave *new_slave);
int bond_alb_xmit(struct sk_buff *skb, struct net_device *bond_dev);
int bond_tlb_xmit(struct sk_buff *skb, struct net_device *bond_dev);
void bond_alb_monitor(struct work_struct *);
int bond_alb_set_mac_address(struct net_device *bond_dev, void *addr);
void bond_alb_clear_vlan(struct bonding *bond, unsigned short vlan_id);
#if defined(MY_ABC_HERE)
void bond_alb_info_show(struct seq_file *seq);
#endif  
#endif  
