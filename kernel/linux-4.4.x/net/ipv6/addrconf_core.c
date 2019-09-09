#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/export.h>
#include <net/ipv6.h>
#include <net/addrconf.h>
#include <net/ip.h>
#ifdef MY_ABC_HERE
#include <linux/module.h>
#endif

void (*__fib6_flush_trees)(struct net *);
EXPORT_SYMBOL(__fib6_flush_trees);

#define IPV6_ADDR_SCOPE_TYPE(scope)	((scope) << 16)

static inline unsigned int ipv6_addr_scope2type(unsigned int scope)
{
	switch (scope) {
	case IPV6_ADDR_SCOPE_NODELOCAL:
		return (IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_NODELOCAL) |
			IPV6_ADDR_LOOPBACK);
	case IPV6_ADDR_SCOPE_LINKLOCAL:
		return (IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL) |
			IPV6_ADDR_LINKLOCAL);
	case IPV6_ADDR_SCOPE_SITELOCAL:
		return (IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_SITELOCAL) |
			IPV6_ADDR_SITELOCAL);
	}
	return IPV6_ADDR_SCOPE_TYPE(scope);
}

int __ipv6_addr_type(const struct in6_addr *addr)
{
	__be32 st;

	st = addr->s6_addr32[0];

	if ((st & htonl(0xE0000000)) != htonl(0x00000000) &&
	    (st & htonl(0xE0000000)) != htonl(0xE0000000))
		return (IPV6_ADDR_UNICAST |
			IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));

	if ((st & htonl(0xFF000000)) == htonl(0xFF000000)) {
		 
		return (IPV6_ADDR_MULTICAST |
			ipv6_addr_scope2type(IPV6_ADDR_MC_SCOPE(addr)));
	}

	if ((st & htonl(0xFFC00000)) == htonl(0xFE800000))
		return (IPV6_ADDR_LINKLOCAL | IPV6_ADDR_UNICAST |
			IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL));		 
	if ((st & htonl(0xFFC00000)) == htonl(0xFEC00000))
		return (IPV6_ADDR_SITELOCAL | IPV6_ADDR_UNICAST |
			IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_SITELOCAL));		 
	if ((st & htonl(0xFE000000)) == htonl(0xFC000000))
		return (IPV6_ADDR_UNICAST |
			IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));			 

	if ((addr->s6_addr32[0] | addr->s6_addr32[1]) == 0) {
		if (addr->s6_addr32[2] == 0) {
			if (addr->s6_addr32[3] == 0)
				return IPV6_ADDR_ANY;

			if (addr->s6_addr32[3] == htonl(0x00000001))
				return (IPV6_ADDR_LOOPBACK | IPV6_ADDR_UNICAST |
					IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL));	 

			return (IPV6_ADDR_COMPATv4 | IPV6_ADDR_UNICAST |
				IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));	 
		}

		if (addr->s6_addr32[2] == htonl(0x0000ffff))
			return (IPV6_ADDR_MAPPED |
				IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));	 
	}

	return (IPV6_ADDR_UNICAST |
		IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));	 
}
EXPORT_SYMBOL(__ipv6_addr_type);

static ATOMIC_NOTIFIER_HEAD(inet6addr_chain);

int register_inet6addr_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_register(&inet6addr_chain, nb);
}
EXPORT_SYMBOL(register_inet6addr_notifier);

int unregister_inet6addr_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_unregister(&inet6addr_chain, nb);
}
EXPORT_SYMBOL(unregister_inet6addr_notifier);

int inet6addr_notifier_call_chain(unsigned long val, void *v)
{
	return atomic_notifier_call_chain(&inet6addr_chain, val, v);
}
EXPORT_SYMBOL(inet6addr_notifier_call_chain);

static int eafnosupport_ipv6_dst_lookup(struct net *net, struct sock *u1,
					struct dst_entry **u2,
					struct flowi6 *u3)
{
	return -EAFNOSUPPORT;
}

const struct ipv6_stub *ipv6_stub __read_mostly = &(struct ipv6_stub) {
	.ipv6_dst_lookup = eafnosupport_ipv6_dst_lookup,
};
EXPORT_SYMBOL_GPL(ipv6_stub);

const struct in6_addr in6addr_loopback = IN6ADDR_LOOPBACK_INIT;
EXPORT_SYMBOL(in6addr_loopback);
const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
EXPORT_SYMBOL(in6addr_any);
const struct in6_addr in6addr_linklocal_allnodes = IN6ADDR_LINKLOCAL_ALLNODES_INIT;
EXPORT_SYMBOL(in6addr_linklocal_allnodes);
const struct in6_addr in6addr_linklocal_allrouters = IN6ADDR_LINKLOCAL_ALLROUTERS_INIT;
EXPORT_SYMBOL(in6addr_linklocal_allrouters);
const struct in6_addr in6addr_interfacelocal_allnodes = IN6ADDR_INTERFACELOCAL_ALLNODES_INIT;
EXPORT_SYMBOL(in6addr_interfacelocal_allnodes);
const struct in6_addr in6addr_interfacelocal_allrouters = IN6ADDR_INTERFACELOCAL_ALLROUTERS_INIT;
EXPORT_SYMBOL(in6addr_interfacelocal_allrouters);
const struct in6_addr in6addr_sitelocal_allrouters = IN6ADDR_SITELOCAL_ALLROUTERS_INIT;
EXPORT_SYMBOL(in6addr_sitelocal_allrouters);

static void snmp6_free_dev(struct inet6_dev *idev)
{
	kfree(idev->stats.icmpv6msgdev);
	kfree(idev->stats.icmpv6dev);
	free_percpu(idev->stats.ipv6);
}

static void in6_dev_finish_destroy_rcu(struct rcu_head *head)
{
	struct inet6_dev *idev = container_of(head, struct inet6_dev, rcu);

	snmp6_free_dev(idev);
	kfree(idev);
}

void in6_dev_finish_destroy(struct inet6_dev *idev)
{
	struct net_device *dev = idev->dev;

	WARN_ON(!list_empty(&idev->addr_list));
	WARN_ON(idev->mc_list);
	WARN_ON(timer_pending(&idev->rs_timer));

#ifdef NET_REFCNT_DEBUG
	pr_debug("%s: %s\n", __func__, dev ? dev->name : "NIL");
#endif
	dev_put(dev);
	if (!idev->dead) {
		pr_warn("Freeing alive inet6 device %p\n", idev);
		return;
	}
	call_rcu(&idev->rcu, in6_dev_finish_destroy_rcu);
}
EXPORT_SYMBOL(in6_dev_finish_destroy);
