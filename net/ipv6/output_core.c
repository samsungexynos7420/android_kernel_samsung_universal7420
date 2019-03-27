/*
 * IPv6 library code, needed by static components when full IPv6 support is
 * not configured or static.  These functions are needed by GSO/GRO implementation.
 */
#include <linux/export.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ip6_fib.h>


/* This function exists only for tap drivers that must support broken
 * clients requesting UFO without specifying an IPv6 fragment ID.
 *
 * This is similar to ipv6_select_ident() but we use an independent hash
 * seed to limit information leakage.
 *
 * The network header must be set before calling this.
 */
void ipv6_proxy_select_ident(struct net *net, struct sk_buff *skb)
{
	struct in6_addr buf[2];
	struct in6_addr *addrs;
	u32 hash, id;

	addrs = skb_header_pointer(skb,
				   skb_network_offset(skb) +
				   offsetof(struct ipv6hdr, saddr),
				   sizeof(buf), buf);
	if (addrs)
	{
		const struct {
			struct in6_addr dst;
			struct in6_addr src;
		} __aligned(SIPHASH_ALIGNMENT) combined = {
			.dst = addrs[1],
			.src = addrs[0],
		};

		/* Note the following code is not safe, but this is okay. */
		if (unlikely(siphash_key_is_zero(&net->ipv4.ip_id_key)))
			get_random_bytes(&net->ipv4.ip_id_key,
					 sizeof(net->ipv4.ip_id_key));

		hash = siphash(&combined, sizeof(combined), &net->ipv4.ip_id_key);

		id = ip_idents_reserve(hash, 1);
		skb_shinfo(skb)->ip6_frag_id = htonl(id);
	}
}
EXPORT_SYMBOL_GPL(ipv6_proxy_select_ident);

int ip6_find_1stfragopt(struct sk_buff *skb, u8 **nexthdr)
{
	u16 offset = sizeof(struct ipv6hdr);
	struct ipv6_opt_hdr *exthdr =
				(struct ipv6_opt_hdr *)(ipv6_hdr(skb) + 1);
	unsigned int packet_len = skb->tail - skb->network_header;
	int found_rhdr = 0;
	*nexthdr = &ipv6_hdr(skb)->nexthdr;

	while (offset + 1 <= packet_len) {

		switch (**nexthdr) {

		case NEXTHDR_HOP:
			break;
		case NEXTHDR_ROUTING:
			found_rhdr = 1;
			break;
		case NEXTHDR_DEST:
#if IS_ENABLED(CONFIG_IPV6_MIP6)
			if (ipv6_find_tlv(skb, offset, IPV6_TLV_HAO) >= 0)
				break;
#endif
			if (found_rhdr)
				return offset;
			break;
		default :
			return offset;
		}

		offset += ipv6_optlen(exthdr);
		*nexthdr = &exthdr->nexthdr;
		exthdr = (struct ipv6_opt_hdr *)(skb_network_header(skb) +
						 offset);
	}

	return offset;
}
EXPORT_SYMBOL(ip6_find_1stfragopt);
