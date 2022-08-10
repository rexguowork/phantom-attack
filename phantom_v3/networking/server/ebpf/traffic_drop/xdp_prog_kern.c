/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "common_kern_user.h" /* defines: struct datarec; */

/* store user configured drop frequency */
struct bpf_map_def SEC("maps") xdp_drop_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u32),
	.max_entries = 2,
};

/* Here an array with XDP_ACTION_MAX (max_)entries are created.
 * The idea is to keep stats per (enum) xdp_action
 */
struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

static __always_inline
__u32 xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	if (action >= XDP_ACTION_MAX)
		return XDP_ABORTED;

	/* Lookup in kernel BPF-side return pointer to actual data record */
	struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
	if (!rec)
		return XDP_ABORTED;

	/* Calculate packet length */
	__u64 bytes = data_end - data;

	/* BPF_MAP_TYPE_PERCPU_ARRAY returns a data record specific to current
	 * CPU and XDP hooks runs under Softirq, which makes it safe to update
	 * without atomic operations.
	 */
	rec->rx_packets++;
	rec->rx_bytes += bytes;

	return action;
}

/* only drop TCP SYN packet for now can be done with other protocols
 * TODO: in this simple POC, we dont differentiate SYN packets from different
 * IPs, can use a MAP to track per IP SYN drop stats
 * */
static __u32 
traffic_drop(void *data, void *data_end)
{
	struct ethhdr *eth = (struct ethhdr *)data;
	struct iphdr *iph = (struct iphdr *)(eth + 1);
	struct tcphdr *tcphdr = (struct tcphdr *)(iph + 1);
	__u32 *rec;
	__u32 key = KEY_DROP_CURR; /* points to the count */
  /* accept packet for every freq_drop # of packets 
   * set default to 4 */
  int freq_drop = DEFAULT_DROP_FREQ; 
	
	/* sanity check needed by the eBPF verifier */
	if ((void *)(tcphdr + 1) > data_end)
		return XDP_ABORTED;

	/* skip non TCP packets */
	if (eth->h_proto != __constant_htons(ETH_P_IP) || iph->protocol != IPPROTO_TCP)
		return XDP_PASS;

	/* We only take actions on SYN packet for now */
  if (tcphdr->syn && bpf_ntohs(tcphdr->dest) == 4444) {
    bpf_printk("tcphdr->source = %d\n", bpf_ntohs(tcphdr->source));
    bpf_printk("tcphdr->dest = %d\n", bpf_ntohs(tcphdr->dest));

		/* Lookup in kernel BPF-side return pointer to actual data record */
		rec = bpf_map_lookup_elem(&xdp_drop_map, &key);
		/* BPF kernel-side verifier will reject program if the NULL pointer
		 * check isn't performed here. Even-though this is a static array where
		 * we know key lookup XDP_PASS always will succeed.
		 */
		if (!rec) {
			bpf_printk("Cannot find rec in map\n");
			return XDP_ABORTED;
		}
		/* Multiple CPUs can access data record. Thus, the accounting needs to
		 * use an atomic operation.
     * Increment SYN packet counter by 1
		 */
		lock_xadd(rec, 1);
		//bpf_printk("total_syn_packets = %d\n", *rec);
    __u32 total_syn_packets = *rec;

    key = KEY_DROP_FREQ;
    rec = bpf_map_lookup_elem(&xdp_drop_map, &key);
    if (!rec)
      return XDP_ABORTED;
    freq_drop = *rec;
  	//bpf_printk("freq drop = %d\n", freq_drop); 

		/* We drop SYN packets unless they are a multiple of freq_drop 
		 * i.e., we will drop the first # of freq_drop SYN packet */
		if (total_syn_packets % freq_drop != 0) {
			return XDP_DROP;
		}
	}
	return XDP_PASS;
}

SEC("xdp_main1")
int xdp_main(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
  __u32 action = XDP_PASS;

	action = traffic_drop(data, data_end);

  return xdp_stats_record_action(ctx, action);
}


char _license[] SEC("license") = "GPL";

/* Copied from: $KERNEL/include/uapi/linux/bpf.h
 *
 * User return codes for XDP prog type.
 * A valid XDP program must return one of these defined values. All other
 * return codes are reserved for future use. Unknown return codes will
 * result in packet drops and a warning via bpf_warn_invalid_xdp_action().
 *
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};

 * user accessible metadata for XDP packet hook
 * new fields must be added to the end of this structure
 *
struct xdp_md {
	// (Note: type __u32 is NOT the real-type)
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	// Below access go through struct xdp_rxq_info
	__u32 ingress_ifindex; // rxq->dev->ifindex
	__u32 rx_queue_index;  // rxq->queue_index
};
*/
