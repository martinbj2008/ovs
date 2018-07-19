#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "packets.h"

#include "rte_config.h"
#include "rte_lcore.h"
#include "rte_per_lcore.h"
#include "rte_eal.h"
#include "rte_launch.h"
#include "rte_atomic.h"
#include "rte_rwlock.h"
#include "rte_common.h" 
#include "rte_timer.h"
#include "rte_mbuf.h"
#include "rte_mempool.h"
#include "rte_net.h"
#include "rte_ip.h"
#include "rte_tcp.h"
#include "rte_udp.h"
#include "rte_icmp.h"
#include "rte_log.h"
#include "rte_memory.h"
#include "rte_memcpy.h"
#include "rte_malloc.h"
#include "rte_memzone.h"
#include "rte_random.h"
#include "rte_jhash.h"
#include "rte_cycles.h"
#include "rte_ether.h"
#include "rte_eth_ctrl.h"
#include "rte_rwlock.h"
#include "rte_hash_crc.h"
#include "rte_ethdev.h"

#define SLB_RS_MAX_SOCKET       2
#define RTE_LOGTYPE_SLB_RS      RTE_LOGTYPE_USER1
#define MEM_NUM(a)              (sizeof(a) / sizeof((a)[0]))

#define DEFAULT_VXLAN_PORT      4789

typedef uint8_t lcoreid_t;

enum {
    OK              = 0,
    NOMEM           = -1,
    IGNORE          = -2,
    INVPKT          = -3,
    ERSTAT          = -4,
    INVREF          = -5,
    BUSY            = -6,
};

static inline int is_ipv4_pkt_valid(struct ipv4_hdr *iph)
{
    if (((iph->version_ihl) >> 4) != 4)
        return INVPKT;

    if ((iph->version_ihl & 0xf) < 5)
        return INVPKT;

    if (rte_cpu_to_be_16(iph->total_length) < sizeof(struct ipv4_hdr))
        return INVPKT;

    /* not need to process UDP */
    if(iph->next_proto_id != IPPROTO_TCP)
        return IGNORE;

    return OK;
}

static inline bool ip4_is_frag(struct ipv4_hdr *iph)
{
    return (iph->fragment_offset
            & htons(IPV4_HDR_MF_FLAG | IPV4_HDR_OFFSET_MASK)) != 0;
}

static inline void ip4_send_csum(struct ipv4_hdr *iph)
{
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);
}

static inline void tcp4_send_csum(struct ipv4_hdr *iph, struct tcp_hdr *th)
{
    th->cksum = 0;
    th->cksum = rte_ipv4_udptcp_cksum(iph, th);
}

static inline void udp_send_csum(struct ipv4_hdr *iph, struct udp_hdr *uh)
{
    uh->dgram_cksum = 0;
    uh->dgram_cksum = rte_ipv4_udptcp_cksum(iph, uh);
}

static inline int eth_addr_equal(const struct ether_addr *addr1,
                                 const struct ether_addr *addr2)
{
    const uint16_t *a = (const uint16_t *)addr1;
    const uint16_t *b = (const uint16_t *)addr2;

    return ((a[0]^b[0]) | (a[1]^b[1]) | (a[2]^b[2])) == 0;
}

static inline char *eth_addr_dump(const struct ether_addr *ea,
                                  char *buf, size_t size)
{
    snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
             ea->addr_bytes[0], ea->addr_bytes[1],
             ea->addr_bytes[2], ea->addr_bytes[3],
             ea->addr_bytes[4], ea->addr_bytes[5]);
    return buf;
}

#endif /* __COMMON_H__ */
