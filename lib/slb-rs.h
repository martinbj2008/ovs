#ifndef __SLB_RS_H
#define __SLB_RS_H 1

#include <stdio.h>

#include "common.h" 
#include "ovs-atomic.h"
#include "dp-packet.h"
#include "tnl-neigh-cache.h"
#include "unixctl.h"
#include "ovs-atomic.h"

#define SLB_RS_CONN_NUM_MAX     200000
#define PER_VM_CONN_MAX		10000 
#define MAX_CONN_TAB_SIZE       50
#define MAX_CONN_TAB_MASK       (MAX_CONN_TAB_SIZE - 1)

#define SLB_RS_CONN_TAB_BITS    5    
#define SLB_RS_CONN_TAB_SIZE    (1 << SLB_RS_CONN_TAB_BITS)
#define SLB_RS_CONN_TAB_MASK    (SLB_RS_CONN_TAB_SIZE - 1)
#define SLB_RS_LOCK_TAB_SIZE    SLB_RS_CONN_TAB_SIZE

#define IPV4_HEADER_LEN		20
#define UDP_HEADER_LEN		8
#define VXLAN_HEADER_LEN	8
#define VXLAN_HF_VNI		0x08000000

#define IP4_VERSION	 	0x40
#define IP_HDRLEN		0x05	/* default IP header length == five 32-bits words. */
#define IP_DEFTTL  		64 	/* from RFC 1340. */
#define IP_VHL_DEF 		(IP4_VERSION | IP_HDRLEN)
#define IP_DN_FRAGMENT_FLAG	0x0040

#define PORT_MIN		49152
#define PORT_MAX		65535
#define PORT_RANGE 		((PORT_MAX - PORT_MIN) + 1)

struct conn_stats {
    rte_atomic32_t	conn_create_failed;
    rte_atomic32_t	tcp_conn_total_count;
    rte_atomic32_t	udp_conn_total_count;
}__attribute__((__packed__));

struct ip_tnl_info {
    uint32_t		daddr;
    uint32_t		saddr;
    uint32_t		vaddr;
    uint16_t		tp_dst;
    uint16_t		tp_src;
}__attribute__((__packed__));

struct slb_rs_conn
{
    struct ovs_list         conn_node;
    uint8_t                 proto;

    /* healthy check or dataplane type */
    uint8_t                 conn_type;
    uint8_t                 state;

    /* hash key proto + (caddr:cport->daddr:dport) + vni*/
    uint32_t                caddr;
    uint32_t                daddr;
    uint16_t                cport;
    uint16_t                dport;
    uint32_t                vni;

    union {
        struct {
            uint32_t                vaddr;
            uint16_t                vport;
        } svc_info;

        /* tunnel info needed by netdev_dpdk_eth_tx_burst(...) */
        struct {
            uint32_t                daddr;
            uint32_t                saddr;
            uint32_t                vaddr;
        } tunnel_info;
    };

    /*  numa sockets */
    unsigned                lcore_id;
    unsigned                socket_id;

    /* lock&refcnt to protect conn */
    rte_atomic32_t          refcnt;
    rte_spinlock_t          lock;

    struct dpcbs_subtable*  subtable;

    /* rte timer per connection */
    struct rte_timer        expire_timer;

    /* number of cycles to callback */
    volatile uint64_t       timeout;
}__attribute__((__packed__));

struct conn_bucket
{
    rte_spinlock_t          lock;
    struct ovs_list         conn_lists;
}__attribute__((__packed__));

struct dpcbs_subtable {
    struct hmap_node        hmap_node; 

    /* dest eth_addr per vm table */
    uint32_t                vni;
    struct ether_addr       vm_mac_addr;

    struct conn_bucket      buckets[SLB_RS_CONN_TAB_SIZE];

    /* limit max conn size per vm table */
    rte_atomic32_t          n_conn;
    rte_atomic32_t          n_conn_limit;
}__attribute__((__packed__));

struct dpcbs {
    /* hmap of vm tables based on vm dmac */
    struct hmap             vm_subtables;

    /* rw_lock of vm tables update */
    rte_rwlock_t            rwlock; 

    /* conn pool */
    struct rte_mempool*     conn_pool;

    /* limit num of vm tables */
    rte_atomic16_t          n_tab;
    rte_atomic16_t          n_tab_limit;

    /* limit max conn size for all vm tables */
    rte_atomic32_t          total_conn;
    rte_atomic32_t          total_conn_limit;

    struct conn_stats       conn_stats;
} __attribute__((__packed__));

static uint32_t conn_hash_rnd; 
static uint32_t dmac_hash_rnd; 

/* per (2 sockets)socket conn mempool for conn_new */
static struct rte_mempool *dpcbs_conn_cache[SLB_RS_MAX_SOCKET];

struct unixctl_conn;

static atomic_bool slb_disable = ATOMIC_VAR_INIT(false);

#define CONN_POOL_SIZE          65536
#define CONN_CACHE_SIZE         128

/* private ip option according to RFC */
#define IPOPT_CHECK             (94)
#define IPOLEN_CHECK	        8

#define IPOPT_TOA		(30)
#define IPOLEN_TOA		8

struct ipopt_toa {
    uint8_t                 opcode;
    uint8_t                 opsize;
    uint16_t                port;
    uint32_t                addr;
} __attribute__((__packed__));

#define TCP_DIR_INPUT           0
#define TCP_DIR_OUTPUT          4
#define TCP_DIR_INPUT_ONLY      8

enum {
    TOA_DIR_INPUT = 0,
    TOA_DIR_OUTPUT,
    TOA_DIR_INPUT_ONLY,
    TOA_DIR_LAST,
};

/* UDP State, but only 1 state is used? */
enum {
    TOA_UDP_S_NORMAL = 0,
    TOA_UDP_S_LAST
};

/*TCP State Values */
enum {
    TOA_TCP_S_NONE = 0,
    TOA_TCP_S_ESTABLISHED,
    TOA_TCP_S_SYN_SENT,
    TOA_TCP_S_SYN_RECV,
    TOA_TCP_S_FIN_WAIT,
    TOA_TCP_S_TIME_WAIT,
    TOA_TCP_S_CLOSE,
    TOA_TCP_S_CLOSE_WAIT,
    TOA_TCP_S_LAST_ACK,
    TOA_TCP_S_LISTEN,
    TOA_TCP_S_SYNACK,
    TOA_TCP_S_LAST
};

static __attribute__((unused)) char * udp_state_name_table[TOA_UDP_S_LAST+1] = {
    [TOA_UDP_S_NORMAL]	        = "UDP",
    [TOA_UDP_S_LAST]	        = "BUG",
};

static int tcp_timeouts[TOA_TCP_S_LAST + 1] = {
    [TOA_TCP_S_NONE]            = 2,     
    [TOA_TCP_S_ESTABLISHED]     = 90,
    [TOA_TCP_S_SYN_SENT]        = 3,
    [TOA_TCP_S_SYN_RECV]        = 30,
    [TOA_TCP_S_FIN_WAIT]        = 7,
    [TOA_TCP_S_TIME_WAIT]       = 7,
    [TOA_TCP_S_CLOSE]           = 3,
    [TOA_TCP_S_CLOSE_WAIT]      = 7,
    [TOA_TCP_S_LAST_ACK]        = 7,
    [TOA_TCP_S_LISTEN]          = 120,
    [TOA_TCP_S_SYNACK]          = 30,
    [TOA_TCP_S_LAST]            = 2
};

static int udp_timeouts[TOA_UDP_S_LAST + 1] = {
    [TOA_UDP_S_NORMAL]          = 5*60,
    [TOA_UDP_S_LAST]            = 2
};

static const char *const tcp_state_name_table[TOA_TCP_S_LAST+1] = {
    [TOA_TCP_S_NONE]            = "NONE",
    [TOA_TCP_S_ESTABLISHED]     = "ESTABLISHED",
    [TOA_TCP_S_SYN_SENT]	= "SYN_SENT",
    [TOA_TCP_S_SYN_RECV]        = "SYN_RECV",
    [TOA_TCP_S_FIN_WAIT]        = "FIN_WAIT",
    [TOA_TCP_S_TIME_WAIT]       = "TIME_WAIT",
    [TOA_TCP_S_CLOSE]           = "CLOSE",
    [TOA_TCP_S_CLOSE_WAIT]      = "CLOSE_WAIT",
    [TOA_TCP_S_LAST_ACK]        = "LAST_ACK",
    [TOA_TCP_S_LISTEN]          = "LISTEN",
    [TOA_TCP_S_SYNACK]          = "SYNACK",
    [TOA_TCP_S_LAST]            = "BUG!",
};

#define sNO TOA_TCP_S_NONE
#define sES TOA_TCP_S_ESTABLISHED
#define sSS TOA_TCP_S_SYN_SENT
#define sSR TOA_TCP_S_SYN_RECV
#define sFW TOA_TCP_S_FIN_WAIT
#define sTW TOA_TCP_S_TIME_WAIT
#define sCL TOA_TCP_S_CLOSE
#define sCW TOA_TCP_S_CLOSE_WAIT
#define sLA TOA_TCP_S_LAST_ACK
#define sLI TOA_TCP_S_LISTEN
#define sSA TOA_TCP_S_SYNACK

struct tcp_states_t {
    int next_state[TOA_TCP_S_LAST];
};

/* per vm table operations */
void dpcbs_init(struct dpcbs*);
void dpcbs_destroy(struct dpcbs*);
void dpcbs_destroy_subtable(struct dpcbs*, struct dpcbs_subtable*);
struct dpcbs_subtable* dpcbs_find_subtable(struct dpcbs*, struct ether_addr*, uint32_t);
struct dpcbs_subtable* dpcbs_lookup_subtable(struct dpcbs*, struct ether_addr*);
struct dpcbs_subtable* dpcbs_create_subtable(struct dpcbs*, struct ether_addr*, uint32_t);

/* tcp connection operations */
inline int tcp_state_idx(const struct tcp_hdr *);
inline void tcp_state_trans(struct slb_rs_conn*, struct tcp_hdr*, int);
int slb_rs_tcp_snat(struct dpcbs_subtable*, struct ipv4_hdr*, 
			struct tcp_hdr*, struct slb_rs_conn* );

void toa_parse_from_ipopt(struct ipv4_hdr*, struct ipopt_toa*);

/* conn subtable operations */
struct slb_rs_conn* conn_new(struct dpcbs_subtable*, uint8_t, uint32_t,
				uint16_t, uint32_t, uint16_t, uint32_t, 
				struct ipopt_toa* , struct ip_tnl_info*);

struct slb_rs_conn* conn_get(struct dpcbs_subtable*, uint8_t, uint32_t, 
				uint16_t, uint32_t, uint16_t, uint32_t);

static inline uint32_t mac_hashkey(struct ether_addr* );
static inline uint32_t conn_hashkey(uint32_t , uint16_t , uint32_t , uint16_t );
static inline int conn_hash(struct dpcbs_subtable* , struct slb_rs_conn *);
static inline int conn_unhash(struct dpcbs_subtable* , struct slb_rs_conn *);
static inline void conn_put(__attribute__((unused)) struct dpcbs_subtable*, 
				struct slb_rs_conn * );

void conn_expire_now(struct dpcbs_subtable* , struct slb_rs_conn* );
void conn_expire_cb(__attribute__((unused)) struct rte_timer *, 
				__attribute__((unused)) void *);

void conn_flush(struct dpcbs_subtable* );

/* module init exit operations export to ovs-dpdk */
int slb_rs_init(void);
int slb_rs_exit(void);

/* hooks export to ovs-dpdk in datapath */
void netdev_dpdk_slb_rs_in(struct dp_packet **, unsigned int );
void netdev_dpdk_slb_rs_out(struct dp_packet_batch *batch, unsigned int );

int __slb_rs_in(struct dp_packet * );
int __slb_rs_out(struct dp_packet * );
void slb_rs_chk_xmit(struct rte_mbuf *, struct slb_rs_conn* );

/* ovs-appctl static */
static void
slb_rs_enable(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED);
static void
slb_rs_disable(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED);
static void
slb_rs_statics(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED);
static void
slb_rs_conn_dump(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED);
static void
slb_rs_conn_flush(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED);
static void
slb_rs_set_maxconns(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED);

/* lookup VF port to send packet */
extern uint16_t netdev_dpdk_lookup_by_port_type(void);

#endif /* __SLB_RS_H */
