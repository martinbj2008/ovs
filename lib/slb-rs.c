#include "slb-rs.h"
#include <config.h>

/* global connections per-vm tables */
static struct dpcbs g_dpcbs;

static const int tcp_state_off[TOA_DIR_LAST] = {
	[TOA_DIR_INPUT]             =   TCP_DIR_INPUT,
	[TOA_DIR_OUTPUT]            =   TCP_DIR_OUTPUT,
	[TOA_DIR_INPUT_ONLY]        =   TCP_DIR_INPUT_ONLY,
};

static struct tcp_states_t tcp_states[] = {
	/*	INPUT */
	/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA	*/
	/*syn*/ {{sSR, sES, sES, sSR, sSR, sSR, sSR, sSR, sSR, sSR, sSR}},
	/*fin*/ {{sCL, sCW, sSS, sTW, sTW, sTW, sCL, sCW, sLA, sLI, sTW}},
	/*ack*/ {{sCL, sES, sSS, sES, sFW, sTW, sCL, sCW, sCL, sLI, sES}},
	/*rst*/ {{sCL, sCL, sCL, sSR, sCL, sCL, sCL, sCL, sLA, sLI, sSR}},

	/*	OUTPUT */
	/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA	*/
	/*syn*/ {{sSS, sES, sSS, sSR, sSS, sSS, sSS, sSS, sSS, sLI, sSR}},
	/*fin*/ {{sTW, sFW, sSS, sTW, sFW, sTW, sCL, sTW, sLA, sLI, sTW}},
	/*ack*/ {{sES, sES, sSS, sES, sFW, sTW, sCL, sCW, sLA, sES, sES}},
	/*rst*/ {{sCL, sCL, sSS, sCL, sCL, sTW, sCL, sCL, sCL, sCL, sCL}},

	/*	INPUT-ONLY */
	/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA	*/
	/*syn*/ {{sSR, sES, sES, sSR, sSR, sSR, sSR, sSR, sSR, sSR, sSR}},
	/*fin*/ {{sCL, sFW, sSS, sTW, sFW, sTW, sCL, sCW, sLA, sLI, sTW}},
	/*ack*/ {{sCL, sES, sSS, sES, sFW, sTW, sCL, sCW, sCL, sLI, sES}},
	/*rst*/ {{sCL, sCL, sCL, sSR, sCL, sCL, sCL, sCL, sLA, sLI, sCL}},
};

int tcp_state_idx(const struct tcp_hdr *th)
{
	if (th->tcp_flags & TCP_RST_FLAG)
		return 3;
	if (th->tcp_flags & TCP_SYN_FLAG)
		return 0;
	if (th->tcp_flags & TCP_FIN_FLAG)
		return 1;
	if (th->tcp_flags & TCP_ACK_FLAG)
		return 2;
	return -1;
}

/* tcp state transite machine */
void tcp_state_trans(struct slb_rs_conn* conn, struct tcp_hdr* tcph, int direction)
{
	int state_idx;
	int new_state = TOA_TCP_S_CLOSE;
	int state_off = tcp_state_off[direction];

	if ((state_idx = tcp_state_idx(tcph)) < 0) {
		RTE_LOG(WARNING, SLB_RS, "%s: conn state tran failed\n", __func__);
		return ;
	}

	rte_spinlock_lock(&conn->lock);
	new_state = tcp_states[state_off + state_idx].next_state[conn->state];
	if (new_state != conn->state) {
		conn->timeout = tcp_timeouts[conn->state = new_state] * rte_get_timer_hz();
	}
	rte_spinlock_unlock(&conn->lock);

}

/* parse specific ip option used by SLB traffic */
void toa_parse_from_ipopt(struct ipv4_hdr* iph, struct ipopt_toa* toa)
{
	unsigned char *ptr;
	int len;

	/* point to start of ip option */
	ptr = (unsigned char *)(iph + 1);
	len = (IPV4_HDR_IHL_MASK & iph->version_ihl) * sizeof(uint32_t) - sizeof(struct ipv4_hdr);

	if( len == 0 )
		return ;

	while (len > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
			case TCPOPT_EOL:
				return;
			case TCPOPT_NOP:
				len--;
				continue;
			default:
				opsize = *ptr++;
				if (opsize < 2)	/* silly options */
					return;
				if (opsize > len)
					return;	/* partial options */
				if (( IPOPT_TOA == opcode && IPOLEN_TOA == opsize) 
						|| (IPOPT_CHECK == opcode && IPOLEN_CHECK == opsize)) {
					toa->opcode = opcode;
					toa->opsize = opsize;
					memcpy(&toa->port, ptr, sizeof(uint16_t));
					memcpy(&toa->addr, ptr + 2, sizeof(uint32_t));
#ifdef CONFIG_SLB_RS_DEBUG
					RTE_LOG(DEBUG, SLB_RS, "[%s] lcore=%u parsed ip option.\n", __func__, rte_lcore_id());
#endif 
					/* 
					 * need to erase the opsize bytes ip option and update checksum
					 * memset(ptr-2, TCPOPT_NOP, opsize);
					 * */
					return;
				}

				ptr += opsize - 2;
				len -= opsize;
				break;
		}
	}
}

/* create vm_subtables based vm mac daddr */
struct dpcbs_subtable* dpcbs_create_subtable(struct dpcbs* dpcbs,  struct ether_addr* eth_addr, uint32_t vni)
{
	int i;
	struct dpcbs_subtable* subtable;

	if (rte_atomic16_read(&dpcbs->n_tab) >= rte_atomic16_read(&dpcbs->n_tab_limit)) {
		RTE_LOG(WARNING, SLB_RS, "%s: vm conn table num limited\n", __func__);
		return NULL;
	}

	/* To designate a numa mempools for subtable ops */
	subtable = rte_zmalloc(NULL, sizeof(struct dpcbs_subtable), 0);

	if (!subtable) {
		RTE_LOG(WARNING, SLB_RS, "%s: vm conn table malloc failed\n", __func__);
		return NULL;
	}

	for (i = 0; i < SLB_RS_CONN_TAB_SIZE; i++) {
		ovs_list_init(&(subtable->buckets[i].conn_lists));
	}

	for (i = 0; i < SLB_RS_LOCK_TAB_SIZE; i++) {
		rte_spinlock_init(&subtable->buckets[i].lock);
	}

	/* vm mac as the key in vm table */
	ether_addr_copy(eth_addr, &subtable->vm_mac_addr);

	/* need to record vni for dataplane snat */
	subtable->vni = vni;

	/* statics */
	rte_atomic32_init(&subtable->n_conn);
	rte_atomic32_init(&subtable->n_conn_limit);

	rte_atomic32_set(&subtable->n_conn, 0);
	rte_atomic32_set(&subtable->n_conn_limit, PER_VM_CONN_MAX);

	rte_rwlock_write_lock(&dpcbs->rwlock);
	hmap_insert(&dpcbs->vm_subtables, &subtable->hmap_node, mac_hashkey(eth_addr));
	rte_rwlock_write_unlock(&dpcbs->rwlock);

	rte_atomic16_inc(&dpcbs->n_tab);

	return subtable;
}

/* destroy vm_subtables */
void dpcbs_destroy_subtable(struct dpcbs* dpcbs, struct dpcbs_subtable* subtable)
{
	rte_rwlock_write_lock(&dpcbs->rwlock);
	hmap_remove(&dpcbs->vm_subtables, &subtable->hmap_node);
	rte_rwlock_write_unlock(&dpcbs->rwlock);

	/* flush connections in subtable */
	conn_flush(subtable);

	rte_atomic16_dec(&dpcbs->n_tab);

	if(subtable && rte_atomic32_read(&subtable->n_conn) == 0) {
		rte_free(subtable);
		subtable = NULL;
	}
}

/* init datapath connection tables for vm_subtables */
void dpcbs_init(struct dpcbs* dpcbs)
{
	RTE_LOG(INFO, SLB_RS, "%s: SLB_RS datapath conn table - initializing.\n", __func__);

	memset(dpcbs, 0, sizeof(struct dpcbs));

	hmap_init(&dpcbs->vm_subtables);

	rte_rwlock_init(&dpcbs->rwlock);

	/* subtables statics */
	rte_atomic16_init(&dpcbs->n_tab);
	rte_atomic16_init(&dpcbs->n_tab_limit);

	rte_atomic16_set(&dpcbs->n_tab, 0);
	rte_atomic16_set(&dpcbs->n_tab_limit, MAX_CONN_TAB_SIZE);

	/* connections statics */
	rte_atomic32_init(&dpcbs->total_conn);
	rte_atomic32_init(&dpcbs->total_conn_limit);

	rte_atomic32_set(&dpcbs->total_conn, 0);
	rte_atomic32_set(&dpcbs->total_conn_limit, SLB_RS_CONN_NUM_MAX);

	rte_atomic32_set(&g_dpcbs.conn_stats.conn_create_failed, 0);
	rte_atomic32_set(&g_dpcbs.conn_stats.tcp_conn_total_count, 0);
	rte_atomic32_set(&g_dpcbs.conn_stats.udp_conn_total_count, 0);

	RTE_LOG(INFO, SLB_RS, "%s: SLB_RS datapath conn table n_tab:[0->%u] n_conn:[0->%u] - initialized.\n", __func__,  MAX_CONN_TAB_SIZE, SLB_RS_CONN_NUM_MAX);
}

/* Lookup subtable for vm. return subtable or NULL */
inline struct dpcbs_subtable* dpcbs_lookup_subtable(struct dpcbs* dpcbs, struct ether_addr* eth_addr)
{
	struct dpcbs_subtable* subtable;

	rte_rwlock_read_lock(&dpcbs->rwlock);
	HMAP_FOR_EACH_WITH_HASH (subtable, hmap_node, mac_hashkey(eth_addr), &dpcbs->vm_subtables) {
		if (eth_addr_equal(&subtable->vm_mac_addr, eth_addr)) {
			rte_rwlock_read_unlock(&dpcbs->rwlock);

			return subtable;
		}
	}
	rte_rwlock_read_unlock(&dpcbs->rwlock);

	return NULL;
}

/* find subtable for vm. return subtable or create a new subtable */
inline struct dpcbs_subtable* dpcbs_find_subtable(struct dpcbs* dpcbs, struct ether_addr* eth_addr, uint32_t vni)
{
	struct dpcbs_subtable* subtable;

#ifdef CONFIG_SLB_RS_DEBUG
	char daddr[18];
	ether_format_addr(daddr, sizeof(daddr), eth_addr);
	RTE_LOG(DEBUG, SLB_RS, "[%s] lcore=%u daddr=%s entering.\n", __func__, rte_lcore_id(), daddr);
#endif 

	rte_rwlock_read_lock(&dpcbs->rwlock);
	HMAP_FOR_EACH_WITH_HASH (subtable, hmap_node, mac_hashkey(eth_addr), &dpcbs->vm_subtables) {
		if (eth_addr_equal(&subtable->vm_mac_addr, eth_addr)) {
			rte_rwlock_read_unlock(&dpcbs->rwlock);

#ifdef CONFIG_SLB_RS_DEBUG
			RTE_LOG(DEBUG, SLB_RS, "[%s] lcore=%u daddr=%s find subtable.\n", __func__, rte_lcore_id(), daddr);
#endif 
			return subtable;
		}
	}
	rte_rwlock_read_unlock(&dpcbs->rwlock);

	return dpcbs_create_subtable(dpcbs, eth_addr, vni);
}

/* destroy datapath connection tables for vm_subtables */
void dpcbs_destroy(struct dpcbs* dpcbs)
{
	if (dpcbs) {
		struct dpcbs_subtable* subtable;

		/* Destroy subtables */
		HMAP_FOR_EACH (subtable, hmap_node, &dpcbs->vm_subtables) {
			dpcbs_destroy_subtable(dpcbs, subtable);
		}

		rte_atomic16_set(&dpcbs->n_tab, 0);
		rte_atomic32_set(&dpcbs->total_conn, 0);

		hmap_destroy(&dpcbs->vm_subtables);
	}
}

static inline void conn_dump(struct ds* reply, struct slb_rs_conn *conn)
{
	char cbuf[64], vbuf[64], dbuf[64], kpd_sbuf[64], kpd_dbuf[64];
	const char *caddr, *vaddr, *daddr, *kpd_saddr, *kpd_daddr;

	caddr = inet_ntop(AF_INET, &conn->caddr, cbuf, sizeof(cbuf)) ? cbuf : "::";
	daddr = inet_ntop(AF_INET, &conn->daddr, dbuf, sizeof(dbuf)) ? dbuf : "::";

	if (conn->conn_type == IPOPT_TOA) {
		vaddr = inet_ntop(AF_INET, &conn->svc_info.vaddr, vbuf, sizeof(vbuf)) ? vbuf : "::";
		ds_put_format(reply, "slb_rs_dataplane_conn : lcore=%d proto=%u caddr=%s: cport=%u daddr=%s dport=%u svc_addr=%s svc_port=%u conn refs %d.\n",
			conn->lcore_id, conn->proto,
			caddr, ntohs(conn->cport), daddr, ntohs(conn->dport), 
			vaddr, ntohs(conn->svc_info.vport), rte_atomic32_read(&conn->refcnt));
	} else if (conn->conn_type == IPOPT_CHECK) {
		kpd_saddr = inet_ntop(AF_INET, &conn->tunnel_info.saddr, kpd_sbuf, sizeof(kpd_sbuf)) ? kpd_sbuf : "::";
		kpd_daddr = inet_ntop(AF_INET, &conn->tunnel_info.daddr, kpd_dbuf, sizeof(kpd_dbuf)) ? kpd_dbuf : "::";
		ds_put_format(reply, "slb_rs_kpd_conn : lcore=%d proto=%u caddr=%s cport=%u daddr=%s dport=%u kpd_vtep_saddr=%s kpd_vtep_daddr=%s conn refs %d.\n",
			conn->lcore_id, conn->proto,
			caddr, ntohs(conn->cport), daddr, ntohs(conn->dport),
			kpd_daddr, kpd_saddr, rte_atomic32_read(&conn->refcnt));
	}
}

#ifdef CONFIG_SLB_RS_DEBUG
static void ipv4_hdr_dump(const struct ipv4_hdr *iph)
{
	char saddr[16], daddr[16];

	if (!inet_ntop(AF_INET, &iph->src_addr, saddr, sizeof(saddr)))
		return;
	if (!inet_ntop(AF_INET, &iph->dst_addr, daddr, sizeof(daddr)))
		return;

	fprintf(stdout, "%s lcore %u ipv4 hl %u tos %u tot %u "
			"id %u ttl %u prot %u src %s dst %s\n",
			__func__, rte_lcore_id(), IPV4_HDR_IHL_MASK & iph->version_ihl,
			iph->type_of_service, ntohs(iph->total_length),
			ntohs(iph->packet_id), iph->time_to_live,
			iph->next_proto_id, saddr, daddr);

	return;
}
#endif

void conn_expire_now(struct dpcbs_subtable* subtable, struct slb_rs_conn* conn) 
{
	unsigned socket_id;

	if(!subtable || !conn)
		return;

	/* Put to socket_id mempool */
	socket_id = conn->socket_id;

	rte_atomic32_inc(&conn->refcnt);

	/* delete the conn safely */
	if (rte_atomic32_read(&conn->refcnt) == 2) {

		/* unhash conn from table */
		conn_unhash(subtable, conn);

		if(conn->proto == IPPROTO_TCP) {
			rte_atomic32_dec(&g_dpcbs.conn_stats.tcp_conn_total_count);
		} else if(conn->proto == IPPROTO_UDP) {
			rte_atomic32_dec(&g_dpcbs.conn_stats.udp_conn_total_count);
		}

		rte_atomic32_dec(&g_dpcbs.total_conn);
		rte_atomic32_dec(&subtable->n_conn);
		rte_atomic32_dec(&conn->refcnt);

		/* Put back in the right mempool */
		rte_mempool_put(dpcbs_conn_cache[socket_id], conn);
	}

	rte_atomic32_dec(&conn->refcnt);

	return ;
}

/* mac address hash */
static inline uint32_t mac_hashkey(struct ether_addr* eth_addr)
{
	uint8_t* mac = (uint8_t* )eth_addr;
	return rte_jhash(mac, ETHER_ADDR_LEN, dmac_hash_rnd) & MAX_CONN_TAB_MASK; 
}

/* 5 tuple conn hash */
static inline uint32_t conn_hashkey(uint32_t caddr, uint16_t cport, uint32_t daddr, uint16_t dport)
{
	return rte_jhash_3words(caddr, daddr, ((uint32_t)cport) << 16 | (uint32_t)dport, conn_hash_rnd) % SLB_RS_CONN_TAB_MASK;
}

/* hash conn to subtable */
static inline int conn_hash(struct dpcbs_subtable* subtable, struct slb_rs_conn *conn)
{
	uint32_t hashkey;
	hashkey = conn_hashkey(conn->caddr, conn->cport, conn->daddr, conn->dport);

	rte_spinlock_lock(&(subtable->buckets[hashkey].lock));
	ovs_list_push_front(&(subtable->buckets[hashkey].conn_lists), &conn->conn_node);
	rte_atomic32_inc(&conn->refcnt);
	rte_spinlock_unlock(&(subtable->buckets[hashkey].lock));

	return OK;
}

/* unhash conn from subtable */
static inline int conn_unhash(struct dpcbs_subtable* subtable, struct slb_rs_conn *conn)
{
	int err;
	uint32_t hashkey;
	hashkey = conn_hashkey(conn->caddr, conn->cport, conn->daddr, conn->dport);

	rte_spinlock_lock(&(subtable->buckets[hashkey].lock));
	/* Here should be 2. otherwise used by others */
	if (rte_atomic32_read(&conn->refcnt) != 2)
		err = BUSY;
	else {
		ovs_list_remove(&conn->conn_node);
		rte_atomic32_dec(&conn->refcnt);
		err = OK;
	}
	rte_spinlock_unlock(&(subtable->buckets[hashkey].lock));

	return err;
}

/* dec conn->refcnt and update timer on locore_id */
static inline void conn_put(__attribute__((unused)) struct dpcbs_subtable* subtable, struct slb_rs_conn *conn)
{
	/* restart conn expire_timer when used */
	if (rte_timer_reset(&conn->expire_timer, 
				conn->timeout, SINGLE, 
				conn->lcore_id, conn_expire_cb, 
				(void *)conn) < 0) {
		rte_exit(EXIT_FAILURE, "%s: vm conn timer restart failed\n", __func__);
	}

	/* dec conn refcnt */
	rte_atomic32_dec(&conn->refcnt);
}

/* timer timeout callback func */
void
conn_expire_cb(__attribute__((unused)) struct rte_timer *tim, void *arg)
{ 
	unsigned socket_id;
	struct slb_rs_conn* conn = (struct slb_rs_conn* )arg;
	struct dpcbs_subtable* subtable = conn->subtable;

	if(!subtable || !conn)
		return;

	/* Put to socket_id mempool */
	socket_id = conn->socket_id;

	rte_atomic32_inc(&conn->refcnt);

	if(rte_timer_pending(&conn->expire_timer)) {
		rte_atomic32_dec(&conn->refcnt);
		return ;
	}

	/* delete the conn safely */
	if (rte_atomic32_read(&conn->refcnt) == 2) {
		/* unhash conn from table */
		conn_unhash(subtable, conn);

		/* update statics */
		if(conn->proto == IPPROTO_TCP) {
			rte_atomic32_dec(&g_dpcbs.conn_stats.tcp_conn_total_count);
		} else if(conn->proto == IPPROTO_UDP) {
			rte_atomic32_dec(&g_dpcbs.conn_stats.udp_conn_total_count);
		}

		rte_atomic32_dec(&subtable->n_conn);
		rte_atomic32_dec(&g_dpcbs.total_conn);
		rte_atomic32_dec(&conn->refcnt);

		/* Put back in the mempool */
		rte_mempool_put(dpcbs_conn_cache[socket_id], conn);

		return ;
	}

	/* dec refcnt */
	rte_atomic32_dec(&conn->refcnt);

	return ;
}

/* look for conn: return NULL or return refcnt incd conn*/
struct slb_rs_conn* conn_get(struct dpcbs_subtable* subtable, uint8_t nw_proto, uint32_t daddr, uint16_t dport, uint32_t caddr, uint16_t cport, uint32_t vni)
{
	uint32_t hash;
	struct slb_rs_conn* conn;

	hash = conn_hashkey(caddr, cport, daddr, dport);

	rte_spinlock_lock(&(subtable->buckets[hash].lock));
	LIST_FOR_EACH(conn, conn_node, &(subtable->buckets[hash].conn_lists)) {
		if( caddr == conn->caddr && daddr == conn->daddr && cport == conn->cport
				&& dport == conn->dport && nw_proto == conn->proto && vni == conn->vni) {
			/* return with lock & inc refcnt */
			rte_atomic32_inc(&conn->refcnt);
			rte_spinlock_unlock(&(subtable->buckets[hash].lock));
			return conn;
		}
	}
	rte_spinlock_unlock(&(subtable->buckets[hash].lock));

	return NULL;
}

/* create a new conn for INPUT syn packet */
struct slb_rs_conn* conn_new(struct dpcbs_subtable* subtable, uint8_t nw_proto, uint32_t daddr, uint16_t dport, uint32_t caddr, uint16_t cport, uint32_t vni, struct ipopt_toa* ip_opt, struct ip_tnl_info* tnl_info)
{
	unsigned socket_id;
	struct slb_rs_conn *new = NULL;
	unsigned lcore_id = rte_lcore_id();

	/*
	if(!rte_lcore_is_enabled(lcore_id))
		return NULL;
	*/

	/* Get conn from local socket mempool */
	socket_id = rte_lcore_to_socket_id(lcore_id);
	if(SOCKET_ID_ANY == socket_id)
		socket_id = 0;

	if (rte_atomic32_read(&g_dpcbs.total_conn) >= rte_atomic32_read(&g_dpcbs.total_conn_limit)) {
		RTE_LOG(WARNING, SLB_RS, "%s: conn num full\n", __func__);
		return NULL;
	}

	if (rte_atomic32_read(&subtable->n_conn) >= rte_atomic32_read(&subtable->n_conn_limit)) {
		RTE_LOG(WARNING, SLB_RS, "%s: vm conn table full\n", __func__);
		return NULL;
	}

	if (unlikely(rte_mempool_get(dpcbs_conn_cache[socket_id], (void **)&new) != 0)) {
		RTE_LOG(WARNING, SLB_RS, "%s: no memory for new conn\n", __func__);
		return NULL;
	}

	memset(new, 0, sizeof(struct slb_rs_conn));

	ovs_list_init(&new->conn_node);

	if(nw_proto == IPPROTO_TCP) {
		new->state = TOA_TCP_S_SYN_RECV;
		new->timeout = tcp_timeouts[new->state] * rte_get_timer_hz();
	} else if(nw_proto == IPPROTO_UDP) {
		new->state = TOA_UDP_S_NORMAL;
		new->timeout = udp_timeouts[new->state] * rte_get_timer_hz();
	}

	new->proto = nw_proto;
	new->caddr = caddr;
	new->cport = cport;
	new->daddr = daddr;
	new->dport = dport;
	new->vni = vni;

	/* get subtable from conn when conn_expire_cb */
	new->subtable = subtable;

	new->conn_type = ip_opt->opcode;

	if(IPOPT_TOA == ip_opt->opcode) {
		/* dataplane ip option */
		new->svc_info.vaddr = ip_opt->addr;
		new->svc_info.vport = ip_opt->port;
	}
	else if(IPOPT_CHECK == ip_opt->opcode) {
		/* healthy check ip option */
		new->tunnel_info.daddr = tnl_info->daddr;
		new->tunnel_info.saddr = tnl_info->saddr;
		new->tunnel_info.vaddr = tnl_info->vaddr;
	}

	new->lcore_id = lcore_id;
	new->socket_id = socket_id;

	/* conn state protect lock */
	rte_spinlock_init(&new->lock);
	rte_atomic32_set(&new->refcnt, 1);

	rte_timer_init(&new->expire_timer);
	if (rte_timer_reset(&new->expire_timer, 
				new->timeout, SINGLE, 
				lcore_id, conn_expire_cb, 
				(void *)new) < 0) {
		rte_exit(EXIT_FAILURE, "%s: vm conn timer start failed\n", __func__);
	}

	if(nw_proto == IPPROTO_TCP) {
		rte_atomic32_inc(&g_dpcbs.conn_stats.tcp_conn_total_count);
	} else if(nw_proto == IPPROTO_UDP) {
		rte_atomic32_inc(&g_dpcbs.conn_stats.udp_conn_total_count);
	}
	rte_atomic32_inc(&subtable->n_conn);
	rte_atomic32_inc(&g_dpcbs.total_conn);

	conn_hash(subtable, new);

	return new;
}

void conn_flush(struct dpcbs_subtable* subtable)
{
	int i;
	struct slb_rs_conn *conn, *next;

//flush_again:
	for (i = 0; i < MEM_NUM(subtable->buckets); i++) {
		rte_spinlock_lock(&subtable->buckets[i].lock);
		LIST_FOR_EACH_SAFE(conn, next, conn_node, &subtable->buckets[i].conn_lists) {
			/* pending status timer */
			if(!rte_timer_pending(&conn->expire_timer))
				break;

			conn_expire_now(subtable, conn);
		}
		rte_spinlock_unlock(&subtable->buckets[i].lock);
	}

/*
	if(rte_atomic32_read(&subtable->n_conn) != 0)
		goto flush_again;
*/
}

/* hook export to ovs-dpdk in pmd_thread_main INPUT datapath : __netdev_dpdk_vhost_send */
void netdev_dpdk_slb_rs_in(struct dp_packet **pkts, unsigned int cnt)
{
	int i;

	if(OVS_UNLIKELY(cnt <= 0))
		return ;

	/* ovs-dpdk process a batch of packets */
	for( i = 0; i < cnt; i++) {
		if(OVS_LIKELY(pkts[i]))
			__slb_rs_in(pkts[i]);
	}

	return ;
}

int __slb_rs_in(struct dp_packet *pkt)
{
	struct rte_mbuf* mbuf = &pkt->mbuf;
	if(!mbuf)
		return INVPKT;

	struct ether_hdr* ethdr;
	struct ipv4_hdr* iph;
	struct tcp_hdr* tcph; 
	struct dpcbs_subtable* subtable = NULL;
	struct slb_rs_conn* conn = NULL;
	struct ip_tnl_info tnl_info = {0};
	struct ipopt_toa toa = {0};
	uint32_t vni = (uint32_t)ntohll(pkt->md.tunnel.tun_id);

	ethdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr*);
	if(ethdr->ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv4)) 
		return IGNORE;

	iph = rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr*, sizeof(struct ether_hdr));
	if (is_ipv4_pkt_valid(iph) < 0)
		return IGNORE;

	tcph = rte_pktmbuf_mtod_offset(mbuf, struct tcp_hdr*, sizeof(struct ether_hdr) + (IPV4_HDR_IHL_MASK & iph->version_ihl) * sizeof(uint32_t));

#ifdef CONFIG_SLB_RS_DEBUG
	ipv4_hdr_dump(iph);
#endif 

	if ((tcph->tcp_flags & TCP_SYN_FLAG) && !(tcph->tcp_flags & TCP_ACK_FLAG)) {

		toa_parse_from_ipopt(iph, &toa);

		if ((IPOPT_TOA != toa.opcode) && (IPOPT_CHECK != toa.opcode))
			return IGNORE;

		/* tunnel info for vxlan_builder */
		if (IPOPT_CHECK == toa.opcode) {
			tnl_info.daddr = toa.addr;
			tnl_info.saddr = pkt->md.tunnel.ip_dst;
			tnl_info.vaddr = pkt->md.tunnel.ip_src;
		}

		/* find or create a new subtable for mac addr hashkey */
		subtable = dpcbs_find_subtable(&g_dpcbs, &ethdr->d_addr, vni);
		if(!subtable)
			return IGNORE;

		conn = conn_get(subtable, iph->next_proto_id, iph->dst_addr, tcph->dst_port, iph->src_addr, tcph->src_port, vni);
		if(NULL == conn) {
			conn = conn_new(subtable, iph->next_proto_id, iph->dst_addr, tcph->dst_port, iph->src_addr, tcph->src_port, vni, &toa, &tnl_info);
			if(NULL == conn) {
				RTE_LOG(WARNING, SLB_RS, "%s: create new conn failed\n", __func__);
				rte_atomic32_inc(&g_dpcbs.conn_stats.conn_create_failed);
				return NOMEM;
			}
			tcp_state_trans(conn, tcph, TOA_DIR_INPUT);
			conn_put(subtable, conn);
		}
		else {
			/* conn found, VS-RS relationship changed */
			if ((toa.opcode == conn->conn_type) 
					&& (IPOPT_CHECK == toa.opcode) 
					&& (toa.addr != conn->tunnel_info.daddr)) {
				conn->tunnel_info.daddr = toa.addr;
			} else if ((toa.opcode == conn->conn_type) 
					&& (IPOPT_TOA == toa.opcode) 
					&& (toa.addr != conn->svc_info.vaddr || toa.port != conn->svc_info.vport)) {
				conn->svc_info.vaddr = toa.addr;
				conn->svc_info.vport = toa.port;
			}

			tcp_state_trans(conn, tcph, TOA_DIR_INPUT);
			conn_put(subtable, conn);
		}
	}
	else {

		/* find or create a new subtable for hashkey */
		subtable = dpcbs_lookup_subtable(&g_dpcbs, &ethdr->d_addr);
		if(!subtable)
			return IGNORE;

		conn = conn_get(subtable, iph->next_proto_id, iph->dst_addr, tcph->dst_port, iph->src_addr, tcph->src_port, vni);
		if(conn) {
			tcp_state_trans(conn, tcph, TOA_DIR_INPUT);
			conn_put(subtable, conn);
		}
	}

	return OK;
}

/* snat src_ip->svc based on conn */
int slb_rs_tcp_snat(struct dpcbs_subtable* subtable, struct ipv4_hdr* iph, struct tcp_hdr* tcph, struct slb_rs_conn* conn)
{
	/* get conn info & dec refcnt */
	uint32_t nw_addr = conn->svc_info.vaddr;
	uint16_t nw_port = conn->svc_info.vport;
	conn_put(subtable, conn);

	iph->src_addr = nw_addr;
	tcph->src_port = nw_port;

	tcp4_send_csum(iph, tcph);
	ip4_send_csum(iph);

	return OK;
}

void slb_rs_chk_xmit(struct rte_mbuf* m, struct slb_rs_conn* conn)
{
	int err;
	uint16_t port_id;
	uint32_t old_len = m->pkt_len, hash, ret;
	struct in6_addr dst;
	struct in6_addr src;
	struct eth_addr dmac;
	struct eth_addr smac;
        /* struct ether_addr smac; */
	struct ip_tnl_info tnl_info;
	struct rte_eth_dev_info dev_info;

	/* get conn info & dec refcnt */
	rte_memcpy(&tnl_info, &conn->tunnel_info, sizeof(struct ip_tnl_info));
	conn_put(conn->subtable, conn);

	struct ether_hdr *phdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

	/* Allocate space for new ethernet, IPv4, UDP and VXLAN headers */
	struct ether_hdr *pneth = (struct ether_hdr *) rte_pktmbuf_prepend(m,
		sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr)
		+ sizeof(struct udp_hdr) + sizeof(struct vxlan_hdr));

    	if (OVS_UNLIKELY(!pneth)) { 
		rte_pktmbuf_free(m);
		return;
	}

	struct ipv4_hdr *ip = (struct ipv4_hdr *) &pneth[1];
	struct udp_hdr *udp = (struct udp_hdr *) &ip[1];
	struct vxlan_hdr *vxlan = (struct vxlan_hdr *) &udp[1];

	/* VXLAN HEADER */
	vxlan->vx_flags = rte_cpu_to_be_32(VXLAN_HF_VNI);
	vxlan->vx_vni = htonl(conn->vni<<8);

	/* UDP HEADER */
	udp->dgram_cksum = 0;
	udp->dgram_len = rte_cpu_to_be_16(old_len
				+ sizeof(struct udp_hdr)
				+ sizeof(struct vxlan_hdr));

	udp->dst_port = htons(4789);
	hash = rte_hash_crc(phdr, 2 * ETHER_ADDR_LEN, phdr->ether_type);
	udp->src_port = rte_cpu_to_be_16((((uint64_t) hash * PORT_RANGE) >> 32)
					+ PORT_MIN);

	/* IP HEADER */
	ip->version_ihl = IP_VHL_DEF;
	ip->type_of_service = 0;
	ip->total_length = 0;
	ip->fragment_offset = IP_DN_FRAGMENT_FLAG;
	ip->time_to_live = IP_DEFTTL;
	ip->next_proto_id = IPPROTO_UDP;
	ip->hdr_checksum = 0;
	ip->src_addr = tnl_info.saddr;
	ip->dst_addr = tnl_info.daddr;
	ip->total_length = rte_cpu_to_be_16(m->pkt_len
			- sizeof(struct ether_hdr));

	/* update ip checksum */
	ip4_send_csum(ip);

	m->ol_flags |= PKT_RX_RSS_HASH;

	/* port_id to send pkt, but note it is not safe now */
	port_id = netdev_dpdk_lookup_by_port_type(); 
	if (RTE_MAX_ETHPORTS == port_id)
		goto drop;

	rte_eth_dev_info_get(port_id, &dev_info);

	src = in6_addr_mapped_ipv4(tnl_info.saddr);
	err = tnl_neigh_lookup("br-dpdk", &src, &smac);
	if (ENOENT == err)
		goto drop;

	dst = in6_addr_mapped_ipv4(tnl_info.vaddr);
	err = tnl_neigh_lookup("br-dpdk", &dst, &dmac);
	if (ENOENT == err)
		goto drop;

	/* ETH HEADER */
	ether_addr_copy((struct ether_addr*)&smac, &pneth->s_addr);
	ether_addr_copy((struct ether_addr*)&dmac, &pneth->d_addr);
	pneth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

	/* send pkt once a pkt */
        ret = rte_eth_tx_burst(port_id, 1, &m, 1);
    	if (OVS_UNLIKELY(!ret)) 
		rte_pktmbuf_free(m);

	return;
drop:
	rte_pktmbuf_free(m);
	return;
}

/* hook export to ovs-dpdk in pmd_thread_main OUTPUT datapath : netdev_dpdk_vhost_rxq_recv & netdev_dpdk_eth_send */
void netdev_dpdk_slb_rs_out(struct dp_packet** pkts, unsigned int cnt)
{
	int i;

	if(OVS_UNLIKELY(cnt <= 0))
		return ;

	/* ovs-dpdk process a batch of packets */
	for( i = 0; i < cnt; i++) {
		if(OVS_LIKELY(pkts[i]))
			__slb_rs_out(pkts[i]);
	}

	return ;
}

int __slb_rs_out(struct dp_packet* pkt)
{
	struct rte_mbuf* mbuf = &pkt->mbuf;
	if(!mbuf)
		return INVPKT;

	struct ether_hdr* ethdr;
	struct ipv4_hdr* iph;
	struct tcp_hdr* tcph;
	struct dpcbs_subtable* subtable = NULL;
	struct slb_rs_conn* conn = NULL;
	/* needed by conn_get */
	uint32_t vni = 0;

	ethdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr*);
	if(ethdr->ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv4)) 
		return IGNORE;

	/* find subtable for hashkey firstly , return if NULL which means not slb traffic */
	subtable = dpcbs_lookup_subtable(&g_dpcbs, &ethdr->s_addr);
	if(!subtable)
		return IGNORE;

	vni = subtable->vni;

	iph = rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr*, sizeof(struct ether_hdr));
	if (is_ipv4_pkt_valid(iph) < 0)
		return IGNORE;

	tcph = rte_pktmbuf_mtod_offset(mbuf, struct tcp_hdr*, sizeof(struct ether_hdr) + (IPV4_HDR_IHL_MASK & iph->version_ihl) * sizeof(uint32_t));

#ifdef CONFIG_SLB_RS_DEBUG
	ipv4_hdr_dump(iph);
#endif 

	conn = conn_get(subtable, iph->next_proto_id, iph->src_addr, tcph->src_port, iph->dst_addr, tcph->dst_port, vni);
	if(NULL == conn) 
		/* unlock safe already, no inc refcnt */
		return IGNORE;
	else {
		/* still hold refcnt here */
		if (conn->conn_type == IPOPT_TOA) {
			tcp_state_trans(conn, tcph, TOA_DIR_OUTPUT);
			/* SLB dataplane */
			slb_rs_tcp_snat(subtable, iph, tcph, conn);
		} else if (conn->conn_type == IPOPT_CHECK) {
			/* SLB chk */
			slb_rs_chk_xmit(mbuf, conn);
		}
	}

	return OK;
}

static void
slb_rs_disable(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
	atomic_store_relaxed(&slb_disable, true);
	/* to release resource */
    	unixctl_command_reply(conn, "OK");
}

static void
slb_rs_statics(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
	struct ds reply = DS_EMPTY_INITIALIZER;

    	ds_put_format(&reply, "total_n_conns : %u\n", rte_atomic32_read(&g_dpcbs.total_conn));
    	ds_put_format(&reply, "total_n_slb_rs : %u\n", rte_atomic16_read(&g_dpcbs.n_tab));
    	ds_put_format(&reply, "tcp_conn_count : %u\n", rte_atomic32_read(&g_dpcbs.conn_stats.tcp_conn_total_count));
    	ds_put_format(&reply, "udp_conn_count : %u\n", rte_atomic32_read(&g_dpcbs.conn_stats.udp_conn_total_count));
    	ds_put_format(&reply, "conn_create_failed : %u\n", rte_atomic32_read(&g_dpcbs.conn_stats.conn_create_failed));

    	unixctl_command_reply(conn, ds_cstr(&reply));
    	ds_destroy(&reply);
}

static void
slb_rs_conn_dump(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED) 
{
	struct ds reply = DS_EMPTY_INITIALIZER;

	int i;
	struct dpcbs_subtable* subtable;
	struct slb_rs_conn *cur_conn, *next;

    	ds_put_format(&reply, "Dump conn start \n");
	HMAP_FOR_EACH (subtable, hmap_node, &g_dpcbs.vm_subtables) {
		for (i = 0; i < MEM_NUM(subtable->buckets); i++) {
			rte_spinlock_lock(&subtable->buckets[i].lock);
			LIST_FOR_EACH_SAFE(cur_conn, next, conn_node, &subtable->buckets[i].conn_lists) {
				conn_dump(&reply, cur_conn);
			}
			rte_spinlock_unlock(&subtable->buckets[i].lock);
		}
	}
    	ds_put_format(&reply, "Dump conn finish\n");

    	unixctl_command_reply(conn, ds_cstr(&reply));
    	ds_destroy(&reply);
}

static void
slb_rs_conn_flush(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
	struct ds reply = DS_EMPTY_INITIALIZER;
	struct dpcbs_subtable* subtable;

    	ds_put_format(&reply, "Dump flush start \n");
	rte_rwlock_write_lock(&g_dpcbs.rwlock);
	HMAP_FOR_EACH (subtable, hmap_node, &g_dpcbs.vm_subtables) {
		conn_flush(subtable);
	}
	rte_rwlock_write_unlock(&g_dpcbs.rwlock);
    	ds_put_format(&reply, "Dump flush finish\n");

    	unixctl_command_reply(conn, ds_cstr(&reply));
    	ds_destroy(&reply);
}

static void
slb_rs_set_maxconns(struct unixctl_conn *conn, int argc,
                     const char *argv[], void *aux OVS_UNUSED)
{
	struct ds reply = DS_EMPTY_INITIALIZER;

    	int conn_limit = atoi(argv[1]);
    	if (argc != 2 || conn_limit > UINT32_MAX) {
        	unixctl_command_reply(conn, "Invalid num.");
        	ds_destroy(&reply);
        	return;
    	}
	rte_atomic32_set(&g_dpcbs.total_conn_limit, conn_limit);
    	ds_put_format(&reply, "set slb_rs_maxconns to : %u\n", conn_limit);
    	unixctl_command_reply(conn, ds_cstr(&reply));
    	ds_destroy(&reply);
}

int slb_rs_exit(void)
{
	int i;
	RTE_LOG(INFO, SLB_RS, "%s: SLB_RS Enabled - releasing.\n", __func__);

	/* free conn pool , further to designate on each socket */
	for (i = 0; i < SLB_RS_MAX_SOCKET; i++) {
		rte_mempool_free(dpcbs_conn_cache[i]);
	}

	/* destroy global connection tables */
	dpcbs_destroy(&g_dpcbs);

	RTE_LOG(INFO, SLB_RS, "%s: SLB_RS Enabled - released.\n", __func__);

	return OK;
}

int slb_rs_init(void)
{
	int i, err;
	char poolname[32];

	RTE_LOG(INFO, SLB_RS, "%s: SLB_RS debug version Enabled - initializing.\n", __func__);

	/* init global connection tables */
	dpcbs_init(&g_dpcbs);

	/* create conn pool cache , further to designate on each socket */
	for (i = 0; i < SLB_RS_MAX_SOCKET; i++) {
		snprintf(poolname, sizeof(poolname), "slb_rs_conn_pool%d", i);
		dpcbs_conn_cache[i] = rte_mempool_create(poolname,
				CONN_POOL_SIZE,
				sizeof(struct slb_rs_conn),
				CONN_CACHE_SIZE,
				0, NULL, NULL, NULL, NULL,
				i, 0);
		if (!dpcbs_conn_cache[i]) {
			err = NOMEM;
			goto cleanup;
		}

		RTE_LOG(INFO, SLB_RS, "%s created for conn mempool size: %u cache_size: %u.\n", poolname, CONN_POOL_SIZE, CONN_CACHE_SIZE);
	}

	/* hash basis */
	conn_hash_rnd = (uint32_t)random();
	dmac_hash_rnd = (uint32_t)random();

	unixctl_command_register("slb-rs/disable", "", 0, 0, slb_rs_disable, NULL);
	unixctl_command_register("slb-rs/statics", "", 0, 0, slb_rs_statics, NULL);
	unixctl_command_register("slb-rs/conn-dump", "", 0, 0, slb_rs_conn_dump, NULL);
	unixctl_command_register("slb-rs/conn-flush", "", 0, 0, slb_rs_conn_flush, NULL);
	unixctl_command_register("slb-rs/set-maxconns", "slb-rs-maxconns", 1, 1, slb_rs_set_maxconns, NULL);

	RTE_LOG(INFO, SLB_RS, "%s: SLB_RS debug version Enabled - initialized.\n", __func__);
	return OK;

cleanup:
	dpcbs_destroy(&g_dpcbs);
	return err;
}
