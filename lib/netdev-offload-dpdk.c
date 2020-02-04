/*
 * Copyright (c) 2014, 2015, 2016, 2017 Nicira, Inc.
 * Copyright (c) 2019 Mellanox Technologies, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <config.h>

#include <rte_flow.h>
#include <rte_mtr.h>

#include "cmap.h"
#include "dpif-netdev.h"
#include "netdev-offload-provider.h"
#include "openvswitch/ofp-meter.h"
#include "netdev-provider.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(netdev_offload_dpdk);

enum {
    OFFLOAD_TABLE_ID_FLOW = 0,
    OFFLOAD_TABLE_ID_UPCALL = 10,
    OFFLOAD_TABLE_ID_MAX,
};

typedef enum {
    OFFLOAD_RECIRC_UNKOWN = -1,
    OFFLOAD_RECIRC_VXLAN = 0,
    OFFLOAD_RECIRC_UPCALL,
    OFFLOAD_RECIRC_CT,
    OFFLOAD_RECIRC_BLACKLIST,
    OFFLOAD_RECIRC_WHITELIST,
}RECIRC_TYPE;

#define OFFLOAD_TABLE_MIN_PRIORITY 3
#define OFFLOAD_TABLE_MAX_PRIORITY 0

#define GET_RECIRC_TYPE_BY_ID(id) ((id >> 16) & 0xF)
#define RECIRC_ID_SPEC_PATTERN 0xFF000000
#define RECIRC_ID_UPCALL_PATTERN (RECIRC_ID_SPEC_PATTERN | (OFFLOAD_RECIRC_UPCALL << 16))
#define RECIRC_ID_VXLAN_PATTERN (RECIRC_ID_SPEC_PATTERN | (OFFLOAD_RECIRC_VXLAN << 16))
#define IS_SPEC_RECIRC_ID(id) ((id & RECIRC_ID_SPEC_PATTERN) == RECIRC_ID_SPEC_PATTERN)
#define IS_VXLAN_RECIRC_ID(id) ((id & RECIRC_ID_VXLAN_PATTERN) == RECIRC_ID_VXLAN_PATTERN)
#define IS_UPCALL_RECIRC_ID(id) ((id & RECIRC_ID_UPCALL_PATTERN) == RECIRC_ID_UPCALL_PATTERN)

bool soft_hard_compatible_flag = false;
enum {
    UPLINK=0,
    UP_TO_DOWN,
    UP_TO_VXLAN,
    DOWN_TO_UP,
    DOWNLINK,
    VXLAN_OFFLOAD,
    VXLAN_SOFT,
    OFFLOAD_PORT_MAX
};

#define MAX_VXLAN_NUM 2
struct vxlan_host_ip_map {
    ovs_be32  host_ip;
    odp_port_t port_id;
};
struct vxlan_host_ip_map vxlan_host_map[MAX_VXLAN_NUM] = {
    [0] = {
        .host_ip = 0,
        .port_id = 0,
    },
    [1] = {
        .host_ip = 0,
        .port_id = 0,
    }
};

struct output_port_map {
    char * name;
    odp_port_t port_id;
    struct netdev *pdev; //record for config netdev lookup odp_port_t id
};

struct output_port_map port_map[] = {
    [UPLINK]={
        .name="uplink",
        .port_id = 0,
        .pdev = NULL,
    },
    [DOWNLINK]={
        .name="downlink",
        .port_id = 0,
        .pdev=NULL,
    },
    [UP_TO_DOWN]={
        .name="up-to-down",
        .port_id = 0,
        .pdev=NULL,
    },
    [DOWN_TO_UP]={
        .name="down-to-up",
        .port_id = 0,
        .pdev=NULL,
    },
    [VXLAN_OFFLOAD]={
        .name="vxlan-offload",
        .port_id = 0,
        .pdev=NULL,
    },
    [UP_TO_VXLAN]={
        .name="up-to-vxlan-off",
        .port_id = 0,
        .pdev=NULL,
    },
    [VXLAN_SOFT]={
        .name="vxlan0",
        .port_id = 0,
        .pdev=NULL,
    },
};

#define get_odp_port_id(enum_id) ((enum_id >= OFFLOAD_PORT_MAX) ? port_map[UPLINK].port_id : port_map[enum_id].port_id)
struct output_port_map* output_no_vxlan_encap_map[OFFLOAD_PORT_MAX][OFFLOAD_PORT_MAX];
struct output_port_map* output_vxlan_encap_map[OFFLOAD_PORT_MAX][OFFLOAD_PORT_MAX];
netdev_port_add_del_hook_func netdev_port_hook_func;

/* Thread-safety
 * =============
 *
 * Below API is NOT thread safe in following terms:
 *
 *  - The caller must be sure that none of these functions will be called
 *    simultaneously.  Even for different 'netdev's.
 *
 *  - The caller must be sure that 'netdev' will not be destructed/deallocated.
 *
 *  - The caller must be sure that 'netdev' configuration will not be changed.
 *    For example, simultaneous call of 'netdev_reconfigure()' for the same
 *    'netdev' is forbidden.
 *
 * For current implementation all above restrictions could be fulfilled by
 * taking the datapath 'port_mutex' in lib/dpif-netdev.c.  */

/*
 * A mapping from ufid to dpdk rte_flow.
 */
static struct cmap ufid_to_rte_flow = CMAP_INITIALIZER;

struct ufid_to_rte_flow_data {
    struct cmap_node node;
    ovs_u128 ufid;
    struct rte_flow *rte_flow;
};

/* Find rte_flow with @ufid. */
static struct rte_flow *
ufid_to_rte_flow_find(const ovs_u128 *ufid)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_rte_flow_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, &ufid_to_rte_flow) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            return data->rte_flow;
        }
    }

    return NULL;
}

static inline void
ufid_to_rte_flow_associate(const ovs_u128 *ufid,
                           struct rte_flow *rte_flow)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_rte_flow_data *data = xzalloc(sizeof *data);

    /*
     * We should not simply overwrite an existing rte flow.
     * We should have deleted it first before re-adding it.
     * Thus, if following assert triggers, something is wrong:
     * the rte_flow is not destroyed.
     */
    ovs_assert(ufid_to_rte_flow_find(ufid) == NULL);

    data->ufid = *ufid;
    data->rte_flow = rte_flow;

    cmap_insert(&ufid_to_rte_flow,
                CONST_CAST(struct cmap_node *, &data->node), hash);
}

static inline void
ufid_to_rte_flow_disassociate(const ovs_u128 *ufid)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_rte_flow_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, &ufid_to_rte_flow) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            cmap_remove(&ufid_to_rte_flow,
                        CONST_CAST(struct cmap_node *, &data->node), hash);
            ovsrcu_postpone(free, data);
            return;
        }
    }

    VLOG_WARN("ufid "UUID_FMT" is not associated with an rte flow\n",
              UUID_ARGS((struct uuid *) ufid));
}

/*
 * To avoid individual xrealloc calls for each new element, a 'curent_max'
 * is used to keep track of current allocated number of elements. Starts
 * by 8 and doubles on each xrealloc call.
 */
struct flow_patterns {
    struct rte_flow_item *items;
    int cnt;
    int current_max;
};

struct flow_actions {
    struct rte_flow_action *actions;
    int cnt;
    int current_max;
};

static void
dump_flow_pattern(struct rte_flow_item *item)
{
    struct ds s;

    if (!VLOG_IS_DBG_ENABLED() || item->type == RTE_FLOW_ITEM_TYPE_END) {
        return;
    }

    ds_init(&s);

    if (item->type == RTE_FLOW_ITEM_TYPE_ETH) {
        const struct rte_flow_item_eth *eth_spec = item->spec;
        const struct rte_flow_item_eth *eth_mask = item->mask;

        ds_put_cstr(&s, "rte flow eth pattern:\n");
        if (eth_spec) {
            ds_put_format(&s,
                          "  Spec: src="ETH_ADDR_FMT", dst="ETH_ADDR_FMT", "
                          "type=0x%04" PRIx16"\n",
                          ETH_ADDR_BYTES_ARGS(eth_spec->src.addr_bytes),
                          ETH_ADDR_BYTES_ARGS(eth_spec->dst.addr_bytes),
                          ntohs(eth_spec->type));
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }
        if (eth_mask) {
            ds_put_format(&s,
                          "  Mask: src="ETH_ADDR_FMT", dst="ETH_ADDR_FMT", "
                          "type=0x%04"PRIx16"\n",
                          ETH_ADDR_BYTES_ARGS(eth_mask->src.addr_bytes),
                          ETH_ADDR_BYTES_ARGS(eth_mask->dst.addr_bytes),
                          ntohs(eth_mask->type));
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_VLAN) {
        const struct rte_flow_item_vlan *vlan_spec = item->spec;
        const struct rte_flow_item_vlan *vlan_mask = item->mask;

        ds_put_cstr(&s, "rte flow vlan pattern:\n");
        if (vlan_spec) {
            ds_put_format(&s,
                          "  Spec: inner_type=0x%"PRIx16", tci=0x%"PRIx16"\n",
                          ntohs(vlan_spec->inner_type), ntohs(vlan_spec->tci));
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }

        if (vlan_mask) {
            ds_put_format(&s,
                          "  Mask: inner_type=0x%"PRIx16", tci=0x%"PRIx16"\n",
                          ntohs(vlan_mask->inner_type), ntohs(vlan_mask->tci));
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_IPV4) {
        const struct rte_flow_item_ipv4 *ipv4_spec = item->spec;
        const struct rte_flow_item_ipv4 *ipv4_mask = item->mask;

        ds_put_cstr(&s, "rte flow ipv4 pattern:\n");
        if (ipv4_spec) {
            ds_put_format(&s,
                          "  Spec: tos=0x%"PRIx8", ttl=%"PRIx8
                          ", proto=0x%"PRIx8
                          ", src="IP_FMT", dst="IP_FMT"\n",
                          ipv4_spec->hdr.type_of_service,
                          ipv4_spec->hdr.time_to_live,
                          ipv4_spec->hdr.next_proto_id,
                          IP_ARGS(ipv4_spec->hdr.src_addr),
                          IP_ARGS(ipv4_spec->hdr.dst_addr));
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }
        if (ipv4_mask) {
            ds_put_format(&s,
                          "  Mask: tos=0x%"PRIx8", ttl=%"PRIx8
                          ", proto=0x%"PRIx8
                          ", src="IP_FMT", dst="IP_FMT"\n",
                          ipv4_mask->hdr.type_of_service,
                          ipv4_mask->hdr.time_to_live,
                          ipv4_mask->hdr.next_proto_id,
                          IP_ARGS(ipv4_mask->hdr.src_addr),
                          IP_ARGS(ipv4_mask->hdr.dst_addr));
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_UDP) {
        const struct rte_flow_item_udp *udp_spec = item->spec;
        const struct rte_flow_item_udp *udp_mask = item->mask;

        ds_put_cstr(&s, "rte flow udp pattern:\n");
        if (udp_spec) {
            ds_put_format(&s,
                          "  Spec: src_port=%"PRIu16", dst_port=%"PRIu16"\n",
                          ntohs(udp_spec->hdr.src_port),
                          ntohs(udp_spec->hdr.dst_port));
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }
        if (udp_mask) {
            ds_put_format(&s,
                          "  Mask: src_port=0x%"PRIx16
                          ", dst_port=0x%"PRIx16"\n",
                          ntohs(udp_mask->hdr.src_port),
                          ntohs(udp_mask->hdr.dst_port));
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_SCTP) {
        const struct rte_flow_item_sctp *sctp_spec = item->spec;
        const struct rte_flow_item_sctp *sctp_mask = item->mask;

        ds_put_cstr(&s, "rte flow sctp pattern:\n");
        if (sctp_spec) {
            ds_put_format(&s,
                          "  Spec: src_port=%"PRIu16", dst_port=%"PRIu16"\n",
                          ntohs(sctp_spec->hdr.src_port),
                          ntohs(sctp_spec->hdr.dst_port));
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }
        if (sctp_mask) {
            ds_put_format(&s,
                          "  Mask: src_port=0x%"PRIx16
                          ", dst_port=0x%"PRIx16"\n",
                          ntohs(sctp_mask->hdr.src_port),
                          ntohs(sctp_mask->hdr.dst_port));
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_ICMP) {
        const struct rte_flow_item_icmp *icmp_spec = item->spec;
        const struct rte_flow_item_icmp *icmp_mask = item->mask;

        ds_put_cstr(&s, "rte flow icmp pattern:\n");
        if (icmp_spec) {
            ds_put_format(&s,
                          "  Spec: icmp_type=%"PRIu8", icmp_code=%"PRIu8"\n",
                          icmp_spec->hdr.icmp_type,
                          icmp_spec->hdr.icmp_code);
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }
        if (icmp_mask) {
            ds_put_format(&s,
                          "  Mask: icmp_type=0x%"PRIx8
                          ", icmp_code=0x%"PRIx8"\n",
                          icmp_spec->hdr.icmp_type,
                          icmp_spec->hdr.icmp_code);
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_TCP) {
        const struct rte_flow_item_tcp *tcp_spec = item->spec;
        const struct rte_flow_item_tcp *tcp_mask = item->mask;

        ds_put_cstr(&s, "rte flow tcp pattern:\n");
        if (tcp_spec) {
            ds_put_format(&s,
                          "  Spec: src_port=%"PRIu16", dst_port=%"PRIu16
                          ", data_off=0x%"PRIx8", tcp_flags=0x%"PRIx8"\n",
                          ntohs(tcp_spec->hdr.src_port),
                          ntohs(tcp_spec->hdr.dst_port),
                          tcp_spec->hdr.data_off,
                          tcp_spec->hdr.tcp_flags);
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }
        if (tcp_mask) {
            ds_put_format(&s,
                          "  Mask: src_port=%"PRIx16", dst_port=%"PRIx16
                          ", data_off=0x%"PRIx8", tcp_flags=0x%"PRIx8"\n",
                          ntohs(tcp_mask->hdr.src_port),
                          ntohs(tcp_mask->hdr.dst_port),
                          tcp_mask->hdr.data_off,
                          tcp_mask->hdr.tcp_flags);
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    VLOG_DBG("%s", ds_cstr(&s));
    ds_destroy(&s);
}

static void
add_flow_pattern(struct flow_patterns *patterns, enum rte_flow_item_type type,
                 const void *spec, const void *mask)
{
    int cnt = patterns->cnt;

    if (cnt == 0) {
        patterns->current_max = 8;
        patterns->items = xcalloc(patterns->current_max,
                                  sizeof *patterns->items);
    } else if (cnt == patterns->current_max) {
        patterns->current_max *= 2;
        patterns->items = xrealloc(patterns->items, patterns->current_max *
                                   sizeof *patterns->items);
    }

    patterns->items[cnt].type = type;
    patterns->items[cnt].spec = spec;
    patterns->items[cnt].mask = mask;
    patterns->items[cnt].last = NULL;
    patterns->cnt++;
}

static void
dump_set_action(struct ds* ps, struct rte_flow_action *action)
{
    const struct rte_flow_action_set_mac *pmac = NULL;
    const struct rte_flow_action_set_ipv4 *pipv4 = NULL;

    if (action->type == RTE_FLOW_ACTION_TYPE_SET_MAC_SRC) {
        pmac = action->conf;
        ds_put_cstr(ps, "\nRTE_FLOW_ACTION_TYPE_SET_MAC_SRC\n");
        ds_put_format(ps, "set mac addr %02x:%02x:%02x:%02x:%02x:%02x",
                pmac->mac_addr[0], pmac->mac_addr[1], pmac->mac_addr[2],
                pmac->mac_addr[3], pmac->mac_addr[4], pmac->mac_addr[5]);
    }

    if (action->type == RTE_FLOW_ACTION_TYPE_SET_MAC_DST) {
        pmac = action->conf;
        ds_put_cstr(ps, "\nRTE_FLOW_ACTION_TYPE_SET_MAC_DST\n");
        ds_put_format(ps, "set mac addr %02x:%02x:%02x:%02x:%02x:%02x",
                pmac->mac_addr[0], pmac->mac_addr[1], pmac->mac_addr[2],
                pmac->mac_addr[3], pmac->mac_addr[4], pmac->mac_addr[5]);

    }
    
    if (action->type == RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC) {
        pipv4 = action->conf;
        ds_put_cstr(ps, "\nRTE_FLOW_ACTION_TYPE_SET_IPV4_SRC\n");
        ds_put_format(ps, "set ipv4 addr 0x%x", pipv4->ipv4_addr);
    }
    
    if (action->type == RTE_FLOW_ACTION_TYPE_SET_IPV4_DST) {
        pipv4 = action->conf;
        ds_put_cstr(ps, "\nRTE_FLOW_ACTION_TYPE_SET_IPV4_DST\n");
        ds_put_format(ps, "set ipv4 addr 0x%x", pipv4->ipv4_addr);
    }
    
    return;
}

static void
dump_flow_action(struct rte_flow_action *action)
{
    struct ds s;

    if (!VLOG_IS_DBG_ENABLED() || action->type == RTE_FLOW_ACTION_TYPE_END) {
        return;
    }

    ds_init(&s);

    if (action->type == RTE_FLOW_ACTION_TYPE_PORT_ID) {
        const struct rte_flow_action_port_id *output = action->conf;
        ds_put_format(&s, "\nRTE_FLOW_ACTION_TYPE_PORT_ID original: %d, id: %d\n",
                output->original, output->id);
    }

    if (action->type == RTE_FLOW_ACTION_TYPE_RAW_ENCAP) {
        const struct rte_flow_action_raw_encap *raw_encap = action->conf;
        int i;
        ds_put_cstr(&s, "\nRTE_FLOW_ACTION_TYPE_RAW_ENCAP:\n");

        for (i = 0; i < raw_encap->size; i++) {
            ds_put_format(&s, "%x", raw_encap->data[i]);
        }

        ds_put_cstr(&s, "\n");
    }

    if (action->type == RTE_FLOW_ACTION_TYPE_VXLAN_DECAP) {
        ds_put_cstr(&s, "\nRTE_FLOW_ACTION_TYPE_VXLAN_DECAP\n");
    }

    if (action->type == RTE_FLOW_ACTION_TYPE_JUMP) {
        const uint32_t *dtable = action->conf;
        ds_put_cstr(&s, "\nRTE_FLOW_ACTION_TYPE_JUMP\n");
        ds_put_format(&s, "dst table is %d", *dtable);
    }
    
    if (action->type == RTE_FLOW_ACTION_TYPE_COUNT) {
        const struct rte_flow_action_count *action_count  = action->conf;
        ds_put_cstr(&s, "\nRTE_FLOW_ACTION_TYPE_COUNT\n");
        ds_put_format(&s, "counter shared: %d, id: %d",
                      action_count->shared,
                      action_count->id);
    }    

    if (action->type == RTE_FLOW_ACTION_TYPE_METER) {
        const struct rte_flow_action_meter *mc = action->conf;
        ds_put_cstr(&s, "\nRTE_FLOW_ACTION_TYPE_METER\n");
        ds_put_format(&s, "meter id %d", mc->mtr_id);
    }

    dump_set_action(&s, action);

    VLOG_DBG("%s", ds_cstr(&s));
    ds_destroy(&s);
}

static void
add_flow_action(struct flow_actions *actions, enum rte_flow_action_type type,
                const void *conf)
{
    int cnt = actions->cnt;

    if (cnt == 0) {
        actions->current_max = 8;
        actions->actions = xcalloc(actions->current_max,
                                   sizeof *actions->actions);
    } else if (cnt == actions->current_max) {
        actions->current_max *= 2;
        actions->actions = xrealloc(actions->actions, actions->current_max *
                                    sizeof *actions->actions);
    }

    actions->actions[cnt].type = type;
    actions->actions[cnt].conf = conf;
    actions->cnt++;
}

struct action_rss_data {
    struct rte_flow_action_rss conf;
    uint16_t queue[0];
};

static void
netdev_offload_dpdk_dump(struct flow_patterns *patterns,
                         struct flow_actions *actions)
{
    int i;
    VLOG_INFO("XXX: dump rte pattern and aciton\n");
    for (i = 0; i < patterns->cnt; i++) {
        dump_flow_pattern(&patterns->items[i]);
    }

    for (i = 0; i < actions->cnt; i++) {
        dump_flow_action(&actions->actions[i]);
    }

    VLOG_INFO("XXX: dump rte pattern and aciton end!\n");
}

struct dpdk_meter_offload {
    uint32_t port_id;
    uint32_t max_rate;
    uint32_t mp_id;
    struct rte_flow_action_meter mc;
};

static void dpdk_meter_destroy(void *data)
{
    struct dpdk_meter_offload *dmo = data;
    struct rte_mtr_error error;

    if (dmo) {
        rte_mtr_meter_profile_delete(dmo->port_id,
                                     dmo->mc.mtr_id,
                                     &error);
        rte_mtr_destroy(dmo->port_id,
                        dmo->mc.mtr_id,
                        &error);
        free(dmo);
    }
}

#define DPDK_METER_UPATE_UP 65536

static void dpdk_meter_update(void *priv_data, void *config)
{
    struct dpdk_meter_offload *dmo = priv_data;
    struct rte_mtr_meter_profile mp;
    struct rte_mtr_error mtr_error;
    uint32_t mp_id, new_mp_id;
    uint32_t max_rate;
    uint32_t ret;

    if (!priv_data || !config) {
        return;
    }

    max_rate = ofputil_meter_config_max_rate(config);
    if (dmo->max_rate == max_rate) {
        return;
    }

    memset(&mp, 0, sizeof(struct rte_mtr_meter_profile));
    mp.alg = RTE_MTR_SRTCM_RFC2697;
    mp.srtcm_rfc2697.cir = max_rate *1024 /8;
    mp.srtcm_rfc2697.cbs = max_rate *1024 /8;
    mp.srtcm_rfc2697.ebs = 0;

    if (dmo->mp_id < DPDK_METER_UPATE_UP) {
        new_mp_id = dmo->mp_id + DPDK_METER_UPATE_UP;
    } else {
        new_mp_id = dmo->mp_id - DPDK_METER_UPATE_UP;
    }

    ret = rte_mtr_meter_profile_add(dmo->port_id, new_mp_id,
                                    &mp, &mtr_error);
    if (ret) {
        VLOG_ERR("rte_mtr_meter_profile_add fail: err_type: %d err_msg: %s\n",
                 mtr_error.type, mtr_error.message);
        return;
    }

    ret = rte_mtr_meter_profile_update(dmo->port_id, dmo->mc.mtr_id,
                                       new_mp_id, &mtr_error);
    if (ret) {
        VLOG_ERR("rte_mtr_meter_profile_update fail: err_type: %d err_msg: %s\n",
                 mtr_error.type, mtr_error.message);
        mp_id = new_mp_id;
        goto out;
    }

    mp_id = dmo->mp_id;
    dmo->mp_id = new_mp_id;
    dmo->max_rate = max_rate;
out:
    ret = rte_mtr_meter_profile_delete(dmo->port_id, mp_id, &mtr_error);
    if (ret) {
        VLOG_ERR("rte_mtr_meter_profile_update fail: err_type: %d err_msg: %s\n",
                 mtr_error.type, mtr_error.message);
    }
}

static struct netdev_offload_meter_api dpdk_meter_offload_api = {
    .meter_destroy  = dpdk_meter_destroy,
    .meter_update   = dpdk_meter_update,
};

static struct rte_flow_action_meter*
dpdk_meter_create(struct dpif *dpif, struct netdev *netdev, uint32_t mid)
{
    uint32_t port_id = netdev_dpdk_get_portid(netdev);
    struct netdev_offload_meter *nom;
    struct dpdk_meter_offload *dmo;
    struct ofputil_meter_config config;
    ofproto_meter_id meter_id;
    struct rte_mtr_meter_profile mp;
    struct rte_mtr_params params;
    struct rte_mtr_error mtr_error;
    uint32_t max_rate;
    int ret;

    meter_id.uint32 = mid;

    if (dpif_meter_get_config(dpif, meter_id, &config)) {
        return NULL;
    }

    nom = xmalloc(sizeof *nom);
    dmo = xmalloc(sizeof *dmo);

    nom->meter_ops = &dpdk_meter_offload_api;
    nom->priv_data = dmo;

    memset(&mp, 0, sizeof(struct rte_mtr_meter_profile));
    max_rate = ofputil_meter_config_max_rate(&config);

    dmo->mc.mtr_id = mid;
    dmo->port_id = port_id;
    dmo->max_rate = max_rate;
    dmo->mp_id = mid;

    mp.alg = RTE_MTR_SRTCM_RFC2697;
    mp.srtcm_rfc2697.cir = max_rate *1024 /8; /* rate_max Kbps*/
    mp.srtcm_rfc2697.cbs = max_rate *1024 /8;
    mp.srtcm_rfc2697.ebs = 0;

    ret = rte_mtr_meter_profile_add(dmo->port_id, dmo->mc.mtr_id,
                                    &mp, &mtr_error);
    if (ret && ret != -EEXIST) {
        VLOG_ERR("rte_mtr_meter_profile_add fail: err_type: %d err_msg: %s, portid: %d\n",
                   mtr_error.type, mtr_error.message, netdev_dpdk_get_portid(netdev));
        goto profile_err;
    }

    enum rte_color dscp_table[2];
    dscp_table[0] = RTE_COLOR_YELLOW;
    dscp_table[1] = RTE_COLOR_RED;

    params.meter_profile_id = dmo->mc.mtr_id;
    params.dscp_table = dscp_table;
    params.meter_enable = 1;
    params.use_prev_mtr_color = 0;
    params.action[RTE_COLOR_GREEN]  = MTR_POLICER_ACTION_COLOR_GREEN;
    params.action[RTE_COLOR_YELLOW] = MTR_POLICER_ACTION_DROP;
    params.action[RTE_COLOR_RED]    = MTR_POLICER_ACTION_DROP;

    ret = rte_mtr_create(dmo->port_id, dmo->mc.mtr_id, &params, 0, &mtr_error);
    if (ret && ret != -EEXIST) {
        VLOG_ERR("rte_mtr_create fail: err_type: %d err_msg: %s, portid: %d\n",
                   mtr_error.type, mtr_error.message, netdev_dpdk_get_portid(netdev));
        goto mtr_err;
    }

    dpif_meter_set_offload(dpif, meter_id, nom);

    free(config.bands);
    return &dmo->mc;

mtr_err:
    rte_mtr_meter_profile_delete(dmo->port_id, dmo->mc.mtr_id, &mtr_error);

profile_err:
    free(nom);
    free(dmo);
    free(config.bands);
    return NULL;
}

static struct rte_flow_action_meter *
netdev_offload_dpdk_meter_conf(struct dpif *dpif, struct netdev *netdev, uint32_t mid)
{
    uint32_t port_id = netdev_dpdk_get_portid(netdev);
    struct netdev_offload_meter *nom = NULL;
    struct dpdk_meter_offload *dmo;
    ofproto_meter_id meter_id;
    uint32_t ret;
    meter_id.uint32 = mid;

    ret = dpif_meter_get_offload(dpif, meter_id, (void **)&nom,
                                 sizeof *nom + sizeof *dmo);
    if (ret) {
        VLOG_INFO("netdev offload dpdk meter, can't get the meter");
        return NULL;
    }

    if (!nom) {
        return dpdk_meter_create(dpif, netdev, mid);
    }

    dmo = (struct dpdk_meter_offload *)nom->priv_data;
    if (port_id != dmo->port_id) {
        VLOG_INFO("dpdk meter %d is used on %d, can't be used for : %d",
                  mid, dmo->port_id, port_id);
        return NULL;
    }

    return &dmo->mc;
}

static void
netdev_offload_output_port_map_init(void)
{
    memset(output_no_vxlan_encap_map, 0, sizeof(output_no_vxlan_encap_map));
    memset(output_vxlan_encap_map, 0, sizeof(output_vxlan_encap_map));
    output_no_vxlan_encap_map[UPLINK][DOWNLINK]=&port_map[UP_TO_DOWN];
    output_no_vxlan_encap_map[DOWNLINK][UPLINK]=&port_map[DOWN_TO_UP];
    output_no_vxlan_encap_map[DOWNLINK][DOWNLINK]=&port_map[DOWNLINK];
    output_no_vxlan_encap_map[UPLINK][UPLINK]=&port_map[UPLINK];
    output_vxlan_encap_map[VXLAN_OFFLOAD][UPLINK]=&port_map[DOWN_TO_UP];
    output_vxlan_encap_map[VXLAN_OFFLOAD][DOWNLINK]=&port_map[DOWNLINK];
    output_vxlan_encap_map[UPLINK][UPLINK]=&port_map[UP_TO_VXLAN]; //vxlan recirc
    output_vxlan_encap_map[DOWNLINK][DOWNLINK]=&port_map[VXLAN_OFFLOAD]; //vxlan recirc
}

static int
netdev_offload_get_enum_by_odp_port(odp_port_t id)
{
    int i = 0;

    for (i = UPLINK; i < OFFLOAD_PORT_MAX; i++) {
        if (port_map[i].port_id == id) {
            return i;
        }
    }

    return i;
}


static odp_port_t
netdev_offload_get_odp_port_by_netdev(struct netdev *netdev)
{
    int i = 0;

    VLOG_INFO("#######netdev: %p", netdev);
    for (i = UPLINK; i < OFFLOAD_PORT_MAX; i++) {
        if (port_map[i].pdev == netdev) {
            return port_map[i].port_id;
        }
    }

    return 0;
}

static odp_port_t
netdev_offload_get_final_output_port_id(odp_port_t cfg_port_id, odp_port_t out_id, bool is_vxlan_encap)
{
    int sid = 0, did = 0;
    struct output_port_map *pport = NULL;

    sid = netdev_offload_get_enum_by_odp_port(cfg_port_id);
    did = netdev_offload_get_enum_by_odp_port(out_id);
    if (sid == OFFLOAD_PORT_MAX || did == OFFLOAD_PORT_MAX) {
        goto error;
    }

    if (is_vxlan_encap) {
        pport = output_vxlan_encap_map[sid][did];
        if (pport) {
            VLOG_INFO("Get vxlan encap output port %s", pport->name);
            return pport->port_id;
        } else {
            goto error;
        }
    }

    pport = output_no_vxlan_encap_map[sid][did];
    if (pport) {
        VLOG_INFO("Get normal output port %s", pport->name);
        return pport->port_id;
    }

error:
    VLOG_ERR("Get offload final output port error!");
    return 0; //error
}

static void
netdev_offload_vxlan_host_store(ovs_be32 host_ip, odp_port_t id)
{
    int i = 0;

    for (i = 0; i < MAX_VXLAN_NUM; i++) {
        if (host_ip == vxlan_host_map[i].host_ip) {
            vxlan_host_map[i].port_id = id;
            break;
        }

        if (vxlan_host_map[i].host_ip == 0) {
            vxlan_host_map[i].host_ip = host_ip;
            vxlan_host_map[i].port_id = id;
            VLOG_INFO("%s, %d, i=%d, host_ip: 0x%x", __FUNCTION__, __LINE__, i, host_ip);
            break;
        }
   }

   return;
}

static odp_port_t
netdev_offload_get_vxlan_pop_pf_id(ovs_be32 host_ip)
{
    int i = 0;

    for (i = 0; i < MAX_VXLAN_NUM; i++) {
        if (vxlan_host_map[i].host_ip == host_ip)
            return vxlan_host_map[i].port_id;
    }

    return -1;
}

static void
netdev_offload_port_add_del_hook(int op, struct netdev* netdev, odp_port_t id)
{
    int i = 0;

    VLOG_INFO("*******OP: %d, netdev: %p, name: %s, id=%d", op, netdev, netdev->name, id);
    for (i = UPLINK; i < OFFLOAD_PORT_MAX; i++) {
        if (!strcmp(netdev->name, port_map[i].name)) {
            if (op == PORT_OP_ADD && port_map[i].port_id != id) {
                port_map[i].port_id = id;
                port_map[i].pdev = netdev;
            }

            if (op == PORT_OP_DEL) {
                port_map[i].pdev = NULL;
                port_map[i].port_id = 0;
            }
        }
    }

    return;
}

static int
netdev_offload_get_dpdk_index_by_odp_port(odp_port_t cfg_port, odp_port_t id, const struct dpif_class *dpif_class, bool is_vxlan_encap)
{
    odp_port_t final_port = 0;
    int dpdk_port;

    final_port=netdev_offload_get_final_output_port_id(cfg_port, id, is_vxlan_encap);
    if (!final_port) {
       final_port = id;
    }

    struct netdev *dst_netdev = netdev_ports_get(final_port, dpif_class);
    if (!dst_netdev) {
        VLOG_ERR("when offload output, can't find output port\n");
        return -1;
    }

    if (strncmp(dst_netdev->netdev_class->type, "dpdk", 4) != 0) {
        VLOG_ERR("can't offload output port to non-dpdk port %s\n", dst_netdev->name);
        return -1;
    }

    VLOG_INFO("### get port name %s ###", dst_netdev->name);
    dpdk_port = netdev_dpdk_get_portid(dst_netdev);
    return dpdk_port;
}

static int
netdev_offload_map_flow_priority(struct rte_flow_attr * flow_attr, struct offload_info * info)
{
    uint32_t priority = info->priority;

    //dpcls priority support 0-16, but hw only support 0-3
    if (priority > 16) {
        VLOG_INFO("DPCLS flow priority error, we only support 0-16, config priority is %d", priority);
        return -1;
    }

    if (priority > 0) {
        priority = (priority -1)/4;
    }

    flow_attr->priority = OFFLOAD_TABLE_MIN_PRIORITY - priority;
    return 0;
}

static int
netdev_offload_jump_group_action(
        struct rte_flow_attr * flow_attr,
        struct flow_actions *pactions,
        RECIRC_TYPE type,
        struct rte_flow_action_jump *ptbl)
{
    int ret = 0;
    uint32_t dst_table = 0;

    switch (type) {
        case OFFLOAD_RECIRC_UPCALL:
            flow_attr->group = OFFLOAD_TABLE_ID_FLOW;
            dst_table = OFFLOAD_TABLE_ID_UPCALL;
            break;
        case OFFLOAD_RECIRC_WHITELIST:
        case OFFLOAD_RECIRC_BLACKLIST:
        case OFFLOAD_RECIRC_VXLAN:
        case OFFLOAD_RECIRC_CT:
        case OFFLOAD_RECIRC_UNKOWN:
            ret = -1;
            VLOG_INFO("Unsupport recirc offload type: %d", type);
            break;
    }

    if (!ret && ptbl) {
        VLOG_INFO("%s, %d, output action #####", __FUNCTION__, __LINE__);
        ptbl->group = dst_table;
        add_flow_action(pactions, RTE_FLOW_ACTION_TYPE_JUMP, ptbl);
    }

    return ret;
}

static int netdev_offload_output_action(
        struct netdev *netdev,
        const struct dpif_class *dpif_class,
        struct flow_actions *pactions,
        struct rte_flow_action_port_id *pport_id,
        int *pout_put_action_cnt,
        odp_port_t port,
        bool is_vxlan_encap)
{
    odp_port_t cfg_port,output_port = port;
    int dpdk_port_id = 0;

    if (*pout_put_action_cnt) {
        VLOG_ERR("MLX5 NIC can only one fate actions in a flow, offload fail\n");
        return -1;
    }

    cfg_port = netdev_offload_get_odp_port_by_netdev(netdev);
    if (!cfg_port) {
        VLOG_ERR("Get config port odp port id failed, netdev name: %s", netdev->name);
        return -1;
    }

    if (!port) {
        output_port = cfg_port;
    }

    dpdk_port_id = netdev_offload_get_dpdk_index_by_odp_port(cfg_port, output_port, dpif_class, is_vxlan_encap);
    if (dpdk_port_id == -1) {
        VLOG_ERR("Get dpdk port index error, cfg_port: %d", cfg_port);
        return -1;
    }

    pport_id->id = dpdk_port_id;
    pport_id->original = 0;
    add_flow_action(pactions, RTE_FLOW_ACTION_TYPE_PORT_ID, pport_id);
    *pout_put_action_cnt += 1;

    return 0;
}

struct netdev_offload_set_action {
    struct rte_flow_action_set_mac smac;
    struct rte_flow_action_set_mac dmac;
    struct rte_flow_action_set_tp nw_tp;
    struct rte_flow_action_set_ipv4 s_addr;
    struct rte_flow_action_set_ipv4 d_addr;
};

#define ETH_ALEN  RTE_ETHER_ADDR_LEN
/* Mask is at the midpoint of the data. */
#define get_mask(a, type) ((const type *)(const void *)(a + 1) + 1)

static int
netdev_offload_set_action(const struct nlattr *a, struct flow_actions *actions, struct netdev_offload_set_action* setact, bool is_mask)
{
    uint8_t ethernet_mask_full[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    enum ovs_key_attr type = nl_attr_type(a);

    switch (type) {
    case OVS_KEY_ATTR_ETHERNET: {
            const struct ovs_key_ethernet *key = nl_attr_get(a);
            const struct ovs_key_ethernet *mask = NULL;
            bool src_flag = false, dst_flag = false;
            if (is_mask) {
                mask = get_mask(a, struct ovs_key_ethernet);
                if (!memcmp(mask->eth_src.ea,  &ethernet_mask_full, ETH_ALEN)) {
                    src_flag = true;
                }

                if (!memcmp(mask->eth_dst.ea,  &ethernet_mask_full, ETH_ALEN)) {
                    dst_flag = true;
                }
            }

            if (src_flag || !is_mask) {
                memcpy(setact->smac.mac_addr, key->eth_src.ea, ETH_ALEN);
                add_flow_action(actions, RTE_FLOW_ACTION_TYPE_SET_MAC_SRC, &setact->smac);
            }

            if (dst_flag || !is_mask) {
                memcpy(setact->dmac.mac_addr, key->eth_dst.ea, ETH_ALEN);
                add_flow_action(actions, RTE_FLOW_ACTION_TYPE_SET_MAC_DST, &setact->dmac);
            }

            break;
        }
    case OVS_KEY_ATTR_IPV4: {
            const struct ovs_key_ipv4 *key = nl_attr_get(a);
            const struct ovs_key_ipv4 *mask = NULL;

            if (is_mask) {
                mask = get_mask(a, struct ovs_key_ipv4);
            } else {
                VLOG_INFO("Not support Set ipv4 no mask type offload!");
                return -1;
            }

            if (mask->ipv4_src) {
                setact->s_addr.ipv4_addr = key->ipv4_src;
                add_flow_action(actions, RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC, &setact->s_addr);
            }

            if (mask->ipv4_dst) {
                setact->d_addr.ipv4_addr = key->ipv4_dst;
                add_flow_action(actions, RTE_FLOW_ACTION_TYPE_SET_IPV4_DST, &setact->d_addr);
            }
            break;
        }
    case OVS_KEY_ATTR_TCP:
        break;

    case OVS_KEY_ATTR_UDP:
        break;

    case OVS_KEY_ATTR_PRIORITY:
    case OVS_KEY_ATTR_IN_PORT:
    case OVS_KEY_ATTR_VLAN:
    case OVS_KEY_ATTR_ICMP:
    case OVS_KEY_ATTR_ICMPV6:
    case OVS_KEY_ATTR_ND:
    case OVS_KEY_ATTR_ND_EXTENSIONS:
    case OVS_KEY_ATTR_SKB_MARK:
    case OVS_KEY_ATTR_TUNNEL:
    case OVS_KEY_ATTR_SCTP:
    case OVS_KEY_ATTR_DP_HASH:
    case OVS_KEY_ATTR_RECIRC_ID:
    case OVS_KEY_ATTR_MPLS:
    case OVS_KEY_ATTR_CT_STATE:
    case OVS_KEY_ATTR_CT_ZONE:
    case OVS_KEY_ATTR_CT_MARK:
    case OVS_KEY_ATTR_CT_LABELS:
    case OVS_KEY_ATTR_PACKET_TYPE:
    case OVS_KEY_ATTR_NSH:
    case OVS_KEY_ATTR_ENCAP:
    case OVS_KEY_ATTR_ETHERTYPE:
    case OVS_KEY_ATTR_IPV6:
    case OVS_KEY_ATTR_ARP:
    case OVS_KEY_ATTR_TCP_FLAGS:
    case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4:
    case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6:
    case OVS_KEY_ATTR_UNSPEC:
    case __OVS_KEY_ATTR_MAX:
    default:
        VLOG_INFO("Not support Set type %d offload!", type);
        return -1;
    }

    return 0;
}

static int
netdev_offload_dpdk_add_flow(struct dpif *dpif, struct netdev *netdev,
                             const struct match *match,
                             struct nlattr *nl_actions,
                             size_t actions_len,
                             const ovs_u128 *ufid,
                             struct offload_info *info)
{
    struct rte_flow_attr flow_attr = {
        .group = OFFLOAD_TABLE_ID_FLOW,
        .priority = OFFLOAD_TABLE_MIN_PRIORITY,
        .ingress = 1,
        .egress = 0,
        .transfer = 1,
    };
    struct flow_patterns patterns = { .items = NULL, .cnt = 0 };
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    struct rte_flow *flow;
    struct rte_flow_error error;
    uint8_t proto = 0;
    int ret = 0;
    struct flow_items {
        struct rte_flow_item_eth  eth;
        struct rte_flow_item_vlan vlan;
        struct rte_flow_item_ipv4 ipv4;
        union {
            struct rte_flow_item_tcp  tcp;
            struct rte_flow_item_udp  udp;
            struct rte_flow_item_sctp sctp;
            struct rte_flow_item_icmp icmp;
        };
        union {
            struct rte_flow_item_tcp  outer_tcp;
            struct rte_flow_item_udp  outer_udp;
            struct rte_flow_item_sctp outer_sctp;
            struct rte_flow_item_icmp outer_icmp;
        };
        struct rte_flow_item_ipv4 outer_ipv4;
        struct rte_flow_item_vxlan vxlan;
    } spec, mask;
    bool vxlan_match_flag = false, vxlan_encap_flag=false;
    odp_port_t cfg_port = 0;

    memset(&spec, 0, sizeof spec);
    memset(&mask, 0, sizeof mask);

    ret = netdev_offload_map_flow_priority(&flow_attr, info);
    if (ret)
        return ret;

    /* vxlan pattern */
    if (match->wc.masks.tunnel.ip_src ||
        match->wc.masks.tunnel.ip_dst ||
        match->wc.masks.tunnel.tun_id ||
        match->wc.masks.tunnel.tp_src ||
        match->wc.masks.tunnel.tp_dst) {

        uint8_t proto_l4 = 0;

        memset(&spec.outer_ipv4, 0, sizeof spec.ipv4);
        memset(&mask.outer_ipv4, 0, sizeof mask.ipv4);

        spec.outer_ipv4.hdr.type_of_service = match->flow.tunnel.ip_tos;
        spec.outer_ipv4.hdr.time_to_live    = match->flow.tunnel.ip_ttl;
        spec.outer_ipv4.hdr.next_proto_id   = IPPROTO_UDP;
        spec.outer_ipv4.hdr.src_addr        = match->flow.tunnel.ip_src;
        spec.outer_ipv4.hdr.dst_addr        = match->flow.tunnel.ip_dst;

        mask.ipv4.hdr.type_of_service = match->wc.masks.tunnel.ip_tos;
        // mask.ipv4.hdr.time_to_live    = match->wc.masks.tunnel.ip_ttl;
        mask.outer_ipv4.hdr.time_to_live    = 0x00u;
        mask.outer_ipv4.hdr.next_proto_id   = 0xffu;
        mask.outer_ipv4.hdr.src_addr        = match->wc.masks.tunnel.ip_src;
        mask.outer_ipv4.hdr.dst_addr        = match->wc.masks.tunnel.ip_dst;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_IPV4,
                         &spec.outer_ipv4, &mask.outer_ipv4);

        /* Save proto for L4 protocol setup */
        proto_l4 = spec.outer_ipv4.hdr.next_proto_id &
                   mask.outer_ipv4.hdr.next_proto_id;

        if (proto_l4 == IPPROTO_UDP) {
            memset(&spec.outer_udp, 0, sizeof spec.udp);
            memset(&mask.outer_udp, 0, sizeof mask.udp);
            spec.outer_udp.hdr.src_port = match->flow.tunnel.tp_src;
            spec.outer_udp.hdr.dst_port = match->flow.tunnel.tp_dst;

            mask.outer_udp.hdr.src_port = match->wc.masks.tunnel.tp_src;
            mask.outer_udp.hdr.dst_port = match->wc.masks.tunnel.tp_dst;

            add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_UDP,
                             &spec.outer_udp, &mask.outer_udp);

            struct vni {
                union  {
                    uint32_t val;
                    uint8_t  vni[4];
                };
            };

            struct vni vni = {
                .val = (uint32_t)(match->flow.tunnel.tun_id >> 32),
            };

            struct vni vni_m = {
                .val = (uint32_t)(match->wc.masks.tunnel.tun_id >> 32),
            };

            /* VXLAN */
            memset(&spec.vxlan, 0, sizeof spec.vxlan);
            memset(&mask.vxlan, 0, sizeof mask.vxlan);

            spec.vxlan.flags  = match->flow.tunnel.flags;
            spec.vxlan.vni[0] = vni.vni[1];
            spec.vxlan.vni[1] = vni.vni[2];
            spec.vxlan.vni[2] = vni.vni[3];

            mask.vxlan.vni[0] = vni_m.vni[1];
            mask.vxlan.vni[1] = vni_m.vni[2];
            mask.vxlan.vni[2] = vni_m.vni[3];

            add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_VXLAN,
                             &spec.vxlan, &mask.vxlan);

            vxlan_match_flag = true;
            cfg_port = netdev_offload_get_vxlan_pop_pf_id(match->flow.tunnel.ip_dst);
            if (!cfg_port) {
                VLOG_ERR("Can not get vxlan pop cfg port id, dst ip: 0x%x", match->flow.tunnel.ip_dst);
            }

            int port_enum;
            port_enum = netdev_offload_get_enum_by_odp_port(cfg_port);
            if (port_enum == OFFLOAD_PORT_MAX) {
                VLOG_ERR("Can not get offload port enum, port id: %d", cfg_port);
            } else {
                VLOG_INFO("match vxlan, set config port to %s", port_map[port_enum].name);
                netdev = port_map[port_enum].pdev;
            }
        } else {
            VLOG_ERR("Tunnel should be on UDP");
        }
    }

    /* Eth */
    if (!eth_addr_is_zero(match->wc.masks.dl_src) ||
        !eth_addr_is_zero(match->wc.masks.dl_dst) ||
        match->wc.masks.dl_type) {
        memcpy(&spec.eth.dst, &match->flow.dl_dst, sizeof spec.eth.dst);
        memcpy(&spec.eth.src, &match->flow.dl_src, sizeof spec.eth.src);
        spec.eth.type = match->flow.dl_type;

        memcpy(&mask.eth.dst, &match->wc.masks.dl_dst, sizeof mask.eth.dst);
        memcpy(&mask.eth.src, &match->wc.masks.dl_src, sizeof mask.eth.src);
        mask.eth.type = match->wc.masks.dl_type;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_ETH,
                         &spec.eth, &mask.eth);
    } else {
        /*
         * If user specifies a flow (like UDP flow) without L2 patterns,
         * OVS will at least set the dl_type. Normally, it's enough to
         * create an eth pattern just with it. Unluckily, some Intel's
         * NIC (such as XL710) doesn't support that. Below is a workaround,
         * which simply matches any L2 pkts.
         */
        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_ETH, NULL, NULL);
    }

    /* VLAN */
    if (match->wc.masks.vlans[0].tci && match->flow.vlans[0].tci) {
        spec.vlan.tci  = match->flow.vlans[0].tci & ~htons(VLAN_CFI);
        mask.vlan.tci  = match->wc.masks.vlans[0].tci & ~htons(VLAN_CFI);

        /* Match any protocols. */
        mask.vlan.inner_type = 0;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_VLAN,
                         &spec.vlan, &mask.vlan);
    }

    /* IP v4 */
    if (match->flow.dl_type == htons(ETH_TYPE_IP)) {
        spec.ipv4.hdr.type_of_service = match->flow.nw_tos;
        spec.ipv4.hdr.time_to_live    = match->flow.nw_ttl;
        spec.ipv4.hdr.next_proto_id   = match->flow.nw_proto;
        spec.ipv4.hdr.src_addr        = match->flow.nw_src;
        spec.ipv4.hdr.dst_addr        = match->flow.nw_dst;

        mask.ipv4.hdr.type_of_service = match->wc.masks.nw_tos;
        mask.ipv4.hdr.time_to_live    = 0x00u;
        mask.ipv4.hdr.next_proto_id   = match->wc.masks.nw_proto;
        mask.ipv4.hdr.src_addr        = match->wc.masks.nw_src;
        mask.ipv4.hdr.dst_addr        = match->wc.masks.nw_dst;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_IPV4,
                         &spec.ipv4, &mask.ipv4);

        /* Save proto for L4 protocol setup. */
        proto = spec.ipv4.hdr.next_proto_id &
                mask.ipv4.hdr.next_proto_id;
    }

    if (proto != IPPROTO_ICMP && proto != IPPROTO_UDP  &&
        proto != IPPROTO_SCTP && proto != IPPROTO_TCP  &&
        (match->wc.masks.tp_src ||
         match->wc.masks.tp_dst ||
         match->wc.masks.tcp_flags)) {
        VLOG_DBG("L4 Protocol (%u) not supported", proto);
        ret = -1;
        goto out;
    }

    if ((match->wc.masks.tp_src && match->wc.masks.tp_src != OVS_BE16_MAX) ||
        (match->wc.masks.tp_dst && match->wc.masks.tp_dst != OVS_BE16_MAX)) {
        ret = -1;
        goto out;
    }

    switch (proto) {
    case IPPROTO_TCP:
        spec.tcp.hdr.src_port  = match->flow.tp_src;
        spec.tcp.hdr.dst_port  = match->flow.tp_dst;
        spec.tcp.hdr.data_off  = ntohs(match->flow.tcp_flags) >> 8;
        spec.tcp.hdr.tcp_flags = ntohs(match->flow.tcp_flags) & 0xff;

        mask.tcp.hdr.src_port  = match->wc.masks.tp_src;
        mask.tcp.hdr.dst_port  = match->wc.masks.tp_dst;
        mask.tcp.hdr.data_off  = ntohs(match->wc.masks.tcp_flags) >> 8;
        mask.tcp.hdr.tcp_flags = ntohs(match->wc.masks.tcp_flags) & 0xff;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_TCP,
                         &spec.tcp, &mask.tcp);

        /* proto == TCP and ITEM_TYPE_TCP, thus no need for proto match. */
        mask.ipv4.hdr.next_proto_id = 0;
        break;

    case IPPROTO_UDP:
        spec.udp.hdr.src_port = match->flow.tp_src;
        spec.udp.hdr.dst_port = match->flow.tp_dst;

        mask.udp.hdr.src_port = match->wc.masks.tp_src;
        mask.udp.hdr.dst_port = match->wc.masks.tp_dst;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_UDP,
                         &spec.udp, &mask.udp);

        /* proto == UDP and ITEM_TYPE_UDP, thus no need for proto match. */
        mask.ipv4.hdr.next_proto_id = 0;
        break;

    case IPPROTO_SCTP:
        spec.sctp.hdr.src_port = match->flow.tp_src;
        spec.sctp.hdr.dst_port = match->flow.tp_dst;

        mask.sctp.hdr.src_port = match->wc.masks.tp_src;
        mask.sctp.hdr.dst_port = match->wc.masks.tp_dst;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_SCTP,
                         &spec.sctp, &mask.sctp);

        /* proto == SCTP and ITEM_TYPE_SCTP, thus no need for proto match. */
        mask.ipv4.hdr.next_proto_id = 0;
        break;

    case IPPROTO_ICMP:
        spec.icmp.hdr.icmp_type = (uint8_t) ntohs(match->flow.tp_src);
        spec.icmp.hdr.icmp_code = (uint8_t) ntohs(match->flow.tp_dst);

        mask.icmp.hdr.icmp_type = (uint8_t) ntohs(match->wc.masks.tp_src);
        mask.icmp.hdr.icmp_code = (uint8_t) ntohs(match->wc.masks.tp_dst);

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_ICMP,
                         &spec.icmp, &mask.icmp);

        /* proto == ICMP and ITEM_TYPE_ICMP, thus no need for proto match. */
        mask.ipv4.hdr.next_proto_id = 0;
        break;
    }

    add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);

    const struct nlattr *a;
    unsigned int left;

    if (!actions_len || !nl_actions) {
        VLOG_INFO("%s: skip flow offload without actions\n", netdev_get_name(netdev));
        ret = -1;
        goto out;
    }

    int out_put_action_cnt = 0;
    struct rte_flow_action_port_id port_id;
    struct rte_flow_action_raw_encap raw_encap = {0};
    const uint32_t* recirc_id;
    const struct ovs_action_push_tnl *tunnel;
    struct netdev_offload_set_action set_action;
    struct rte_flow_action_of_push_vlan vlan_push = {0};
    struct rte_flow_action_of_set_vlan_vid vlan_vid = {0};
    const struct ovs_action_push_vlan *vlan = NULL;
    struct rte_flow_action_jump tbl;

    if (vxlan_match_flag && !(IS_UPCALL_RECIRC_ID(match->flow.recirc_id))) {
        VLOG_INFO("### add vxlan decap action ###");
        add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_VXLAN_DECAP, NULL);
    }

    NL_ATTR_FOR_EACH_UNSAFE (a, left, nl_actions, actions_len) {
        int type = nl_attr_type(a);
        switch ((enum ovs_action_attr) type) {
        case OVS_ACTION_ATTR_OUTPUT: {
            odp_port_t odp_port = nl_attr_get_odp_port(a);
            ret = netdev_offload_output_action(netdev, info->dpif_class, &actions, &port_id, &out_put_action_cnt, odp_port, vxlan_encap_flag);
            if (ret == -1) {
                continue;
            }
            break;
        }
        case OVS_ACTION_ATTR_METER: {
            struct rte_flow_action_meter *mc;
            mc = netdev_offload_dpdk_meter_conf(dpif, netdev, nl_attr_get_u32(a));
            if (mc) {
                VLOG_INFO("add flow action: RTE_FLOW_ACTION_TYPE_METER: %d", RTE_FLOW_ACTION_TYPE_METER);
                add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_METER, mc);
            } else {
                VLOG_INFO("Can't get the rte flow meter, meter offload fail");
            }
            break;
        }
        case OVS_ACTION_ATTR_RECIRC: {
            recirc_id = nl_attr_get(a);
            if (recirc_id == NULL || !IS_SPEC_RECIRC_ID(*recirc_id)) {
                VLOG_INFO("Unsupported this recirc id action: %d", ((recirc_id==NULL) ? -1: *recirc_id));
                continue;
            }

            if (IS_UPCALL_RECIRC_ID(*recirc_id)) {
                netdev_offload_jump_group_action(&flow_attr, &actions, OFFLOAD_RECIRC_UPCALL, &tbl);
                continue;
            }

            netdev_offload_output_action(netdev, info->dpif_class, &actions, &port_id, &out_put_action_cnt, 0, true);
            break;
        }
        case OVS_ACTION_ATTR_TUNNEL_PUSH: {
            tunnel = nl_attr_get(a);

            raw_encap.data = (uint8_t *)tunnel->header;
            raw_encap.preserve = NULL;
            raw_encap.size = tunnel->header_len;

            vxlan_encap_flag = true;                  //this flag will be used for normal output
            if (port_map[VXLAN_OFFLOAD].pdev) {
                netdev = port_map[VXLAN_OFFLOAD].pdev;  //config port set to vxlan-offload port
            }
            add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_RAW_ENCAP, &raw_encap);
            break;
        }
        case OVS_ACTION_ATTR_TUNNEL_POP:
            cfg_port=netdev_offload_get_odp_port_by_netdev(netdev);
            if (!cfg_port) {
                VLOG_ERR("Get config port odp port id failed, netdev name: %s", netdev->name);
                continue;
            }
            netdev_offload_vxlan_host_store(match->flow.nw_dst, cfg_port);
            //add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_VXLAN_DECAP, NULL);
            break;
        case OVS_ACTION_ATTR_SET:
            VLOG_INFO("### set action ###");
            ret = netdev_offload_set_action(nl_attr_get(a), &actions, &set_action, false);
            if (ret) {
                VLOG_INFO("Set Action offload return error  %d", ret);
                continue;
            }
            break;
        case OVS_ACTION_ATTR_SET_MASKED:
            VLOG_INFO("### set mask action ###");
            ret = netdev_offload_set_action(nl_attr_get(a), &actions, &set_action, true);
            if (ret) {
                VLOG_INFO("Set Mask Action offload return error  %d", ret);
                continue;
            }
            break;
        case OVS_ACTION_ATTR_PUSH_VLAN:
            vlan = nl_attr_get(a);

            vlan_push.ethertype = vlan->vlan_tpid;
            vlan_vid.vlan_vid = vlan->vlan_tci;

            /* RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP */
            add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN, &vlan_push);
            add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID, &vlan_vid);
            break;
        case OVS_ACTION_ATTR_POP_VLAN:
            add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_OF_POP_VLAN, NULL);
            break;
        case OVS_ACTION_ATTR_CLONE:
        case OVS_ACTION_ATTR_HASH:
        case OVS_ACTION_ATTR_PUSH_MPLS:
        case OVS_ACTION_ATTR_POP_MPLS:
        case OVS_ACTION_ATTR_CHECK_PKT_LEN:
        case OVS_ACTION_ATTR_UNSPEC:
        case OVS_ACTION_ATTR_USERSPACE:
        case OVS_ACTION_ATTR_SAMPLE:
        case OVS_ACTION_ATTR_CT:
        case OVS_ACTION_ATTR_TRUNC:
        case OVS_ACTION_ATTR_PUSH_ETH:
        case OVS_ACTION_ATTR_POP_ETH:
        case OVS_ACTION_ATTR_CT_CLEAR:
        case OVS_ACTION_ATTR_PUSH_NSH:
        case OVS_ACTION_ATTR_POP_NSH:
        case __OVS_ACTION_ATTR_MAX:
        default:
            VLOG_INFO("%s: only support output action\n", netdev_get_name(netdev));
            ret = -1;
            goto out;
        }
    }

    struct rte_flow_action_count action_count;
    action_count.shared = 0;
    action_count.id = info->flow_mark;
    add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_COUNT, &action_count);
    add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_END, NULL);
    
    netdev_offload_dpdk_dump(&patterns, &actions);

    flow = netdev_dpdk_rte_flow_create(netdev, &flow_attr,
                                       patterns.items,
                                       actions.actions, &error);

    if (!flow) {
        VLOG_ERR("%s: rte flow create error: %u : message : %s\n",
                 netdev_get_name(netdev), error.type, error.message);
        ret = -1;
        goto out;
    }
    ufid_to_rte_flow_associate(ufid, flow);
    VLOG_INFO("%s: installed flow %p by ufid "UUID_FMT"\n",
             netdev_get_name(netdev), flow, UUID_ARGS((struct uuid *)ufid));

out:
    free(patterns.items);
    free(actions.actions);
    return ret;
}

/*
 * Check if any unsupported flow patterns are specified.
 */
static int
netdev_offload_dpdk_validate_flow(const struct match *match)
{
    struct match match_zero_wc;
    const struct flow *masks = &match->wc.masks;

    /* Create a wc-zeroed version of flow. */
    match_init(&match_zero_wc, &match->flow, &match->wc);

    if (masks->metadata || masks->skb_priority ||
        masks->pkt_mark || masks->dp_hash) {
        goto err;
    }

    if (masks->ct_state || masks->ct_nw_proto ||
        masks->ct_zone  || masks->ct_mark     ||
        !ovs_u128_is_zero(masks->ct_label)) {
        goto err;
    }

    if (masks->conj_id || masks->actset_output) {
        goto err;
    }

    /* Unsupported L2. */
    if (!is_all_zeros(masks->mpls_lse, sizeof masks->mpls_lse)) {
        goto err;
    }

    /* Unsupported L3. */
    if (masks->ipv6_label || masks->ct_nw_src || masks->ct_nw_dst     ||
        !is_all_zeros(&masks->ipv6_src,    sizeof masks->ipv6_src)    ||
        !is_all_zeros(&masks->ipv6_dst,    sizeof masks->ipv6_dst)    ||
        !is_all_zeros(&masks->ct_ipv6_src, sizeof masks->ct_ipv6_src) ||
        !is_all_zeros(&masks->ct_ipv6_dst, sizeof masks->ct_ipv6_dst) ||
        !is_all_zeros(&masks->nd_target,   sizeof masks->nd_target)   ||
        !is_all_zeros(&masks->nsh,         sizeof masks->nsh)         ||
        !is_all_zeros(&masks->arp_sha,     sizeof masks->arp_sha)     ||
        !is_all_zeros(&masks->arp_tha,     sizeof masks->arp_tha)) {
        goto err;
    }

    /* If fragmented, then don't HW accelerate - for now. */
    if (match_zero_wc.flow.nw_frag) {
        goto err;
    }

    /* Unsupported L4. */
    if (masks->igmp_group_ip4 || masks->ct_tp_src || masks->ct_tp_dst) {
        goto err;
    }

    return 0;

err:
    VLOG_ERR("cannot HW accelerate this flow due to unsupported protocols");
    return -1;
}

static int
netdev_offload_dpdk_destroy_flow(struct netdev *netdev,
                                 const ovs_u128 *ufid,
                                 struct rte_flow *rte_flow)
{
    struct rte_flow_error error;
    int ret = netdev_dpdk_rte_flow_destroy(netdev, rte_flow, &error);

    if (ret == 0) {
        ufid_to_rte_flow_disassociate(ufid);
        VLOG_DBG("%s: removed rte flow %p associated with ufid " UUID_FMT "\n",
                 netdev_get_name(netdev), rte_flow,
                 UUID_ARGS((struct uuid *)ufid));
    } else {
        VLOG_ERR("%s: rte flow destroy error: %u : message : %s\n",
                 netdev_get_name(netdev), error.type, error.message);
    }

    return ret;
}

static int
netdev_offload_dpdk_flow_put(struct dpif *dpif, struct netdev *netdev,
                             struct match *match, struct nlattr *actions,
                             size_t actions_len, const ovs_u128 *ufid,
                             struct offload_info *info,
                             struct dpif_flow_stats *stats OVS_UNUSED)
{
    struct rte_flow *rte_flow;
    int ret;

    /*
     * If an old rte_flow exists, it means it's a flow modification.
     * Here destroy the old rte flow first before adding a new one.
     */
    rte_flow = ufid_to_rte_flow_find(ufid);
    if (rte_flow) {
        ret = netdev_offload_dpdk_destroy_flow(netdev, ufid, rte_flow);
        if (ret < 0) {
            return ret;
        }
    }

    ret = netdev_offload_dpdk_validate_flow(match);
    if (ret < 0) {
        return ret;
    }

    return netdev_offload_dpdk_add_flow(dpif, netdev, match, actions,
                                        actions_len, ufid, info);
}

static int
netdev_offload_dpdk_flow_del(struct netdev *netdev, const ovs_u128 *ufid,
                             struct dpif_flow_stats *stats OVS_UNUSED)
{
    struct rte_flow *rte_flow = ufid_to_rte_flow_find(ufid);

    if (!rte_flow) {
        return -1;
    }

    return netdev_offload_dpdk_destroy_flow(netdev, ufid, rte_flow);
}

static bool
netdev_offload_dpdk_flow_dump_next(struct netdev_flow_dump *dump,
                                   struct match *match OVS_UNUSED,
                                   struct nlattr **actions OVS_UNUSED,
                                   struct dpif_flow_stats *stats,
                                   struct dpif_flow_attrs *attrs OVS_UNUSED,
                                   ovs_u128 *ufid,
                                   struct ofpbuf *rbuffer OVS_UNUSED,
                                   struct ofpbuf *wbuffer OVS_UNUSED)
{
    struct rte_flow *rte_flow = ufid_to_rte_flow_find(ufid);

    if (!rte_flow) {
        return false;
    }

    struct rte_flow_query_count ethdev_count;
    struct rte_flow_action action[2];
    struct rte_flow_error error;

    action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    ethdev_count.reset = 0;
    ethdev_count.hits_set = 1;
    ethdev_count.bytes_set = 1;

    int ret = rte_flow_query(netdev_dpdk_get_portid(dump->netdev),
                             rte_flow, action,
                             &ethdev_count, &error);
    if (ret) {
        VLOG_INFO("rte_flow_query fail: error.type: %d, error.message: %s",
                  error.type,
                  error.message ? error.message : "(no stated reason)");

        return false;
    }

    stats->n_packets = ethdev_count.hits;
    stats->n_bytes = ethdev_count.bytes;
    stats->used = time_msec();
    return true;
}

static int
netdev_offload_dpdk_init_flow_api(struct netdev *netdev)
{
    if (!netdev_port_hook_func) {
        netdev_offload_output_port_map_init();
        netdev_port_hook_func = netdev_offload_port_add_del_hook;
    }
    return netdev_dpdk_flow_api_supported(netdev) ? 0 : EOPNOTSUPP;
}

const struct netdev_flow_api netdev_offload_dpdk = {
    .type = "dpdk_flow_api",
    .flow_put = netdev_offload_dpdk_flow_put,
    .flow_del = netdev_offload_dpdk_flow_del,
    .init_flow_api = netdev_offload_dpdk_init_flow_api,
    .flow_dump_create = NULL,
    .flow_dump_destroy = NULL,
    .flow_dump_next = netdev_offload_dpdk_flow_dump_next,
};
