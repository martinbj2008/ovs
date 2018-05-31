/*
 * Copyright (c) 2014, 2015, 2016 Nicira, Inc.
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
#include <unistd.h>

#include "tnl-neigh-cache.h"

#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <stdlib.h>

#include "bitmap.h"
#include "cmap.h"
#include "coverage.h"
#include "dpif-netdev.h"
#include "openvswitch/dynamic-string.h"
#include "errno.h"
#include "flow.h"
#include "netdev.h"
#include "ovs-thread.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "seq.h"
#include "socket-util.h"
#include "timeval.h"
#include "unaligned.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"


/* In seconds */
#define NEIGH_ENTRY_DEFAULT_IDLE_TIME  (24 * 60 * 60)

struct tnl_neigh_entry {
    struct cmap_node cmap_node;
    struct in6_addr ip;
    struct eth_addr mac;
    time_t expires;             /* Expiration time. */
    char br_name[IFNAMSIZ];
};

static struct cmap table = CMAP_INITIALIZER;
static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;

static uint32_t
tnl_neigh_hash(const struct in6_addr *ip)
{
    return hash_bytes(ip->s6_addr, 16, 0);
}

static struct tnl_neigh_entry *
tnl_neigh_lookup__(const char br_name[IFNAMSIZ], const struct in6_addr *dst)
{
    struct tnl_neigh_entry *neigh;
    uint32_t hash;

    hash = tnl_neigh_hash(dst);
    CMAP_FOR_EACH_WITH_HASH (neigh, cmap_node, hash, &table) {
        if (ipv6_addr_equals(&neigh->ip, dst) && !strcmp(neigh->br_name, br_name)) {
            if (neigh->expires <= time_now()) {
                return NULL;
            }

            neigh->expires = time_now() + NEIGH_ENTRY_DEFAULT_IDLE_TIME;
            return neigh;
        }
    }
    return NULL;
}

int
tnl_neigh_lookup(const char br_name[IFNAMSIZ], const struct in6_addr *dst,
                 struct eth_addr *mac)
{
    struct tnl_neigh_entry *neigh;
    int res = ENOENT;

    neigh = tnl_neigh_lookup__(br_name, dst);
    if (neigh) {
        *mac = neigh->mac;
        res = 0;
    }
    return res;
}

static void
neigh_entry_free(struct tnl_neigh_entry *neigh)
{
    free(neigh);
}

static void
tnl_neigh_delete(struct tnl_neigh_entry *neigh)
{
    uint32_t hash = tnl_neigh_hash(&neigh->ip);
    cmap_remove(&table, &neigh->cmap_node, hash);
    ovsrcu_postpone(neigh_entry_free, neigh);
}

static void
tnl_neigh_set__(const char name[IFNAMSIZ], const struct in6_addr *dst,
                const struct eth_addr mac)
{
    ovs_mutex_lock(&mutex);
    struct tnl_neigh_entry *neigh = tnl_neigh_lookup__(name, dst);
    if (neigh) {
        if (eth_addr_equals(neigh->mac, mac)) {
            neigh->expires = time_now() + NEIGH_ENTRY_DEFAULT_IDLE_TIME;
            ovs_mutex_unlock(&mutex);
            return;
        }
        tnl_neigh_delete(neigh);
    }
    seq_change(tnl_conf_seq);

    neigh = xmalloc(sizeof *neigh);

    neigh->ip = *dst;
    neigh->mac = mac;
    neigh->expires = time_now() + NEIGH_ENTRY_DEFAULT_IDLE_TIME;
    ovs_strlcpy(neigh->br_name, name, sizeof neigh->br_name);
    cmap_insert(&table, &neigh->cmap_node, tnl_neigh_hash(&neigh->ip));
    ovs_mutex_unlock(&mutex);
}

static void
tnl_arp_set(const char name[IFNAMSIZ], ovs_be32 dst,
            const struct eth_addr mac)
{
    struct in6_addr dst6 = in6_addr_mapped_ipv4(dst);
    tnl_neigh_set__(name, &dst6, mac);
}

static int
tnl_arp_snoop(const struct flow *flow, struct flow_wildcards *wc,
              const char name[IFNAMSIZ])
{
    if (flow->dl_type != htons(ETH_TYPE_ARP)
        || FLOW_WC_GET_AND_MASK_WC(flow, wc, nw_proto) != ARP_OP_REPLY
        || eth_addr_is_zero(FLOW_WC_GET_AND_MASK_WC(flow, wc, arp_sha))) {
        return EINVAL;
    }

    tnl_arp_set(name, FLOW_WC_GET_AND_MASK_WC(flow, wc, nw_src), flow->arp_sha);
    return 0;
}

static int
tnl_nd_snoop(const struct flow *flow, struct flow_wildcards *wc,
             const char name[IFNAMSIZ])
{
    if (!is_nd(flow, wc) || flow->tp_src != htons(ND_NEIGHBOR_ADVERT)) {
        return EINVAL;
    }
    /* - RFC4861 says Neighbor Advertisements sent in response to unicast Neighbor
     *   Solicitations SHOULD include the Target link-layer address. However, Linux
     *   doesn't. So, the response to Solicitations sent by OVS will include the
     *   TLL address and other Advertisements not including it can be ignored.
     * - OVS flow extract can set this field to zero in case of packet parsing errors.
     *   For details refer miniflow_extract()*/
    if (eth_addr_is_zero(FLOW_WC_GET_AND_MASK_WC(flow, wc, arp_tha))) {
        return EINVAL;
    }

    memset(&wc->masks.ipv6_src, 0xff, sizeof wc->masks.ipv6_src);
    memset(&wc->masks.ipv6_dst, 0xff, sizeof wc->masks.ipv6_dst);
    memset(&wc->masks.nd_target, 0xff, sizeof wc->masks.nd_target);

    tnl_neigh_set__(name, &flow->nd_target, flow->arp_tha);
    return 0;
}

int
tnl_neigh_snoop(const struct flow *flow, struct flow_wildcards *wc,
                const char name[IFNAMSIZ])
{
    int res;
    res = tnl_arp_snoop(flow, wc, name);
    if (res != EINVAL) {
        return res;
    }
    return tnl_nd_snoop(flow, wc, name);
}

void
tnl_neigh_cache_run(void)
{
    struct tnl_neigh_entry *neigh;
    bool changed = false;

    ovs_mutex_lock(&mutex);
    CMAP_FOR_EACH(neigh, cmap_node, &table) {
        if (neigh->expires <= time_now()) {
            tnl_neigh_delete(neigh);
            changed = true;
        }
    }
    ovs_mutex_unlock(&mutex);

    if (changed) {
        seq_change(tnl_conf_seq);
    }
}

static void
tnl_neigh_cache_flush(struct unixctl_conn *conn, int argc OVS_UNUSED,
                    const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct tnl_neigh_entry *neigh;
    bool changed = false;

    ovs_mutex_lock(&mutex);
    CMAP_FOR_EACH(neigh, cmap_node, &table) {
        tnl_neigh_delete(neigh);
        changed = true;
    }
    ovs_mutex_unlock(&mutex);
    if (changed) {
        seq_change(tnl_conf_seq);
    }
    unixctl_command_reply(conn, "OK");
}

static int
lookup_any(const char *host_name, struct in6_addr *address)
{
    if (addr_is_ipv6(host_name)) {
        return lookup_ipv6(host_name, address);
    } else {
        int r;
        struct in_addr ip;
        r = lookup_ip(host_name, &ip);
        if (r == 0) {
            in6_addr_set_mapped_ipv4(address, ip.s_addr);
        }
        return r;
    }
    return ENOENT;
}

static void
tnl_neigh_cache_add(struct unixctl_conn *conn, int argc OVS_UNUSED,
                    const char *argv[], void *aux OVS_UNUSED)
{
    const char *br_name = argv[1];
    struct eth_addr mac;
    struct in6_addr ip6;

    if (lookup_any(argv[2], &ip6) != 0) {
        unixctl_command_reply_error(conn, "bad IP address");
        return;
    }

    if (!eth_addr_from_string(argv[3], &mac)) {
        unixctl_command_reply_error(conn, "bad MAC address");
        return;
    }

    tnl_neigh_set__(br_name, &ip6, mac);
    unixctl_command_reply(conn, "OK");
}

static void
tnl_neigh_cache_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct tnl_neigh_entry *neigh;

    ds_put_cstr(&ds, "IP                                            MAC                 Bridge\n");
    ds_put_cstr(&ds, "==========================================================================\n");
    ovs_mutex_lock(&mutex);
    CMAP_FOR_EACH(neigh, cmap_node, &table) {
        int start_len, need_ws;

        start_len = ds.length;
        ipv6_format_mapped(&neigh->ip, &ds);

        need_ws = INET6_ADDRSTRLEN - (ds.length - start_len);
        ds_put_char_multiple(&ds, ' ', need_ws);

        ds_put_format(&ds, ETH_ADDR_FMT"   %s",
                      ETH_ADDR_ARGS(neigh->mac), neigh->br_name);
        if (neigh->expires <= time_now()) {
            ds_put_format(&ds, " STALE");
        }
        ds_put_char(&ds, '\n');

    }
    ovs_mutex_unlock(&mutex);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

#define ROUTE_CMD "/usr/sbin/ip route show dev"
#define MAC_CMD "/usr/sbin/arp -a"
#define ARP_CMD "/usr/bin/ping -c 1"
#define IPLEN 16
#define MACLEN 32
#define BUF_LEN 128

struct rtinf{
    char rt[IPLEN];
    int mask;
};

static void send_arp(char *ip){
    char ping_buf[BUF_LEN] = {0};
    sprintf(ping_buf, "%s %s > /dev/null &", ARP_CMD, ip);
    FILE *fp = popen(ping_buf, "r");
    if(fp){
        pclose(fp);
        fp = NULL;
    }
}

static void send_arp_subnet(char *route, int mask){
    uint32_t rt = ntohl(inet_addr(route));
    uint32_t sub_addr = (1 << (32 - mask)) - 1;
    int i = 0;
    struct in_addr in;
    memset(&in, 0, sizeof(struct in_addr));

    for(i = 1; i < sub_addr; i++){
        in.s_addr = htonl(rt + i);
        send_arp(inet_ntoa(in));
    }
}

static void get_mac(char *ip, char *mac){
    FILE *fd = NULL;
    char buf[BUF_LEN] = {0};
    char *str = NULL;
    sprintf(buf, "%s %s", MAC_CMD, ip);
    fd = popen(buf, "r");
    if(fd){
        if(fgets(buf, sizeof(buf), fd)){
            if((str = strstr(buf, "at ")) && !strstr(buf, "incomplete")){
                memcpy(mac, str + 3, 17);
            }
        }
        pclose(fd);
        fd = NULL;
    }
}

static void ovs_route_add(const char *bridge, char *ip, char *mac_addr){
    struct eth_addr mac;
    struct in6_addr ip6;

    if (lookup_any(ip, &ip6) != 0) {
        return;
    }

    if (!eth_addr_from_string(mac_addr, &mac)) {
        return;
    }

    tnl_neigh_set__(bridge, &ip6, mac);
}

static void ovs_route_add_subnet(const char *bridge, char *route, int mask){
    in_addr_t rt = ntohl(inet_addr(route));
    uint32_t sub_addr = (1 << (32 - mask)) - 1;
    int i = 0;
    char *ip;
    struct in_addr in;
    memset(&in, 0, sizeof(struct in_addr));
    char mac[MACLEN] = {0};

    for(i = 1; i < sub_addr; i++){
        in.s_addr = htonl(rt + i);
        ip = inet_ntoa(in);
        memset(mac, 0, MACLEN);
        get_mac(ip, mac);
        if(strlen(mac)){
            ovs_route_add(bridge, ip, mac);
        }
    }
}

static void tnl_arp_set_by_sys_route(const char *bridge, const char *iface) {
    FILE *fp = NULL;
    char buff[BUF_LEN] = {0};
    char default_gw[IPLEN] = {0};
    int i = 0, j = 0;
    char dgw_mac[MACLEN] = {0};
    struct rtinf *route = NULL;
    char cmd[BUF_LEN] = {0};

    sprintf(cmd, "%s %s", ROUTE_CMD, iface);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        return;
    }

    while (fgets(buff, sizeof(buff), fp)) {
        if (strstr(buff, "default")) {
            sscanf(buff, "default via %s", default_gw);
            send_arp(default_gw);
        }

        if (strstr(buff, "proto kernel")) {
            route = (struct rtinf *) realloc(route, sizeof(struct rtinf) * (i + 1));
            if (route == NULL) {
                goto out;
            }

            memset(&route[i], 0, sizeof(struct rtinf));
            *(strchr(buff, '/')) = ' ';
            sscanf(buff, "%s %d proto kernel", route[i].rt, &route[i].mask);
            send_arp_subnet(route[i].rt, route[i].mask);
            i++;
        }
    }

    //sleep(5);
    get_mac(default_gw, dgw_mac);
    ovs_route_add(bridge, default_gw, dgw_mac);

    for (j = 0; j < i; j++) {
        ovs_route_add_subnet(bridge, route[j].rt, route[j].mask);
    }

out:
    if (route) {
        free(route);
        route = NULL;
    }

    fclose(fp);
    fp = NULL;
}

static void tnl_neigh_cache_update(struct unixctl_conn *conn, int argc OVS_UNUSED,
                                   const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED){
    const char *br_name = argv[1];
    const char *iface = argv[2];
    tnl_arp_set_by_sys_route(br_name, iface);
    unixctl_command_reply(conn, "OK");
}

void
tnl_neigh_cache_init(void)
{
    unixctl_command_register("tnl/arp/show", "", 0, 0, tnl_neigh_cache_show, NULL);
    unixctl_command_register("tnl/arp/set", "BRIDGE IP MAC", 3, 3, tnl_neigh_cache_add, NULL);
    unixctl_command_register("tnl/arp/flush", "", 0, 0, tnl_neigh_cache_flush, NULL);
    unixctl_command_register("tnl/arp/update", "BRIDGE INTERFACE", 2, 2, tnl_neigh_cache_update, NULL);
    unixctl_command_register("tnl/neigh/show", "", 0, 0, tnl_neigh_cache_show, NULL);
    unixctl_command_register("tnl/neigh/set", "BRIDGE IP MAC", 3, 3, tnl_neigh_cache_add, NULL);
    unixctl_command_register("tnl/neigh/flush", "", 0, 0, tnl_neigh_cache_flush, NULL);
    tnl_arp_set_by_sys_route("br-dpdk", "bond4");
}
