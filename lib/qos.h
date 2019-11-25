#ifndef OVS_QOS_H
#define OVS_QOS_H 1

#include <rte_meter.h>
#include <rte_cycles.h>
#include <config.h>

#include "rculist.h"
#include "hash.h"
#include "openvswitch/thread.h"
#include "openvswitch/compiler.h"
#include "openvswitch/vlog.h"

/* useful data center */
#define OVS_QOS_BUCKET_MAX	0x10000

enum ovs_qos_action {
    OVS_QOS_ACT_ACCEPT = 1,
    OVS_QOS_ACT_DROP = 2,
};

enum ovs_qos_direction {
    OVS_QOS_DIR_INVALID	= 0,
    OVS_QOS_DIR_INPUT	= 1,
    OVS_QOS_DIR_OUTPUT	= 2,
    OVS_QOS_DIR_ACTION	= 3,
};

struct ovs_qos_bucket {
    struct rculist rculist;	
};

extern struct ovs_qos_bucket ovs_qos_hash[OVS_QOS_BUCKET_MAX];
extern struct rculist mask_list;

struct ovs_qos_key {
    uint32_t dst;
    uint32_t reg;
    enum ovs_qos_direction dir; /* only support input or output*/
};

struct ovs_qos_node {
    struct rculist list;
    struct ovs_mutex mutex; /* for qos */

    /* match field */
    struct ovs_qos_key match; /* masked */
    struct ovs_qos_mask *mask;

    struct rte_meter_srtcm_profile qos_profile;
    struct rte_meter_srtcm qos;
};

struct ovs_qos_mask {
    struct rculist list;
    struct ovs_refcount ref;

    uint32_t dst;
};

struct ovs_qos_param {
    struct ovs_qos_key match;
    struct ovs_qos_mask mask;
    uint32_t rate;
};

void ovs_qos_init(void);
struct ovs_qos_node *ovs_qos_key_alloc(struct ovs_qos_param *param);
struct ovs_qos_node *ovs_qos_key_lookup(struct ovs_qos_key *match);
void ovs_qos_key_destroy(struct ovs_qos_node *n);
void ovs_qos_key_insert(struct ovs_qos_node *n);
void ovs_qos_key_remove(struct ovs_qos_node *n);
enum ovs_qos_action ovs_qos_counter(struct ovs_qos_key *match, uint32_t pkt_len);

struct ovs_qos_mask *ovs_qos_mask_alloc(struct ovs_qos_param *param);
void ovs_qos_mask_destroy(struct ovs_qos_mask *mask);

#define OVS_QOS_NODE_FOREACH \
    struct ovs_qos_node *n;     \
    int i;                      \
    for (i = 0; i < OVS_QOS_BUCKET_MAX; i++)        \
        RCULIST_FOR_EACH(n, list, &ovs_qos_hash[i].rculist)

#define OVS_QOS_NODE_FOREACH_SAFE \
    struct ovs_qos_node *n;     \
    struct ovs_qos_node *next;     \
    int i;                      \
    for (i = 0; i < OVS_QOS_BUCKET_MAX; i++)        \
        RCULIST_FOR_EACH_SAFE_PROTECTED(n, next, list, &ovs_qos_hash[i].rculist)

#define OVS_QOS_MASK_FOREACH \
    struct ovs_qos_mask *m;     \
    RCULIST_FOR_EACH(m, list, &mask_list)

#endif
