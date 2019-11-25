#include "qos.h"
#include <config.h>

VLOG_DEFINE_THIS_MODULE(ovs_qos);

struct ovs_qos_bucket ovs_qos_hash[OVS_QOS_BUCKET_MAX];
struct rculist mask_list;

void ovs_qos_init(void)
{
    int i;
    for (i = 0; i < OVS_QOS_BUCKET_MAX; i++)
        rculist_init(&ovs_qos_hash[i].rculist);
    
    rculist_init(&mask_list);
}

static void ovs_qos_key_init(struct ovs_qos_node *n, struct ovs_qos_param *param)
{
    n->match.dst = param->match.dst & param->mask.dst;
    n->match.reg = param->match.reg;
    n->match.dir = param->match.dir;
}

static bool ovs_qos_key_eq(struct ovs_qos_key *m1, struct ovs_qos_key *m2)
{
    return memcmp(m1, m2, sizeof (struct ovs_qos_key)) == 0;
}

struct ovs_qos_node *ovs_qos_key_alloc(struct ovs_qos_param *param)
{
    struct ovs_qos_node *n;
    struct rte_meter_srtcm_params srtcm_param;

    n = xmalloc(sizeof (struct ovs_qos_node));
    rculist_init(&n->list);
    ovs_mutex_init(&n->mutex);

    srtcm_param.cir = param->rate *1024 /8;
    srtcm_param.cbs = param->rate *1024 /8;
    srtcm_param.ebs = 0;
    
    if (rte_meter_srtcm_profile_config(&n->qos_profile, &srtcm_param))
        goto err;

    if (rte_meter_srtcm_config(&n->qos, &n->qos_profile))
        goto err;

    ovs_qos_key_init(n, param);
    n->mask = NULL;

    return n;

err:
    free(n);
    return NULL;
}

void ovs_qos_key_destroy(struct ovs_qos_node *n)
{
    ovsrcu_postpone(free, n);
}

static struct ovs_qos_bucket *ovs_qos_hash_bucket(struct ovs_qos_key *m)
{
    return &ovs_qos_hash[hash_int(m->dst, m->reg) & (OVS_QOS_BUCKET_MAX -1)];
}

void ovs_qos_key_insert(struct ovs_qos_node *n)
{
    struct ovs_qos_bucket *b = ovs_qos_hash_bucket(&n->match);
    rculist_insert(&b->rculist, &n->list);
}

void ovs_qos_key_remove(struct ovs_qos_node *n)
{
    rculist_remove(&n->list);
}

struct ovs_qos_node *ovs_qos_key_lookup(struct ovs_qos_key *match)
{
    struct ovs_qos_bucket *b = ovs_qos_hash_bucket(match);
    struct ovs_qos_node *n;

    RCULIST_FOR_EACH(n, list, &b->rculist) {
        if (ovs_qos_key_eq(&n->match, match))
            return n;
    }

    return NULL;
}

static bool ovs_qos_mask_eq(struct ovs_qos_mask *m1, struct ovs_qos_mask *m2)
{
    return m1->dst == m2->dst;
}

static struct ovs_qos_mask *ovs_qos_mask_lookup(struct ovs_qos_param *param)
{
    struct ovs_qos_mask *m;

    RCULIST_FOR_EACH(m, list, &mask_list) {
        if (ovs_qos_mask_eq(m, &param->mask))
            return m;
    }

    return NULL;
}

struct ovs_qos_mask *ovs_qos_mask_alloc(struct ovs_qos_param *param)
{
    struct ovs_qos_mask *m;
    m = ovs_qos_mask_lookup(param);
    if (m) {
        ovs_refcount_ref(&m->ref);
        return m;
    }

    m = xmalloc(sizeof (*m));
    
    ovs_refcount_init(&m->ref);
    rculist_init(&m->list);

    m->dst = param->mask.dst;

    struct ovs_qos_mask *m1, *m_next;

    RCULIST_FOR_EACH_SAFE_PROTECTED(m1, m_next, list, &mask_list) {
        if (m->dst > m1->dst) {
            rculist_insert(&m1->list, &m->list);
            goto out;
        }
    }
    
    rculist_insert(&mask_list, &m->list);

out:
    return m;
}

void ovs_qos_mask_destroy(struct ovs_qos_mask *mask)
{
    if (ovs_refcount_unref(&mask->ref) == 1) {
        rculist_remove(&mask->list);
        ovsrcu_postpone(free, mask);
    }
}

enum ovs_qos_action ovs_qos_counter(struct ovs_qos_key *match, uint32_t pkt_len)
{
    struct ovs_qos_node *n;
    enum rte_meter_color co = e_RTE_METER_GREEN;

    OVS_QOS_MASK_FOREACH {
        struct ovs_qos_key match_masked;
        match_masked.dst = match->dst & m->dst;
        match_masked.dir = match->dir;
        match_masked.reg = match->reg;

        struct ovs_qos_bucket *b = ovs_qos_hash_bucket(&match_masked);

        RCULIST_FOR_EACH(n, list, &b->rculist) {

            if (ovs_qos_key_eq(&n->match, &match_masked)) {
                ovs_mutex_lock(&n->mutex);
                co = rte_meter_srtcm_color_blind_check(&n->qos,
                                                       &n->qos_profile,
                                                       rte_rdtsc(),
                                                       pkt_len);
                ovs_mutex_unlock(&n->mutex);
                goto out;
            }
        }
    }

out:
    if (OVS_LIKELY(co == e_RTE_METER_GREEN))
        return OVS_QOS_ACT_ACCEPT;

    return OVS_QOS_ACT_DROP;
}
