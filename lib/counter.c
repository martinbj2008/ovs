#include "counter.h"
#include <config.h>

VLOG_DEFINE_THIS_MODULE(dp_counter);

static struct dp_counter_t dp_counter;
void dp_counter_init(void)
{
    cmap_init(&dp_counter.counter_cmap);
    ovs_mutex_init(&dp_counter.mutex);
}

static void
dp_counter_pmd_counter_init_default(struct dp_counter_node_t *node)
{
    int i = 0;
    for (i = 0; i < MAX_PMD_OBJ_HASH_BUCKET; i++) {
        ovs_mutex_init(&node->pmd_cnt[i].mutex);
        hmap_init(&node->pmd_cnt[i].pmd_obj);
    }
}

static void
dp_counter_pmd_counter_destroy(struct dp_counter_node_t *node)
{
    int i = 0;
    struct dp_counter_obj_t * obj, *next;
    for (i = 0; i < MAX_PMD_OBJ_HASH_BUCKET; i++) {
        ovs_mutex_lock(&node->pmd_cnt[i].mutex);
        HMAP_FOR_EACH_SAFE(obj, next, node, &node->pmd_cnt[i].pmd_obj) {
            hmap_remove(&node->pmd_cnt[i].pmd_obj, &obj->node);
            free(obj);
        }
        ovs_mutex_unlock(&node->pmd_cnt[i].mutex);
    }
}

static int
dp_counter_pmd_counter_add(
        struct dp_counter_node_t *node,
        struct dp_counter_obj_t **pmd OVS_UNUSED ,
        int pmd_id,
        uint32_t hash)
OVS_REQUIRES(node->pmd_cnt[hash].mutex)
{
    struct dp_counter_obj_t * obj;
    int err = DP_COUNTER_ERR_NONE;

    HMAP_FOR_EACH_WITH_HASH(obj, node, hash, &node->pmd_cnt[hash].pmd_obj) {
        if (obj->pmd_id == pmd_id) {
            err = DP_COUNTER_ERR_EXSIT;
            goto err;
        }
    }

    obj = xmalloc(sizeof(*obj));
    if (!obj) {
        err = DP_COUNTER_ERR_MEMORY;
        goto err;
    }

    memset(obj, 0, sizeof(*obj));
    obj->pmd_id = pmd_id;
    hmap_insert(&node->pmd_cnt[hash].pmd_obj, &obj->node, hash);
    *pmd = obj;
err:
    return err;
}

static void
dp_counter_node_init_default(struct dp_counter_node_t *node, int id)
{
    memset(node, 0, sizeof(struct dp_counter_node_t));
    node->id = id;
    ovs_refcount_init(&node->ref_cnt);
    dp_counter_pmd_counter_init_default(node);
}

int
dp_counter_add(int id)
{
    struct dp_counter_node_t *counter_node = NULL;
    int err = DP_COUNTER_ERR_NONE;

    ovs_mutex_lock(&dp_counter.mutex);
    CMAP_FOR_EACH_WITH_HASH(counter_node, node, id, &dp_counter.counter_cmap) {
        if (id == counter_node->id) {
            err = DP_COUNTER_ERR_EXSIT;
            goto finish;
        }
    }

    counter_node = xmalloc(sizeof(struct dp_counter_node_t));
    if (NULL == counter_node) {
        err = DP_COUNTER_ERR_MEMORY;
        goto finish;
    }

    dp_counter_node_init_default(counter_node, id);
    cmap_insert(&dp_counter.counter_cmap, &counter_node->node, id);

finish:
    ovs_mutex_unlock(&dp_counter.mutex);
    return err;
}

static struct dp_counter_node_t *
dp_counter_node_get(int id)
{
    struct dp_counter_node_t *counter_node = NULL;
    CMAP_FOR_EACH_WITH_HASH (counter_node, node, id, &dp_counter.counter_cmap) {
        if (id == counter_node->id) {
            return counter_node;
        }
    }

    return NULL;
}


static int
dp_counter_get_stats_by_node(
    struct dp_counter_node_t *node,
    struct dp_counter_dump_t* dump OVS_UNUSED
    )
{
    int i = 0;
    struct dp_counter_obj_t * obj;
    uint64_t npkts = 0, nbytes = 0;

    memset(dump, 0, sizeof(struct dp_counter_dump_t));
    dump->id = node->id;
    dump->ref_cnt = ovs_refcount_read(&node->ref_cnt);
    for (i = 0; i < MAX_PMD_OBJ_HASH_BUCKET; i++) {
        ovs_mutex_lock(&node->pmd_cnt[i].mutex);
        HMAP_FOR_EACH(obj, node, &node->pmd_cnt[i].pmd_obj) {
            atomic_read_relaxed(&obj->n_packets, &npkts);
            atomic_read_relaxed(&obj->n_bytes, &nbytes);
            dump->npkts += npkts;
            dump->nbytes += nbytes;
            dump->pmd[dump->n_pmd].pmd_id = obj->pmd_id;
            dump->pmd[dump->n_pmd].npkts = npkts;
            dump->pmd[dump->n_pmd].nbytes = nbytes;
            dump->pmd[dump->n_pmd].hash = i;
            dump->n_pmd ++;
            if (dump->n_pmd >= MAX_DUMP_PMD) {
                ovs_mutex_unlock(&node->pmd_cnt[i].mutex);
                VLOG_ERR("Max dump pmd number is %d", MAX_DUMP_PMD);
                return DP_COUNTER_ERR_RANGE;
            }
        }
        ovs_mutex_unlock(&node->pmd_cnt[i].mutex);
    }

    return DP_COUNTER_ERR_NONE;
}

int
dp_counter_get_dump_all_counter(struct dp_counter_dump_t** dump OVS_UNUSED, int *cnt)
{
    int count = 0;
    struct dp_counter_dump_t* dump_tmp = NULL;
    struct dp_counter_node_t *cnt_node = NULL;
    int cnt_tmp = 0;

    count = cmap_count(&dp_counter.counter_cmap);
    *cnt = count;
    if (count)  {
        //need free by user
        dump_tmp = (struct dp_counter_dump_t *)xmalloc(sizeof(struct dp_counter_dump_t) * count);
        if (!dump_tmp) {
            return DP_COUNTER_ERR_MEMORY;
        }

        CMAP_FOR_EACH(cnt_node, node, &dp_counter.counter_cmap) {
            dp_counter_get_stats_by_node(cnt_node, &dump_tmp[cnt_tmp]);
            if (cnt_tmp >= count) {
                dump = NULL;
                free(dump_tmp);
                return DP_COUNTER_ERR_RANGE;
            }
            cnt_tmp ++;
        }
    }

    *dump = dump_tmp;
    return DP_COUNTER_ERR_NONE;
}

int
dp_counter_get_dump_info_by_id(int id, struct dp_counter_dump_t** dump OVS_UNUSED)
{
    struct dp_counter_node_t *node = NULL;
    struct dp_counter_dump_t* dump_tmp = NULL;

    node = dp_counter_node_get(id);
    if (node) {
        //need free by user
        dump_tmp = (struct dp_counter_dump_t *)xmalloc(sizeof(struct dp_counter_dump_t));
        if (!dump_tmp) {
            return DP_COUNTER_ERR_MEMORY;
        }
        dp_counter_get_stats_by_node(node, dump_tmp);
        *dump = dump_tmp;
    } else {
        return DP_COUNTER_ERR_NO_EXSIT;
    }

    return DP_COUNTER_ERR_NONE;
}

int
dp_counter_delete(int id)
{
    int err = DP_COUNTER_ERR_NONE;
    struct dp_counter_node_t *counter_node = NULL;

    ovs_mutex_lock(&dp_counter.mutex);
    counter_node = dp_counter_node_get(id);
    if (counter_node) {
        if (ovs_refcount_read(&counter_node->ref_cnt) == 1) {
            cmap_remove(&dp_counter.counter_cmap, &counter_node->node, id);
            dp_counter_pmd_counter_destroy(counter_node);
            ovsrcu_postpone(free, counter_node);
        }
        else {
            err = DP_COUNTER_ERR_USED;
        }
    } else {
        err = DP_COUNTER_ERR_NO_EXSIT;
    }
    ovs_mutex_unlock(&dp_counter.mutex);
    return err;
}

void
dp_counter_ref(int id)
{
    struct dp_counter_node_t *counter_node = NULL;
    if (!id) {
        return;
    }

    ovs_mutex_lock(&dp_counter.mutex);
    counter_node = dp_counter_node_get(id);
    if (!counter_node) {
        counter_node = xmalloc(sizeof(struct dp_counter_node_t));
        if (NULL == counter_node) {
            ovs_mutex_unlock(&dp_counter.mutex);
            return;
        }

        dp_counter_node_init_default(counter_node, id);
        cmap_insert(&dp_counter.counter_cmap, &counter_node->node, id);
    }
    ovs_refcount_ref(&counter_node->ref_cnt);
    ovs_mutex_unlock(&dp_counter.mutex);
    return;
}

void
dp_counter_unref(int id)
{
    struct dp_counter_node_t *counter_node = NULL;
    if (!id) {
        return;
    }

    ovs_mutex_lock(&dp_counter.mutex);
    counter_node = dp_counter_node_get(id);
    if (counter_node) {
        ovs_refcount_unref(&counter_node->ref_cnt);
        if (ovs_refcount_read(&counter_node->ref_cnt) == 1) {
            cmap_remove(&dp_counter.counter_cmap, &counter_node->node, id);
            dp_counter_pmd_counter_destroy(counter_node);
            ovsrcu_postpone(free, counter_node);
        }
    }
    ovs_mutex_unlock(&dp_counter.mutex);
    return;
}

static void
dp_counter_pmd_obj_stats_push(
    struct dp_counter_obj_t * obj,
    uint64_t n_pkts,
    uint64_t n_bytes,
    int type
    )
{
    uint64_t tmp;

    if (type == DP_COUNTER_PMD_STATS_TYPE_ADD) {
        atomic_read_relaxed(&obj->n_packets, &tmp);
        tmp += n_pkts;
        atomic_store_relaxed(&obj->n_packets, tmp);
        atomic_read_relaxed(&obj->n_bytes, &tmp);
        tmp += n_bytes;
        atomic_store_relaxed(&obj->n_bytes, tmp);
    } else {
        atomic_store_relaxed(&obj->n_packets, n_pkts);
        atomic_store_relaxed(&obj->n_bytes, n_bytes);
    }
}

void
dp_counter_push(int counter_id, int pmd_id,  uint64_t n_pkts, uint64_t n_bytes, int type)
{
    struct dp_counter_node_t *counter_node = NULL;
    uint32_t hash = 0;
    struct ovs_mutex *mutex_pmd;
    struct hmap * hmap_pmd;
    struct dp_counter_obj_t * obj = NULL;

    counter_node = dp_counter_node_get(counter_id);
    if (!counter_node) {
        VLOG_WARN("No counter instance of id %d", counter_id);
        return;
    }

    hash = dp_counter_pmdid_hash(pmd_id);
    mutex_pmd = &counter_node->pmd_cnt[hash].mutex;
    hmap_pmd = &counter_node->pmd_cnt[hash].pmd_obj;
    ovs_mutex_lock(mutex_pmd);
    HMAP_FOR_EACH_WITH_HASH(obj, node, hash, hmap_pmd) {
        if (obj->pmd_id == pmd_id) {
                dp_counter_pmd_obj_stats_push(obj, n_pkts, n_bytes, type);
            goto finish;
        }
    }

    dp_counter_pmd_counter_add(counter_node, &obj, pmd_id, hash);
    if (!obj) {
        VLOG_WARN("Can not get pmd %d counter object", pmd_id);
    } else {
        dp_counter_pmd_obj_stats_push(obj, n_pkts, n_bytes, type);
    }

finish:
    ovs_mutex_unlock(mutex_pmd);
}

/*test for pmd hash*/
static void
OVS_UNUSED dp_counter_test_hash(void)
{
    int i = 0;
    uint32_t hash = 0;
    uint32_t ret[MAX_PMD_OBJ_HASH_BUCKET] = {0};

    for (i = 0; i < 128; i++) {
        hash = dp_counter_pmdid_hash(i);
        VLOG_INFO("val: %d, hash: %u", i, hash);
        ret[hash] +=1;
    }

    hash = dp_counter_pmdid_hash(INT_MAX);
    VLOG_INFO("val: %d, hash: %u", INT_MAX, hash);
    hash = dp_counter_pmdid_hash(UINT32_MAX);
    VLOG_INFO("val: %d, hash: %u", UINT32_MAX, hash);
    for (i= 0; i < MAX_PMD_OBJ_HASH_BUCKET; i++) {
        VLOG_INFO("Bucket id: %d, number: %d", i, ret[hash]);
    }
}
