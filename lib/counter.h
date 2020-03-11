#ifndef OVS_COUNTER_H
#define OVS_COUNTER_H 1

#include "cmap.h"
#include "ovs-atomic.h"
#include "hmapx.h"
#include "openvswitch/thread.h"
#include "hash.h"
#include "openvswitch/compiler.h"
#include "openvswitch/vlog.h"

#define MAX_PMD_OBJ_HASH_BUCKET 16
#define MAX_PMD_OBJ_HASH_BUCKET_MASK (MAX_PMD_OBJ_HASH_BUCKET - 1)
#define MAX_DUMP_PMD     16
struct dp_counter_dump_pmd_t {
    int pmd_id;
    uint32_t hash;
    uint64_t npkts;
    uint64_t nbytes;
};

struct dp_counter_dump_t {
    uint64_t npkts;
    uint64_t nbytes;
    int n_pmd;
    int id;
    int ref_cnt;
    struct dp_counter_dump_pmd_t pmd[MAX_DUMP_PMD];
};

struct dp_counter_obj_t {
    struct hmap_node node;
    int pmd_id;
    atomic_ullong n_packets;
    atomic_ullong n_bytes;
};

struct dp_counter_pmd_t {
    struct ovs_mutex mutex;
    struct hmap pmd_obj;
};

struct dp_counter_node_t {
    struct cmap_node node;
    int id;
    uint64_t n_pkts;
    uint64_t n_bytes;
    struct ovs_refcount ref_cnt;
    struct dp_counter_pmd_t pmd_cnt[MAX_PMD_OBJ_HASH_BUCKET];
};

struct dp_counter_t {
    struct ovs_mutex mutex;
    struct cmap counter_cmap;
};

enum dp_counter_error {
    DP_COUNTER_ERR_NONE = 0,
    DP_COUNTER_ERR_EXSIT,
    DP_COUNTER_ERR_MEMORY,
    DP_COUNTER_ERR_NO_EXSIT,
    DP_COUNTER_ERR_RANGE,
    DP_COUNTER_ERR_USED
};

enum dp_counter_pmd_stats_type {
    DP_COUNTER_PMD_STATS_TYPE_ADD = 0,
    DP_COUNTER_PMD_STATS_TYPE_STORE
};

void dp_counter_init(void);
int dp_counter_add(int id);
int dp_counter_delete(int id);
void dp_counter_ref(int id);
void dp_counter_unref(int id);
void dp_counter_push(int counter_id, int pmd_id,  uint64_t n_pkts, uint64_t n_bytes, int type);
int dp_counter_get_dump_info_by_id(int id, struct dp_counter_dump_t** dump OVS_UNUSED);
int dp_counter_get_dump_all_counter(struct dp_counter_dump_t** dump OVS_UNUSED, int *cnt);

static inline uint32_t dp_counter_pmdid_hash(int pmd)
{
    return (hash_int((uint32_t)pmd, 0) & MAX_PMD_OBJ_HASH_BUCKET_MASK);
}

static inline char *
dp_counter_get_error_string(int error_no)
{
    switch (error_no) {
        case DP_COUNTER_ERR_NONE:
            return "none";
        case DP_COUNTER_ERR_NO_EXSIT:
            return "not exsit";
        case DP_COUNTER_ERR_MEMORY:
            return "has no memory";
        case DP_COUNTER_ERR_USED:
            return "delete counter is in use";
        case DP_COUNTER_ERR_EXSIT:
            return "counter exsit";
        case DP_COUNTER_ERR_RANGE:
            return "out of range";
        default:
            return "unkown";
    }

    return "unkown";
}
#endif
