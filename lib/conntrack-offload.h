#ifndef CONNTRACK_OFFLOAD_H
#define CONNTRACK_OFFLOAD_H

#include "conntrack-private.h"

bool
conntrack_nat_offload_is_enable(void);

uint32_t
conntrack_nat_offload_flow_hash(const ovs_u128 *ufid);

void
conntrack_nat_offload_flow_put(struct conntrack *ct, struct dp_packet *pkt,
                               struct conn *conn, bool is_reply)
    OVS_REQUIRES(conn->lock);
void
conntrack_nat_offload_flow_del(struct conntrack *ct, ovs_u128 *ufid, uint32_t priority);

#endif
