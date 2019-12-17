/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
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

#ifndef DPIF_NETDEV_H
#define DPIF_NETDEV_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "dpif.h"
#include "openvswitch/types.h"
#include "dp-packet.h"
#include "packets.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Enough headroom to add a vlan tag, plus an extra 2 bytes to allow IP
 * headers to be aligned on a 4-byte boundary.  */
enum { DP_NETDEV_HEADROOM = 2 + VLAN_HEADER_LEN };

struct dp_meter_band {
    struct ofputil_meter_band up; /* type, prec_level, pad, rate, burst_size */
    uint32_t bucket; /* In 1/1000 packets (for PKTPS), or in bits (for KBPS) */
    uint64_t packet_count;
    uint64_t byte_count;
};

struct dp_meter {
    uint16_t flags;
    uint16_t n_bands;
    uint32_t max_delta_t;
    uint64_t used;
    uint64_t packet_count;
    uint64_t byte_count;
    struct dp_meter_band bands[];
};

bool dpif_is_netdev(const struct dpif *);

#define NR_QUEUE   1
#define NR_PMD_THREADS 1

#ifdef  __cplusplus
}
#endif

#endif /* netdev.h */
