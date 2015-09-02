#ifndef INCLUDED_SNIFF_RTP_H
#define INCLUDED_SNIFF_RTP_H

#include "uthash.h"
#include <inttypes.h>

struct rtpstat_t {
    /* Part of hash */
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t ssrc;

    /* Contents */
    uint32_t packets;
    /*uint32_t timestamp? */
    uint16_t seq;
    uint16_t missed;	/* +1 for every missed increment */
    uint16_t misssize;	/* +N for every missed N increments */
    uint16_t late;	/* +1 for every out-of-order sequence */
    uint16_t jumps;	/* +1 for every large jump */

    UT_hash_handle hh;
};

#define HASH_FIRST src_ip
#define HASH_SIZE(rtpstat) ((char*)&((rtpstat).packets) - (char*)&((rtpstat).HASH_FIRST))
    
#endif /* INCLUDED_SNIFF_RTP_H */
