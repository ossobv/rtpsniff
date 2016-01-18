/* vim: set ts=8 sw=4 sts=4 et: */
/*======================================================================
Copyright (C) 2014,2015 OSSO B.V. <walter+rtpsniff@osso.nl>
This file is part of RTPSniff.

RTPSniff is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

RTPSniff is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License along
with RTPSniff.  If not, see <http://www.gnu.org/licenses/>.
======================================================================*/

#include "sniff_rtp.h"

#include "anysniff.h"
#include <syslog.h>


void out_help() {
    printf(
        "/*********************"
        " module: out (syslog) ***********************************/\n"
        "This is the syslog output module. Logs to LOG_LOCAL7.\n"
        "FIXME: define what it does...\n"
        "\n"
    );
}

int out_open(char const *config_file) {
    openlog("rtpsniff", LOG_NDELAY, LOG_LOCAL7);
    return 0;
}

void out_close() {
    closelog();
}

void out_write(uint32_t unixtime_begin, uint32_t interval, void *data) {
    struct rtpstat_t *memory = data;
    char src_ip[16];
    char dst_ip[16];
    unsigned streams = 0;
    unsigned packets = 0;
    unsigned lost = 0;
    unsigned late = 0;

    struct rtpstat_t *rtpstat, *tmp;

    HASH_ITER(hh, memory, rtpstat, tmp) {
        streams += 1;
        packets += rtpstat->packets;
        lost += rtpstat->misssize;
        late += rtpstat->late;

        /* Streams with significant amounts of packets */
        if (rtpstat->packets < 20)
            continue;
        /* Streams with issues */
        if (rtpstat->missed == 0 && rtpstat->late == 0 && rtpstat->jumps == 0)
            continue;
        /* Packets lost minimum 5% */
        if (rtpstat->misssize * 100 / rtpstat->packets < 5)
            continue;

        sprintf(src_ip, "%hhu.%hhu.%hhu.%hhu",
                rtpstat->src_ip >> 24, (rtpstat->src_ip >> 16) & 0xff,
                (rtpstat->src_ip >> 8) & 0xff, rtpstat->src_ip & 0xff);
        sprintf(dst_ip, "%hhu.%hhu.%hhu.%hhu",
                rtpstat->dst_ip >> 24, (rtpstat->dst_ip >> 16) & 0xff,
                (rtpstat->dst_ip >> 8) & 0xff, rtpstat->dst_ip & 0xff);
        syslog(LOG_NOTICE,
               "stream=%" PRIu32 " from=%s:%hu to=%s:%hu "
               "packets=%" PRIu32 " lost=%" PRIu32 " lostpct=%.2f "
               "late=%" PRIu16 " latepct=%.2f "
               "missdetect=%" PRIu16 " jumpdetect=%" PRIu16 " "
               "lastseq=%" PRIu16,
               rtpstat->ssrc,
               src_ip, rtpstat->src_port,
               dst_ip, rtpstat->dst_port,
               rtpstat->packets,
               rtpstat->misssize, /* lost */
               100.0 * rtpstat->misssize / rtpstat->packets,
               rtpstat->late,
               100.0 * rtpstat->late / rtpstat->packets,
               rtpstat->missed,
               rtpstat->jumps,
               rtpstat->seq);
    }

    if (!packets) {
        syslog(LOG_NOTICE, "streams=0 packets=0 lost=0 lostpct=0 late=0 latepct=0");
    } else {
        syslog(LOG_NOTICE, "streams=%u packets=%u lost=%u lostpct=%.2f late=%u latepct=%.2f",
               streams, packets, lost, 100.0 * lost / packets,
               late, 100.0 * late / packets);
    }
}
