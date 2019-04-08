/* vim: set ts=8 sw=4 sts=4 et: */
/*======================================================================
Copyright (C) 2008,2009,2014,2019 OSSO B.V. <walter+rtpsniff@osso.nl>
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

#include "rtpsniff.h"
#include <stdio.h>
#include <stdlib.h>


static char *out__filename = NULL;
static char out__filename_tmp[4096];

void out_help() {
    printf(
        "/*********************"
        " module: out (stream) ***********************************/\n"
        "This is the console/stream output module.\n"
        "It will stream the response to stdout and optionally to a status\n"
        "file, defined by the OUT_STATUS envvar.\n"
        "For example OUT_STATUS=/run/rtpsniff/iface1.status\n"
        "\n"
    );
}

int out_open() {
    out__filename = getenv("OUT_STATUS");
    if (out__filename && !*out__filename)
        out__filename = NULL;
    if (out__filename) {
        int ret;
        FILE *testfp;
        if ((ret = snprintf(out__filename_tmp, sizeof(out__filename_tmp) - 1,
                "%s.tmp", out__filename)) < 0 ||
                ret  >= sizeof(out__filename_tmp)) {
            return 1;
        }
        if ((testfp = fopen(out__filename_tmp, "w")) == NULL) {
            perror("error opening temp status file");
            return 1;
        }
        if (fprintf(testfp, "test\n") != 5) {
            perror("error writing temp status file");
            fclose(testfp);
            return 1;
        }
        fclose(testfp);
        fprintf(stderr, "Selected output file: %s\n", out__filename);
    }
    return 0;
}

void out_close() {
}

void out_write(uint32_t unixtime_begin, uint32_t interval, struct rtpstat_t *memory) {
    FILE *fps[3] = {stdout, NULL, NULL};
    FILE **fp;
    char src_ip[16];
    char dst_ip[16];
    unsigned streams = 0;
    unsigned packets = 0;
    unsigned lost = 0;
    unsigned late = 0;

    struct rtpstat_t *rtpstat, *tmp;

    /* Open temp file */
    if (out__filename) {
        if ((fps[1] = fopen(out__filename_tmp, "w")) == NULL) {
            perror("error opening temp status file");
        }
    }

    for (fp = fps; *fp; ++fp) {
        fprintf(*fp, "Storage output: unixtime_begin=%" SCNu32 ", "
                "interval=%" SCNu32 ", memory=%p\n",
                unixtime_begin, interval, memory);
    }

    HASH_ITER(hh, memory, rtpstat, tmp) {
        float miss_percent;
        streams += 1;
        packets += rtpstat->packets;
        lost += rtpstat->missed;
        late += rtpstat->late;

        /* Streams with significant amounts of packets */
        if ((rtpstat->packets + rtpstat->missed) < 20)
            continue;
        /* Streams with issues */
        if (rtpstat->gaps == 0 && rtpstat->late == 0 && rtpstat->jumps == 0)
            continue;
        /* Packets lost minimum 5% */
        if (rtpstat->missed * 100 / (rtpstat->packets + rtpstat->missed) < 5)
            continue;

        sprintf(src_ip, "%hhu.%hhu.%hhu.%hhu",
                rtpstat->src_ip >> 24, (rtpstat->src_ip >> 16) & 0xff,
                (rtpstat->src_ip >> 8) & 0xff, rtpstat->src_ip & 0xff);
        sprintf(dst_ip, "%hhu.%hhu.%hhu.%hhu",
                rtpstat->dst_ip >> 24, (rtpstat->dst_ip >> 16) & 0xff,
                (rtpstat->dst_ip >> 8) & 0xff, rtpstat->dst_ip & 0xff);
        miss_percent = (
            100.0 * rtpstat->missed / (rtpstat->packets + rtpstat->missed));

        for (fp = fps; *fp; ++fp) {
            fprintf(
                *fp,
                "RTP: %s:%hu > %s:%hu"
                ", ssrc: %" PRIu32
                ", packets: %" PRIu32
                ", seq: %" PRIu16
                ", lost: %" PRIu16
                ", lostpct: %.1f%%"
                ", gaps: %" PRIu16
                ", late-or-dupe: %" PRIu16
                ", jump: %" PRIu16
                "\n",
                src_ip, rtpstat->src_port,
                dst_ip, rtpstat->dst_port,
                rtpstat->ssrc,
                (rtpstat->packets + rtpstat->missed),
                rtpstat->seq,
                rtpstat->missed,
                miss_percent,
                rtpstat->gaps,
                rtpstat->late,
                rtpstat->jumps);
        }
    }

    for (fp = fps; *fp; ++fp) {
        if (!packets) {
            fprintf(*fp, "RTP-SUM: nothing\n");
        } else {
            fprintf(*fp, "RTP-SUM: streams %u, not-lost %u, lost %u (%.2f%%), "
                    "late-or-dupe %u (%.2f%%)\n",
                    streams, packets, lost, 100.0 * lost / (lost + packets),
                    late, 100.0 * late / (lost + packets));
        }
        fflush(*fp);
    }

    /* Flush/close/rename */
    if (fps[1]) {
        fclose(fps[1]);
        rename(out__filename_tmp, out__filename);
    }
}
