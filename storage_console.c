/* vim: set ts=8 sw=4 sts=4 noet: */
/*======================================================================
Copyright (C) 2008,2009,2014 OSSO B.V. <walter+rtpsniff@osso.nl>
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


void storage_help() {
    printf(
	"/********************* module: storage (console) ******************************/\n"
	"This is a dummy storage module. Use this to test the rest of the program when\n"
	"you don't have or want a database.\n"
	"\n"
#if 0 /* FIXME */
#endif 
    );
}

int storage_open(char const *config_file) {
    printf("Initializing storage: config_file=\"%s\"\n", config_file);
    return 0;
}

void storage_close() {
    printf("Finishing storage!\n");
}

void storage_write(uint32_t unixtime_begin, uint32_t interval, struct rtpstat_t *memory) {
    char src_ip[16];
    char dst_ip[16];
    unsigned streams = 0;
    unsigned packets = 0;
    unsigned lost = 0;
    unsigned late = 0;

    struct rtpstat_t *old, *tmp;

    printf("Storage output: unixtime_begin=%" SCNu32 ", interval=%" SCNu32 ", memory=%p\n",
	    unixtime_begin, interval, memory);

    HASH_ITER(hh, memory, old, tmp) {
	streams += 1;
	packets += old->packets;
	lost += old->misssize;
	late += old->late;

	/* Streams with significant amounts of packets */
	if (packets < 20)
	    continue;
	/* Streams with issues */
	if (old->missed == 0 && old->late == 0 && old->jumps == 0)
	    continue;
	/* Packets lost minimum 5% */
	if (old->misssize * 100 / old->packets < 5)
	    continue;

	sprintf(src_ip, "%hhu.%hhu.%hhu.%hhu",
		old->src_ip >> 24, (old->src_ip >> 16) & 0xff,
		(old->src_ip >> 8) & 0xff, old->src_ip & 0xff);
	sprintf(dst_ip, "%hhu.%hhu.%hhu.%hhu",
		old->dst_ip >> 24, (old->dst_ip >> 16) & 0xff,
		(old->dst_ip >> 8) & 0xff, old->dst_ip & 0xff);
	printf("RTP: %s:%hu > %s:%hu"
		", ssrc: %" PRIu32
		", packets: %" PRIu32
		", seq: %" PRIu16
		", missed: %" PRIu16
		", misssize: %" PRIu16
		", late: %" PRIu16
		", jump: %" PRIu16
		"\n",
		src_ip, old->src_port,
		dst_ip, old->dst_port,
		old->ssrc,
		old->packets,
		old->seq,
		old->missed,
		old->misssize,
		old->late,
		old->jumps);
    }

    if (!packets) {
	printf("RTP-SUM: nothing\n");
    } else {
	printf("RTP-SUM: streams %u, packets %u, lost %u (%.2f%%), late %u (%.2f%%)\n",
	       streams, packets, lost, 100.0 * lost / packets,
	       late, 100.0 * late / packets);
    }
}

void storage_memfree(struct rtpstat_t **memory) {
    /* FIXME: move me to sniff_pcap? */
    struct rtpstat_t *old, *tmp;
    HASH_ITER(hh, *memory, old, tmp) {
	HASH_DEL(*memory, old);
	free(old);
    }
}
