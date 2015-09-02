/* vim: set ts=8 sw=4 sts=4 noet: */
/*======================================================================
Copyright (C) 2008,2009,2014,2015 OSSO B.V. <walter+rtpsniff@osso.nl>
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

#include "anysniff.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


const char *argv0;

int main(int argc, char const *const *argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    pcap_t *handle = NULL;
    int bufsize;
    const char *tmp;

    struct memory_t memory = {
	.data = {NULL, NULL},
	.active = 0,
	.request_switch = 0,
    };

    /* Set argv0 to basename of the called program */
    argv0 = argv[0];
    if ((tmp = strrchr(argv0, '/')) != NULL) {
	argv0 = tmp + 1;
    }

    /* User wants help? */
    if (argc == 2 && argv[1][0] == '-' && argv[1][1] == 'h' && argv[1][2] == '\0') {
	anysniff_help();
	sniff_help();
	timer_help();
	out_help();
	return 0;
    }

    /* Try initialization */
    errbuf[0] = '\0';
    strncat(errbuf, "Not enough arguments", PCAP_ERRBUF_SIZE - 1);
    if (argc != 4 ||
	    ((handle = pcap_create(argv[1], errbuf)) == NULL) ||
	    (pcap_set_snaplen(handle, sniff_snaplen()) != 0) ||
	    (pcap_set_timeout(handle, 1000) != 0) ||
	    /* frame size is 128 for our snaplen,
	     * we need to hold MAX_KPPS*1000*128 bytes if we poll and flush
	     * every second. add a little extra for kicks.
	     * If you set this too low, the "packets dropped by kernel" total
	     * will increase dramatically. Note that that figure will always
	     * show some packets because of startup/shutdown misses. */
	    (pcap_set_buffer_size(handle, (bufsize = atoi(argv[2]) * 1024 * 192)) != 0) ||
	    (pcap_activate(handle) != 0) ||
	    (pcap_compile(handle, &fp, argv[3], 0, PCAP_NETMASK_UNKNOWN) == -1) ||
	    (pcap_setfilter(handle, &fp) == -1)) {
	fprintf(stderr, "%s: Initialization failed or bad command line "
		        "options. See -h for help:\n%s\n", argv0, errbuf);
	if (handle)
	    pcap_close(handle);
	return 0;
    }

#ifndef NDEBUG
    fprintf(stderr, "%s: Initialized a packet ring buffer of %d KB, "
		    "should safely handle more than %d thousand packets per second.\n",
	    argv0, bufsize / 1024, atoi(argv[2]));
#endif

    /* Initialize updater thread */
    timer_loop_bg(&memory);

    /* Start the main loop (ends on INT/HUP/TERM/QUIT or error) */
    sniff_loop(handle, &memory);

    /* Finish updater thread */
    timer_loop_stop();

    /* Finish/close open stuff */
    sniff_release_data(&memory.data[0]);
    sniff_release_data(&memory.data[1]);
	
    out_close();
    pcap_close(handle);
    return 0;
}

void anysniff_help() {
    printf(
	"Usage:\n"
	"  %s IFACE MAX_KPPS PCAP_FILTER\n"
	"\n"
	"  MAX_KPPS is the amount of Kpackets per second you expect. if you\n"
	"    go too low, the buffers won't be sufficient.\n"
	"  IFACE is the interface to sniff on.\n"
	"  PCAP_FILTER is the common BPF filter.\n"
	"\n"
	"Example:\n"
	"  %s eth0 100 'udp and not port 53'\n"
	"\n",
	argv0, argv0
    );
}
