/* vim: set ts=8 sw=4 sts=4 et: */
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

#include "sniff_loss.h"

#include "anysniff.h"
#include "endian.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static struct memory_t *sniff__memory;
static pcap_t *sniff__handle;


static void sniff__switch_memory(int signum);
static void sniff__loop_done(int signum);


void sniff_help() {
    printf(
        "/*********************"
        " module: sniff (pcap+rtp) *******************************/\n"
        "Sniff uses libpcap to listen for all incoming and outgoing RTP packets.\n"
        "\n"
    );
}

static void sniff_got_packet(u_char *args, const struct pcap_pkthdr *header,
                             const u_char *packet) {
    time_t sec = header->ts.tv_sec;
    long int usec = header->ts.tv_usec;
    int recently_active = sniff__memory->active;
    struct lossstat_t *curmem = ((struct lossstat_t **)sniff__memory->data)[recently_active];

    uint64_t now = (uint32_t)sec * 1000000 + usec;
    int64_t off;

    /* Auto-alloc stuff here */
    if (!curmem) {
        curmem = calloc(1, sizeof(struct lossstat_t));
        if (!curmem)
            abort();
        sniff__memory->data[recently_active] = curmem;
        curmem->min_diff_usec = (uint64_t)-1;
    }

    /* Keep statistics */
    if (curmem->packets != 0) {
        off = now - curmem->prev;
        if (off >= 0) {
            if (off < curmem->min_diff_usec)
                curmem->min_diff_usec = off;
            if (off > curmem->max_diff_usec)
                curmem->max_diff_usec = off;
        } else {
            /* Got packets out of order! Ignoring timestamp! */
            curmem->out_of_order += 1;
        }
    }

    curmem->packets += 1;
    curmem->prev = now;
}

int sniff_snaplen() {
    return 1; /* we don't care about any data, must be >0 */
}

void sniff_loop(pcap_t *handle, struct memory_t *memory) {
    struct pcap_stat stat = {0,};

    /* Set memory and other globals */
    sniff__handle = handle;
    sniff__memory = memory;

    /* Add signal handlers */
    util_signal_set(SIGUSR1, sniff__switch_memory);
    util_signal_set(SIGINT, sniff__loop_done);
    util_signal_set(SIGHUP, sniff__loop_done);
    util_signal_set(SIGQUIT, sniff__loop_done);
    util_signal_set(SIGTERM, sniff__loop_done);

#ifndef NDEBUG
    fprintf(stderr, "sniff_loop: Starting loop (mem %p/%p/%i).\n",
            memory->data[0], memory->data[1], memory->active);
#endif

    /* This uses the fast PACKET_RX_RING if available. */
    pcap_loop(handle, 0, sniff_got_packet, NULL);

#ifndef NDEBUG
    fprintf(stderr, "sniff_loop: Ended loop at user/system request.\n");
#endif

    if (pcap_stats(handle, &stat) < 0) {
            fprintf(stderr, "pcap_stats: %s\n", pcap_geterr(handle));
            return;
    }

    // FIXME: move this to out_*
    //fprintf(stderr, "%u packets captured\n", packets_captured);
    // and how many minutes? produce a grand total?
    fprintf(stderr, "%u packets received by filter\n", stat.ps_recv);
    fprintf(stderr, "%u packets dropped by kernel\n", stat.ps_drop);
    fprintf(stderr, "%u packets dropped by interface\n", stat.ps_ifdrop);

    /* Remove signal handlers */
    util_signal_set(SIGUSR1, SIG_IGN);
    util_signal_set(SIGINT, SIG_IGN);
    util_signal_set(SIGHUP, SIG_IGN);
    util_signal_set(SIGQUIT, SIG_IGN);
    util_signal_set(SIGTERM, SIG_IGN);
}

static void sniff__switch_memory(int signum) {
    int recently_active = sniff__memory->active;
    sniff__memory->active = !recently_active;
#ifndef NDEBUG
    fprintf(stderr, "sniff__switch_memory: Switched from memory %d (%p) to %d (%p).\n",
            recently_active, sniff__memory->data[recently_active],
            !recently_active, sniff__memory->data[!recently_active]);
#endif
}

static void sniff__loop_done(int signum) {
    pcap_breakloop(sniff__handle);
}

void sniff_release_data(void **data) {
    struct lossstat_t **memory = (struct lossstat_t **)data;
    free(*memory);
    *memory = NULL;
}
