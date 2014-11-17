/* vim: set ts=8 sw=4 sts=4 noet: */
/*======================================================================
Copyright (C) 2014 OSSO B.V. <walter+rtpsniff@osso.nl>
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

/*
 * WHAT
 *
 *   This module adds a 500ms sleep to every poll call.
 *
 * HOW
 *
 *   By replacing the poll library call with a custom one that calls
 *   usleep first. For temporary effect, it can be LD_PRELOADed, or for
 *   more permanent effect, it must be linked *before* libpcap.
 *
 * WHY
 *
 *   Libpcap uses PACKET_RX_RING to capture packets into a ring buffer,
 *   if they pass the SO_ATTACH_FILTER. The pcap loop then polls for
 *   new packets on the socket. Since RTP flows a lot, this means that
 *   poll returns almost immediately. And that results in a huge
 *   performance drop because of all the dummy (directly returning) poll
 *   calls.
 *
 *   By sleeping for half a second, we allow the buffer to fill up
 *   before we start looking at the results. If you ensure that the
 *   buffer is sufficiently large, this causes no trouble.
 *
 * Compile:
 *   gcc -D_GNU_SOURCE -fPIC -ldl -shared -o libslowpoll.so slowpoll.c
 * Usage:
 *   LD_PRELOAD=./libslowpoll.so app-to-run
 * or:
 *   gcc app-to-link.o -lslowpoll -lpcap -o app-to-link
 */

#include <dlfcn.h>
#include <poll.h>
#include <unistd.h>


static int (*real_poll)(struct pollfd *, nfds_t, int);

__attribute__((constructor)) void init() {
    real_poll = dlsym(RTLD_NEXT, "poll");
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    usleep(500000);
    return real_poll(fds, nfds, timeout);
}
