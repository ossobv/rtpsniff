#ifndef INCLUDED_RTPSNIFF_H
#define INCLUDED_RTPSNIFF_H
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
#include "uthash.h"
#include <inttypes.h>
#include <pcap.h>
#include <sys/types.h>


/*----------------------------------------------------------------------------*
 | Program: rtpsniff                                                          |
 |                                                                            |
 | The program is divided in a couple of modules that could be replaced by    |
 | different implementations. These modules must implement the functions      |
 | listed below. For every module a remark is made about which other module   |
 | functions it calls.                                                        |
 |                                                                            |
 | The `*_help` functions provide implementation specific information.        |
 | Everything is assumed to be single-threaded and non-reentrant, except for  |
 | the timer that uses a thread to call `out_write` at a specified        |
 | interval.                                                                  |
 *----------------------------------------------------------------------------*/

struct rtpstat_t;

struct memory_t {
    /* Use two memory buffers. */
    struct rtpstat_t *rtphash[2];
    /* Of which the Nth is active (written to). */
    volatile int active;
    /* After a signal, a switch is requested. */
    volatile int request_switch;
};
    
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
    

/*----------------------------------------------------------------------------*
 | Module: rtpsniff                                                           |
 |                                                                            |
 | Does the user interface.                                                   |
 |                                                                            |
 | Calls: any of the functions listed here (from the main thread)             |
 *----------------------------------------------------------------------------*/
void rtpsniff_help(); /* show help */


/*----------------------------------------------------------------------------*
 | Module: sniff                                                              |
 |                                                                            |
 | Does the sniffing of the ethernet packets. As `sniff_loop` is the main     |
 | (foreground) loop, it listens for the quit signals: HUP, INT, TERM and     |
 | QUIT.                                                                      |
 |                                                                            |
 | Calls: (nothing.. manually adds to the memory)                             |
 *----------------------------------------------------------------------------*/
void sniff_help(); /* show info */
int sniff_snaplen();
void sniff_loop(pcap_t *handle, struct memory_t *memory);
void sniff_release(struct rtpstat_t **memory);


/*----------------------------------------------------------------------------*
 | Module: storage                                                            |
 |                                                                            |
 | Stores the packet/byte count averages. You must call `out_open` and    |
 | `out_close` while single-threaded. A config file name must be passed   |
 | to `out_open` that can be used to read settings like (1) which IP      |
 | addresses to store/ignore or (2) to which database to connect.             |
 |                                                                            |
 | Calls: (nothing)                                                           |
 *----------------------------------------------------------------------------*/
void out_help();
int out_open(char const *config_file);
void out_close();
void out_write(uint32_t unixtime_begin, uint32_t interval, struct rtpstat_t *rtphash);


/*----------------------------------------------------------------------------*
 | Module: timer                                                              |
 |                                                                            |
 | Runs a thread that wakes up every interval. When waking up, it raises      |
 | SIGUSR1 to signal `sniff_loop` to begin writing to a different buffer so   |
 | it can safely give the current buffer to `out_write` for processing.   |
 |                                                                            |
 | Calls: `out_write` (from a thread)                                     |
 *----------------------------------------------------------------------------*/
void timer_help();
int timer_loop_bg(struct memory_t *memory);
void timer_loop_stop();


/*----------------------------------------------------------------------------*
 | Utility functions that are not module specific.                            |
 *----------------------------------------------------------------------------*/
int util_signal_set(int signum, void (*handler)(int));
#if !(_BSD_SOURCE || _XOPEN_SOURCE >= 500)
int usleep(unsigned usecs);
#endif /* !(_BSD_SOURCE || _XOPEN_SOURCE >= 500) */

#endif /* INCLUDED_RTPSNIFF_H */
