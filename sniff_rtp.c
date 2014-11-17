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
#include "endian.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netpacket/packet.h> /* linux-specific: struct_ll and PF_PACKET */

/* Static constants (also found in linux/if_ether.h) */
#if BYTE_ORDER == LITTLE_ENDIAN
# define ETH_P_ALL 0x0300   /* all frames */
# define ETH_P_IP 0x0008    /* IP frames */
# define ETH_P_8021Q 0x0081 /* 802.1q vlan frames */
#elif BYTE_ORDER == BIG_ENDIAN
# define ETH_P_ALL 0x0003   /* all frames */
# define ETH_P_IP 0x0800    /* IP frames */
# define ETH_P_8021Q 0x8100 /* 802.1q vlan frames */
#endif


/* Ethernet header */
struct sniff_ether {
    uint8_t dest[6];	    /* destination host address */
    uint8_t source[6];	    /* source host address */
    uint16_t type;	    /* ETH_P_* type */
    uint16_t pcp_cfi_vid;   /* 3bit prio, 1bit format indic, 12bit vlan (0=no, fff=reserved) */
    uint16_t type2;	    /* encapsulated type */
};

/* IP header */
struct sniff_ip {
    /* Take care, place the bitmasks in high order first. */
    uint8_t hl:4,	    /* header length */
	    ver:4;	    /* version */
    uint8_t  tos;	    /* type of service */
    uint16_t len;	    /* total length */
    uint16_t id;	    /* identification */
    uint16_t off;	    /* fragment offset field */
#define IP_RF 0x8000	    /* reserved fragment flag */
#define IP_DF 0x4000	    /* dont fragment flag */
#define IP_MF 0x2000	    /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    uint8_t  ttl;	    /* time to live */
    uint8_t  proto;	    /* protocol */
    uint16_t sum;	    /* checksum */
    uint32_t src;	    /* source address */
    uint32_t dst;	    /* dest address */
};

#define PROTO_TCP 6
#define PROTO_UDP 17

/* UDP header */
struct sniff_udp {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t sum;
};

/* RTP header */
struct sniff_rtp {
    /* Take care, place the bitmasks in high order first. */
    uint8_t cc:4,
	    x:1,
	    p:1,
	    ver:2;
    uint8_t pt:7,
	    m:1;
    uint16_t seq;
    uint32_t stamp;
    uint32_t ssrc;
    /* ... */
};

#define PT_ULAW 0
#define PT_ALAW 8

//static struct rtpstat_t **sniff__memory[2]; /* two locations to store counts in */
//static struct rtpstat_t **sniff__memp;	    /* the "current" memory location */
static struct memory_t *sniff__memory;
static pcap_t *sniff__handle;


static void sniff__switch_memory(int signum);
static void sniff__loop_done(int signum);


void sniff_help() {
    printf(
	"/********************* module: sniff (packet_socket) **************************/\n"
	"Sniff uses a packet socket to listen for all inbound and outbound packets.\n"
	"Specify the interface name as IFACE or 'any' if you want to listen on all\n"
	"interfaces.\n"
	"\n"
#if 0 /* FIXME */
	"Internally, we listen on the ETH_P_ALL SOCK_RAW protocol for packets with\n"
	"an ETH_P_IP or ETH_P_8021Q ethernet type. (In 802.1q packets we examine only\n"
	"IP packets. Double tagged packets are ignored.) The packet count, length\n"
	"(including ethernet frame) and destination is recorded.\n"
	"\n"
	"Note one: packets from localhost to localhost are seen twice. We seem them\n"
	"once outbound and once inbound. And, as both source and destination is\n"
	"counted, you should expect a multiplication of four. You should expect a\n"
	"similar multiplication on machines doing NAT.\n"
	"\n"
	"Note two: if you want to see VLANs, your kernel must not process them. The\n"
	"Linux kernels on which this is tested use something called hardware VLAN\n"
	"acceleration. This mangles the ethernet frames to look like regular IP\n"
	"containing frames. Unload the 8021q module to be sure.\n"
	"\n"
	"Note three: if you want to capture packets not intended for your host -- a\n"
	"common setup is to mirror all traffic to a host that only runs the lightcount\n"
	"daemon -- you need to manually set the interfaces in promiscuous mode.\n"
	"\n"
#endif
    );
}

static void sniff_got_packet(u_char *args, const struct pcap_pkthdr *header,
		        const u_char *packet) {
    struct sniff_ether *ether = (struct sniff_ether*)packet;
    struct sniff_ip *ip;
    struct sniff_udp *udp;
    uint16_t sport;
    uint16_t dport;
    struct sniff_rtp *rtp;
    
    if (ether->type == ETH_P_IP) {
	ip = (struct sniff_ip*)(packet + 14);
    } else if (ether->type == ETH_P_8021Q && ether->type2 == ETH_P_IP) {
	ip = (struct sniff_ip*)(packet + 18);
    } else {
	/* Skip. */
	return;
    }

    if (ip->proto != PROTO_UDP) {
	return;
    }

    udp = (struct sniff_udp*)(ip + 1);
    sport = htons(udp->sport);
    dport = htons(udp->dport);
    rtp = (struct sniff_rtp*)(udp + 1);
	
    if (ntohs(udp->len) < sizeof(struct sniff_rtp)) {
	return;
    }
    if (rtp->ver != 2) {
	return;
    }

    {
	int recently_active = sniff__memory->active;
	struct rtpstat_t *curmem = sniff__memory->rtphash[recently_active];
	uint16_t seq = ntohs(rtp->seq);
	struct rtpstat_t find = {
	    .src_ip = ntohl(ip->src),
	    .dst_ip = ntohl(ip->dst),
	    .src_port = sport,
	    .dst_port = dport,
	    /* ignore: tlen, vlan */
	    .ssrc = ntohl(rtp->ssrc),
	    /* the rest: zero */
	};
	struct rtpstat_t *old;

#if 0
	fprintf(stderr, "len: %hhu, %hhu, %hhu, %hhu, %hhu, %hhu\n",
		rtp->ver, rtp->p, rtp->x, rtp->cc, rtp->m, rtp->pt);
#endif

	HASH_FIND(hh, curmem, &find.HASH_FIRST, HASH_SIZE(find), old);
	if (!old) {
	    struct rtpstat_t *rtpstat = malloc(sizeof(*rtpstat));
	    if (rtpstat) {
		memcpy(rtpstat, &find, sizeof(*rtpstat));
		/* ignore: rtp->stamp */
		rtpstat->seq = seq;
		rtpstat->packets = 1;
	    
		HASH_ADD(hh, curmem, HASH_FIRST, HASH_SIZE(*rtpstat), rtpstat);
	    }
	} else {
	    if (old->seq + 1 == seq) {
		/* Excellent! */
	    } else {
		int16_t diff = seq - old->seq;
		if (diff < -15 || 15 < diff) {
		    old->jumps += 1;
		} else if (diff > 0) {
		    old->missed += 1;
		    old->misssize += (diff - 1);
		} else {
		    old->late += 1;
		}
	    }
	    old->packets += 1;
	    old->seq = seq;
	}

	/* HASH_ADD may have mutated the pointer. */
	sniff__memory->rtphash[recently_active] = curmem;
    }
}

int sniff_snaplen() {
    return (sizeof(struct sniff_ether) +
	    sizeof(struct sniff_ip) +
	    sizeof(struct sniff_udp) +
	    sizeof(struct sniff_rtp));
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
	    memory->rtphash[0], memory->rtphash[1], memory->active);
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

    //fprintf(stderr, "%u packets captured\n", packets_captured);
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
	    recently_active, sniff__memory->rtphash[recently_active],
	    !recently_active, sniff__memory->rtphash[!recently_active]);
#endif
}

static void sniff__loop_done(int signum) {
    pcap_breakloop(sniff__handle);
}
