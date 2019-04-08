RTPSniff
========

RTPSniff is a tool to sniff RTP traffic and show stats about it.

(I'm considering renaming `rtpsniff` to `rtpstat` -- like `vmstat` --
since it prints a status update every N seconds.)


TODO
----

* Add example zabbix template.

* Add logging to `/var/run` instead of syslog. That helps zabbix.
  (Don't forget to include options to set the user and the file permissions.)

* Also log the unixtime and interval. If needed, the zabbix reader can then
  divide by interval to get packets/second. And zabbix can check if the unixtime
  is recent enough to consider this value.

* Allow output of either all streams or only those "with issues".

* Change the interface:
  * `rtpsniff 10` should show the summary every 10 seconds, like
    `vmstat`.
  * `-v` should make things verbose.
  * `-i` for the interface (take eth0 by default).
  * `-B` for buffer size? or `-P` for packets per second?
  * `-b` for bpf filter? or `-p` for pcap-style filter?
    and default to udp and not 53? add example for filtering even
    ports only?
    `udp and not port 53 and (udp[1] & 1 = 0) and (udp[3] & 1 = 0)`
  * Take into account that we may want to dump the contents.

* Decide the best form of output. Allow sequence reordering as long as
  it's within reasonable limits.

* Output requirements are:
  * Fix that all packets are counted, not just the seen ones, so a percentage
    more accurately reflects loss.

  * Always show the total packets next to the percentage. Because only a
    percentage is misleading when there are only a few streams.

  * A total of the RTP loss/badness; preferably a percentage.

  * List of streams with issues.

  * Current output looks like this:

            RTP: 21x.17x.21x.18x:5014 > 19x.3x.11x.10x:17886, \
              ssrc: 4022267390, packets: 43, seq: 47, lost: 5, \
              graps: 5, late: 0, jump: 0
            RTP: 19x.3x.11x.10x:14136 > 21x.17x.21x.18x:5012, \
              ssrc: 4022267390, packets: 39, seq: 47, lost: 4, \
              graps: 4, late: 0, jump: 0
            RTP-SUM: streams 1097, not-lost 214039, lost 69 (0.03%), \
              late 140 (0.07%)

  * For starters, the individual streams should get a loss counter.

* Move libpcap stuff out of rtpsniff.c and into sniff\_pcap.c.

* Move rtp stuff out of sniff\_rtp.c into cap\_rtp.c.

* Document/note that timestamps are not used, only sequence numbers.

* Document/note that the streams also include RTCP.

* Features:
  * Parse RTCP from the wire and print that.

  * Create a "jitter/reorder"-buffer to store sequence numbers:
 
            100: [UUUUUUUUU] (91..99)
            104: [UUUUUx...] (95..103)
            102: [UUUUUx.x.] (95..103)

    That way we could count dupes and properly check reordering.
    (Store as 2bitfield? `00=unknown, 11=set, 01=skipped?
    init=0, increment: val=(val<<2)|3, skip: val=(val<<2)|1
    oldmask=(val<<(2*seqdiff))&0x3`)


Docs
----
  
* This is an adapted version of lightcount, altered to sniff RTP
  traffic and show which streams have packet loss.
  URL: https://code.osso.nl/projects/lightcount

* Simulating packet loss from the gateway:

        # 45% drop should be sufficient to get a nice robotic sound.
        iptables -I FORWARD -d SOME_IP -p udp \
          -m statistic --mode random --probability 0.45 -j DROP
