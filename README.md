rtpsniff
========

* This is an adapted version of lightcount, altered to sniff RTP
  traffic and show which streams have packet loss.
  URL: https://code.osso.nl/projects/lightcount

* Note that the streams also include RTCP.

* Right now the tool eats very much CPU. This is most likely caused
  by all the recvfrom. We should fix this by using PACKET\_RX\_RING
  like tcpdump does.
