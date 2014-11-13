rtpsniff
========

* This is an adapted version of lightcount, altered to sniff RTP
  traffic and show which streams have packet loss.
  URL: https://code.osso.nl/projects/lightcount

* It segfaults right now, so it's not ready for production use.
  We should probably alter how the memory switching is done.
  (Shared volatile pointer to "current" memory? Or, as a last
  resort locking.)
