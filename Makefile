# vim:ts=8:noet
#
# Makefile for rtpsniff.
# By Walter Doekes, 2009,2014.

ifeq ($(CFLAGS),)
    CFLAGS = -Wall
endif
ifeq ($(LDFLAGS),)
    # -lslowpoll goes first
    LDFLAGS = -Wall -L./bin
endif
ifeq ($(LDLIBS),)
    LDLIBS = -lslowpoll -lpthread -lpcap
endif
ifeq ($(PREFIX),)
    PREFIX = /usr/local
endif


.PHONY: all clean distclean variables \
	rtpsniff rtpsniff-debug \
	losssniff losssniff-debug

all: rtpsniff rtpsniff-debug losssniff losssniff-debug

clean:
	$(RM) -r bin

distclean: clean

variables:
	@if test -z "$(MOD_OUT)"; then \
	    echo 'Please select output module through MOD_OUT:' >&2; \
	    echo '  make MOD_OUT=console  # for console output' >&2; \
	    echo '  #make MOD_OUT=syslog  # for syslog output' >&2; \
	    false; fi

rtpsniff: variables
	APPNAME="$@" CPPFLAGS="$(CPPFLAGS) -DNDEBUG" \
	CFLAGS="$(CFLAGS) -g -O3" LDFLAGS="$(LDFLAGS) -g -O3" \
	MODULES="anysniff sniff_rtp sniff_rtp_$(MOD_OUT) timer_interval util" \
	$(MAKE) bin/$@
	@#strip bin/$@

rtpsniff-debug: variables
	APPNAME="$@" CPPFLAGS="$(CPPFLAGS)" \
	CFLAGS="$(CFLAGS) -g -O0" LDFLAGS="$(LDFLAGS) -g" \
	MODULES="anysniff sniff_rtp sniff_rtp_$(MOD_OUT) timer_interval util" \
	$(MAKE) bin/$@

losssniff: variables
	APPNAME="$@" CPPFLAGS="$(CPPFLAGS) -DNDEBUG" \
	CFLAGS="$(CFLAGS) -g -O3" LDFLAGS="$(LDFLAGS) -g -O3" \
	MODULES="anysniff sniff_loss sniff_loss_$(MOD_OUT) timer_interval util" \
	$(MAKE) bin/$@
	@#strip bin/$@

losssniff-debug: variables
	APPNAME="$@" CPPFLAGS="$(CPPFLAGS)" \
	CFLAGS="$(CFLAGS) -g -O0" LDFLAGS="$(LDFLAGS) -g" \
	MODULES="anysniff sniff_loss sniff_loss_$(MOD_OUT) timer_interval util" \
	$(MAKE) bin/$@


.PHONY: install uninstall

install: bin/losssniff bin/rtpsniff bin/libslowpoll.so
	install -DT -m 644 bin/libslowpoll.so $(PREFIX)/lib/libslowpoll.so
	install -DT -m 755 bin/rtpsniff $(PREFIX)/sbin/rtpsniff
	install -DT -m 755 bin/losssniff $(PREFIX)/sbin/losssniff
	-ldconfig
uninstall:
	$(RM) $(PREFIX)/lib/libslowpoll.so \
		$(PREFIX)/sbin/losssniff
		$(PREFIX)/sbin/rtpsniff
	-ldconfig


$(addprefix bin/.$(APPNAME)/, $(addsuffix .o, $(MODULES))): \
	  Makefile endian.h anysniff.h sniff_loss.h sniff_rtp.h

bin/libslowpoll.so: slowpoll.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -D_GNU_SOURCE -fPIC -ldl -shared -o $@ $<

bin/.$(APPNAME)/%.o: %.c
	@mkdir -p $(dir $@)
	$(COMPILE.c) $< -o $@
bin/$(APPNAME): bin/libslowpoll.so $(addprefix bin/.$(APPNAME)/, $(addsuffix .o, $(MODULES)))
	$(LINK.o) -L./bin $(filter-out bin/libslowpoll.so, $^) $(LDLIBS) -o $@
