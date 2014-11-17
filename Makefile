# vim:ts=8:noet
#
# Makefile for rtpsniff.
# By Walter Doekes, 2009,2014.

ifeq ($(CFLAGS),)
    CFLAGS = -Wall
endif
ifeq ($(LDFLAGS),)
    # -lslowpoll goes first
    LDFLAGS = -Wall -L./bin -lslowpoll -lpthread -lpcap
endif

.PHONY: all clean \
	rtpsniff rtpsniff-nodebug rtpsniff-verbose

all: rtpsniff rtpsniff-nodebug rtpsniff-verbose bin/libslowpoll.so

clean:
	@rm -r bin

rtpsniff:
	APPNAME="$@" CPPFLAGS="$(CPPFLAGS)" \
	CFLAGS="$(CFLAGS) -g -O3" LDFLAGS="$(LDFLAGS) -g" \
	MODULES="rtpsniff sniff_rtp storage_console timer_interval util" \
	$(MAKE) bin/$@

rtpsniff-nodebug:
	APPNAME="$@" CPPFLAGS="$(CPPFLAGS) -DNDEBUG" \
	CFLAGS="$(CFLAGS) -O3" LDFLAGS="$(LDFLAGS) -O3" \
	MODULES="rtpsniff sniff_rtp storage_console timer_interval util" \
	$(MAKE) bin/$@
	@strip bin/$@

rtpsniff-verbose:
	APPNAME="$@" CPPFLAGS="$(CPPFLAGS) -DDEBUG -DPRINT_EVERY_PACKET" \
	CFLAGS="$(CFLAGS) -g -O0" LDFLAGS="$(LDFLAGS) -g" \
	MODULES="rtpsniff sniff_rtp storage_console timer_interval util" \
	$(MAKE) bin/$@

bin/libslowpoll.so: slowpoll.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -fPIC -ldl -shared -o $@ $<


.PHONY: install uninstall

install: bin/rtpsniff bin/libslowpoll.so
	install -o root -m 644 bin/libslowpoll.so /usr/local/lib/
	ldconfig
	install -o root -m 755 bin/rtpsniff /usr/local/bin/
uninstall:
	$(RM) /usr/local/lib/libslowpoll.so /usr/local/bin/rtpsniff
	ldconfig


$(addprefix bin/.$(APPNAME)/, $(addsuffix .o, $(MODULES))): Makefile endian.h rtpsniff.h

bin/.$(APPNAME)/%.o: %.c
	@mkdir -p $(dir $@)
	$(COMPILE.c) $< -o $@
bin/$(APPNAME): $(addprefix bin/.$(APPNAME)/, $(addsuffix .o, $(MODULES)))
	@if false && ! ldconfig -p | grep -q libslowpoll; then \
	    printf "***\nYou must 'make install_slowpoll' first\n****\n" >&2; \
	    false; \
	fi
	$(LINK.o) -L./bin $^ -o $@
