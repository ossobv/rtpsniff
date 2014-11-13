# vim:ts=8:noet
#
# Makefile for rtpsniff.
# By Walter Doekes, 2009,2014.

ifeq ($(CFLAGS),)
    CFLAGS = -Wall
endif
ifeq ($(LDFLAGS),)
    LDFLAGS = -Wall -lpthread
endif

.PHONY: all clean \
	rtpsniff rtpsniff-nodebug rtpsniff-verbose

all: rtpsniff rtpsniff-nodebug rtpsniff-verbose

clean:
	@rm -r bin

rtpsniff:
	APPNAME="$@" CPPFLAGS="$(CPPFLAGS)" \
	CFLAGS="$(CFLAGS) -g -O3" LDFLAGS="$(LDFLAGS) -g" \
	MODULES="rtpsniff sniff_packsock storage_console timer_interval util" \
	$(MAKE) bin/$@

rtpsniff-nodebug:
	APPNAME="$@" CPPFLAGS="$(CPPFLAGS) -DNDEBUG" \
	CFLAGS="$(CFLAGS) -O3" LDFLAGS="$(LDFLAGS) -O3" \
	MODULES="rtpsniff sniff_packsock storage_console timer_interval util" \
	$(MAKE) bin/$@
	@strip bin/$@

rtpsniff-verbose:
	APPNAME="$@" CPPFLAGS="$(CPPFLAGS) -DDEBUG -DPRINT_EVERY_PACKET" \
	CFLAGS="$(CFLAGS) -g -O0" LDFLAGS="$(LDFLAGS) -g" \
	MODULES="rtpsniff sniff_packsock storage_console timer_interval util" \
	$(MAKE) bin/$@


$(addprefix bin/.$(APPNAME)/, $(addsuffix .o, $(MODULES))): Makefile endian.h rtpsniff.h
bin/.$(APPNAME)/%.o: %.c
	@mkdir -p $(dir $@)
	$(COMPILE.c) $< -o $@
bin/$(APPNAME): $(addprefix bin/.$(APPNAME)/, $(addsuffix .o, $(MODULES)))
	$(LINK.o) $^ -o $@
