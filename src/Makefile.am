# Pound - the reverse-proxy load-balancer
# Copyright (C) 2002-2010 Apsis GmbH
# Copyright (C) 2018-2026 Sergey Poznyakoff
#
# Pound is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# Pound is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pound.  If not, see <http://www.gnu.org/licenses/>.

AM_CFLAGS = @PTHREAD_CFLAGS@

AM_CPPFLAGS = @SSL_CPPFLAGS@ @LUA_CFLAGS@ @PCRE_CFLAGS@ \
 -DSYSCONFDIR=\"$(sysconfdir)\"\
 -DLOCALSTATEDIR=\"$(localstatedir)\"\
 -DPKGDATADIR=\"$(pkgdatadir)\"
AM_LDFLAGS  = @SSL_LDFLAGS@
LDADD = libpound.a @LUA_LIBS@ @PCRE_LIBS@ @PTHREAD_LIBS@

sbin_PROGRAMS=pound
pound_SOURCES=\
 bauth.c\
 config.c\
 genpat.c\
 http.c\
 log.c\
 metrics.c\
 pound.c\
 svc.c\
 tbf.c\
 watcher.c

if COND_PCRE
  pound_SOURCES += regex_pcre.c
endif
if COND_PCRE2
  pound_SOURCES += regex_pcre2.c
endif
if COND_DYNAMIC_BACKENDS
  pound_SOURCES += resolver.c dynbe.c
endif
if COND_LUA
  pound_SOURCES += pndlua.c
endif

if COND_INOTIFY
  pound_SOURCES += fsevmon.c watcher/inotify.c
  AM_CPPFLAGS += -DWITH_INOTIFY=1
else
if  COND_KQUEUE
  pound_SOURCES += fsevmon.c watcher/kqueue.c
  AM_CPPFLAGS += -DWITH_KQUEUE=1
else
  pound_SOURCES += watcher/periodic.c
endif
endif

noinst_LIBRARIES = libpound.a
libpound_a_SOURCES = \
 capbio.c\
 capbio.h\
 cctype.c\
 cctype.h\
 cfg-gram.c\
 cfg-lex.c\
 cfgdef.c\
 cfgdef.h\
 closefrom.c\
 json.c\
 json.h\
 mem.c\
 mem.h\
 nullsink.c\
 progname.c

pkgdata_DATA = poundctl.tmpl mvh.inc

BUILT_SOURCES = cfg-lex.c cfg-gram.c cfg-gram.h
EXTRA_DIST = $(pkgdata_DATA) pound-mode.el cfg-lex.l cfg-gram.y

cfg-gram.h: cfg-gram.c
cfg-lex.o: cfg-lex.c cfg-gram.h

noinst_HEADERS=pound.h extern.h list.h ht.h resolver.h watcher.h cfg-gram.h

bin_PROGRAMS=poundctl
poundctl_SOURCES=poundctl.c tmpl.c
poundctl_LDFLAGS=-lm

AM_YFLAGS=-dtv
AM_LFLAGS=-d

.l.c:
	$(FLEX) -o $@ $(AM_LFLAGS) $<
.y.c:
	$(BISON) -o $@ $(AM_YFLAGS) $<
