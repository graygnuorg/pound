# Pound - the reverse-proxy load-balancer                -*- automake -*-
# Copyright (C) 2002-2010 Apsis GmbH
# Copyright (C) 2018-2022 Sergey Poznyakoff
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
SUBDIRS = . tests

AM_CFLAGS = @PTHREAD_CFLAGS@

AM_CPPFLAGS = @SSL_CPPFLAGS@ \
 -DSYSCONFDIR=\"$(sysconfdir)\"\
 -DLOCALSTATEDIR=\"$(localstatedir)\"
AM_LDFLAGS  = @SSL_LDFLAGS@
LDADD=@PTHREAD_LIBS@

sbin_PROGRAMS=pound
pound_SOURCES=\
 config.c\
 http.c\
 pound.c\
 svc.c

install-exec-hook:
	-@if test "$${EUID:-65535}" -eq 0; then \
		for program in $(sbin_PROGRAMS); do \
			chown @I_OWNER@:@I_GRP@ $(DESTDIR)$(sbindir)/$$program$(EXEEXT); \
		done; \
		for program in $(bin_PROGRAMS); do \
			chown @I_OWNER@:@I_GRP@ $(DESTDIR)$(bindir)/$$program$(EXEEXT); \
		done; \
	fi

noinst_HEADERS=pound.h config.h

if OPENSSL_V3
DHSRC =
else
noinst_HEADERS += dh.h
DHSRC = dh512.h dh@DH_LEN@.h

dh512.h:
	openssl dhparam -5 -C -noout 512 > dh512.h

dh@DH_LEN@.h:
	openssl dhparam -5 -C -noout @DH_LEN@ > dh@DH_LEN@.h

dh.h: $(DHSRC)
	cat $(DHSRC) > dh.h

BUILT_SOURCES=dh.h $(DHSRC)
DISTCLEANFILES=dh.h dh512.h dh1024.h dh2048.h
endif

bin_PROGRAMS=poundctl
poundctl_SOURCES=poundctl.c

dist_man_MANS=pound.8 poundctl.8

EXTRA_DIST = COPYING ChangeLog ChangeLog.apsis README.md AUTHORS THANKS

.PHONY: ChangeLog
ChangeLog:
	$(AM_V_GEN)if test -d .git; then                                    \
	   (git log --pretty='format:%ad  %cn  <%ae>%n%n%w(72,8,8)%s%n%n%b' \
                    --date=short;                                           \
            echo "";                                                        \
            echo "Local Variables:";                                        \
            echo "mode: change-log";                                        \
            echo "version-control: never";                                  \
            echo "buffer-read-only: t";                                     \
            echo "End:";                                                    \
            echo "";                                                        \
            sed -n -e '2,/^$$/s/^##//p' Makefile.am) > ChangeLog;           \
	fi
