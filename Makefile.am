CC=@PTHREAD_CC@
AM_CFLAGS=\
 -DF_CONF=\"@sysconfdir@/pound.cfg\"\
 -DVERSION=\"@PACKAGE_VERSION@\"\
 -DC_SSL=\"@C_SSL@\"\
 -DC_T_RSA=\"@C_T_RSA@\"\
 -DC_DH_LEN=\"@C_DH_LEN@\"\
 -DC_MAXBUF=\"@C_MAXBUF@\"\
 -DC_OWNER=\"@C_OWNER@\"\
 -DC_GROUP=\"@C_GROUP@\"\
 -DC_SUPER=\"@C_SUPER@\"\
 -DC_CERT1L=\"@C_CERT1L@\"\
 @CFLAGS@ @PTHREAD_CFLAGS@ @CPPFLAGS@

LIBS=@LIBS@ @PTHREAD_LIBS@

sbin_PROGRAMS=pound
pound_SOURCES=\
 config.c\
 http.c\
 pound.c\
 svc.c

INSTALL_PROGRAM = ${INSTALL} -o @I_OWNER@ -g @I_GRP@ -m 555

noinst_HEADERS=pound.h config.h dh.h

dh.h: 
	(openssl dhparam -5 -C -noout 512; \
	 openssl dhparam -5 -C -noout @C_DH_LEN@) > dh.h

bin_PROGRAMS=poundctl
poundctl_SOURCES=poundctl.c

BUILT_SOURCES=dh.h

dist_man_MANS=pound.8 poundctl.8
