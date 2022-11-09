# Pound - the reverse-proxy load-balancer                -*- autoconf -*-
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
# along with this pound.  If not, see <http://www.gnu.org/licenses/>.
AC_PREREQ([2.69])
AC_INIT([pound],[2.8-gray],[gray+pound@gnu.org.ua],[pound],[https://github.com/graygnuorg/pound])
AC_CONFIG_SRCDIR([pound.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([1.11 foreign tar-ustar])

# Checks for programs.
AC_PROG_CC
dnl AC_PROG_RANLIB

# Checks for libraries.
AC_MSG_NOTICE([*** Checking for threads library and/or flags ***])

AX_PTHREAD([CC="$PTHREAD_CC"],
           [AC_MSG_ERROR([No suitable pthread library found])])

AC_SUBST(SSL_CPPFLAGS)
AC_SUBST(SSL_LDFLAGS)
AC_ARG_WITH([ssl],
 AS_HELP_STRING([--with-ssl=directory],[location of OpenSSL package]),
 [SSL_CPPFLAGS="-I${withval}/include"
  SSL_LDFLAGS="-L${withval}/lib ${LDFLAGS}"
  C_SSL="${withval}"],
 [C_SSL=""])

saved_CPPFLAGS=$CFLAGS
CPPFLAGS=$SSL_CPPFLAGS
saved_LDFLAGS=$LDFLAGS
LDFLAGS=$SSL_LDFLAGS
AC_MSG_CHECKING([for OpenSSL version 3])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([#include <openssl/opensslv.h>],
 [#if OPENSSL_VERSION_MAJOR >= 3
#error "OpenSSL v3"
#endif
])],[openssl_v3=no],[openssl_v3=yes])
AC_MSG_RESULT([$openssl_v3])
CPPFLAGS=$saved_CPPFLAGS
LDFLAGS=$saved_LDFLAGS
AM_CONDITIONAL([OPENSSL_V3],[test "$openssl_v3" = "yes"])

AC_ARG_WITH([t_rsa],
 AS_HELP_STRING([--with-t_rsa=nnn],[Timeout for RSA ephemeral keys generation]),
 [T_RSA_KEYS=${withval}],
 [T_RSA_KEYS=7200])

AC_DEFINE_UNQUOTED([T_RSA_KEYS],[$T_RSA_KEYS],
 [Timeout for RSA ephemeral keys generation])

AC_ARG_WITH([dh],
 AS_HELP_STRING([--with-dh=nnn],[DH key length parameter (default: 2048, can set to 1024)]),
 [case ${withval} in
  1024|2048) DH_LEN=${withval};;
  *) AC_MSG_FAILURE([invalid value for DH key length])
  esac],
 [DH_LEN=2048])

AC_SUBST(DH_LEN) 
AC_DEFINE_UNQUOTED([DH_LEN],[$DH_LEN],
 [DH key length])

AC_ARG_WITH([maxbuf],
 AS_HELP_STRING([--with-maxbuf=nnn],[Value of the MAXBUF parameter (default: 4096)]),
 [MAXBUF=${withval}],
 [MAXBUF=4096])

AC_DEFINE_UNQUOTED([MAXBUF],[$MAXBUF],
 [Max. buffer size])
 
AC_SUBST(I_OWNER)
AC_ARG_WITH([owner],
 AS_HELP_STRING([--with-owner=name],[The account that will own the files installed by Pound]),
 [I_OWNER="${with_owner}"; C_OWNER="${with_owner}"],
 [C_OWNER=""])

AC_SUBST(I_GRP)
AC_ARG_WITH([group],
 AS_HELP_STRING([--with-group=name],[The group that will own the files installed by Pound]),
 [I_GRP="${with_group}"; C_GROUP="${with_group}"],
 [C_GROUP=""])

AC_ARG_ENABLE([super], 
 AS_HELP_STRING([--enable-super],[enable or disable running with supervisor process (default: enabled)]),
 [if test ${enableval} = "yes"; then
    SUPERVISOR=1
  else
    SUPERVISOR=0
  fi],
 [SUPERVISOR=1])

AC_DEFINE_UNQUOTED([SUPERVISOR],[$SUPERVISOR],
 [Run supervisor process])
 
AC_ARG_ENABLE([pcreposix],
 AS_HELP_STRING([--enable-pcreposix],[enable or disable using the pcreposix library (default: enabled if available)]),
 [C_PCREPOSIX=${enableval}],
 [C_PCREPOSIX=yes])

AC_ARG_ENABLE([tcmalloc],
 AS_HELP_STRING([--enable-tcmalloc],[enable or disable using the tcmalloc library (default: enabled if available)]),
 [C_TCMALLOC=${enableval}],
 [C_TCMALLOC=yes])

AC_ARG_ENABLE([hoard],
 AS_HELP_STRING([--enable-hoard],[enable or disable using the hoard library (default: enabled if available and tcmalloc NOT available)]),
 [C_HOARD=${enableval}],
 [C_HOARD=yes])


AC_MSG_NOTICE([*** Checking for libraries ***])
AC_CHECK_LIB([dl],[dlopen])
AC_CHECK_LIB([socket],[socket],[LIBS="-lsocket -lnsl ${LIBS}"])
AC_CHECK_LIB([resolv],[hstrerror],[LIBS="-lresolv ${LIBS}"])
AC_CHECK_LIB([crypto],[BIO_new],
             [LIBS="-lcrypto ${LIBS}"],
	     [AC_MSG_FAILURE([Missing OpenSSL (-lcrypto) - aborted],[1])])
AC_CHECK_LIB([ssl],[SSL_CTX_new],
             [LIBS="-lssl ${LIBS}"],
	     [AC_MSG_FAILURE([Missing OpenSSL (-lssl) - aborted])])
if test x"$C_PCREPOSIX" = xyes; then
  AC_CHECK_LIB([pcreposix],[regcomp],[],
    [save_LIBS="$LIBS"
     LIBS="-lpcre $LIBS"
     AC_CHECK_LIB([pcreposix],[regexec],
       [LIBS="-lpcreposix -lpcre $save_LIBS"
        AC_DEFINE([HAVE_LIBPCREPOSIX],[1],[])],
       [LIBS="$save_LIBS"])])
fi

if test x"$C_TCMALLOC" = xyes; then
  AC_CHECK_LIB([tcmalloc],[malloc],
    [LIBS="${LIBS} -ltcmalloc"])
elif test x"$C_HOARD" = xyes; then
  AC_CHECK_LIB([hoard],[malloc],
    [LIBS="${LIBS} -lhoard"])
fi    

AC_MSG_CHECKING([for pthread_attr_setstacksize in LIBS=$LIBS with CFLAGS=$CFLAGS"])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[char pthread_attr_setstacksize ();]], [[return pthread_attr_setstacksize ();]])],[CFLAGS="${CFLAGS} -DNEED_STACK"],[]);
AC_MSG_RESULT([OK]);

AC_MSG_NOTICE([*** Checking for header files ***])

AC_CHECK_HEADERS([arpa/inet.h errno.h netdb.h netinet/in.h netinet/tcp.h sys/socket.h sys/un.h sys/time.h unistd.h getopt.h pthread.h sys/types.h sys/poll.h openssl/ssl.h openssl/engine.h pwd.h grp.h signal.h regex.h ctype.h wait.h sys/wait.h sys/stat.h sys/syslog.h syslog.h fcntl.h pcreposix.h pcre/pcreposix.h fnmatch.h])

AC_MSG_NOTICE([*** Checking for additonal information ***])

save_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -DSYSLOG_NAMES=1"
AC_MSG_CHECKING([for facilitynames presence])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <stdio.h>
             #include <syslog.h>
            ]], [[void *attr=(void *)facilitynames;]])],[ok=yes],[ok=no])
if test x"$ok" = xyes; then
  AC_MSG_RESULT([yes])
  AC_DEFINE([HAVE_FACILITYNAMES],1,
    [The facilitynames array is defined in sys/syslog.h])
else
  AC_MSG_RESULT([missing])
fi  
CFLAGS=$save_CFLAGS

AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_CHECK_HEADERS_ONCE([sys/time.h])

AC_TYPE_UNSIGNED_LONG_LONG_INT
AC_TYPE_LONG_LONG_INT
AC_CHECK_TYPE([in_addr_t],[],[CFLAGS="${CFLAGS} -DNEED_INADDRT"],
 [#include <sys/types.h>
  #include <netinet/in.h>
  ])
AC_CHECK_TYPE([in_port_t],[],[CFLAGS="${CFLAGS} -DNEED_INPORTT"],
 [#include <sys/types.h>
  #include <netinet/in.h>
  ])
AC_CHECK_TYPE([time_t],[],[CFLAGS="${CFLAGS} -DNEED_TIMET"],
 [#include <time.h>])

AC_FUNC_FORK
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_STAT
AC_FUNC_STRFTIME

AC_CHECK_FUNCS([getaddrinfo inet_ntop memset regcomp poll socket strcasecmp strchr strdup\
 strerror strncasecmp strspn strtol X509_STORE_set_flags localtime_r gettimeofday])

AC_DEFINE_UNQUOTED([C_SSL], ["$C_SSL"],
 [Location of OpenSSL package])
AC_DEFINE_UNQUOTED([C_OWNER],["$C_OWNER"],
 [Account that owns Pound files])
AC_DEFINE_UNQUOTED([C_GROUP],["$C_GROUP"],
 [Group for the Pound files])

if test -z "${I_OWNER}"
then
    egrep -s '^root' /etc/passwd > /dev/null && I_OWNER=root
    egrep -s '^sys' /etc/passwd > /dev/null && I_OWNER=sys
    egrep -s '^bin' /etc/passwd > /dev/null && I_OWNER=bin
    egrep -s '^daemon' /etc/passwd > /dev/null && I_OWNER=daemon
    egrep -s '^www' /etc/passwd > /dev/null && I_OWNER=www
    egrep -s '^proxy' /etc/passwd > /dev/null && I_OWNER=proxy
fi


if test -z "${I_GRP}"
then
    egrep -s '^root' /etc/group > /dev/null && I_GRP=root
    egrep -s '^sys' /etc/group > /dev/null && I_GRP=sys
    egrep -s '^bin' /etc/group > /dev/null && I_GRP=bin
    egrep -s '^daemon' /etc/group > /dev/null && I_GRP=daemon
    egrep -s '^www' /etc/group > /dev/null && I_GRP=www
    egrep -s '^proxy' /etc/group > /dev/null && I_GRP=proxy
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

