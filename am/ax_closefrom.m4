# SYNOPSIS
#
#   AX_CLOSEFROM
#
# DESCRIPTION
#
#   This macro figures out the best way to close all file descriptors
#   greater than or equal to the given one.  It evaluates the following
#   variants:
#
#     1. closefrom call    (FreeBSD)
#     2. F_CLOSEM fcntl (NetBSD, AIX, IRIX)
#     3. proc_pidinfo call (Darwin)
#     4. /proc/self/fd filesystem   (Linux)
#
#   If none of these is applicable, brute force approach will be used.
#
# LICENSE
#
# Copyright (C) 2021-2023, 2025-2026 Sergey Poznyakoff
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_DEFUN([AX_CLOSEFROM],
[
AC_CHECK_FUNCS([sysconf getdtablesize closefrom proc_pidinfo])

AC_CHECK_DECL([F_CLOSEM],
	      AC_DEFINE([HAVE_FCNTL_CLOSEM], [1],
			[Use F_CLOSEM fcntl for wy_close_fds_from]),
	      [],
	      [#include <limits.h>
	       #include <fcntl.h>
])

AC_CHECK_HEADERS([libproc.h])

AC_MSG_CHECKING([for closefrom interface])
if test "$ac_cv_func_closefrom" = yes; then
  closefrom_api=closefrom
elif test "$ac_cv_have_decl_F_CLOSEM" = yes; then
  closefrom_api=F_CLOSEM
elif test "${ac_cv_header_libproc_h}-$ac_cv_func_proc_pidinfo" = "yes-yes"; then
  closefrom_api=proc_pidinfo
elif test -d "/proc/self/fd" ; then
  AC_DEFINE([HAVE_PROC_SELF_FD], [1], [Define if you have /proc/self/fd])
  closefrom_api=proc
else
  closefrom_api=bruteforce
fi
AC_MSG_RESULT([$closefrom_api])
])
