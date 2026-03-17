# SYNOPSIS
#
#   AX_LUA(MIN, [MAX], [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
#
# DESCRIPTION
#
#   Checks for Lua libraries and header files in version range [MIN,MAX]
#   (MAX can be omitted) and selects the one with the highest version number.
#
#   On success, defines LUA_CFLAGS to any special C compiler flags needed,
#   LUA_LIBS to linker flags, and executes ACTION-IF-FOUND.
#
#   On error, runs ACTION-IF-NOT-FOUND.
#
#   The macro looks for Lua headers in /usr/include/lua* (where * is
#   a Lua version number satisfying [MIN,MAX]) and in /usr/include, in
#   that order.
#
#   If any of LUA_CFLAGS or LUA_LIBS is defined upon invoking the macro,
#   the lookup is not done. Instead, the macro checks for lua.h and liblua.a
#   using the supplied compiler and linker flags.
#
# LICENSE
#
#   Copyright (C) 2026 Sergey Poznyakoff
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_SUBST([LUA_CFLAGS])
AC_SUBST([LUA_LIBS])

# Arguments:
#   $1     - [madatory] minumum version number to use;
#   $2     - [optional] maximum version number;
#   $3     - [optional] actions to do on success;
#   $4     - [optional] actions to do on failure;
AC_DEFUN([AX_LUA],
[ax_lua_ok=no
AC_MSG_CHECKING([for Lua headers and libraries])
if test -n "$LUA_LIBS" || test -n "$LUA_CFLAGS"; then
  _AX_LUA_SUBTEST($1,$2)
else
  version=$(ls -1 /usr/include/lua*/lua.h 2>/dev/null |
    sed -n -e 's|^/usr/include/lua||' \
	   -e 's|/lua\.h$||' \
	   -e ['/^[0-9]\.[0-9]/p'] |
    sort -t . -n -r -k1,2 |
    while read version
    do
      case $version in
	$1.*) # Give it a chance
	      ;;
	*)
	   m4_if($2,,,
              [AS_IF([test -n "$2"],
                 [AS_VERSION_COMPARE($2, $version, continue)]]))
	   AS_VERSION_COMPARE($version, $1, break)
      esac
      LUA_CFLAGS="-I/usr/include/lua$version"
      LUA_LIBS="-llua$version"
      _AX_LUA_SUBTEST($1,$2)
      if test "$ax_lua_ok" = yes; then
	 echo $version
	 break
      fi
    done)
  if test -n "$version"; then
    ax_lua_ok=yes
    LUA_CFLAGS="-I/usr/include/lua$version"
    LUA_LIBS="-llua$version"
  else
    LUA_LIBS="-llua"
    _AX_LUA_SUBTEST($1,$2)
  fi
fi
AC_MSG_RESULT([$ax_lua_ok])
if test "$ax_lua_ok" = no; then
  unset LUA_LIBS
  unset LUA_CFLAGS
  $4
m4_if($3,,,[else
  $3
])dnl
fi])

# Auxiliary macro, used by AX_LUA. Given minimum and optional maximum
# Lua version numbers *and* C compiler and linker flags supplied by
# environment variables LUA_CFLAGS and LUA_LIBS, compiles and runs a
# test program to see if the lua library and header files exist, are
# usable, and consistent.
#
# On success, sets environment variable ax_lua_ok=yes. On failure,
# sets ax_lua_ok=no.
#
# Arguments:
#   $1     - [madatory] minumum version number to use;
#   $2     - [optional] maximum version number;
AC_DEFUN([_AX_LUA_SUBTEST],
[saved_CFLAGS="$CFLAGS"
saved_LIBS="$LIBS"
LIBS="$LIBS $LUA_LIBS"
CFLAGS="$CFLAGS $LUA_CFLAGS"
AC_RUN_IFELSE(
  [AC_LANG_PROGRAM([
#include <stdlib.h>
#include "lua.h"
#include "lauxlib.h"
long vextract(char const **a)
{
  char *p;
  long n = strtol(*a, &p, 10);
  if (*p == '.')
    *a = p+1;
  else if (*p == 0)
    *a = p;
  else
    return -1;
  return n;
}
int vcmp(char const *a, char const *b)
{
  int i;
  for (i = 0; i < 3 && *a && *b; i++)
    {
      long an = vextract(&a), bn = vextract(&b);
      if (an < 0 || bn < 0 || an < bn)
	return 1;
      if (an > bn)
	break;
    }
  return 0;
}
#define V LUA_VERSION_MAJOR "." LUA_VERSION_MINOR "." LUA_VERSION_RELEASE
],
  [luaL_checkversion (luaL_newstate ());
if (vcmp(V, "$1"))
    return 1;
return m4_if($2,,0,vcmp("$2",V));])],
  [ax_lua_ok=yes],
  [ax_lua_ok=no])
CFLAGS="$saved_CFLAGS"
LIBS="$saved_LIBS"])dnl # AX_LUA
