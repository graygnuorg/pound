/*
 * Lua support for pound.
 * Copyright (C) 2024 Sergey Poznyakoff
 *
 * Pound is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Pound is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with pound.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "pound.h"
#include "extern.h"
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

static lua_State *pndlua_state;
static pthread_mutex_t pndlua_state_mutex = PTHREAD_MUTEX_INITIALIZER;

static int
pndlua_load (char const *fname)
{
  int res;

  if (luaL_loadfile (pndlua_state, fname) != LUA_OK)
    {
      logmsg (LOG_ERR, "error loading Lua file %s: %s", fname,
	      lua_tostring (pndlua_state, -1));
      lua_pop (pndlua_state, 1);
      return -1;
    }

  res = lua_pcall (pndlua_state, 0, LUA_MULTRET, 0);
  switch (res)
    {
    case LUA_OK:
      break;

    case LUA_ERRRUN:
      logmsg (LOG_ERR, "Lua runtime error in %s: %s",
	      fname, lua_tostring (pndlua_state, -1));
      lua_pop (pndlua_state, 1);
      return -1;

    case LUA_ERRMEM:
      logmsg (LOG_ERR, "out of memory running Lua code in %s", fname);
      return -1;

    case LUA_ERRERR:
      logmsg (LOG_ERR, "Lua message handler error in %s: %s",
	      fname, lua_tostring (pndlua_state, -1));
      lua_pop (pndlua_state, 1);
      return -1;

    case LUA_ERRGCMM:
      logmsg (LOG_ERR, "Lua garbage collector error in %s: %s",
	      fname, lua_tostring (pndlua_state, -1));
      lua_pop (pndlua_state, 1);
      return -1;

    default:
      logmsg (LOG_ERR, "unhandled Lua error %d in file %s",
	      res, fname);
      return -1;
    }

  return 0;
}

int
pndlua_match (POUND_HTTP *phttp, char const *fname, int argc, char **argv)
{
  int i;
  int res;

  pthread_mutex_lock (&pndlua_state_mutex);

  lua_getglobal (pndlua_state, fname);
  for (i = 0; i < argc; i++)
    lua_pushstring (pndlua_state, argv[i]);

  res = lua_pcall (pndlua_state, argc, 1, 0);
  if (res)
    {
      logmsg (LOG_ERR, "(%"PRItid") error calling Lua function %s: %s",
	      POUND_TID (), fname, lua_tostring (pndlua_state, -1));
      res = -1;
    }
  else
    {
      res = lua_toboolean (pndlua_state, -1);
    }

  lua_pop (pndlua_state, 1);

  pthread_mutex_unlock (&pndlua_state_mutex);
  return res;
}

static void
check_args (lua_State *s, char *fname, int nargs)
{
  if (lua_gettop (s) == nargs)
    return;
  luaL_error(s, "'%s' requires %d arguments", fname, nargs);
}

static int
pndlua_pound_log (lua_State *s)
{
  char const *msg;
  int prio;

  check_args (s, "log", 2);
  prio = luaL_checkinteger (s, 1);
  msg = luaL_checkstring (s, 2);
  logmsg (prio, "%s", msg);
  return 0;
}


typedef int (*PND_LUAFUNC) (lua_State *);

static void
pndlua_dcl_function (lua_State *s, char const *name, PND_LUAFUNC func)
{
  lua_pushstring (s, name);
  lua_pushcfunction (s, func);
  lua_rawset (s, -3);
}

static void
pndlua_dcl_integer (lua_State *s, char const *name, int value)
{
  lua_pushstring (s, name);
  lua_pushinteger (s, value);
  lua_rawset (s, -3);
}

static struct kwtab severity_table[] = {
  { "EMERG",   LOG_EMERG },
  { "ALERT",   LOG_ALERT },
  { "CRIT",    LOG_CRIT },
  { "ERR",     LOG_ERR },
  { "WARNING", LOG_WARNING },
  { "NOTICE",  LOG_NOTICE },
  { "INFO",    LOG_INFO },
  { "DEBUG",   LOG_DEBUG },
  { NULL }
};

void
pndlua_init (void)
{
  int i;

  pndlua_state = luaL_newstate ();
  luaL_openlibs (pndlua_state);

  lua_newtable (pndlua_state);

  for (i = 0; severity_table[i].name; i++)
    pndlua_dcl_integer (pndlua_state,
			severity_table[i].name, severity_table[i].tok);

  pndlua_dcl_function (pndlua_state, "log", pndlua_pound_log);
  lua_setglobal (pndlua_state, "pound");
}

int
pndlua_parse_lua_load (void *call_data, void *section_data)
{
  struct token *tok;
  char *filename;
  int res;

  if ((tok = gettkn_expect (T_STRING)) == NULL)
    return CFGPARSER_FAIL;

  if ((filename = filename_resolve (tok->str)) == NULL)
    return CFGPARSER_FAIL;

  if (pndlua_load (filename) == 0)
    res = CFGPARSER_OK;
  else
    res = CFGPARSER_FAIL;

  free (filename);

  return res;
}

int
pndlua_parse_cond (struct cond_lua *cond)
{
  struct token *tok;
  size_t argmax = 0;

  if ((tok = gettkn_expect (T_STRING)) == NULL)
    return CFGPARSER_FAIL;
  cond->func = xstrdup (tok->str);
  while (1)
    {
      if ((tok = gettkn_any ()) == NULL)
	return CFGPARSER_FAIL;
      if (tok->type == T_STRING)
	{
	  if (cond->argc == argmax)
	    {
	      cond->argv = x2nrealloc (cond->argv, &argmax,
				       sizeof cond->argv[0]);
	    }
	  cond->argv[cond->argc++] = xstrdup (tok->str);
	}
      else if (tok->type == '\n')
	break;
      else
	{
	  conf_error ("expected string or newline, but found %s",
		      token_type_str (tok->type));
	  return CFGPARSER_FAIL;
	}
    }
  return CFGPARSER_OK_NONL;
}
