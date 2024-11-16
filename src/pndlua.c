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

static lua_State *p_lua_state;
static pthread_mutex_t p_lua_state_mutex = PTHREAD_MUTEX_INITIALIZER;

static int
pndlua_load (char const *fname)
{
  int res;

  if (luaL_loadfile (p_lua_state, fname) != LUA_OK)
    {
      logmsg (LOG_ERR, "error loading Lua file %s: %s", fname,
	      lua_tostring (p_lua_state, -1));
      lua_pop (p_lua_state, 1);
      return -1;
    }

  res = lua_pcall (p_lua_state, 0, LUA_MULTRET, 0);
  switch (res)
    {
    case LUA_OK:
      break;

    case LUA_ERRRUN:
      logmsg (LOG_ERR, "Lua runtime error in %s: %s",
	      fname, lua_tostring (p_lua_state, -1));
      lua_pop (p_lua_state, 1);
      return -1;

    case LUA_ERRMEM:
      logmsg (LOG_ERR, "out of memory running Lua code in %s", fname);
      return -1;

    case LUA_ERRERR:
      logmsg (LOG_ERR, "Lua message handler error in %s: %s",
	      fname, lua_tostring (p_lua_state, -1));
      lua_pop (p_lua_state, 1);
      return -1;

    case LUA_ERRGCMM:
      logmsg (LOG_ERR, "Lua garbage collector error in %s: %s",
	      fname, lua_tostring (p_lua_state, -1));
      lua_pop (p_lua_state, 1);
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

  pthread_mutex_lock (&p_lua_state_mutex);

  lua_getglobal (p_lua_state, fname);
  for (i = 0; i < argc; i++)
    lua_pushstring (p_lua_state, argv[i]);

  res = lua_pcall (p_lua_state, argc, 1, 0);
  if (res)
    {
      logmsg (LOG_ERR, "(%"PRItid") error calling Lua function %s: %s",
	      POUND_TID (), fname, lua_tostring (p_lua_state, -1));
      res = -1;
    }
  else
    {
      res = lua_toboolean (p_lua_state, -1);
    }

  lua_pop (p_lua_state, 1);

  pthread_mutex_unlock (&p_lua_state_mutex);
  return res;
}

void
pndlua_init (void)
{
  p_lua_state = luaL_newstate ();
  luaL_openlibs (p_lua_state);
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
