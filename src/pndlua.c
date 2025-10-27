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

struct pndlua
{
  lua_State *state;
  DLIST_ENTRY (pndlua) link;
};

static DLIST_HEAD (, pndlua) pndlua_head =
  DLIST_HEAD_INITIALIZER (pndlua_head);
static pthread_mutex_t pndlua_mutex = PTHREAD_MUTEX_INITIALIZER;

void
pndlua_http_init (POUND_HTTP *phttp)
{
  if (!DLIST_EMPTY (&pndlua_head))
    {
      pthread_mutex_lock (&pndlua_mutex);
      phttp->pndlua = malloc (sizeof (phttp->pndlua[0]));
      if (phttp->pndlua)
	{
	  phttp->pndlua = DLIST_FIRST (&pndlua_head);
	  DLIST_SHIFT (&pndlua_head, link);
	}
      else
	lognomem ();
      pthread_mutex_unlock (&pndlua_mutex);
    }
}

void
pndlua_http_deinit (POUND_HTTP *phttp)
{
  if (phttp->pndlua)
    {
      pthread_mutex_lock (&pndlua_mutex);
      DLIST_INSERT_HEAD (&pndlua_head, phttp->pndlua, link);
      pthread_mutex_unlock (&pndlua_mutex);
      phttp->pndlua = NULL;
    }
}

static struct pndlua *pndlua_state;
static int pndlua_state_count;
static pthread_mutex_t pndlua_state_mutex = PTHREAD_MUTEX_INITIALIZER;

struct pndlua_source
{
  char *name;
  struct locus_range locus;
  SLIST_ENTRY (pndlua_source) next;
};

static SLIST_HEAD (pndlua_source_head,pndlua_source)
  global_sources = SLIST_HEAD_INITIALIZER (global_sources),
  thread_sources = SLIST_HEAD_INITIALIZER (thread_sources);

struct path_dir
{
  SLIST_ENTRY (path_dir) next;
  char name[1];
};
typedef SLIST_HEAD(,path_dir) PATH_HEAD;

enum
  {
    PNDLUA_PATH,
    PNDLUA_CPATH
  };

static char *path_name[] = { "path", "cpath" };
static PATH_HEAD path_head[2] = {
  SLIST_HEAD_INITIALIZER (path_head[0]),
  SLIST_HEAD_INITIALIZER (path_head[1])
};

static void
path_list_add (PATH_HEAD *head, char const *name)
{
  struct path_dir *dir = xmalloc (sizeof (*dir) + strlen (name));
  strcpy (dir->name, name);
  SLIST_INSERT_TAIL (head, dir, next);
}

static void
path_list_free (PATH_HEAD *head)
{
  while (!SLIST_EMPTY (head))
    {
      struct path_dir *dir = SLIST_FIRST (head);
      SLIST_REMOVE_HEAD (head, next);
      free (dir);
    }
}

struct cond_entry
{
  struct cond_lua *cond;
  SLIST_ENTRY (cond_entry) next;
};

static SLIST_HEAD (,cond_entry) cond_head = SLIST_HEAD_INITIALIZER (cond_head);

static void
cond_head_add (struct cond_lua *cond)
{
    struct cond_entry *ent;
    XZALLOC (ent);
    ent->cond = cond;
    SLIST_INSERT_TAIL (&cond_head, ent, next);
}

static void
cond_head_free (void)
{
  while (!SLIST_EMPTY (&cond_head))
    {
      struct cond_entry *ent = SLIST_FIRST (&cond_head);
      SLIST_REMOVE_HEAD (&cond_head, next);
      free (ent);
    }
}

static inline int
function_is_defined (lua_State *state, char const *name)
{
  int f;

  lua_getglobal (state, name);
  f = lua_isfunction (state, -1);
  lua_pop (state, 1);
  return f;
}

static int
cond_lua_resolve (struct cond_lua *cond)
{
  if (pndlua_state_count > 1 &&
      function_is_defined (pndlua_state[1].state, cond->func))
    cond->ctx = PNDLUA_CTX_THREAD;
  else if (function_is_defined (pndlua_state[0].state, cond->func))
    cond->ctx = PNDLUA_CTX_GLOBAL;
  else
    {
      conf_error_at_locus_range (&cond->locus, "Lua function %s not defined",
				 cond->func);
      return -1;
    }
  return 0;
}

static int
cond_head_resolve (void)
{
  struct cond_entry *ent;
  int err = 0;
  SLIST_FOREACH (ent, &cond_head, next)
    if (cond_lua_resolve (ent->cond))
      ++err;
  return err;
}

static int
source_load (lua_State *state, struct pndlua_source *source)
{
  int res;

  if (luaL_loadfile (state, source->name) != LUA_OK)
    {
      conf_error_at_locus_range (&source->locus,
				 "error loading Lua file %s: %s",
				 source->name,
				 lua_tostring (state, -1));
      lua_pop (state, 1);
      return -1;
    }

  res = lua_pcall (state, 0, LUA_MULTRET, 0);
  switch (res)
    {
    case LUA_OK:
      break;

    case LUA_ERRRUN:
      conf_error_at_locus_range (&source->locus,
				 "Lua runtime error in %s: %s",
				 source->name, lua_tostring (state, -1));
      lua_pop (state, 1);
      return -1;

    case LUA_ERRMEM:
      conf_error_at_locus_range (&source->locus,
				 "out of memory running Lua code in %s",
				 source->name);
      return -1;

    case LUA_ERRERR:
      conf_error_at_locus_range (&source->locus,
				 "Lua message handler error in %s: %s",
				 source->name, lua_tostring (state, -1));
      lua_pop (state, 1);
      return -1;

    case LUA_ERRGCMM:
      conf_error_at_locus_range (&source->locus,
				 "Lua garbage collector error in %s: %s",
				 source->name, lua_tostring (state, -1));
      lua_pop (state, 1);
      return -1;

    default:
      conf_error_at_locus_range (&source->locus, "unhandled Lua error %d",
				 res);
      return -1;
    }

  return 0;
}

int
pndlua_match (POUND_HTTP *phttp, struct cond_lua *cond, char **argv)
{
  int i;
  int res;
  lua_State *state;

  if (cond->ctx == PNDLUA_CTX_GLOBAL)
    {
      pthread_mutex_lock (&pndlua_state_mutex);
      state = pndlua_state[0].state;
    }
  else
    {
      state = phttp->pndlua->state;
      if (!state)
	{
	  logmsg (LOG_ERR, "(%"PRItid") no Lua state (allocation error)",
		  POUND_TID ());
	  return -1;
	}
    }

  lua_getglobal (state, cond->func);
  for (i = 0; i < cond->argc; i++)
    lua_pushstring (state, argv[i]);

  res = lua_pcall (state, cond->argc, 1, 0);
  if (res)
    {
      conf_error_at_locus_range (&cond->locus,
				 "(%"PRItid") error calling Lua function %s: %s",
				 POUND_TID (), cond->func,
				 lua_tostring (state, -1));
      res = -1;
    }
  else
    {
      res = lua_toboolean (state, -1);
    }

  lua_pop (state, 1);

  if (cond->ctx == PNDLUA_CTX_GLOBAL)
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

static void
pndlua_add_path (lua_State *L, int type)
{
  struct path_dir *dir;
  int n;

  if (SLIST_EMPTY (&path_head[type]))
    return;

  lua_getglobal (L, "package");
  n = 1;
  SLIST_FOREACH (dir, &path_head[type], next)
    {
      lua_pushstring (L, dir->name);
      lua_pushstring (L, ";");
      n += 2;
    }

  /* Concatenate. */
  lua_getfield (L, -n, path_name[type]);
  lua_concat (L, n);

  /* Store new path and clean up stack. */
  lua_setfield (L, -2, path_name[type]);
  lua_pop (L, 1);
}

static lua_State *
pndlua_new_state (void)
{
  int i;
  lua_State *state;

  state = luaL_newstate ();
  luaL_openlibs (state);

  lua_newtable (state);

  for (i = 0; severity_table[i].name; i++)
    pndlua_dcl_integer (state, severity_table[i].name, severity_table[i].tok);

  pndlua_dcl_function (state, "log", pndlua_pound_log);
  lua_setglobal (state, "pound");

  for (i = 0; i < sizeof (path_head) / sizeof (path_head[0]); i++)
    pndlua_add_path (state, i);

  return state;
}

static int
source_list_load (int i, struct pndlua_source_head *head)
{
  lua_State *L = pndlua_state[i].state;
  struct pndlua_source *source;
  int rc = 0;

  lua_getglobal (L, "pound");
  lua_pushstring (L, "loadctx");
  lua_pushinteger (L, i);
  lua_rawset (L, -3);

  SLIST_FOREACH (source, head, next)
    {
      if ((rc = source_load (L, source)) != 0)
	break;
    }

  lua_pushstring (L, "loadctx");
  lua_pushnil (L);
  lua_rawset (L, -3);

  lua_pop (L, 1);

  return rc;
}

static void
source_list_free (struct pndlua_source_head *head)
{
  while (!SLIST_EMPTY (head))
    {
      struct pndlua_source *source = SLIST_FIRST (head);
      SLIST_REMOVE_HEAD (head, next);
      locus_range_unref (&source->locus);
      free (source->name);
      free (source);
    }
}

int
pndlua_init (void)
{
  int i;

  pndlua_state_count = 1;
  if (!SLIST_EMPTY (&thread_sources))
    pndlua_state_count += worker_max_count;

  pndlua_state = xcalloc (pndlua_state_count, sizeof (*pndlua_state));
  pndlua_state[0].state = pndlua_new_state ();
  for (i = 1; i < pndlua_state_count; i++)
    {
      pndlua_state[i].state = pndlua_new_state ();
      DLIST_INSERT_TAIL (&pndlua_head, &pndlua_state[i], link);
    }

  /* Load global sources. */
  if (source_list_load (0, &global_sources))
    return -1;

  /* Load per-thread sources. */
  for (i = 1; i < pndlua_state_count; i++)
    if (source_list_load (i, &thread_sources))
      return -1;

  /* Resolve invocation contexts. */
  if (cond_head_resolve ())
    return -1;

  /* Free unneeded memory. */
  source_list_free (&global_sources);
  source_list_free (&thread_sources);
  path_list_free (&path_head[PNDLUA_PATH]);
  path_list_free (&path_head[PNDLUA_CPATH]);
  cond_head_free ();

  return 0;
}

static int
parse_lua_path (int n)
{
  char *path, *s, *p;
  int rc = cfg_assign_string (&path, NULL);
  if (rc != CFGPARSER_OK)
    return rc;
  for (s = strtok_r (path, ";", &p); s; s = strtok_r (NULL, ";", &p))
    {
      if (!strchr (s, '?'))
	{
	  conf_error ("%s: this doesn't look like a Lua path component", s);
	  rc = CFGPARSER_FAIL;
	}
      else
	path_list_add (&path_head[n], s);
    }
  return rc;
}

static int
pndlua_parse_lua_path (void *call_data, void *section_data)
{
  return parse_lua_path (PNDLUA_PATH);
}

static int
pndlua_parse_lua_cpath (void *call_data, void *section_data)
{
  return parse_lua_path (PNDLUA_CPATH);
}

static int
parse_lua_load (struct pndlua_source_head *head)
{
  struct token *tok;
  char *filename;
  struct pndlua_source *src;

  if ((tok = gettkn_expect (T_STRING)) == NULL)
    return CFGPARSER_FAIL;

  if ((filename = filename_resolve (tok->str)) == NULL)
    return CFGPARSER_FAIL;

  XZALLOC (src);
  src->name = filename;
  locus_range_init (&src->locus);
  locus_range_copy (&src->locus, &tok->locus);
  SLIST_INSERT_TAIL (head, src, next);

  return 0;
}

static int
pndlua_parse_lua_load (void *call_data, void *section_data)
{
  return parse_lua_load (&thread_sources);
}

static int
pndlua_parse_lua_load_global (void *call_data, void *section_data)
{
  return parse_lua_load (&global_sources);
}

int
pndlua_parse_cond (struct cond_lua *cond)
{
  struct token *tok;
  size_t argmax = 0;

  if ((tok = gettkn_expect (T_STRING)) == NULL)
    return CFGPARSER_FAIL;

  locus_range_init (&cond->locus);
  locus_range_copy (&cond->locus, &tok->locus);

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
  cond_head_add (cond);
  return CFGPARSER_OK_NONL;
}

static CFGPARSER_TABLE lua_parsetab[] = {
  {
    .name = "End",
    .parser = cfg_parse_end
  },
  {
    .name = "Path",
    .parser = pndlua_parse_lua_path
  },
  {
    .name = "CPath",
    .parser = pndlua_parse_lua_cpath
  },
  {
    .name = "Load",
    .parser = pndlua_parse_lua_load
  },
  {
    .name = "LoadGlobal",
    .parser = pndlua_parse_lua_load_global
  },
  { NULL }
};

int
pndlua_parse_config (void *call_data, void *section_data)
{
  return parser_loop (lua_parsetab, NULL, NULL, NULL);
}
