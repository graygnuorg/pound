/*
 * Lua support for pound.
 * Copyright (C) 2024-2025 Sergey Poznyakoff
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

/* Lua context, associated with a worker thread (POUND_HTTP structure). */
struct pndlua
{
  lua_State *state;           /* Lua state.  Null if global context. */
  DLIST_ENTRY (pndlua) link;  /* Links to free context list. */
};

/*
 * Array of allocated contexts.  It holds from 1 to worker_max_count + 1
 * entries.  pndlua_ctx[0] is global context.  Rest of entries are contexts
 * to use with worker threads.
 */
static struct pndlua *pndlua_ctx;
/* Number of entries allocated in pndlua_ctx. */
static int pndlua_ctx_count;
/* Global mutex serializes access to pndlua_ctx[0]. */
static pthread_mutex_t pndlua_global_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Free context list. */
static DLIST_HEAD (, pndlua) pndlua_avail =
  DLIST_HEAD_INITIALIZER (pndlua_avail);
static pthread_mutex_t pndlua_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_key_t pndlua_key;
static pthread_once_t pndlua_key_once = PTHREAD_ONCE_INIT;

static void
pndlua_reclaim (void *ptr)
{
  struct pndlua *pndlua = ptr;
  pthread_mutex_lock (&pndlua_mutex);
  DLIST_INSERT_HEAD (&pndlua_avail, pndlua, link);
  pthread_mutex_unlock (&pndlua_mutex);
}

static void
make_pndlua_key (void)
{
  pthread_key_create (&pndlua_key, pndlua_reclaim);
}

static struct pndlua *
pndlua_get (void)
{
  struct pndlua *pndlua;
  pthread_once (&pndlua_key_once, make_pndlua_key);
  if ((pndlua = pthread_getspecific (pndlua_key)) == NULL)
    {
      pthread_mutex_lock (&pndlua_mutex);
      pndlua = DLIST_FIRST (&pndlua_avail);
      DLIST_SHIFT (&pndlua_avail, link);
      pthread_mutex_unlock (&pndlua_mutex);
      pthread_setspecific (pndlua_key, pndlua);
    }
  return pndlua;
}

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

struct closure_entry
{
  struct pndlua_closure *cond;
  SLIST_ENTRY (closure_entry) next;
};

static SLIST_HEAD (,closure_entry) closure_head =
  SLIST_HEAD_INITIALIZER (closure_head);

static void
closure_head_add (struct pndlua_closure *cond)
{
    struct closure_entry *ent;
    XZALLOC (ent);
    ent->cond = cond;
    SLIST_INSERT_TAIL (&closure_head, ent, next);
}

static void
closure_head_free (void)
{
  while (!SLIST_EMPTY (&closure_head))
    {
      struct closure_entry *ent = SLIST_FIRST (&closure_head);
      SLIST_REMOVE_HEAD (&closure_head, next);
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
closure_resolve (struct pndlua_closure *cond)
{
  if (pndlua_ctx_count > 1 &&
      function_is_defined (pndlua_ctx[1].state, cond->func))
    cond->ctx = PNDLUA_CTX_THREAD;
  else if (function_is_defined (pndlua_ctx[0].state, cond->func))
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
closure_head_resolve (void)
{
  struct closure_entry *ent;
  int err = 0;
  SLIST_FOREACH (ent, &closure_head, next)
    if (closure_resolve (ent->cond))
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
				 "Lua runtime error: %s",
				 lua_tostring (state, -1));
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

#ifdef LUA_ERRGCMM
    case LUA_ERRGCMM:
      conf_error_at_locus_range (&source->locus,
				 "Lua garbage collector error in %s: %s",
				 source->name, lua_tostring (state, -1));
      lua_pop (state, 1);
      return -1;
#endif

    default:
      conf_error_at_locus_range (&source->locus, "unhandled Lua error %d",
				 res);
      return -1;
    }

  return 0;
}

static void pndlua_set_http (lua_State *s, POUND_HTTP *http,
			     struct stringbuf *sb);
static void pndlua_unset_http (lua_State *s);

int
pndlua_match (POUND_HTTP *phttp, struct pndlua_closure *cond, char **argv)
{
  int i;
  int res;
  lua_State *state;

  if (cond->ctx == PNDLUA_CTX_GLOBAL)
    {
      pthread_mutex_lock (&pndlua_global_mutex);
      state = pndlua_ctx[0].state;
    }
  else
    {
      struct pndlua *pndlua = pndlua_get ();
      state = pndlua->state;
    }

  pndlua_set_http (state, phttp, NULL);

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

  pndlua_unset_http (state);

  if (cond->ctx == PNDLUA_CTX_GLOBAL)
    pthread_mutex_unlock (&pndlua_global_mutex);
  return res;
}

int
pndlua_backend (POUND_HTTP *phttp, struct pndlua_closure *be, char **argv,
		struct stringbuf *sb)
{
  int i;
  int res;
  lua_State *state;

  if (be->ctx == PNDLUA_CTX_GLOBAL)
    {
      pthread_mutex_lock (&pndlua_global_mutex);
      state = pndlua_ctx[0].state;
    }
  else
    {
      struct pndlua *pndlua = pndlua_get ();
      state = pndlua->state;
    }

  pndlua_set_http (state, phttp, sb);

  lua_getglobal (state, be->func);
  for (i = 0; i < be->argc; i++)
    lua_pushstring (state, argv[i]);

  res = lua_pcall (state, be->argc, 0, 0);
  if (res)
    {
      conf_error_at_locus_range (&be->locus,
				 "(%"PRItid") error calling Lua function %s: %s",
				 POUND_TID (), be->func,
				 lua_tostring (state, -1));
      res = -1;
    }

  pndlua_unset_http (state);

  if (be->ctx == PNDLUA_CTX_GLOBAL)
    pthread_mutex_unlock (&pndlua_global_mutex);
  return res;
}


static void
check_args (lua_State *s, char *fname, int nargs)
{
  if (lua_gettop (s) == nargs)
    return;
  luaL_error (s, "'%s' requires %d arguments", fname, nargs);
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


static void
pndlua_dcl_function (lua_State *s, char const *name, lua_CFunction func)
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

/*FIXME
static void
pndlua_dcl_string (lua_State *s, char const *name, char const *value)
{
  lua_pushstring (s, name);
  lua_pushstring (s, value);
  lua_rawset (s, -3);
}
*/

static void
pndlua_new_metatable (lua_State *s, char const *name)
{
  lua_newtable (s);
  /* Leave the value on stack upon exit. */
  lua_pushvalue (s, -1);

  /* Create __name field. */
  lua_pushstring (s, name);
  lua_setfield (s, -2, "__name");  /* metatable.__name = tname */

  /* Register the table. */
  lua_setfield (s, LUA_REGISTRYINDEX, name);
}

struct cfidx
{
  char *name;
  lua_CFunction fun;
};

static lua_CFunction
pndlua_cfidx_find (char const *letidx, luaL_Reg *cfidx, char const *field)
{
  int i;
  char *p;
  size_t cfidx_size = strlen (letidx);

  if ((p = strchr (letidx, field[0])) != NULL)
    for (i = p - letidx; i < cfidx_size && cfidx[i].name[0] == field[0]; i++)
      if (strcmp (field, cfidx[i].name) == 0)
	return cfidx[i].func;
  return NULL;
}

static void *
pndlua_get_userdata (lua_State *L, int idx)
{
  void *p;

  if (!lua_istable (L, idx))
    luaL_argerror (L, idx, NULL);
  lua_rawgeti (L, idx, 0);
  p = lua_touserdata (L, -1);
  if (!p)
    luaL_argerror (L, idx, NULL);
  lua_pop (L, 1);
  return p;
}

static int
ro_newindex (lua_State *s)
{
  luaL_error (s, "attempt to modify read-only data");
  return 0;
}

/* HTTP accessors. */
/*
  http.req   - returns HTTP request
  http.resp  - returns HTTP response

  req.line    - full request line
  req.method  - request method (string)
  req.headers - headers (table)
  req.version - HTTP version (table)
  req.url
  req.path
  req.query   - query (table)

  tostring(VERSION) string
  VERSION.major - major number
  VERSION.minor - minor number

  QUERY         - string
  QUERY[k]      - value of parameter k
 */

struct req_ud
{
  struct http_request *req;
};

static int
req_line (lua_State *s)
{
  struct req_ud *ud  = pndlua_get_userdata (s, 1);
  lua_pushstring (s, ud->req->request);
  return 1;
}

static int
req_method (lua_State *s)
{
  struct req_ud *ud  = pndlua_get_userdata (s, 1);
  lua_pushstring (s, method_name (ud->req->method));
  return 1;
}

static int
req_headers_str (lua_State *s)
{
  struct req_ud *ud  = pndlua_get_userdata (s, 1);
  struct http_header *hdr;
  luaL_Buffer b;

  luaL_buffinit (s, &b);
  DLIST_FOREACH (hdr, &ud->req->headers, link)
    {
      luaL_addstring (&b, hdr->header);
      luaL_addstring (&b, "\n");
    }
  luaL_pushresult (&b);

  return 1;
}

static int
req_headers_index (lua_State *s)
{
  struct req_ud *ud  = pndlua_get_userdata (s, 1);
  char const *field = lua_tostring (s, 2);
  char const *val;
  struct http_header *hdr;

  hdr = http_header_list_locate_name (&ud->req->headers, field, strlen (field));
  if (hdr == NULL)
    lua_pushnil (s);
  else
    {
      if ((val = http_header_get_value (hdr)) == NULL)
	luaL_error (s, "out of memory");
      lua_pushstring (s, val);
      if ((hdr = http_header_list_next (hdr)) != NULL)
	{
	  int n = 1;

	  /* Return multiple values as a table. */
	  lua_newtable (s);
	  lua_rotate (s, -2, 1);
	  lua_rawseti (s, -2, 0);

	  do
	    {
	      if ((val = http_header_get_value (hdr)) == NULL)
		luaL_error (s, "out of memory");
	      lua_pushstring (s, val);
	      lua_rawseti (s, -2, n);
	      n++;
	    }
	  while ((hdr = http_header_list_next (hdr)) != NULL);
	}
    }
  return 1;
}

/*
 * Get string value from index IDX and append it to the headers list, using
 * the indicated mode.  Bail out on error.
 */
static void
pndlua_header_list_append (lua_State *L, HTTP_HEADER_LIST *head, int idx, int mode)
{
  switch (http_header_list_append (head, lua_tostring (L, idx), mode))
    {
    case -1:
      luaL_error (L, "out of memory");
      break;
    case 1:
      luaL_error (L, "internal error");
    }
}

static int
headers_set (lua_State *s, HTTP_HEADER_LIST *head)
{
  char const *field = lua_tostring (s, 2);

  if (lua_isnil (s, 3))
    {
      http_header_list_remove_field (head, field);
    }
  else if (lua_istable (s, 3))
    {
      http_header_list_remove_field (head, field);

      lua_pushnil (s);  /* first key */
      while (lua_next (s, 3) != 0)
	{
	  lua_pushstring (s, field);
	  lua_pushstring (s, ": ");
	  lua_rotate (s, -3, -1);
	  lua_concat (s, 3);
	  pndlua_header_list_append (s, head, -1, H_APPEND);
	  lua_pop (s, 1);
	}
    }
  else if (lua_isstring (s, 3))
    {
      lua_pushvalue (s, 2);
      lua_pushstring (s, ": ");
      lua_pushvalue (s, 3);
      lua_concat (s, 3);
      pndlua_header_list_append (s, head, -1, H_REPLACE);
      lua_pop (s, 1);
    }
  return 0;
}

static int
req_headers_newindex (lua_State *s)
{
  struct req_ud *ud = pndlua_get_userdata (s, 1);
  return headers_set (s, &ud->req->headers);
}

static int
req_headers_len (lua_State *s)
{
  struct req_ud *ud  = pndlua_get_userdata (s, 1);
  struct http_header *hdr;
  int n = 0;
  DLIST_FOREACH (hdr, &ud->req->headers, link)
    n++;
  lua_pushinteger (s, n);
  return 1;
}

static int
req_new_headers (lua_State *s, int n, int rw)
{
  /* Create the object */
  lua_newtable (s);
  /* Account for new element on stack. */
  if (n < 0)
    n--;
  /* t[0] = ud */
  lua_rawgeti (s, n, 0);
  lua_rawseti (s, -2, 0);

  /* Prepare metatable */
  lua_newtable (s);

  lua_pushcfunction (s, req_headers_str);
  lua_setfield (s, -2, "__tostring");

  lua_pushcfunction (s, req_headers_index);
  lua_setfield (s, -2, "__index");

  lua_pushcfunction (s, rw ? req_headers_newindex : ro_newindex);
  lua_setfield (s, -2, "__newindex");

  lua_pushcfunction (s, req_headers_len);
  lua_setfield (s, -2, "__len");

  /* Set metatable. */
  lua_setmetatable (s, -2);

  return 1;
}

static int
req_headers (lua_State *s)
{
  return req_new_headers (s, 1, 0);
}

static int
req_version_str (lua_State *s)
{
  lua_pushvalue (s, lua_upvalueindex (1));
  return 1;
}

static int
req_version (lua_State *s)
{
  struct req_ud *ud  = pndlua_get_userdata (s, 1);
  char *p;

  /* Create the object */
  lua_newtable (s);

  /* Prepare metatable */
  lua_newtable (s);
  /* Create __name field. */
  p = strrchr (ud->req->request, '/');
  if (!p)
    luaL_error (s, "malformed request");
  p++;
  lua_pushstring (s, p);
  lua_pushvalue (s, -1);
  lua_setfield (s, -3, "__name");  /* metatable.__name = tname */

  lua_pushcclosure (s, req_version_str, 1);
  lua_setfield (s, -2, "__tostring");

  /* Set metatable. */
  lua_setmetatable (s, -2);

  lua_pushinteger (s, 1);
  lua_setfield (s, -2, "major");
  lua_pushinteger (s, ud->req->version);
  lua_setfield (s, -2, "minor");

  return 1;
}

static int
req_url (lua_State *s)
{
  struct req_ud *ud  = pndlua_get_userdata (s, 1);
  char const *v;
  http_request_get_url (ud->req, &v);
  lua_pushstring (s, v);
  return 1;
}

static int
req_path (lua_State *s)
{
  struct req_ud *ud  = pndlua_get_userdata (s, 1);
  char const *v;
  if (http_request_get_path (ud->req, &v))
    luaL_error (s, "out of memory");
  lua_pushstring (s, v);
  return 1;
}

static int
req_query_str (lua_State *s)
{
  struct req_ud *ud  = pndlua_get_userdata (s, 1);
  char const *v;
  if (http_request_get_query (ud->req, &v))
    luaL_error (s, "out of memory");
  lua_pushstring (s, v ? v : "");
  return 1;
}

static int
req_query_len (lua_State *s)
{
  struct req_ud *ud = pndlua_get_userdata (s, 1);
  lua_pushinteger (s, http_request_count_query_param (ud->req));
  return 1;
}

static int
req_query_index (lua_State *s)
{
  struct req_ud *ud = pndlua_get_userdata (s, 1);
  char const *field = lua_tostring (s, 2);
  char const *val;
  switch (http_request_get_query_param_value (ud->req, field, &val))
    {
    case RETRIEVE_ERROR:
      luaL_error (s, "out of memory");
      break;
    case RETRIEVE_NOT_FOUND:
      lua_pushnil (s);
      break;
    case RETRIEVE_OK:
      lua_pushstring (s, val);
    }
  return 1;
}

static int
req_query (lua_State *s)
{
  /* Create the object */
  lua_newtable (s);
  /* t[0] = ud */
  lua_rawgeti (s, 1, 0);
  lua_rawseti (s, -2, 0);

  /* Prepare metatable */
  lua_newtable (s);

  lua_pushcfunction (s, req_query_str);
  lua_setfield (s, -2, "__tostring");

  lua_pushcfunction (s, req_query_index);
  lua_setfield (s, -2, "__index");

  lua_pushcfunction (s, req_query_len);
  lua_setfield (s, -2, "__len");

  /* Set metatable. */
  lua_setmetatable (s, -2);

  return 1;
}

static int
pndlua_req_index (lua_State *s)
{
  char const *field;
  lua_CFunction fun;

  static char letidx[] = "hlmpquv";
  static struct luaL_Reg cfidx[] = {
    { "headers", req_headers },
    { "line", req_line },
    { "method", req_method },
    { "path", req_path },
    { "query", req_query },
    { "url", req_url },
    { "version", req_version },
  };

  field = lua_tostring (s, 2);
  if ((fun = pndlua_cfidx_find (letidx, cfidx, field)) == NULL)
    luaL_error (s, "no such field");
  return fun (s);
}

static char const pndlua_req_class[] = "req";

static void
pndlua_dcl_req (lua_State *s)
{
  pndlua_new_metatable (s, pndlua_req_class);
  /* Prepare the __index entry. */
  pndlua_dcl_function (s, "__index", pndlua_req_index);
  lua_pop (s, 1);
}

struct http_ud
{
  POUND_HTTP *phttp;
  struct stringbuf *sb;
};

static int
resp_get_body (lua_State *s)
{
  struct http_ud *ud = pndlua_get_userdata (s, 1);
  lua_pushlstring (s, stringbuf_value (ud->sb), stringbuf_len (ud->sb));
  return 1;
}

static int
resp_get_code (lua_State *s)
{
  struct http_ud *ud = pndlua_get_userdata (s, 1);
  lua_pushinteger (s, ud->phttp->response_code);
  return 1;
}

static int
resp_get_headers (lua_State *s)
{
  struct http_ud *http = pndlua_get_userdata (s, 1);
  struct req_ud *rud;
  int rc;

  /* Create request userdata. */
  lua_newtable (s);
  rud = lua_newuserdata (s, sizeof (*rud));
  rud->req = &http->phttp->response;
  lua_rawseti (s, -2, 0);
  /* Create the headers table. */
  rc = req_new_headers (s, -1, 1);
  /* Swap return value and the original userdata. */
  lua_rotate (s, -2, 1);
  /* Get rid of the original userdata. */
  lua_pop (s, 1);
  return rc;
}

static int
resp_get_reason (lua_State *s)
{
  struct http_ud *ud = pndlua_get_userdata (s, 1);
  lua_pushstring (s, ud->phttp->response.request);
  return 1;
}

static int
pndlua_resp_index (lua_State *s)
{
  char const *field;
  lua_CFunction fun;

  static char letidx[] = "bchr";
  static struct luaL_Reg cfidx[] = {
    { "body",  resp_get_body },
    { "code",  resp_get_code },
    { "headers", resp_get_headers },
    { "reason", resp_get_reason }
  };

  field = lua_tostring (s, 2);
  if ((fun = pndlua_cfidx_find (letidx, cfidx, field)) == NULL)
    luaL_error (s, "no such field");
  return fun (s);
}

static int
resp_set_body (lua_State *s)
{
  struct http_ud *ud = pndlua_get_userdata (s, 1);

  stringbuf_reset (ud->sb);
  if (!lua_isnil (s, 3))
    {
      char const *val = lua_tostring (s, 3);
      stringbuf_add_string (ud->sb, val);
    }
  return 0;
}

static int
resp_set_code (lua_State *s)
{
  struct http_ud *ud = pndlua_get_userdata (s, 1);
  int code = lua_tointeger (s, 3);
  if (code >= 100 && code < 600)
    {
      ud->phttp->response_code = code;
    }
  else
    luaL_argerror (s, 3, "argument out of allowed range");
  return 0;
}

static int
resp_set_headers (lua_State *s)
{
  struct http_ud *ud = pndlua_get_userdata (s, 1);
  HTTP_HEADER_LIST *head = &ud->phttp->response.headers;

  http_header_list_free (head);
  if (lua_istable (s, 3))
    {
      lua_pushnil (s);
      while (lua_next (s, 3) != 0)
	{
	  lua_pushvalue (s, -2);
	  lua_pushstring (s, ": ");
	  lua_rotate (s, -3, -1);
	  lua_concat (s, 3);
	  pndlua_header_list_append (s, head, -1, H_APPEND);
	  lua_pop (s, 1);
	}
    }
  else if (!lua_isnil (s, 3))
    luaL_argerror (s, 3, NULL);
  return 0;
}

static int
resp_set_reason (lua_State *s)
{
  struct http_ud *ud = pndlua_get_userdata (s, 1);

  free (ud->phttp->response.request);
  if (lua_isnil (s, 3))
    {
      ud->phttp->response.request = NULL;
    }
  else
    {
      ud->phttp->response.request = strdup (lua_tostring (s, 3));
      if (!ud->phttp->response.request)
	luaL_error (s, "out of memory");
    }
  return 0;
}

static int
pndlua_resp_newindex (lua_State *s)
{
  char const *field;
  lua_CFunction fun;

  static char letidx[] = "bchr";
  static struct luaL_Reg cfidx[] = {
    { "body",  resp_set_body },
    { "code",  resp_set_code },
    { "headers", resp_set_headers },
    { "reason", resp_set_reason }
  };

  field = lua_tostring (s, 2);
  if ((fun = pndlua_cfidx_find (letidx, cfidx, field)) == NULL)
    luaL_error (s, "no such field");
  return fun (s);
}

static char const pndlua_resp_class[] = "resp";

static void
pndlua_dcl_resp (lua_State *s)
{
  pndlua_new_metatable (s, pndlua_resp_class);
  pndlua_dcl_function (s, "__index", pndlua_resp_index);
  pndlua_dcl_function (s, "__newindex", pndlua_resp_newindex);
  lua_pop (s, 1);
}

static int
http_req (lua_State *s)
{
  struct http_ud *http = pndlua_get_userdata (s, 1);
  struct req_ud *rud;

  lua_newtable (s);
  rud = lua_newuserdata (s, sizeof (*rud));
  lua_rawseti (s, -2, 0);

  rud->req = &http->phttp->request;

  lua_getfield (s, LUA_REGISTRYINDEX, pndlua_req_class);
  lua_setmetatable (s, -2);

  return 1;
}

static int
http_resp (lua_State *s)
{
  /* Create the object */
  lua_newtable (s);
  /* t[0] = ud */
  lua_rawgeti (s, 1, 0);
  lua_rawseti (s, -2, 0);

  lua_getfield (s, LUA_REGISTRYINDEX, pndlua_resp_class);
  lua_setmetatable (s, -2);

  return 1;
}

static int
pndlua_http_index (lua_State *s, int rw)
{
  char const *field;
  lua_CFunction fun;

  static char *letidx[] = { "r", "rr" };
  static struct luaL_Reg cfidx[] = {
    { "req", http_req },
    { "resp", http_resp }
  };

  field = lua_tostring (s, 2);
  if ((fun = pndlua_cfidx_find (letidx[rw], cfidx, field)) == NULL)
    luaL_error (s, "no such field");
  return fun (s);
}

static int
pndlua_http_full_index (lua_State *s)
{
  return pndlua_http_index (s, 1);
}

static int
pndlua_http_req_index (lua_State *s)
{
  return pndlua_http_index (s, 0);
}

static void
pndlua_set_http (lua_State *s, POUND_HTTP *phttp, struct stringbuf *sb)
{
  struct http_ud *ud;

  /* Create table with userdata at t[0] */
  lua_newtable (s);
  ud = lua_newuserdata (s, sizeof (*ud));
  lua_rawseti (s, -2, 0);
  ud->phttp = phttp;
  if (sb)
    stringbuf_init_log (sb); // FIXME: Use custom log function for Lua.
  ud->sb = sb;

  pndlua_new_metatable (s, "http");
  /* Create __index entry. */
  pndlua_dcl_function (s, "__index",
		       sb ? pndlua_http_full_index : pndlua_http_req_index);
  /* Create __newindex entry. */
  pndlua_dcl_function (s, "__newindex", ro_newindex);

  /* Set metatable. */
  lua_setmetatable (s, -2);

  lua_setglobal (s, "http");
}

static void
pndlua_unset_http (lua_State *s)
{
  lua_pushnil (s);
  lua_setglobal (s, "http");
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

  pndlua_dcl_req (state);
  pndlua_dcl_resp (state);

  return state;
}

static int
source_list_load (int i, struct pndlua_source_head *head)
{
  lua_State *L = pndlua_ctx[i].state;
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

  pndlua_ctx_count = 1;
  if (!SLIST_EMPTY (&thread_sources))
    pndlua_ctx_count += worker_max_count;

  pndlua_ctx = xcalloc (pndlua_ctx_count, sizeof (*pndlua_ctx));
  pndlua_ctx[0].state = pndlua_new_state ();
  for (i = 1; i < pndlua_ctx_count; i++)
    {
      pndlua_ctx[i].state = pndlua_new_state ();
      DLIST_INSERT_TAIL (&pndlua_avail, &pndlua_ctx[i], link);
    }

  /* Load global sources. */
  if (source_list_load (0, &global_sources))
    return -1;

  /* Load per-thread sources. */
  for (i = 1; i < pndlua_ctx_count; i++)
    if (source_list_load (i, &thread_sources))
      return -1;

  /* Resolve invocation contexts. */
  if (closure_head_resolve ())
    return -1;

  /* Free unneeded memory. */
  source_list_free (&global_sources);
  source_list_free (&thread_sources);
  path_list_free (&path_head[PNDLUA_PATH]);
  path_list_free (&path_head[PNDLUA_CPATH]);
  closure_head_free ();

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
pndlua_parse_closure (struct pndlua_closure *cls)
{
  struct token *tok;
  size_t argmax = 0;

  if ((tok = gettkn_expect (T_STRING)) == NULL)
    return CFGPARSER_FAIL;

  locus_range_init (&cls->locus);
  locus_range_copy (&cls->locus, &tok->locus);

  cls->func = xstrdup (tok->str);
  while (1)
    {
      if ((tok = gettkn_any ()) == NULL)
	return CFGPARSER_FAIL;
      if (tok->type == T_STRING)
	{
	  if (cls->argc == argmax)
	    {
	      cls->argv = x2nrealloc (cls->argv, &argmax,
				       sizeof cls->argv[0]);
	    }
	  cls->argv[cls->argc++] = xstrdup (tok->str);
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
  closure_head_add (cls);
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
