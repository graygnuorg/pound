/*
 * Pound - the reverse-proxy load-balancer
 * Copyright (C) 2026 Sergey Poznyakoff
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
#include "config.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include "pound.h"
#include "cctype.h"
#include "cfgdef.h"

extern char const *progname;

int
kwn_to_tok (struct kwtab *kwt, char const *name, size_t len,
	    int ci, int *retval)
{
  for (; kwt->name; kwt++)
    if ((ci ? c_strncasecmp : strncmp) (kwt->name, name, len) == 0)
      {
	*retval = kwt->tok;
	return 0;
      }
  return -1;
}

int
kw_to_tok (struct kwtab *kwt, char const *name, int ci, int *retval)
{
  return kwn_to_tok (kwt, name, strlen (name), ci, retval);
}

char const *
kw_to_str (struct kwtab *kwt, int t)
{
  for (; kwt->name; kwt++)
    if (kwt->tok == t)
      break;
  return kwt->name;
}

static void
stderr_error_msg (char const *msg)
{
  if (progname)
    fprintf (stderr, "%s: ", progname);
  fputs (msg, stderr);
  fputc ('\n', stderr);
}

void (*cfg_error_msg) (char const *msg) = stderr_error_msg;

void
stringbuf_format_locus_point (struct stringbuf *sb,
			      struct locus_point const *loc)
{
  stringbuf_printf (sb, "%s:%d", string_ptr (loc->filename), loc->line);
  if (loc->col)
    stringbuf_printf (sb, ".%d", loc->col);
}

static int
same_file (struct locus_point const *a, struct locus_point const *b)
{
  return a->filename == b->filename
	 || (a->filename && b->filename &&
	     strcmp (string_ptr (a->filename), string_ptr (b->filename)) == 0);
}

void
stringbuf_format_locus_range (struct stringbuf *sb,
			      struct locus_range const *range)
{
  stringbuf_format_locus_point (sb, &range->beg);
  if (range->end.filename)
    {
      if (!same_file (&range->beg, &range->end))
	{
	  stringbuf_add_char (sb, '-');
	  stringbuf_format_locus_point (sb, &range->end);
	}
      else if (range->beg.line != range->end.line)
	{
	  stringbuf_add_char (sb, '-');
	  stringbuf_printf (sb, "%d", range->end.line);
	  if (range->end.col)
	    stringbuf_printf (sb, ".%d", range->end.col);
	}
      else if (range->beg.col && range->beg.col != range->end.col)
	{
	  stringbuf_add_char (sb, '-');
	  stringbuf_printf (sb, "%d", range->end.col);
	}
    }
}

void
vconf_error_at_locus_range (struct locus_range const *loc,
			    char const *fmt, va_list ap)
{
  struct stringbuf sb;

  xstringbuf_init (&sb);
  if (loc && loc->beg.filename)
    {
      stringbuf_format_locus_range (&sb, loc);
      stringbuf_add_string (&sb, ": ");
    }
  stringbuf_vprintf (&sb, fmt, ap);
  cfg_error_msg (sb.base);
  stringbuf_free (&sb);
}

void
conf_error_at_locus_range (struct locus_range const *loc, char const *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  vconf_error_at_locus_range (loc, fmt, ap);
  va_end (ap);
}

void
vconf_error_at_locus_point (struct locus_point const *loc,
			    char const *fmt, va_list ap)
{
  struct stringbuf sb;

  xstringbuf_init (&sb);
  if (loc)
    {
      stringbuf_format_locus_point (&sb, loc);
      stringbuf_add_string (&sb, ": ");
    }
  stringbuf_vprintf (&sb, fmt, ap);
  cfg_error_msg (sb.base);
  stringbuf_free (&sb);
}

void
conf_error_at_locus_point (struct locus_point const *loc, char const *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  vconf_error_at_locus_point (loc, fmt, ap);
  va_end (ap);
}

char const *include_dir = SYSCONFDIR;
WORKDIR *include_wd;

typedef DLIST_HEAD (, workdir) WORKDIR_HEAD;

static WORKDIR_HEAD workdir_head = DLIST_HEAD_INITIALIZER (workdir_head);

static char *
xgetcwd (void)
{
  char *buf = NULL;
  size_t size = 0;

  for (;;)
    {
      buf = x2nrealloc (buf, &size, 1);
      if (getcwd (buf, size) != NULL)
	break;
      if (errno != ERANGE)
	{
	  // FIXME: error locus
	  conf_error_at_locus_point (NULL, "getcwd: %s", strerror (errno));
	  exit (1);
	}
    }
  return buf;
}

WORKDIR *
workdir_get (char const *name)
{
  WORKDIR *wp;
  char *cwd = NULL;
  int fd;

  if (name == NULL)
    {
      cwd = xgetcwd ();
      name = cwd;
    }

  DLIST_FOREACH (wp, &workdir_head, link)
    if (strcmp (wp->name, name) == 0)
      {
	wp->refcount++;
	free (cwd);
	return wp;
      }

  if (cwd)
    fd = AT_FDCWD;
  else
    {
      int dfd = include_wd ? include_wd->fd : AT_FDCWD;
      if ((fd = openat (dfd, name, O_RDONLY | O_NONBLOCK | O_DIRECTORY)) == -1)
	{
	  int ec = errno;
	  free (cwd);
	  errno = ec;
	  return NULL;
	}
    }

  wp = xzalloc (sizeof (*wp) + strlen (name));
  strcpy (wp->name, name);
  wp->refcount = 1;
  wp->fd = fd;
  DLIST_PUSH (&workdir_head, wp, link);
  free (cwd);
  return wp;
}

int
workdir_free (WORKDIR *wd)
{
  if (!wd)
    return 0;
  if (wd->refcount == 0)
    {
      DLIST_REMOVE (&workdir_head, wd, link);
      if (wd->fd != AT_FDCWD)
	close (wd->fd);
      free (wd);
      return 0;
    }
  return 1;
}

int
workdir_cleanup (int keepwd)
{
  WORKDIR *wd, *tmp;
  int cwd = -1;
  DLIST_FOREACH_SAFE (wd, tmp, &workdir_head, link)
    {
      if (workdir_free (wd))
	{
	  if (wd->fd == AT_FDCWD && keepwd)
	    {
	      if (cwd == -1)
		{
		  int fd = openat (wd->fd, ".",
				   O_RDONLY | O_NONBLOCK | O_DIRECTORY);
		  if (fd == -1)
		    {
		      conf_error ("can't open current working directory: %s",
				  strerror (errno));
		      return -1;
		    }
		  cwd = fd;
		}
	      wd->fd = cwd;
	    }
	}
    }
  return 0;
}

void
set_include_wd (WORKDIR *wd)
{
  workdir_free (include_wd);
  include_wd = wd;
}

WORKDIR *
get_include_wd (void)
{
  if (!include_wd)
    {
      include_wd = workdir_get (include_dir);
      if (!include_wd)
	conf_error ("can't open include directory %s: %s",
		    include_dir, strerror (errno));
    }
  return include_wd;
}

int
open_wd (WORKDIR *wd, const char *filename, int flags, mode_t mode)
{
  int dirfd = AT_FDCWD;

  if (!wd)
    wd = include_wd;
  if (wd)
    dirfd = wd->fd;
  return openat (dirfd, filename, flags, mode);
}

FILE *
fopen_wd (WORKDIR *wd, const char *filename)
{
  int fd = open_wd (wd, filename, O_RDONLY, 0);
  if (fd == -1)
    return NULL;
  return fdopen (fd, "r");
}

FILE *
fopen_include (const char *filename)
{
  WORKDIR *wd = get_include_wd ();
  if (!wd)
    return NULL;
  return fopen_wd (wd, filename);
}

char *
filename_resolve (const char *filename)
{
  char *ret;
  if (filename[0] == '/')
    ret = xstrdup (filename);
  else
    {
      WORKDIR *wd = get_include_wd ();
      if (!wd)
	return NULL;
      ret = xmalloc (strlen (wd->name) + strlen (filename) + 2);
      strcat (strcat (strcpy (ret, wd->name), "/"), filename);
    }
  return ret;
}

void
fopen_error (int pri, int ec, WORKDIR *wd, const char *filename,
	     struct locus_range const *loc)
{
  if (filename[0] == '/' || wd == NULL)
    conf_error_at_locus_range (loc, "can't open %s: %s",
			       filename, strerror (ec));
  else
    conf_error_at_locus_range (loc, "can't open %s/%s: %s",
			       wd->name, filename, strerror (ec));
}

int
globat (int wd, const char *restrict pattern, int flags,
	int (*errfunc)(const char *epath, int eerrno),
	glob_t *restrict pglob)
{
  int curfd;
  int ret;

  if (wd == AT_FDCWD)
    curfd = AT_FDCWD;
  else
    {
      curfd = openat (AT_FDCWD, ".", O_DIRECTORY | O_RDONLY | O_NDELAY);
      if (curfd == -1)
	return GLOB_ABORTED;

      if (fchdir (wd))
	{
	  close (curfd);
	  return GLOB_ABORTED;
	}
    }

  ret = glob (pattern, flags, errfunc, pglob);

  if (curfd != AT_FDCWD)
    {
      if (fchdir (curfd))
	{
	  int ec = errno;
	  globfree (pglob);
	  close (curfd);
	  errno = ec;
	  return -1;
	}
      close (curfd);
    }
  return ret;
}

char const *
globstrerror (int rc)
{
  switch (rc)
    {
    case 0:
      return "success";

    case GLOB_NOSPACE:
      return "not enough memory";

    case GLOB_ABORTED:
      return "read error";

    case GLOB_NOMATCH:
      return "no matches found";
    }
  return "unknown error";
}

static char *
fslurp (FILE *fp, char const *filename, struct locus_range const *locus,
	size_t *plen)
{
  struct stat st;
  char *s;

  if (fstat (fileno (fp), &st))
    {
      conf_error_at_locus_range (locus, "can't stat %s: %s", filename,
				 strerror (errno));
      return NULL;
    }
  if (!S_ISREG (st.st_mode))
    {
      conf_error_at_locus_range (locus, "%s: not a regular file", filename);
      return NULL;
    }
  if (st.st_size == 0)
    {
      conf_error_at_locus_range (locus, "%s: empty file", filename);
      return NULL;
    }
  if (st.st_size > (size_t)-1)
    {
      conf_error_at_locus_range (locus, "%s: file too big", filename);
      return NULL;
    }

  s = xmalloc (st.st_size + 1);
  if (fread (s, st.st_size, 1, fp) != 1)
    {
      conf_error_at_locus_range (locus, "%s: read error: %s",
				 filename, strerror (errno));
      free (s);
      return NULL;
    }
  s[st.st_size] = 0;
  if (plen)
    *plen = st.st_size;
  return s;
}

char *
slurp (char const *filename, WORKDIR *wd, struct locus_range const *locus,
       size_t *plen)
{
  FILE *fp;
  char *s;

  if ((fp = fopen_wd (wd, filename)) == NULL)
    {
      fopen_error (LOG_ERR, errno, wd, filename, locus);
      return NULL;
    }
  s = fslurp (fp, filename, locus, plen);
  fclose (fp);
  return s;
}

int
cfg_arglist_getflag (CFG_ARG *arg, CFG_ARG **flarg, CFG_ARG **nextarg)
{
  CFG_FLAG *fdef;

  if (arg == NULL || arg->type != T_FLAG)
    {
      *nextarg = arg;
      return 0;
    }

  fdef = arg->v.flag;
  if (fdef->has_arg)
    {
      arg = cfg_arg_next (arg);
      if (flarg)
	*flarg = arg;
    }
  else if (flarg)
    *flarg = NULL;

  *nextarg = cfg_arg_next (arg);

  return fdef->code;
}

static int
cfg_string_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  *(char **) cfg_rcvr_ptr (&node->rcvr, baseptr) =
    xstrdup (string_ptr (arg->v.string));
  return 0;
}

struct cfg_type cfg_type_string = {
  .argdef = "s",
  .commit = cfg_string_commit
};

struct cfg_type cfg_type_literal = {
  .argdef = "l",
  .commit = cfg_string_commit
};

struct cfg_type cfg_type_lazy_string = {
  .argdef = "[sl]",
  .commit = cfg_string_commit
};

static int
cfg_bool_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  int *ptr = cfg_rcvr_ptr (&node->rcvr, baseptr);
  if (arg->type == T_NUMBER)
    {
      if (arg->v.number != 0 && arg->v.number != 1)
	{
	  conf_error_at_locus_range (&node->locus, "invalid boolean value");
	  conf_error_at_locus_range (&node->locus,
				     "valid booleans are: "
				     "%s for true value, and %s for false value",
				     "1, yes, true, on",
				     "0, no, false, off");
	  return -1;
	}
    }
  *ptr = arg->v.number == 1;
  return 0;
}

struct cfg_type cfg_type_bool = {
  .argdef = "[bn]",
  .commit = cfg_bool_commit
};

static int
cfg_opt_bool_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  if (cfg_arglist_empty (&node->arglist))
    *(int*)cfg_rcvr_ptr (&node->rcvr, baseptr) = 1;
  else
    return cfg_bool_commit (node, unused, baseptr);
  return 0;
}

struct cfg_type cfg_type_opt_bool = {
  .argdef = "[bn]?",
  .commit = cfg_opt_bool_commit
};

int
cfg_assert_range (CFG_ARG *arg, unsigned long min, unsigned long max)
{
  if (arg->v.number < min || arg->v.number > max)
    {
      conf_error_at_locus_range (&arg->locus, "value out of range [%lu..%lu]",
				 min, max);
      return -1;
    }
  return 0;
}

static int
cfg_int_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);

  if (cfg_assert_range (arg, 0, INT_MAX))
    return -1;

  *(int*) cfg_rcvr_ptr (&node->rcvr, baseptr) = arg->v.number;
  return 0;
}

struct cfg_type cfg_type_int = {
  .argdef = "n",
  .commit = cfg_int_commit
};

static int
cfg_uint_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);

  if (cfg_assert_range (arg, 0, UINT_MAX))
    return -1;

  *(unsigned int*) cfg_rcvr_ptr (&node->rcvr, baseptr) = arg->v.number;
  return 0;
}

struct cfg_type cfg_type_uint = {
  .argdef = "n",
  .commit = cfg_uint_commit
};

enum
  {
    ARG_OK = 0,
    ARG_RANGE = -1,
    ARG_SUF = -2
  };

static int
arg_to_size_int (CFG_ARG *arg, uintmax_t maxval, uintmax_t *retval)
{
  uintmax_t val;

  if (arg->type == T_NUMBER)
    {
      if (arg->v.number > maxval)
	return ARG_RANGE;
      val = arg->v.number;
    }
  else
    {
      char const *str = string_ptr (arg->v.string);
      char *p;

      errno = 0;
      val = strtoumax (str, &p, 10);
      if (errno || val > maxval)
	return ARG_RANGE;

      if (*p && p[1])
	return ARG_SUF;

      switch (*p)
	{
	case 'g':
	case 'G':
	  if (maxval / 1024 < val)
	    return ARG_RANGE;
	  val <<= 10;
	case 'm':
	case 'M':
	  if (maxval / 1024 < val)
	    return ARG_RANGE;
	  val <<= 10;
	case 'k':
	case 'K':
	  if (maxval / 1024 < val)
	    return ARG_RANGE;
	  val <<= 10;
	  break;

	default:
	  return ARG_SUF;
	}
    }
  *retval = val;
  return ARG_OK;
}

static int
arg_to_size (CFG_ARG *arg, uintmax_t maxval, uintmax_t *retval)
{
  int rc = arg_to_size_int (arg, maxval, retval);
  switch (rc)
    {
    case ARG_OK:
      break;

    case ARG_RANGE:
      conf_error_at_locus_range (&arg->locus,
				 "value out of range [0.." PRIuMAX "]",
				 maxval);
      break;

    case ARG_SUF:
      conf_error_at_locus_range (&arg->locus, "unrecognized size suffix");
      break;
    }

  return rc;
}

#ifndef SIZE_MAX
# define SIZE_MAX ((size_t)-1)
#endif

static int
cfg_size_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  uintmax_t size;

  if (arg_to_size (cfg_arglist_first (&node->arglist), SIZE_MAX, &size)
      != ARG_OK)
    return -1;
  *(size_t*) cfg_rcvr_ptr (&node->rcvr, baseptr) = size;
  return 0;
}

struct cfg_type cfg_type_size = {
  .argdef = "[nl]",
  .commit = cfg_size_commit
};

static int
cfg_content_length_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  uintmax_t size;

  if (arg_to_size (cfg_arglist_first (&node->arglist), CONTENT_LENGTH_MAX,
		   &size) != ARG_OK)
    return -1;
  *(CONTENT_LENGTH *) cfg_rcvr_ptr (&node->rcvr, baseptr) = size;
  return 0;
}

struct cfg_type cfg_type_content_length = {
  .argdef = "[nl]",
  .commit = cfg_content_length_commit
};

static int
cfg_duration_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  unsigned result = 0;

  if (arg->type == T_NUMBER)
    {
      if (cfg_assert_range (arg, 1, UINT_MAX))
	return -1;
      result = arg->v.number;
    }
  else
    {
      char const *str = string_ptr (arg->v.string);
      struct locus_range loc;
      int rc = 0;

      locus_range_init (&loc);
      locus_point_copy (&loc.beg, &arg->locus.beg);
      locus_point_copy (&loc.end, &arg->locus.beg);

      while (*str)
	{
	  unsigned long n;
	  char *p;
	  errno = 0;
	  n = strtoul (str, &p, 10);
	  if (errno || n > UINT_MAX)
	    {
	      rc = -1;
	      break;
	    }
	  loc.end.col += p - str;

	  switch (*p)
	    {
	    case 0:
	    case 's':
	      break;

	    case 'm':
	      if (UINT_MAX / 60 < n)
		{
		  rc = -1;
		  break;
		}
	      n *= 60;
	      break;

	    case 'h':
	      if (UINT_MAX / 3600 < n)
		{
		  rc = -1;
		  break;
		}
	      n *= 3600;
	      break;

	    case 'd':
	      if (UINT_MAX / 86400 < n)
		{
		  rc = -1;
		  break;
		}
	      n *= 86400;
	      break;

	    default:
	      rc = -1;
	    }

	  if (rc)
	    break;

	  if (UINT_MAX - result < n)
	    {
	      rc = -1;
	      break;
	    }

	  result += n;

	  str = p;
	  if (*str)
	    {
	      str++;
	      loc.end.col++;
	    }
	}
      locus_range_unref (&loc);

      if (rc)
	{
	  conf_error_at_locus_range (&loc, "bad duration");
	  return rc;
	}
    }

  *(unsigned int*) cfg_rcvr_ptr (&node->rcvr, baseptr) = result;
  return 0;
}

struct cfg_type cfg_type_duration = {
  .argdef = "[nl]",
  .commit = cfg_duration_commit
};

static int
commit_ignored (CFG_NODE *node, void *unused, void *baseptr)
{
  conf_error_at_locus_range (&node->locus, "statement ignored");
  return 0;
}

struct cfg_type cfg_type_ignored = {
  .argdef = "[bflns]*",
  .commit = commit_ignored,
};

static int
commit_null (CFG_NODE *node, void *unused, void *baseptr)
{
  return 0;
}

struct cfg_type cfg_type_null = {
  .argdef = "",
  .commit = commit_null,
};

struct cfg_type cfg_type_any = {
  .argdef = ".*",
  .commit = commit_null,
};

static int
commit_port (CFG_NODE *node, void *unused, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  int *port = cfg_rcvr_ptr (&node->rcvr, baseptr);

  if (arg->type == T_NUMBER)
    {
      if (cfg_assert_range (arg, 1, USHRT_MAX))
	return -1;
      *port = htons (arg->v.number);
    }
  else
    {
      struct addrinfo hints, *res;
      int rc;

      memset (&hints, 0, sizeof(hints));
      hints.ai_flags = 0;
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      rc = getaddrinfo (NULL, string_ptr (arg->v.string), &hints, &res);
      if (rc != 0)
	{
	  conf_error_at_locus_range (&arg->locus, "%s", gai_strerror (rc));
	  return -1;
	}

      switch (res->ai_family)
	{
	case AF_INET:
	  *port = ((struct sockaddr_in *)res->ai_addr)->sin_port;
	  break;

	case AF_INET6:
	  *port = ((struct sockaddr_in6 *)res->ai_addr)->sin6_port;
	  break;

	default:
	  conf_error_at_locus_range (&arg->locus, "%s",
				     "Port is supported only for INET/INET6 back-ends");
	  return -1;
	}
      freeaddrinfo (res);
    }
  return 0;
}

struct cfg_type cfg_type_port = {
  .argdef = "[nls]",
  .commit = commit_port
};

static int
commit_port_string (CFG_NODE *node, void *unused, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  char **port_str = cfg_rcvr_ptr (&node->rcvr, baseptr);
  struct stringbuf sb;

  switch (arg->type)
    {
    case T_STRING:
    case T_LITERAL:
      *port_str = xstrdup (string_ptr (arg->v.string));
      break;

    case T_NUMBER:
      xstringbuf_init (&sb);
      stringbuf_printf (&sb, "%lu", arg->v.number);
      *port_str = stringbuf_value (&sb);
      break;

    default:
      abort ();
    }
  return 0;
}

struct cfg_type cfg_type_port_string = {
  .argdef = "[nls]",
  .commit = commit_port_string
};

static int
cfg_node_verify (CFG_NODE *node)
{
  int rc = 0;

  if (node->defn->vtype && node->defn->verify)
    if ((rc = node->defn->verify (node)) != 0)
      return rc;

  switch (node->defn->token)
    {
    case T_CONTROL:
      if (!node->subtree)
	break;
    case T_SECTION:
    case T_NOT:
    case T_REWRITE:
      if ((rc = cfg_ast_verify (node->subtree)) != 0)
	return rc;
      break;

    default:
      assert (node->subtree == NULL);
    }
  return 0;
}

static int
cfg_node_commit (CFG_NODE *node, void *data)
{
  int rc = 0;
  void *baseptr = cfg_rcvr_ptr (&node->rcvr, NULL);

  if (node->defn->vtype)
    {
      if (node->defn->vtype->prepare)
	{
	  rc = node->defn->vtype->prepare (node, data, &baseptr);
	  if (rc)
	    return rc;
	}
    }

  switch (node->defn->token)
    {
    case T_CONTROL:
      if (!node->subtree)
	break;
    case T_SECTION:
    case T_NOT:
    case T_REWRITE:
      if ((rc = cfg_ast_commit (node->subtree, baseptr, data)) != 0)
	return rc;
      break;

    default:
      assert (node->subtree == NULL);
    }

  if (node->defn->commit)
    rc = node->defn->commit (node, data, baseptr);
  else if (node->defn->vtype && node->defn->vtype->commit)
    rc = node->defn->vtype->commit (node, data, baseptr);

  return rc;
}

int
cfg_ast_verify (CFG_AST *ast)
{
  CFG_NODE *node;
  int rc = 0;
  DLIST_FOREACH (node, ast, link)
    {
      if (cfg_node_verify (node))
	rc++;
    }
  return rc;
}

int
cfg_ast_commit (CFG_AST *ast, void *baseptr, void *data)
{
  CFG_NODE *node;
  int rc;

  DLIST_FOREACH (node, ast, link)
    {
      if (baseptr && node->rcvr.data == NULL)
	node->rcvr.data = baseptr;
      if ((rc = cfg_node_commit (node, data)) != 0)
	{
	  if (cfg_debug & CFG_DEBUG_AST)
	    conf_error_at_locus_range (&node->locus, "commit failed");
	  break;
	}
    }
  return rc;
}

CFG_NODE *
cfg_ast_locate_node (CFG_AST *ast, int (*eqf) (CFG_NODE *, void *), void *key)
{
  CFG_NODE *node;
  DLIST_FOREACH (node, ast, link)
    {
      if (eqf (node, key))
	return node;
    }
  return NULL;
}

CFG_NODE *
cfg_node_locate_next (CFG_NODE *node, int (*eqf) (CFG_NODE *, void *), void *key)
{
  while ((node = DLIST_NEXT (node, link)) != NULL)
    {
      if (eqf (node, key))
	return node;
    }
  return NULL;
}

int
cfg_node_defn_eq (CFG_NODE *node, void *key)
{
  return node->defn == key;
}

int
cfg_node_name_eq (CFG_NODE *node, void *key)
{
  return c_strcasecmp (node->defn->name, key) == 0;
}

int
cfg_node_name_memberof (CFG_NODE *node, void *nameset)
{
  char **a = nameset;
  int i;
  for (i = 0; a[i]; i++)
    if (c_strcasecmp (node->defn->name, a[i]) == 0)
      return 1;
  return 0;
}

int
cfg_node_name_not_memberof (CFG_NODE *node, void *nameset)
{
  return !cfg_node_name_memberof (node, nameset);
}

static struct pound_feature *feature_tab;
static size_t feature_count;

void
feature_init (struct pound_feature *ftab)
{
  feature_tab = ftab;
  if (feature_tab)
    {
      feature_tab = ftab;
      for (feature_count = 0; feature_tab[feature_count].name; feature_count++)
	;
    }
  else
    feature_count = 0;
}

int
feature_is_set (int f)
{
  return feature_tab != NULL && f >= 0 && f < feature_count &&
    feature_tab[f].enabled;
}

int
feature_set (char const *name)
{
  int i, enabled = F_ON;
  size_t len;
  char *val;

  if ((val = strchr (name, '=')) != NULL)
    {
      len = val - name;
      val++;
    }
  else
    len = strlen (name);

  if (val == NULL && strncmp (name, "no-", 3) == 0)
    {
      name += 3;
      len -= 3;
      enabled = F_OFF;
    }

  if (*name)
    {
      for (i = 0; feature_tab[i].name; i++)
	{
	  if (strlen (feature_tab[i].name) == len &&
	      memcmp (feature_tab[i].name, name, len) == 0)
	    {
	      if (feature_tab[i].setfn)
		feature_tab[i].setfn (enabled, val);
	      else if (val)
		break;
	      feature_tab[i].enabled = enabled;
	      return 0;
	    }
	}
    }
  return -1;
}

static int
feature_name_cmp (const void *a, const void *b)
{
  int const *ia = a;
  int const *ib = b;
  return strcmp (feature_tab[*ia].name, feature_tab[*ib].name);
}

void
features_print (FILE *fp)
{
  int i;
  int *idx;

  if (!feature_tab)
    return;

  idx = xcalloc (feature_count, sizeof (idx[0]));
  for (i = 0; i < feature_count; i++)
    idx[i] = i;
  qsort (idx, feature_count, sizeof (idx[0]), feature_name_cmp);
  for (i = 0; i < feature_count; i++)
    fprintf (fp, "   %-16s %s\n", feature_tab[idx[i]].name,
	     feature_tab[idx[i]].descr);
  free (idx);
}

void
set_debug_feature (int enabled, char const *val)
{
  enum { DBG_LEX, DBG_GRAM, DBG_AST };
  static char *dbgtok[] = { "lex", "gram", "ast", NULL };
  char *v;
  int i;

  if (enabled)
    {
      char *valstr = xstrdup (val);
      char *valptr = valstr;
      while (*valptr && (i = getsubopt (&valptr, dbgtok, &v)) != -1)
	{
	  switch (i)
	    {
	    case DBG_LEX:
	      cfg_debug |= CFG_DEBUG_LEX;
	      break;

	    case DBG_GRAM:
	      cfg_debug |= CFG_DEBUG_GRAM;
	      break;

	    case DBG_AST:
	      cfg_debug |= CFG_DEBUG_AST;
	      break;

	    default:
	      conf_error_at_locus_point (NULL, "bad debug token: %s", v);
	      exit (1);
	    }
	}
      free (valstr);
    }
  else
    {
      cfg_debug = 0;
    }
}
