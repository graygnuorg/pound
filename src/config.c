/*
 * Pound - the reverse-proxy load-balancer
 * Copyright (C) 2002-2010 Apsis GmbH
 * Copyright (C) 2018-2026 Sergey Poznyakoff
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
#include "resolver.h"
#include <openssl/x509v3.h>
#include <dirent.h>
#include <assert.h>
#include <wordexp.h>

/*
 * Special features.
 */
static void
set_include_dir (char const *fname, int enabled, char const *val)
{
  if (enabled)
    {
      struct stat st;
      if (val && (*val == 0 || strcmp (val, ".") == 0))
	val = NULL;
      else if (stat (val, &st))
	{
	  logmsg (LOG_ERR, "-W%s: can't stat %s: %s", fname, val,
		  strerror (errno));
	  exit (1);
	}
      else if (!S_ISDIR (st.st_mode))
	{
	  logmsg (LOG_ERR, "-W%s: %s is not a directory", fname, val);
	  exit (1);
	}
      include_dir = val;
    }
  else
    include_dir = NULL;
}

static void
set_deprec (char const *fname, int enabled, char const *val)
{
  if (enabled)
    {
      char *v, *valstr, *valptr;
      static char *depopt[] = { "ok", "warn", "err", NULL };
      int n;

      if (!val)
	abend (NULL, "-W%s requires argument", fname);

      valstr = xstrdup (val);
      valptr = valstr;
      n = getsubopt (&valptr, depopt, &v);
      if (n != -1)
	{
	  if (*valptr)
	    abend (NULL, "-W%s: multiple values not allowed", fname);
	  free (valstr);
	  cfg_deprecation_mode = n;
	}
      else
	abend (NULL, "-W%s: bad deprecation token: %s", fname, v);
    }
  else
    cfg_deprecation_mode = DEPREC_ERR;
}

static void
set_deprec_warn (char const *fname, int enabled, char const *val)
{
  if (val)
    abend (NULL, "-W%s: unexpected value (%s)", fname, val);
  cfg_deprecation_mode = enabled ? DEPREC_WARN : DEPREC_OK;
}

static void
enable_preproc (char const *fname, int enabled, char const *val)
{
  if (enabled)
    {
      wordexp_t wexp;

      if (!val)
	abend (NULL, "-W%s requires argument", fname);

      wexp.we_offs = 1;
      switch (wordexp (val, &wexp, WRDE_SHOWERR|WRDE_DOOFFS))
	{
	case 0:
	  break;

	case WRDE_BADCHAR:
	  abend (NULL, "-W%s: bad character encountered", fname);

	case WRDE_SYNTAX:
	  abend (NULL, "-W%s: syntax error", fname);

	case WRDE_NOSPACE:
	  xnomem ();

	default:
	  abend (NULL, "-W%s=%s: can't split", fname, val);
	}
      memmove (wexp.we_wordv, wexp.we_wordv + wexp.we_offs,
	       wexp.we_wordc * sizeof (wexp.we_wordv[0]));
      preproc_argc = wexp.we_wordc;
      preproc_argv = wexp.we_wordv;
    }
}

static struct pound_feature feature[] = {
  [FEATURE_DNS] = {
    .name = "dns",
    .descr = "resolve host names found in configuration file (default)",
    .enabled = F_ON
  },
  [FEATURE_INCLUDE_DIR] = {
    .name = "include-dir",
    .descr = "include file directory",
    .enabled = F_DFL,
    .setfn = set_include_dir
  },
  [FEATURE_WARN_DEPRECATED] = {
    .name = "warn-deprecated",
    .descr = "same as -Wdeprecated=warn",
    .enabled = F_ON,
    .setfn = set_deprec_warn
  },
  [FEATURE_DEPRECATED] = {
    .name = "deprecated",
    .descr = "deprecated features: ok, warn (default), error",
    .enabled = F_DFL,
    .setfn = set_deprec
  },
  [FEATURE_CLOSE_EXTRA_FDS] = {
    .name = "close-extra-fds",
    .descr = "close file descriptors greater than 2 at startup (default)",
    .enabled = F_ON
  },
  [FEATURE_DEBUG] = {
    .name = "debug",
    .descr = "enable additional debugging",
    .enabled = F_OFF,
    .setfn = set_debug_feature
  },
  [FEATURE_PREPROC] = {
    .name = "preprocess",
    .descr = "preprocess configuration files",
    .enabled = F_OFF,
    .setfn = enable_preproc
  },
  { NULL }
};

/*
 * Additional help output.
 */
struct string_value pound_settings[] = {
  { "Configuration file",  STRING_CONSTANT, { .s_const = POUND_CONF } },
  { "Include directory",   STRING_CONSTANT, { .s_const = SYSCONFDIR } },
  { "PID file",   STRING_CONSTANT,  { .s_const = POUND_PID } },
  { "Buffer size",STRING_INT, { .s_int = MAXBUF } },
  { "Regex types", STRING_CONSTANT, { .s_const = "POSIX"
#if HAVE_LIBPCRE == 1
				       ", PCRE"
#elif HAVE_LIBPCRE == 2
				       ", PCRE2"
#endif
    }
  },
  { "Dynamic backends", STRING_CONSTANT, { .s_const =
#if ENABLE_DYNAMIC_BACKENDS
					  "enabled"
#else
					  "disabled"
#endif
    }
  },
  { "FS event monitoring", STRING_CONSTANT, { .s_const =
#if WITH_INOTIFY
				 "inotify"
#elif WITH_KQUEUE
				 "kqueue"
#else
				 "periodic"
#endif
    }
  },
  { "Lua support", STRING_CONSTANT, { .s_const =
#if ENABLE_LUA
				     "enabled"
#else
				     "disabled"
#endif
    }
  },
  { NULL }
};

void
print_help (void)
{
  printf ("usage: %s [-EFVcehv] [-W [no-]FEATURE] [-f FILE] [-p FILE]\n", progname);
  printf ("HTTP/HTTPS reverse-proxy and load-balancer\n");
  printf ("\nOptions are:\n\n");
  printf ("   -c               check configuration file syntax and exit\n");
  printf ("   -E               show preprocessed configuration file and exit\n");
  printf ("   -e               print errors on stderr (implies -F)\n");
  printf ("   -F               remain in foreground after startup\n");
  printf ("   -f FILE          read configuration from FILE\n");
  printf ("                    (default: %s)\n", POUND_CONF);
  printf ("   -p FILE          write PID to FILE\n");
  printf ("                    (default: %s)\n", POUND_PID);
  printf ("   -V               print program version, compilation settings, and exit\n");
  printf ("   -v               print log messages to stdout/stderr during startup\n");
  printf ("   -W [no-]FEATURE  enable or disable optional feature\n");
  printf ("\n");
  printf ("FEATUREs are:\n");
  features_print (stdout);
  printf ("\n");
  printf ("Report bugs and suggestions to <%s>\n", PACKAGE_BUGREPORT);
#ifdef PACKAGE_URL
  printf ("%s home page: <%s>\n", PACKAGE_NAME, PACKAGE_URL);
#endif
}

/*
 * Parse comman line options and configuration file.
 */
static int parse_config_file (char const *file, int nosyslog);

void
config_parse (int argc, char **argv)
{
  int c;
  int check_only = 0;
  char *conf_name = POUND_CONF;
  char *pid_file_option = NULL;
  int foreground_option = 0;
  int stderr_option = 0;
  int preproc_only = 0;

  set_progname (argv[0]);
  feature_init (feature);

  while ((c = getopt (argc, argv, "cEeFf:hp:VvW:")) > 0)
    switch (c)
      {
      case 'c':
	check_only = 1;
	break;

      case 'E':
	preproc_only = 1;
	break;

      case 'e':
	stderr_option = foreground_option = 1;
	setlinebuf (stderr);
	setlinebuf (stdout);
	break;

      case 'F':
	foreground_option = 1;
	break;

      case 'f':
	conf_name = optarg;
	break;

      case 'h':
	print_help ();
	exit (0);

      case 'p':
	pid_file_option = optarg;
	break;

      case 'V':
	print_version (pound_settings);
	exit (0);

      case 'v':
	print_log = 1;
	break;

      case 'W':
	if (feature_set (optarg))
	  {
	    logmsg (LOG_ERR, "invalid feature name: %s", optarg);
	    exit (1);
	  }
	break;

      default:
	exit (1);
      }

  if (optind < argc)
    {
      logmsg (LOG_ERR, "unknown extra arguments (%s...)", argv[optind]);
      exit (1);
    }

  if (preproc_only)
    exit (cfg_lex_preproc (conf_name));

  if (feature_is_set (FEATURE_CLOSE_EXTRA_FDS))
    close_fds_above (2);

  if (parse_config_file (conf_name, stderr_option))
    exit (1);

  if (check_only)
    {
      logmsg (LOG_INFO, "Config file %s is OK", conf_name);
      exit (0);
    }

  if (SLIST_EMPTY (&listeners))
    abend (NULL, "no listeners defined");

  if (pid_file_option)
    pid_name = pid_file_option;
  if (strcmp (pid_name, "-") == 0)
    pid_name = NULL;

  if (foreground_option)
    daemonize = 0;

  if (daemonize)
    {
      if (log_facility == -1)
	log_facility = LOG_DAEMON;
    }
}

/*
 * Additional diagnostic functions.
 */
static void
conf_regcomp_error (struct locus_range const *loc, GENPAT rx, char const *expr)
{
  size_t off;
  char const *errmsg = genpat_error (rx, &off);

  if (off)
    conf_error_at_locus_range (loc, "%s at byte %zu", errmsg, off);
  else
    conf_error_at_locus_range (loc, "%s", errmsg);
  if (expr)
    conf_error_at_locus_range (loc, "regular expression: %s", expr);
}

static void
conf_openssl_error (struct locus_range const *loc,
		    char const *filename, char const *msg)
{
  unsigned long n = ERR_get_error ();
  if (filename)
    conf_error_at_locus_range (loc, "%s: %s: %s", filename, msg,
			       ERR_error_string (n, NULL));
  else
    conf_error_at_locus_range (loc, "%s: %s", msg, ERR_error_string (n, NULL));

  if ((n = ERR_get_error ()) != 0)
    {
      do
	{
	  conf_error_at_locus_range (loc, "%s", ERR_error_string (n, NULL));
	}
      while ((n = ERR_get_error ()) != 0);
    }
}

/*
 * Named backend table.
 */
typedef struct named_backend
{
  char *name;
  struct locus_range locus;
  int priority;
  int disabled;
  struct be_matrix bemtx;
  SLIST_ENTRY (named_backend) link;
} NAMED_BACKEND;

#define HT_TYPE NAMED_BACKEND
#include "ht.h"

typedef struct named_backend_table
{
  NAMED_BACKEND_HASH *hash;
  SLIST_HEAD(,named_backend) head;
} NAMED_BACKEND_TABLE;

static void
named_backend_table_init (NAMED_BACKEND_TABLE *tab)
{
  tab->hash = NAMED_BACKEND_HASH_NEW ();
  SLIST_INIT (&tab->head);
}

static void
named_backend_table_free (NAMED_BACKEND_TABLE *tab)
{
  NAMED_BACKEND_HASH_FREE (tab->hash);
  while (!SLIST_EMPTY (&tab->head))
    {
      NAMED_BACKEND *ent = SLIST_FIRST (&tab->head);
      SLIST_SHIFT (&tab->head, link);
      free (ent);
    }
}

static NAMED_BACKEND *
named_backend_insert (NAMED_BACKEND_TABLE *tab, char const *name, BACKEND *be)
{
  NAMED_BACKEND *bp, *old;

  bp = xmalloc (sizeof (*bp) + strlen (name) + 1);
  bp->name = (char*) (bp + 1);
  strcpy (bp->name, name);
  locus_range_init (&bp->locus);
  locus_range_copy (&bp->locus, &be->locus);
  bp->priority = be->priority;
  bp->disabled = be->disabled;
  bp->bemtx = be->v.mtx;
  if ((old = NAMED_BACKEND_INSERT (tab->hash, bp)) != NULL)
    {
      free (bp);
      return old;
    }
  SLIST_PUSH (&tab->head, bp, link);
  return NULL;
}

static NAMED_BACKEND *
named_backend_retrieve (NAMED_BACKEND_TABLE *tab, char const *name)
{
  NAMED_BACKEND key;

  key.name = (char*) name;
  return NAMED_BACKEND_RETRIEVE (tab->hash, &key);
}

/* Pound defaults structure. */
typedef struct
{
  int log_level;
  int facility;
  unsigned clnt_to;
  unsigned be_to;
  unsigned ws_to;
  unsigned be_connto;
  unsigned ignore_case;
  int re_type;
  int header_options;
  BALANCER_ALGO balancer_algo;
  NAMED_BACKEND_TABLE named_backend_table;
  struct resolver_config resolver;
  size_t linebufsize;
} POUND_DEFAULTS;

/* Codes for the most often used flags. */
enum
  {
    FLG_WATCHER = 1,
    FLG_FWD,
    FLG_FILE,
    FLG_FILEWATCH,
    FLG_TRIM
  };

/*
 * Node verification functions.
 */

/* Check if first argument is in range [0..INT_MAX] */
static int
verify_range_nonnegative_int (CFG_NODE *node)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  return cfg_assert_range (arg, 0, INT_MAX);
}

/* Check if first argument is in range [1..INT_MAX] */
static int
verify_range_positive_int (CFG_NODE *node)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  return cfg_assert_range (arg, 1, INT_MAX);
}

/* Threads statement (deprecated). */
static int
cfg_threads_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);

  if (cfg_assert_range (arg, 1, UINT_MAX))
    return -1;

  worker_min_count = worker_max_count = arg->v.number;
  return 0;
}

/* ConnectionQueueSize N */
static int
cfg_connqsize_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  pound_http_set_qsize (arg->v.number);
  return 0;
}

/* ReserveFD [-watcher] N */
static int
commit_reserve_fd (CFG_NODE *node, void *unused, void *baseptr)
{
  int per_watcher;
  CFG_ARG *arg;

  per_watcher = cfg_arglist_getflag (cfg_arglist_first (&node->arglist),
				     NULL, &arg);
  if (per_watcher == -1)
    return -1;
  if (cfg_assert_range (arg, 0, UINT_MAX))
    return -1;

  if (per_watcher)
    {
      if (cfg_assert_range (arg, 0, INT_MAX - per_worker_fds))
	return -1;
      per_worker_fds += arg->v.number;
    }
  else
    {
      if (cfg_assert_range (arg, 0, INT_MAX - num_reserved_fds))
	return -1;
      num_reserved_fds += arg->v.number;
    }
  return 0;
}

static CFG_FLAG reserve_fd_flagdef[] = {
    { "watcher", FLG_WATCHER },
    { NULL }
};

struct cfg_type cfg_type_reserve_fd = {
  .argdef = "f?n",
  .flagdef = reserve_fd_flagdef,
  .commit = commit_reserve_fd
};

/* Syslog facilities. */
static struct kwtab facility_table[] = {
  { "auth", LOG_AUTH },
#ifdef  LOG_AUTHPRIV
  { "authpriv", LOG_AUTHPRIV },
#endif
  { "cron", LOG_CRON },
  { "daemon", LOG_DAEMON },
#ifdef  LOG_FTP
  { "ftp", LOG_FTP },
#endif
  { "kern", LOG_KERN },
  { "lpr", LOG_LPR },
  { "mail", LOG_MAIL },
  { "news", LOG_NEWS },
  { "syslog", LOG_SYSLOG },
  { "user", LOG_USER },
  { "uucp", LOG_UUCP },
  { "local0", LOG_LOCAL0 },
  { "local1", LOG_LOCAL1 },
  { "local2", LOG_LOCAL2 },
  { "local3", LOG_LOCAL3 },
  { "local4", LOG_LOCAL4 },
  { "local5", LOG_LOCAL5 },
  { "local6", LOG_LOCAL6 },
  { "local7", LOG_LOCAL7 },
  { NULL }
};

/* LogFacility NAME */
static int
commit_logfacility (CFG_NODE *node, void *unused, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  int *ptr = cfg_rcvr_ptr (&node->rcvr, baseptr);

  if (arg->type == T_NUMBER)
    {
      if (cfg_assert_range (arg, 0, INT_MAX))
	return -1;
      *ptr = arg->v.number;
    }
  else /* string or literal */
    {
      char const *str = string_ptr (arg->v.string);
      int n;

      if (strcmp (str, "-") == 0)
	n = -1;
      else if (kw_to_tok (facility_table, str, 1, &n) != 0)
	{
	  conf_error_at_locus_range (&arg->locus, "unknown log facility name");
	  return -1;
	}
      *ptr = n;
    }
  return 0;
}

struct cfg_type cfg_type_logfacility = {
  .argdef = "[lsn]",
  .commit = commit_logfacility
};

/*
 * LogLevel N
 * LogLevel STR
 */
static int
commit_loglevel (CFG_NODE *node, void *unused,  void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  int *ptr = cfg_rcvr_ptr (&node->rcvr, baseptr);
  int level;

  if (arg->type == T_STRING)
    {
      level = http_log_format_find (string_ptr (arg->v.string));
      if (level == -1)
	{
	  conf_error_at_locus_range (&arg->locus, "undefined format");
	  return -1;
	}
    }
  else
    {
      level = arg->v.number;
      if (arg->v.number > INT_MAX || http_log_format_check (level))
	{
	  conf_error_at_locus_range (&arg->locus, "undefined log level");
	  return -1;
	}
    }
  *ptr = level;
  return 0;
}

struct cfg_type cfg_type_loglevel = {
  .argdef = "[sn]",
  .commit = commit_loglevel
};

/* Canned (i.e. predefined) log formats. */

struct canned_log_format
{
  char *name;  /* Format name. */
  char *fmt;   /* Format specification. */
  int line;    /* Source line to prepare a locus structure for diagnostics. */
};

static struct canned_log_format canned_log_format[] = {
  /* 0 - not used */
  { "null", "", __LINE__ },
  /* 1 - regular logging */
  {
    "regular",
    "%a %r - %>s",
    __LINE__
  },
  /* 2 - extended logging (show chosen backend server as well) */
  {
    "extended",
    "%a %r - %>s (%{Host}i/%{service}N -> %{backend}N) %{f}T sec",
    __LINE__
  },
  /* 3 - Apache-like format (Combined Log Format with Virtual Host) */
  {
    "vhost_combined",
    "%v:%p %a %l %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i\"",
    __LINE__
  },
  /* 4 - same as 3 but without the virtual host information */
  { "combined",
    "%a %l %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i\"",
    __LINE__
  },
  /* 5 - same as 3 but with information about the Service and Backend used */
  { "detailed",
    "%v:%p %a %l %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i\""
    " (%{service}N -> %{backend}N) %{f}T sec",
    __LINE__
  }
};
static int max_canned_log_format =
  sizeof (canned_log_format) / sizeof (canned_log_format[0]);

struct log_format_data
{
  struct locus_range locus;
  int fn;
  int fatal;
};

static void
log_format_diag (void *data, int fatal, char const *msg, int off)
{
  struct log_format_data *ld = data;
  if (ld->fn == -1)
    {
      struct locus_range loc = ld->locus;
      loc.beg.col += off;
      loc.end = loc.beg;
      conf_error_at_locus_range (&loc, "%s", msg);
    }
  else
    {
      conf_error_at_locus_range (&ld->locus,
				 "INTERNAL ERROR: error compiling built-in format %d", ld->fn);
      conf_error_at_locus_range (&ld->locus, "%s: near %s", msg,
				 canned_log_format[ld->fn].fmt + off);
      conf_error_at_locus_range (&ld->locus, "please report");
    }
  ld->fatal = fatal;
}

static void
compile_canned_formats (void)
{
  struct log_format_data ld;
  int i;

  ld.locus.beg.filename = string_init (__FILE__);
  ld.locus.end.filename = ld.locus.beg.filename;
  ld.fatal = 0;

  for (i = 0; i < max_canned_log_format; i++)
    {
      ld.fn = i;
      ld.locus.beg.line = ld.locus.end.line = canned_log_format[i].line;
      ld.locus.beg.col = 5;
      ld.locus.end.col = ld.locus.beg.col + strlen (canned_log_format[i].fmt);
      if (http_log_format_compile (canned_log_format[i].name,
				   canned_log_format[i].fmt,
				   log_format_diag, &ld) == -1 || ld.fatal)
	exit (1);
    }
  string_unref (ld.locus.beg.filename);
}

/* LogFormat "NAME" "DEFN" */
static int
commit_logformat (CFG_NODE *node, void *unused, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  char const *name, *format;
  struct log_format_data ld;

  name = string_ptr (arg->v.string);
  arg = cfg_arg_next (arg);
  format = string_ptr (arg->v.string);

  ld.locus = arg->locus;
  ld.locus.beg.col++;
  ld.locus.end.col--;
  ld.fn = -1;
  ld.fatal = 0;

  if (http_log_format_compile (name, format, log_format_diag, &ld) == -1 ||
      ld.fatal)
    return -1;

  return 0;
}

struct cfg_type cfg_type_logformat = {
  .argdef = "[sl]s",
  .commit = commit_logformat
};

/* HeaderOption OPT... */
static int
commit_headeroptions (CFG_NODE *node, void *unused, void *baseptr)
{
  CFG_ARG *arg;
  int *ptr = cfg_rcvr_ptr (&node->rcvr, baseptr);
  int opt = *ptr;

  static struct kwtab options[] = {
    { "forwarded", HDROPT_FORWARDED_HEADERS },
    { "ssl",       HDROPT_SSL_HEADERS },
    { "all",       HDROPT_FORWARDED_HEADERS|HDROPT_SSL_HEADERS },
    { NULL }
  };

  CFG_ARG_FOREACH (arg, &node->arglist)
    {
      char const *name = string_ptr (arg->v.string);

      if (c_strcasecmp (name, "none") == 0)
	opt = 0;
      else
	{
	  int neg, n;

	  if (c_strncasecmp (name, "no-", 3) == 0)
	    {
	      neg = 1;
	      name += 3;
	    }
	  else
	    neg = 0;

	  if (kw_to_tok (options, name, 1, &n))
	    {
	      conf_error_at_locus_range (&arg->locus, "unknown option");
	      return -1;
	    }

	  if (neg)
	    opt &= ~n;
	  else
	    opt |= n;
	}
    }
  *ptr = opt;
  return 0;
}

struct cfg_type cfg_type_headeroptions = {
  .argdef = "[sl]+",
  .commit = commit_headeroptions
};

/* Balancer ALGO */
static int
commit_balancer (CFG_NODE *node, void *unused, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  static struct kwtab btab[] = {
    { "random", BALANCER_ALGO_RANDOM },
    { "iwrr", BALANCER_ALGO_IWRR },
    { NULL }
  };
  int n;
  BALANCER_ALGO *ptr = cfg_rcvr_ptr (&node->rcvr, baseptr);

  if (kw_to_tok (btab, string_ptr (arg->v.string), 1, &n))
    {
      conf_error_at_locus_range (&arg->locus,
				 "unsupported balancing strategy");
      return -1;
    }
  *ptr = n;
  return 0;
}

struct cfg_type cfg_type_balancer = {
  .argdef = "[sl]",
  .commit = commit_balancer
};

/* (ListenHTTPS) Cert "NAME" */
static int
cfg_cert_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  X509 **x509_ptr = baseptr, *cert;
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  char const *filename = string_ptr (arg->v.string);
  FILE *fp;

  if ((fp = fopen_include (filename)) == NULL)
    {
      fopen_error (LOG_ERR, errno, include_wd, filename, &arg->locus);
      return -1;
    }
  cert = PEM_read_X509 (fp, NULL, NULL, NULL);
  fclose (fp);
  if (cert == NULL)
    {
      conf_openssl_error (&arg->locus, filename, "can't load certificate");
      return -1;
    }
  *x509_ptr = cert;

  return 0;
}

struct cfg_type cfg_type_cert = {
  .argdef = "s",
  .commit = cfg_cert_commit
};

/* SSLEngine "NAME" */
static int
commit_sslengine (CFG_NODE *node, void *unused, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  char const *str = string_ptr (arg->v.string);
#if HAVE_OPENSSL_ENGINE_H && OPENSSL_VERSION_MAJOR < 3
  ENGINE *e;

  if (!(e = ENGINE_by_id (str)))
    {
      conf_error_at_locus_range (&arg->locus, "unrecognized engine");
      return -1;
    }

  if (!ENGINE_init (e))
    {
      ENGINE_free (e);
      conf_error_at_locus_range (&arg->locus, "could not init engine");
      return -1;
    }

  if (!ENGINE_set_default (e, ENGINE_METHOD_ALL))
    {
      ENGINE_free (e);
      conf_error_at_locus_range (&arg->locus, "could not set all defaults");
    }

  ENGINE_finish (e);
  ENGINE_free (e);
#else
  conf_error_at_locus_range (&arg->locus, "statement ignored");
#endif

  return -1;
}

/* RegexType TYPE */
static int
commit_regex_type (CFG_NODE *node, void *unused, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  int *ptr = cfg_rcvr_ptr (&node->rcvr, baseptr);
  int n;

  static struct kwtab regex_type_table[] = {
    { "posix", GENPAT_POSIX },
#ifdef HAVE_LIBPCRE
    { "pcre",  GENPAT_PCRE },
    { "perl",  GENPAT_PCRE },
#endif
    { NULL }
  };

  if (kw_to_tok (regex_type_table, string_ptr (arg->v.string), 1, &n))
    {
      conf_error_at_locus_range (&arg->locus, "unrecognized regex type");
      return -1;
    }
  *ptr = n;
  return 0;
}

/*
 * Backends
 */

/* Family NAME */
static int
commit_address_family (CFG_NODE *node, void *unused, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  int *ptr = cfg_rcvr_ptr (&node->rcvr, baseptr);
  int n;

  static struct kwtab kwtab[] = {
    { "any",  AF_UNSPEC },
    { "unix", AF_UNIX },
    { "inet", AF_INET },
    { "inet6", AF_INET6 },
    { NULL }
  };

  if (kw_to_tok (kwtab, string_ptr (arg->v.string), 1, &n))
    {
      conf_error_at_locus_range (&arg->locus, "unsupported address family");
      return -1;
    }
  *ptr = n;
  return 0;
}

static struct kwtab resolve_mode_kwtab[] = {
  { "immediate", bres_immediate },
  { "first", bres_first },
  { "all", bres_all },
  { "srv", bres_srv },
  { NULL }
};

char const *
resolve_mode_str (int mode)
{
  char const *ret = kw_to_str (resolve_mode_kwtab, mode);
  return ret ? ret : "UNKNOWN";
}

/* Resolve TYPE */
static int
commit_resolve_mode (CFG_NODE *node, void *unused, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  int *ptr = cfg_rcvr_ptr (&node->rcvr, baseptr);
  int n;

  if (kw_to_tok (resolve_mode_kwtab, string_ptr (arg->v.string), 1, &n))
    {
      conf_error_at_locus_range (&arg->locus, "unsupported resolve mode");
      return -1;
    }

#ifndef ENABLE_DYNAMIC_BACKENDS
  if (n != bres_immediate)
    {
      conf_error_at_locus_range (&arg->locus,
				 "value not supported;"
				 " pound compiled without support"
				 " for dynamic backends");
      return -1;
    }
#endif
  *ptr = n;
  return 0;
}

static int
cfg_commit_null (CFG_NODE *node, void *call_data, void *baseptr)
{
  return 0;
}

BACKEND *
backend_create (BACKEND_TYPE type, int prio, struct locus_range const *loc)
{
  BACKEND *be = calloc (1, sizeof (*be));
  if (be)
    {
      be->be_type = type;
      be->priority = prio;
      pthread_mutex_init (&be->mut, &mutex_attr_recursive);
      locus_range_init (&be->locus);
      if (loc)
	locus_range_copy (&be->locus, loc);
      backend_refcount_init (be);
    }
  return be;
}

static BACKEND *
xbackend_create (BACKEND_TYPE type, int prio, struct locus_range const *loc)
{
  BACKEND *be = backend_create (type, prio, loc);
  if (!be)
    xnomem ();
  return be;
}

/* (Backend) Cert "FILE" */
static int
commit_backend_cert (CFG_NODE *node, void *unused, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  BACKEND *be = cfg_rcvr_ptr (&node->rcvr, baseptr);
  char *filename;

  if ((filename = filename_resolve (string_ptr (arg->v.string))) == NULL)
    return -1;

  if (SSL_CTX_use_certificate_chain_file (be->v.mtx.ctx, filename) != 1)
    {
      conf_openssl_error (&arg->locus, filename,
			  "SSL_CTX_use_certificate_chain_file");
      return -1;
    }

  if (SSL_CTX_use_PrivateKey_file (be->v.mtx.ctx, filename, SSL_FILETYPE_PEM)
      != 1)
    {
      conf_openssl_error (&arg->locus, filename,
			  "SSL_CTX_use_PrivateKey_file");
      return -1;
    }

  if (SSL_CTX_check_private_key (be->v.mtx.ctx) != 1)
    {
      conf_openssl_error (&arg->locus, filename,
			  "SSL_CTX_check_private_key failed");
      return -1;
    }
  free (filename);

  return 0;
}

/*
 * Ciphers [TYPEOPT] "CIPHERS"
 *
 * Used in: ListenHTTPS, Backend
 */
enum {
  CIPHER_LIST = 1,
  CIPHER_SUITES
};

static char const *cipherset_str[] = { NULL, "cipher list", "ciphersuites" };

static int
set_ciphers (SSL_CTX *ctx, int opt, char const *str)
{
  switch (opt)
    {
    case CIPHER_LIST:
      return SSL_CTX_set_cipher_list (ctx, str);

    case CIPHER_SUITES:
      return SSL_CTX_set_ciphersuites (ctx, str);
    }
  abort ();
}

static CFG_FLAG cipherflagdef[] = {
  { "ciphersuites", CIPHER_SUITES, 1 },
  { "cipherlist", CIPHER_LIST, 1 },
  { NULL }
};

static int
gen_ciphers_commit (CFG_ARG *arg, int (*setc)(void *, int, char const *),
		    void *data)
{
  int copt = CIPHER_LIST;

  while (arg)
    {
      char const *str;
      CFG_ARG *ap;
      int n = cfg_arglist_getflag (arg, &ap, &arg);
      if (n > 0)
	{
	  copt = n;
	  if (!(ap->type == T_STRING || ap->type == T_LITERAL))
	    {
	      conf_error_at_locus_range (&ap->locus, "bad argument");
	      return -1;
	    }
	  str = string_ptr (ap->v.string);
	}
      else if (arg)
	{
	  ap = arg;
	  str = string_ptr (ap->v.string);
	  arg = cfg_arg_next (arg);
	}

      if (setc (data, copt, str) == 0)
	{
	  conf_error_at_locus_range (&ap->locus,
				     "failed to set %s %s",
				     cipherset_str[copt], str);
	  return -1;
	}
    }
  return 0;
}

static int
be_set_ciphers (void *ptr, int opt, char const *str)
{
  BACKEND *be = ptr;
  return set_ciphers (be->v.mtx.ctx, opt, str);
}

/* (Backend) Ciphers [TYPEOPT] "CIPHERS" ... */
static int
backend_ciphers_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  BACKEND *be = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  return gen_ciphers_commit (arg, be_set_ciphers, be);
}

static CFG_TYPE cfg_type_backend_ciphers = {
  .argdef = "[fsl]+",
  .flagdef = cipherflagdef,
  .commit = backend_ciphers_commit
};

static int
lst_set_ciphers (void *ptr, int opt, char const *str)
{
  LISTENER *lst = ptr;
  POUND_CTX *pc;

  SLIST_FOREACH (pc, &lst->ctx_head, next)
    {
      if (set_ciphers (pc->ctx, opt, str) == 0)
	return 0;
    }
  return 1;
}

/* (ListenHTTPS) Ciphers [TYPEOPT] "CIPHERS" ... */
static int
lst_ciphers_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  LISTENER *lst = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  return gen_ciphers_commit (arg, lst_set_ciphers, lst);
}

static CFG_TYPE cfg_type_lst_ciphers = {
  .argdef = "[fls]+",
  .flagdef = cipherflagdef,
  .commit = lst_ciphers_commit
};

/* (Backend) Disable PROTO */
static int
commit_disable_proto (CFG_NODE *node, void *unused, void *baseptr)
{
  SSL_CTX *ctx = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  int opt;

  static struct kwtab kwtab[] = {
    { "SSLv2", SSL_OP_NO_SSLv2 },
    { "SSLv3", SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 },
#ifdef SSL_OP_NO_TLSv1
    { "TLSv1", SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 },
#endif
#ifdef SSL_OP_NO_TLSv1_1
    { "TLSv1_1", SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
		 SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 },
#endif
#ifdef SSL_OP_NO_TLSv1_2
    { "TLSv1_2", SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
		 SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
		 SSL_OP_NO_TLSv1_2 },
#endif
    { NULL }
  };

  if (kw_to_tok (kwtab, string_ptr (arg->v.string), 1, &opt))
    {
      conf_error_at_locus_range (&arg->locus, "unknown protocol");
      return -1;
    }

  SSL_CTX_set_options (ctx, opt);

  return 0;
}

/*
 * Definitions of directives common for all Backend statements.
 */
static CFG_DEFN common_backend_defn[] = {
  {
    .name = "Address",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_LAZY_STRING,
    .rcvr = {
      .off = offsetof (BACKEND, v.mtx.hostname)
    }
  },
  {
    .name = "Port",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_PORT,
    .rcvr = {
      .off = offsetof (BACKEND, v.mtx.port)
    }
  },
  {
    .name = "Family",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_LITERAL,
    .commit = commit_address_family,
    .rcvr = {
      .off = offsetof (BACKEND, v.mtx.family)
    }
  },
  {
    .name = "Resolve",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_LITERAL,
    .commit = commit_resolve_mode,
    .rcvr = {
      .off = offsetof (BACKEND, v.mtx.resolve_mode)
    },
  },

  {
    .name = "IgnoreSRVWeight",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_BOOL,
    .rcvr = {
      .off = offsetof (BACKEND, v.mtx.ignore_srv_weight)
    },
  },
  {
    .name = "OverrideTTL",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_DURATION,
    .rcvr = {
      .off = offsetof (BACKEND, v.mtx.override_ttl)
    }
  },
  {
    .name = "RetryInterval",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_DURATION,
    .rcvr = {
      .off = offsetof (BACKEND, v.mtx.retry_interval)
    }
  },
  {
    .name = "Priority",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_INT,
    .rcvr = {
      .off = offsetof (BACKEND, priority)
    }
  },
  {
    .name = "TimeOut",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_DURATION,
    .rcvr = {
      .off = offsetof (BACKEND, v.mtx.to)
    }
  },
  {
    .name = "WSTimeOut",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_DURATION,
    .rcvr = {
      .off = offsetof (BACKEND, v.mtx.ws_to)
    }
  },
  {
    .name = "ConnTO",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_DURATION,
    .rcvr = {
      .off = offsetof (BACKEND, v.mtx.conn_to)
    }
  },
  {
    .name = "HTTPS",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_OPT_BOOL,
    .commit = cfg_commit_null
  },
  {
    .name = "Cert",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = commit_backend_cert
  },
  {
    .name = "Ciphers",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_backend_ciphers,
  },
  {
    .name = "Disable",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_LAZY_STRING,
    .commit = commit_disable_proto,
    .rcvr = {
      .off = offsetof (BACKEND, v.mtx.ctx)
    }
  },
  {
    .name = "Disabled",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_BOOL,
    .rcvr = {
      .off = offsetof (BACKEND, disabled)
    }
  },
  {
    .name = "ServerName",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .rcvr = {
      .off = offsetof (BACKEND, v.mtx.servername)
    }
  },
  { NULL }
};

static char *https_kw[] = { "Cert", "Ciphers", "Disable", NULL };

/*
 * Prepare backend for HTTPS I/O.
 */
static int
backend_prepare_https (BACKEND *be)
{
  struct stringbuf sb;

  if ((be->v.mtx.ctx = SSL_CTX_new (SSLv23_client_method ())) == NULL)
    {
      conf_openssl_error (&be->locus, NULL, "SSL_CTX_new");
      return -1;
    }

  SSL_CTX_set_app_data (be->v.mtx.ctx, be);
  SSL_CTX_set_verify (be->v.mtx.ctx, SSL_VERIFY_NONE, NULL);
  SSL_CTX_set_mode (be->v.mtx.ctx, SSL_MODE_AUTO_RETRY);
#ifdef SSL_MODE_SEND_FALLBACK_SCSV
  SSL_CTX_set_mode (be->v.mtx.ctx, SSL_MODE_SEND_FALLBACK_SCSV);
#endif
  SSL_CTX_set_options (be->v.mtx.ctx, SSL_OP_ALL);
#ifdef  SSL_OP_NO_COMPRESSION
  SSL_CTX_set_options (be->v.mtx.ctx, SSL_OP_NO_COMPRESSION);
#endif
  SSL_CTX_clear_options (be->v.mtx.ctx,
			 SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
  SSL_CTX_clear_options (be->v.mtx.ctx, SSL_OP_LEGACY_SERVER_CONNECT);

  xstringbuf_init (&sb);
  stringbuf_printf (&sb, "%d-Pound-%ld", getpid (), random ());
  SSL_CTX_set_session_id_context (be->v.mtx.ctx,
				  (unsigned char *) stringbuf_value (&sb),
				  stringbuf_len (&sb));
  stringbuf_free (&sb);

  POUND_SSL_CTX_init (be->v.mtx.ctx);

  return 0;
}

/* Create and initialize a backend reference. */
static BACKEND *
backend_ref_init (CFG_ARG *arg, CFG_NODE *node)
{
  BACKEND *be = xbackend_create (BE_BACKEND_REF, -1, NULL);
  if (!be)
    return NULL;
  be->v.be_name = xstrdup (string_ptr (arg->v.string));
  be->disabled = -1;
  locus_range_init (&be->locus);
  locus_range_copy (&be->locus, &node->locus);
  return be;
}

static char *beref_allowed[] = { "Use", "Priority", "Disabled", NULL };

static int
check_beref_allowed (CFG_NODE *node)
{
  CFG_NODE *np = cfg_ast_locate_node (node->subtree,
				      cfg_node_name_not_memberof,
				      beref_allowed);
  if (np)
    {
      while (np)
	{
	  conf_error_at_locus_range (&np->locus,
				     "statement cannot be used in backend reference");
	  np = cfg_node_locate_next (np, cfg_node_name_not_memberof,
				     beref_allowed);
	}
      return -1;
    }
  return 0;
}

/*
 * Create and initialize a backend as described in node. Take default values
 * from dfl.
 */
static BACKEND *
backend_init (CFG_NODE *node, POUND_DEFAULTS *dfl)
{
  CFG_NODE *ub;
  BACKEND *be;

  ub = cfg_ast_locate_node (node->subtree, cfg_node_name_eq, "Use");
  if (ub)
    {
      CFG_ARG *arg;
      if (check_beref_allowed (node))
	return NULL;
      arg = cfg_arglist_first (&ub->arglist);
      be = backend_ref_init (arg, node);
    }
  else
    {
      CFG_NODE *https;
      int is_https = 0;

      be = xbackend_create (BE_MATRIX, 5, NULL);
      be->v.mtx.to = dfl->be_to;
      be->v.mtx.conn_to = dfl->be_connto;
      be->v.mtx.ws_to = dfl->ws_to;

      https = cfg_ast_locate_node (node->subtree, cfg_node_name_eq, "HTTPS");
      if (https)
	{
	  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
	  is_https = arg == NULL || arg->v.number != 0;
	}
      if (cfg_ast_locate_node (node->subtree, cfg_node_name_memberof,
			       https_kw))
	is_https = 1;

      if (is_https)
	{
	  if (backend_prepare_https (be))
	    // FIXME: free be
	    return NULL;
	}

      locus_range_init (&be->locus);
      locus_range_copy (&be->locus, &node->locus);
    }

  return be;
}

/*
 * Create a backend as described by node and call_data, pointing to
 * a POUND_DEFAULTS. On success store the backend in *baseptr. Set
 * node->data to point to NAMED_BACKEND_TABLE, passed in the rcvr.
 */
static int
named_backend_prepare (CFG_NODE *node, void *call_data, void **baseptr)
{
  POUND_DEFAULTS *dfl = call_data;
  BACKEND *be;
  NAMED_BACKEND *olddef;
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);

  if (!arg)
    {
      conf_error_at_locus_range (&node->locus, "tag is missing");
      return -1;
    }

  olddef = named_backend_retrieve (&dfl->named_backend_table,
				   string_ptr (arg->v.string));
  if (olddef)
    {
      conf_error_at_locus_range (&node->locus,
				 "redefinition of named backend %s",
				 olddef->name);
      conf_error_at_locus_range (&olddef->locus,
				 "original definition was here");
      return -1;
    }

  be = backend_init (node, dfl);
  if (!be)
    return -1;

  *baseptr = be;

  return 0;
}

/* Commit a named backend passed in baseptr. */
static int
named_backend_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  POUND_DEFAULTS *dfl = call_data;
  BACKEND *be = baseptr;
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);

  named_backend_insert (&dfl->named_backend_table,
			string_ptr (arg->v.string), be);
  return 0;
}

/* Free a half-constructed backend structure. This function is invoked
   only if an error occurred while parsing the backend statement. */
static void
backend_free (void *data)
{
  BACKEND *be = data;

  switch (be->be_type)
    {
    case BE_MATRIX:
      free (be->v.mtx.hostname);
      if (be->v.mtx.ctx)
	SSL_CTX_free (be->v.mtx.ctx);
      break;

    case BE_BACKEND_REF:
      free (be->v.be_name);
      break;

    default:
      break;
    }

  free (be);
}

struct cfg_type cfg_type_named_backend = {
  .argdef = "s",
  .prepare = named_backend_prepare,
  .commit = named_backend_commit,
};

/*
 * Service backends.
 */

/* Prepare a service backend and store it in *baseptr. Set node->data to
   point to it. */
static int
service_backend_prepare (CFG_NODE *node, void *call_data, void **baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  BACKEND *be;

  if (arg)
    {
      CFG_NODE *ub;

      if (cfg_deprecation_mode)
	{
	  conf_error_at_locus_range (&arg->locus,
				     "referring to a named backend by tagged"
				     " Backend statement is deprecated; use"
				     " the 'Use \"%s\"' statement instead",
				     string_ptr (arg->v.string));
	  if (cfg_deprecation_mode == DEPREC_ERR)
	    return -1;
	}

      ub = cfg_ast_locate_node (node->subtree, cfg_node_name_eq, "Use");
      if (ub)
	{
	  conf_error_at_locus_range (&arg->locus,
				     "this backend uses both deprecated"
				     " reference style and the Use statement");
	  conf_error_at_locus_range (&ub->locus, "duplicate reference here");
	  return -1;
	}
      if (check_beref_allowed (node))
	return -1;

      be = backend_ref_init (arg, node);
    }
  else
    be = backend_init (node, call_data);

  if (!be)
    return -1;

  *baseptr = be;
  /* Make sure it will be freed on error. */
  node->data = be;

  return 0;
}

static int
service_backend_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  BACKEND *be = node->data;
  BALANCER_LIST *bml = cfg_rcvr_ptr (&node->rcvr, baseptr);
  balancer_add_backend (balancer_list_get_normal (bml), be);
  /* Prevent it from being freed. */
  node->data = NULL;
  return 0;
}

/* Statements allowed within a Backend section. */
static CFG_DEFN service_backend_defn[] = {
  {
    .name = "",
    .type = KWT_TABREF,
    .ref = common_backend_defn
  },
  {
    .name = "Use",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = cfg_commit_null
  },
  { NULL }
};

static CFG_TYPE cfg_type_service_backend = {
  .argdef = "s?",
  .prepare = service_backend_prepare,
  .commit = service_backend_commit
};

/*
 * Emergency backend.
 */
static int
service_emergency_prepare (CFG_NODE *node, void *call_data, void **baseptr)
{
  BACKEND *be;
  POUND_DEFAULTS dfl = *(POUND_DEFAULTS *)call_data;

  dfl.be_to = 120;
  dfl.be_connto = 120;
  dfl.ws_to = 120;

  be = backend_init (node, &dfl);

  if (!be)
    return -1;

  *baseptr = be;
  /* Make sure it will be freed on error. */
  node->data = be;

  return 0;
}

static int
service_emergency_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  BACKEND *be = node->data;
  BALANCER_LIST *bml = cfg_rcvr_ptr (&node->rcvr, baseptr);
  balancer_add_backend (balancer_list_get_emerg (bml), be);
  node->data = NULL;
  return 0;
}

static CFG_TYPE cfg_type_service_emergency = {
  .argdef = "",
  .prepare = service_emergency_prepare,
  .commit = service_emergency_commit
};

/* UseBackend "NAME" */
static int
service_use_backend_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  BALANCER_LIST *bml = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  BACKEND *be = backend_ref_init (arg, node);
  if (!be)
    return -1;
  balancer_add_backend (balancer_list_get_normal (bml), be);
  return 0;
}

/*
 * The Redirect backend:
 *
 *  Redirect [CODE] "URL"
 */
static int
service_redirect_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  BALANCER_LIST *bml = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  int code = 302;
  BACKEND *be;
  POUND_REGMATCH matches[5];

  if (arg->type == T_NUMBER)
    {
      switch (arg->v.number)
	{
	case 301:
	case 302:
	case 303:
	case 307:
	case 308:
	  code = arg->v.number;
	  break;

	default:
	  conf_error_at_locus_range (&arg->locus, "invalid status code");
	  return -1;
	}
      arg = cfg_arg_next (arg);
    }

  be = xbackend_create (BE_REDIRECT, 1, &node->locus);
  be->v.redirect.status = code;
  be->v.redirect.url = xstrdup (string_ptr (arg->v.string));

  if (genpat_match (LOCATION, be->v.redirect.url, 4, matches))
    {
      conf_error_at_locus_range (&node->locus, "Redirect bad URL");
      backend_free (be);
      return -1;
    }

  if ((be->v.redirect.has_uri = matches[3].rm_eo - matches[3].rm_so) == 1)
    /* the path is a single '/', so remove it */
    be->v.redirect.url[matches[3].rm_so] = '\0';

  balancer_add_backend (balancer_list_get_normal (bml), be);

  return 0;
}

static CFG_TYPE cfg_type_service_redirect = {
  .argdef = "n?s",
  .commit = service_redirect_commit
};

/*
 * The Error backend.
 */
static int
parse_http_errmsg (struct http_errmsg *errmsg, CFG_ARG *arg)
{
  char *p;

  p = slurp (string_ptr (arg->v.string), get_include_wd (),
	     &arg->locus, NULL);
  if (!p)
    return -1;
  errmsg->text = p;

  DLIST_INIT (&errmsg->hdr);
  if (http_header_list_parse (&errmsg->hdr, errmsg->text, H_REPLACE, &p) == 0
      && p != errmsg->text)
    {
      p++;
      memmove (errmsg->text, p, strlen (p) + 1);
    }
  else
    http_header_list_free (&errmsg->hdr);
  return 0;
}

static void
http_errmsg_free (struct http_errmsg *errmsg)
{
  free (errmsg->text);
  http_header_list_free (&errmsg->hdr);
}

/* Error STATUS ["FILE"] */
static int
service_error_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  BALANCER_LIST *bml = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  struct http_errmsg errmsg = HTTP_ERRMSG_INITIALIZER (errmsg);
  BACKEND *be;
  int status;

  if ((status = http_status_to_pound (arg->v.number)) == -1)
    {
      conf_error_at_locus_range (&arg->locus, "unsupported status code");
      return -1;
    }
  arg = cfg_arg_next (arg);

  if (arg)
    {
      if (parse_http_errmsg (&errmsg, arg))
	{
	  http_errmsg_free (&errmsg);
	  return -1;
	}
    }

  be = xbackend_create (BE_ERROR, 1, &node->locus);
  be->v.error.status = status;
  be->v.error.msg = errmsg;

  balancer_add_backend (balancer_list_get_normal (bml), be);

  return 0;
}

static CFG_TYPE cfg_type_service_error = {
  .argdef = "ns?",
  .commit = service_error_commit
};

/*
 * The SendFile backend.
 */

/* SendFile "DIR" */
static int
service_sendfile_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  BALANCER_LIST *bml = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  char const *filename = string_ptr (arg->v.string);
  WORKDIR *wd = get_include_wd ();
  BACKEND *be;
  int fd;

  fd = openat (wd->fd, filename, O_DIRECTORY | O_RDONLY | O_NDELAY);
  if (fd == -1)
    {
      conf_error_at_locus_range (&node->locus, "can't open %s: %s",
				 filename, strerror (errno));
      return -1;
    }

  be = xbackend_create (BE_FILE, 1, &node->locus);
  be->v.file.wd = fd;

  balancer_add_backend (balancer_list_get_normal (bml), be);

  return 0;
}

/*
 * The Success backend.
 */
static int
service_success_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  BALANCER_LIST *bml = cfg_rcvr_ptr (&node->rcvr, baseptr);
  BACKEND *be = xbackend_create (BE_SUCCESS, 1, &node->locus);
  balancer_add_backend (balancer_list_get_normal (bml), be);
  return 0;
}

/*
 * The Metrics backend.
 */
static int
service_metrics_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  BALANCER_LIST *bml = cfg_rcvr_ptr (&node->rcvr, baseptr);
  BACKEND *be = xbackend_create (BE_METRICS, 1, &node->locus);
  balancer_add_backend (balancer_list_get_normal (bml), be);
  return 0;
}

/*
 * The Control backend.
 */
static int
service_control_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  BALANCER_LIST *bml = cfg_rcvr_ptr (&node->rcvr, baseptr);
  BACKEND *be = xbackend_create (BE_CONTROL, 1, &node->locus);
  balancer_add_backend (balancer_list_get_normal (bml), be);
  return 0;
}

/*
 * Lua Backend:
 *
 *   LuaBackend "arg" ...
 */
static int
service_luabackend_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  BALANCER_LIST *bml = cfg_rcvr_ptr (&node->rcvr, baseptr);
  BACKEND *be = xbackend_create (BE_LUA, 1, &node->locus);

  if (pndlua_parse_closure (node, &be->v.lua))
    {
      backend_free (be);
      return -1;
    }

  balancer_add_backend (balancer_list_get_normal (bml), be);
  return 0;
}

static CFG_TYPE cfg_type_luabackend = {
  .argdef = "s+",
  .commit = &service_luabackend_commit
};

/*
 * Sessions.
 */
static int
service_session_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  SERVICE *svc = cfg_rcvr_ptr (&node->rcvr, baseptr);

  if (svc->sess_type == SESS_NONE)
    {
      conf_error_at_locus_range (&node->locus, "Session type not defined");
      return -1;
    }

  if (svc->sess_ttl == 0)
    {
      conf_error_at_locus_range (&node->locus, "Session TTL not defined");
      return -1;
    }

  switch (svc->sess_type)
    {
    case SESS_COOKIE:
    case SESS_URL:
    case SESS_HEADER:
      if (svc->sess_id == NULL)
	{
	  conf_error_at_locus_range (&node->locus, "Session ID not defined");
	  return -1;
	}
      break;

    default:
      break;
    }

  return 0;
}

struct service_session
{
  int type;
  char *id;
  unsigned ttl;
};

static struct kwtab sess_type_tab[] = {
  { "IP", SESS_IP },
  { "COOKIE", SESS_COOKIE },
  { "URL", SESS_URL },
  { "PARM", SESS_PARM },
  { "BASIC", SESS_BASIC },
  { "HEADER", SESS_HEADER },
  { NULL }
};

char const *
sess_type_to_str (int type)
{
  if (type == SESS_NONE)
    return "NONE";
  return kw_to_str (sess_type_tab, type);
}

static int
session_type_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  SESS_TYPE *type = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  int n;

  if (kw_to_tok (sess_type_tab, string_ptr (arg->v.string), 1, &n))
    {
      conf_error_at_locus_range (&arg->locus, "unknown session type");
      return -1;
    }
  *type = n;

  return 0;
}

static CFG_DEFN service_session_defn[] = {
  {
    .name = "Type",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_LAZY_STRING,
    .commit = session_type_commit,
    .rcvr = {
      .off = offsetof (SERVICE, sess_type)
    }
  },
  {
    .name = "TTL",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_DURATION,
    .rcvr = {
      .off = offsetof (SERVICE, sess_ttl)
    }
  },
  {
    .name = "ID",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .rcvr = {
      .off = offsetof (SERVICE, sess_id)
    }
  },

  { NULL }
};

static CFG_TYPE cfg_type_service_session = {
  .argdef = "",
  .commit = service_session_commit
};

/* LogSuppress CLASS [CLASS ...] */
static int
session_log_suppress_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  int *ptr = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg;
  int result = 0;
  static struct kwtab status_table[] = {
    { "all",      STATUS_MASK (100) | STATUS_MASK (200) |
		  STATUS_MASK (300) | STATUS_MASK (400) | STATUS_MASK (500) },
    { "info",     STATUS_MASK (100) },
    { "success",  STATUS_MASK (200) },
    { "redirect", STATUS_MASK (300) },
    { "clterr",   STATUS_MASK (400) },
    { "srverr",   STATUS_MASK (500) },
    { NULL }
  };

  CFG_ARG_FOREACH (arg, &node->arglist)
    {
      int n;

      switch (arg->type)
	{
	case T_NUMBER:
	  if (arg->v.number <= 0 ||
	      arg->v.number >= sizeof (status_table) / sizeof (status_table[0]))
	    {
	      conf_error_at_locus_range (&arg->locus, "unsupported status mask");
	      return -1;
	    }
	  n = STATUS_MASK (arg->v.number * 100);
	  break;

	case T_LITERAL:
	  if (kw_to_tok (status_table, string_ptr (arg->v.string), 1, &n) != 0)
	    {
	      conf_error_at_locus_range (&arg->locus,
					 "unsupported status mask");
	      return -1;
	    }
	}
      result |= n;
    }
  *ptr = result;
  return 0;
}

static CFG_TYPE cfg_type_log_suppress = {
  .argdef = "[lsn]+",
  .commit = session_log_suppress_commit
};

/*
 * Service conditions.
 */

/* Allocate and return a new condition. */
static SERVICE_COND *
service_cond_alloc (int type)
{
  SERVICE_COND *sc;
  XZALLOC (sc);
  service_cond_init (sc, type);
  return sc;
}

/* Free the condition. */
static void
service_cond_free (SERVICE_COND *sc)
{
  switch (sc->type)
    {
    case COND_QUERY_PARAM:
    case COND_STRING_MATCH:
    case COND_NAMEHDR:
      string_unref (sc->sm.string);
      genpat_free (sc->sm.re);
      break;

    case COND_URL:
    case COND_PATH:
    case COND_QUERY:
    case COND_HDR:
    case COND_METHOD:
      genpat_free (sc->re);
      break;

    case COND_LUA:
      pndlua_closure_free (&sc->clua);
      break;

    case COND_TBF:
      string_unref (sc->tbf.key);
      tbf_free (sc->tbf.tbf);
      break;

    case COND_DYN:
      string_unref (sc->dyn.string);
      /* fall through */
    case COND_BOOL:
      {
	SERVICE_COND *cp;
	while ((cp = SLIST_FIRST (&sc->boolean.head)) != NULL)
	  {
	    SLIST_REMOVE_HEAD (&sc->boolean.head, next);
	    service_cond_free (cp);
	  }
      }
      break;

    case COND_BASIC_AUTH:
      pass_file_clear (&sc->pwfile);
      break;

    case COND_CLIENT_CERT:
      X509_free (sc->x509);
      break;

    case COND_ACL:
      acl_free (sc->acl.acl);
      break;

    case COND_REF:
      break;

    default:
      /* shouldn't happen; this includes COND_HOST. */
      abort ();
    }
  string_unref (sc->tag);
  free (sc);
}

/*
 * Create a new condition of the given TYPE and append it to the condition
 * list in COND, which must be a boolean (COND_BOOL) or dynamic (COND_DYN)
 * condition.
 */
static SERVICE_COND *
service_cond_append (SERVICE_COND *cond, int type)
{
  SERVICE_COND *sc;

  assert (cond->type == COND_BOOL || cond->type == COND_DYN);
  sc = service_cond_alloc (type);
  SLIST_PUSH (&cond->boolean.head, sc, next);

  return sc;
}

/*
 * Internal function to read patterns for (dynamic) condition from a
 * disk file.  Arguments:
 *
 *   COND      - a condition of type COND_DYN or COND_BOOL;
 *   FILENAME  - name of file to read;
 *   WD        - working directory to resolve relative filenames;
 *   REF       - name of the object, for StringMatch, QueryParam, and
 *               two-argument Header conditions;
 *   COND_TYPE - type of underlying conditions, to be created for each
 *               valid input line;
 *   PAT_TYPE  - pattern type;
 *   FLAGS     - flags to pass to genpat_compile;
 *
 * Returns number of errors encountered.
 */
static int
dyncond_read_internal (SERVICE_COND *cond, char const *filename, WORKDIR *wd,
		       STRING *ref, enum service_cond_type cond_type,
		       int pat_type, int flags)
{
  FILE *fp;
  struct locus_range loc;
  char *p;
  char buf[MAXBUF];
  int rc;
  struct stringbuf sb;

  fp = fopen_wd (wd, filename);
  if (fp == NULL)
    return -1;

  locus_point_init (&loc.beg, filename, wd->name);
  locus_point_init (&loc.end, NULL, NULL);

  rc = 0;

  xstringbuf_init (&sb);
  loc.beg.line--;
  while ((p = fgets (buf, sizeof buf, fp)) != NULL)
    {
      int rc;
      size_t len = strlen (p);
      SERVICE_COND *hc;
      int gpt = pat_type;

      loc.beg.line++;

      if (len == 0)
	continue;
      if (p[len-1] == '\n')
	len--;
      p = c_trimws (p, &len);
      if (len == 0 || *p == '#')
	continue;
      p[len] = 0;

      hc = service_cond_alloc (cond_type);
      hc->tag = string_ref (cond->tag);
      rc = genpat_compile (&hc->re, gpt, p, flags);
      if (rc)
	{
	  conf_regcomp_error (&loc, hc->re, NULL);
	  service_cond_free (hc);
	  rc++;
	}
      else
	{
	  switch (cond_type)
	    {
	    case COND_NAMEHDR:
	    case COND_QUERY_PARAM:
	    case COND_STRING_MATCH:
	      memmove (&hc->sm.re, &hc->re, sizeof (hc->sm.re));
	      hc->sm.string = string_ref (ref);
	      break;

	    default:
	      break;
	    }

	  SLIST_PUSH (&cond->boolean.head, hc, next);
	}
    }
  stringbuf_free (&sb);
  locus_range_unref (&loc);
  fclose (fp);
  return rc;
}

/* Dynamic condition reader, to be passed as READ parameter to
   watcher_register. */
static int
dyncond_read (void *obj, char const *filename, WORKDIR *wd)
{
  SERVICE_COND *cond = obj;
  return dyncond_read_internal (cond, filename, wd,
				cond->dyn.string,
				cond->dyn.cond_type,
				cond->dyn.pat_type,
				cond->dyn.flags);
}

/*
 * Initialize a boolean condition from a file.  See dyncond_read_internal
 * for the description of its parameters.
 */
static int
dyncond_read_immediate (SERVICE_COND *cond, char const *filename,
			STRING *ref, enum service_cond_type cond_type,
			int pat_type, int flags)
{
  WORKDIR *wd;
  char const *basename;
  int rc;

  if ((basename = filename_split_wd (filename, &wd)) == NULL)
    return -1;
  rc = dyncond_read_internal (cond, basename, wd, ref, cond_type, pat_type,
			      flags);
  workdir_unref (wd);
  if (rc == -1)
    {
      if (errno == ENOENT)
	conf_error ("file %s does not exist", filename);
      else
	conf_error ("can't open %s: %s", filename, strerror (errno));
      return -1;
    }
  else if (rc > 0)
    {
      conf_error ("errors reading %s", filename);
      return -1;
    }
  return 0;
}

/*
 * Clear a dynamic condition.
 */
static void
dyncond_clear (void *obj)
{
  SERVICE_COND *cond = obj;
  assert (cond->type == COND_BOOL || cond->type == COND_DYN);
  while (!SLIST_EMPTY (&cond->boolean.head))
    {
      SERVICE_COND *sc = SLIST_FIRST (&cond->boolean.head);
      SLIST_SHIFT (&cond->boolean.head, next);
      service_cond_free (sc);
    }
}

/* Register dynamic condition COND to monitor changes in FILENAME. */
static int
dyncond_register (SERVICE_COND *cond, char const *filename,
		  struct locus_range const *loc)
{
  cond->watcher = watcher_register (cond, filename, loc,
				    dyncond_read, dyncond_clear);
  return cond->watcher == NULL;
}

/*
 * Structure for keeping condition parameters, supplied by flags:
 */
struct match_param
{
  STRING *from_file; /* Name of the file given with -file or -filewatch
			flag. */
  int watch;         /* 1 if the -filewatch flag was given. */
  STRING *tag;       /* Tag (given with the -tag flag. */
  int decode;        /* 1 if the -decode flag was given. */
};

#define MATCH_PARAM_INITIALIZER { NULL, 0, NULL, -1 }

static void
match_param_free (struct match_param *p)
{
  string_unref (p->from_file);
  string_unref (p->tag);
}

/* Code names for condition flags. */
enum
  {
    MATCH_RE = 1,
    MATCH_EXACT,
    MATCH_BEG,
    MATCH_END,
    MATCH_CONTAIN,
    MATCH_ICASE,
    MATCH_CASE,
    MATCH_FILE,
    MATCH_FILEWATCH,
    MATCH_POSIX,
    MATCH_PCRE,
    MATCH_TAG,
    MATCH_DECODE
  };

static CFG_FLAG cond_re_flags[] = {
  { "re",        MATCH_RE },
  { "exact",     MATCH_EXACT },
  { "beg",       MATCH_BEG },
  { "end",       MATCH_END },
  { "contain",   MATCH_CONTAIN },
  { "icase",     MATCH_ICASE },
  { "case",      MATCH_CASE },
  { "posix",     MATCH_POSIX },
  { "pcre",      MATCH_PCRE },
  { "perl",      MATCH_PCRE },
  { "file",      MATCH_FILE, 1 },
  { "filewatch", MATCH_FILEWATCH, 1 },
  { "tag",       MATCH_TAG, 1 },
  { NULL }
};

static CFG_FLAG cond_re_decode_flags[] = {
  { "re",        MATCH_RE },
  { "exact",     MATCH_EXACT },
  { "beg",       MATCH_BEG },
  { "end",       MATCH_END },
  { "contain",   MATCH_CONTAIN },
  { "icase",     MATCH_ICASE },
  { "case",      MATCH_CASE },
  { "posix",     MATCH_POSIX },
  { "pcre",      MATCH_PCRE },
  { "perl",      MATCH_PCRE },
  { "file",      MATCH_FILE, 1 },
  { "filewatch", MATCH_FILEWATCH, 1 },
  { "tag",       MATCH_TAG, 1 },
  { "decode",    MATCH_DECODE },
  { NULL }
};

/*
 * Read condition parameters from arguments.
 * Input arguments:
 *     ARG          - Pointer to the first argument in list;
 *     DLF_RE_TYPE  - Default pattern type (used unless explicitly specified
 *                    otherwise);
 * Output arguments:
 *     GP_TYPE      - Type of the pattern to use (-re, -posix, -exact, -beg,
 *                    -end, -contain, or -pcre flags);
 *     SP_FLAGS     - Case-sensitivity (-case, -icase);
 *     PARAM        - Settings given by -file, -filewatch, -tag and -decode
 *                    flags.
 *     ARGPTR       - Pointer to the first non-flag argument.
 */
static int
parse_match_mode (CFG_ARG *arg, int dfl_re_type, int *gp_type, int *sp_flags,
		  struct match_param *param, CFG_ARG **argptr)
{
  int c;
  CFG_ARG *nxt, *farg;

  while ((c = cfg_arglist_getflag (arg, &farg, &nxt)) > 0)
    {
      switch (c)
	{
	case MATCH_CASE:
	  *sp_flags &= ~GENPAT_ICASE;
	  break;

	case MATCH_ICASE:
	  *sp_flags |= GENPAT_ICASE;
	  break;

	case MATCH_FILE:
	  param->from_file = string_ref (farg->v.string);
	  param->watch = 0;
	  break;

	case MATCH_FILEWATCH:
	  param->from_file = string_ref (farg->v.string);
	  param->watch = 1;
	  break;

	case MATCH_RE:
	  *gp_type = dfl_re_type;
	  break;

	case MATCH_POSIX:
	  *gp_type = GENPAT_POSIX;
	  break;

	case MATCH_EXACT:
	  *gp_type = GENPAT_EXACT;
	  break;

	case MATCH_BEG:
	  *gp_type = GENPAT_PREFIX;
	  break;

	case MATCH_END:
	  *gp_type = GENPAT_SUFFIX;
	  break;

	case MATCH_CONTAIN:
	  *gp_type = GENPAT_CONTAIN;
	  break;

	case MATCH_PCRE:
#ifdef HAVE_LIBPCRE
	  *gp_type = GENPAT_PCRE;
#else
	  conf_error_at_locus_range(&arg->locus,
				     "pound compiled without PCRE support");
	  return -1;
#endif
	  break;

	case MATCH_TAG:
	  param->tag = string_ref (farg->v.string);
	  break;

	case MATCH_DECODE:
	  param->decode = 1;
	}
      arg = nxt;
    }
  *argptr = arg;
  return 0;
}

/*
 * Generic condition creation function.
 * Arguments:
 *    NODE        - AST node describing the condition.
 *    ARG         - Pattern argument.
 *    TOP_COND    - Top-level condition (COND_BOOL or COND_DYN) to attach the
 *                  newly created condition to.
 *    TYPE        - Type of the condition to create.
 *    DFL_RE_TYPE - Default pattern type.
 *    GP_TYPE     - Pattern type.
 *    FLAGS       - flags to pass to genpat_compile.
 */
static int
cond_matcher_commit_generic (CFG_NODE *node, CFG_ARG *arg,
			     SERVICE_COND *top_cond,
			     enum service_cond_type type,
			     int dfl_re_type,
			     int gp_type, int flags, STRING *ref)
{
  int rc = 0;
  SERVICE_COND *cond;
  struct match_param match_param = MATCH_PARAM_INITIALIZER;

  if (parse_match_mode (arg, dfl_re_type, &gp_type, &flags, &match_param,
			&arg))
    return -1;

  if (match_param.from_file)
    {
      if (arg)
	{
	  conf_error_at_locus_range (&arg->locus, "superfluous arguments");
	  rc = -1;
	}
      else
	{
	  if (match_param.watch)
	    {
	      cond = service_cond_append (top_cond, COND_DYN);
	      cond->tag = match_param.tag;
	      cond->decode = match_param.decode;
	      cond->dyn.boolean.op = BOOL_OR;
	      cond->dyn.string = string_ref (ref);
	      cond->dyn.cond_type = type;
	      cond->dyn.pat_type = gp_type;
	      cond->dyn.flags = flags;
	      if (dyncond_register (cond, string_ptr (match_param.from_file),
				    &node->locus))
		rc = -1;
	    }
	  else
	    {
	      cond = service_cond_append (top_cond, COND_BOOL);
	      cond->tag = string_ref (match_param.tag);
	      cond->decode = match_param.decode;
	      cond->boolean.op = BOOL_OR;
	      rc = dyncond_read_immediate (cond,
					   string_ptr (match_param.from_file),
					   ref, type, gp_type, flags);
	    }
	}
    }
  else if (arg)
    {
      cond = service_cond_append (top_cond, type);
      cond->tag = string_ref (match_param.tag);
      cond->decode = match_param.decode;
      rc = genpat_compile (&cond->re, gp_type, string_ptr (arg->v.string),
			   flags);
      if (rc)
	{
	  conf_regcomp_error (&arg->locus, cond->re, NULL);
	  // FIXME: genpat_free (cond->re);
	  rc = -1;
	}
      else
	{
	  switch (type)
	    {
	    case COND_NAMEHDR:
	    case COND_QUERY_PARAM:
	    case COND_STRING_MATCH:
	      memmove (&cond->sm.re, &cond->re, sizeof (cond->sm.re));
	      cond->sm.string = string_ref (ref);
	      break;

	    default:
	      break;
	    }
	}
    }
  else
    {
      conf_error_at_locus_range (&node->locus, "required argument missing");
      rc = -1;
    }

  match_param_free (&match_param);

  return rc;
}

/*
 * Simple condition creation: Method, URL, Path, and the like.
 */
static int
cond_matcher_commit_simple (CFG_NODE *node, void *call_data, void *baseptr)
{
  POUND_DEFAULTS *dfl = call_data;
  SERVICE_COND *cond = cfg_rcvr_ptr (&node->rcvr, baseptr);
  return cond_matcher_commit_generic (node, cfg_arglist_first (&node->arglist),
				      cond, (int)(intptr_t)node->defn->data,
				      dfl->re_type, dfl->re_type,
				      (dfl->ignore_case ? GENPAT_ICASE : 0),
				      NULL);
}

/* Host [FLAGS] "PAT" */
static int
cond_host_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  POUND_DEFAULTS *dfl = call_data;
  SERVICE_COND *cond = cfg_rcvr_ptr (&node->rcvr, baseptr);
  STRING *s = string_init ("Host");
  int rc = cond_matcher_commit_generic (node,
					cfg_arglist_first (&node->arglist),
					cond, COND_NAMEHDR,
					dfl->re_type, GENPAT_EXACT,
					GENPAT_ICASE,
					s);
  string_unref (s);
  return rc;
}

/*
 * Two-argument conditions:
 *   Header "NAME" [FLAGS] "PAT"
 *   QueryParam "NAME" [FLAGS] "PAT"
 *   StringMatch "STR" [FLAGS] "PAT"
 */
static int
cond_matcher_commit_twoarg (CFG_NODE *node, void *call_data, void *baseptr)
{
  POUND_DEFAULTS *dfl = call_data;
  SERVICE_COND *cond = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  return cond_matcher_commit_generic (node, cfg_arg_next (arg),
				      cond, (int)(intptr_t)node->defn->data,
				      dfl->re_type, dfl->re_type,
				      (dfl->ignore_case ? GENPAT_ICASE : 0),
				      arg->v.string);
}

/*
 * The Header condition:
 *   Header [FLAGS] "PAT"
 *   Header "NAME" [FLAGS] "PAT"
 */
static int
cond_header_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  POUND_DEFAULTS *dfl = call_data;
  SERVICE_COND *cond = cfg_rcvr_ptr (&node->rcvr, baseptr);
  static char single_arg[] = "f*s?";
  static char two_arg[] = "sf*s?";
  char const *expdef;
  CFG_ARG *errarg;
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  STRING *string;
  int type;

  if (lex_argcmp (single_arg, &node->arglist, &expdef, &errarg) == 0)
    {
      type = COND_HDR;
      string = NULL;
    }
  else if (lex_argcmp (two_arg, &node->arglist, &expdef, &errarg) == 0)
    {
      type = COND_NAMEHDR;
      string = arg->v.string;
      arg = cfg_arg_next (arg);
    }
  else
    {
      arg_mismatch_error (expdef, errarg, &node->locus);
      return -1;
    }

  return cond_matcher_commit_generic (node, arg,
				      cond, type,
				      dfl->re_type, dfl->re_type,
				      GENPAT_MULTILINE | GENPAT_ICASE,
				      string);
}

/*
 * Prepare function for committing the Match statement:
 *
 *   Match [AND|OR]
 *       ...
 *   End
 *
 * The function creates a new boolean condition and attaches it to the
 * condition supplied by the node receiver and baseptr. Upon successful
 * return, the new condition is saved in *baseptr.
 */
static int
match_prepare (CFG_NODE *node, void *call_data, void **baseptr)
{
  SERVICE_COND *cond = cfg_rcvr_ptr (&node->rcvr, *baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  int op;

  if (!arg)
    op = BOOL_AND;
  else
    {
      char const *opname = string_ptr (arg->v.string);
      if (c_strcasecmp (opname, "and") == 0)
	op = BOOL_AND;
      else if (c_strcasecmp (opname, "or") == 0)
	op = BOOL_OR;
      else
	{
	  conf_error_at_locus_range (&arg->locus,
				     "expected AND or OR, but found %s",
				     opname);
	  return -1;
	}
    }

  cond = service_cond_append (cond, COND_BOOL);
  cond->boolean.op = op;

  *baseptr = cond;

  return 0;
}

/*
 * Not COND
 */
static int
not_prepare (CFG_NODE *node, void *call_data, void **baseptr)
{
  SERVICE_COND *cond =
    service_cond_append (cfg_rcvr_ptr (&node->rcvr, *baseptr), COND_BOOL);
  cond->boolean.op = BOOL_NOT;

  *baseptr = cond;

  return 0;
}

static CFG_TYPE cfg_type_match = {
  .argdef = "l?",
  .prepare = match_prepare
};

static CFG_TYPE cfg_type_not = {
  .argdef = "",
  .prepare = not_prepare
};

/*
 * The ClientCert condition:
 *   ClientCert MODE [DEPTH]
 */
static int
clientcert_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  SERVICE_COND *cond =
    service_cond_append (cfg_rcvr_ptr (&node->rcvr, baseptr), COND_CLIENT_CERT);
  return cfg_cert_commit (node, call_data, &cond->x509);
}

/* Named and detached conditions. */

/*
 * Named condition represents a detached condition during configuration
 * file processing.  At the end of parsing phase, all references to named
 * conditions are resolved, the conditions (SERVICE_COND pointers) they
 * refer to are moved to the detcond_index array and assigned the condition
 * number.  Finally, the memory allocated to named conditions is freed.
 */
typedef struct named_cond
{
  char *name;                 /* Condition name */
  SERVICE_COND *cond;
  CFG_NODE const *node;
  int idx;                    /* Index of the evaluated result in
				 eval_response of struct http_request */
} NAMED_COND;

#define HT_TYPE NAMED_COND
#define HT_NO_DELETE
#define HT_NO_FOREACH_SAFE
#include "ht.h"

static NAMED_COND_HASH *named_cond_hash;

/* Array of detached conditions. */
static SERVICE_COND **detcond_index;
static int detcond_count;

/* Return a pointer to the detached condition with the given number. */
SERVICE_COND *
detached_cond (int n)
{
  assert (n >= 0 && n < detcond_count);
  return detcond_index[n];
}

/*
 * eval_result array
 *
 * An array of detcond_count char elements is associated with each HTTP
 * request.  Each element keeps the result of evaluation of the corresponding
 * detached condition, increased by 1.  Thus, eval_result[n] == 0 means that
 * condition n has not yet been evaluated.
 */

/*
 * Get result of the latest evaluation of detached condition n.
 * Returns -1 if the condition has not been evaluated yet.
 */
int
http_request_eval_get (struct http_request *http, int n)
{
  assert (n >= 0 && n < detcond_count);
  if (!http->eval_result)
    return -1;
  return http->eval_result[n] - 1;
}

/* Store result res of evaluating the detached condition n. */
int
http_request_eval_cache (struct http_request *http, int n, int res)
{
  assert (n >= 0 && n < detcond_count);
  if (!http->eval_result)
    {
      http->eval_result = calloc (detcond_count,
				  sizeof (http->eval_result[0]));
      if (!http->eval_result)
	{
	  lognomem ();
	  return -1;
	}
    }
  return http->eval_result[n] = !!res + 1;
}

/*
 * Named condition hash management.
 */

/*
 * Free a named condition entry.
 * The service condition pointer is not freed.
 */
static void
named_cond_free (NAMED_COND *nc)
{
  free (nc->name);
}

/*
 * Store the condition in the detcond_index array and free the named condition.
 */
static void
named_cond_store (NAMED_COND *nc, void *data)
{
  detcond_index[nc->idx] = nc->cond;
  named_cond_free (nc);
}

/* Finalize detached condition processing. */
static void
named_cond_finish (void)
{
  if (detcond_count)
    {
      detcond_index = xcalloc (detcond_count, sizeof (detcond_index[0]));
      NAMED_COND_FOREACH (named_cond_hash, named_cond_store, NULL);
      NAMED_COND_HASH_FREE (named_cond_hash);
    }
}

/* Find named condition by its name. */
static NAMED_COND *
named_cond_lookup (char const *name)
{
  NAMED_COND *cond = NULL;
  if (named_cond_hash)
    {
      NAMED_COND key;
      key.name = (char*)name;
      cond = NAMED_COND_RETRIEVE (named_cond_hash, &key);
    }
  return cond;
}

/* Allocate new named condition with boolean operation op. */
static NAMED_COND *
named_cond_new (char const *name, int op, CFG_NODE const *node)
{
  NAMED_COND *nc, *old;

  if (!named_cond_hash)
    named_cond_hash = NAMED_COND_HASH_NEW ();
  XZALLOC (nc);
  nc->name = xstrdup (name);
  nc->cond = service_cond_alloc (COND_BOOL);
  nc->cond->boolean.op = op;
  nc->node = node;

  old = NAMED_COND_INSERT (named_cond_hash, nc);
  if (old != NULL)
    {
      conf_error_at_locus_range (&node->locus, "%s redefined", name);
      conf_error_at_locus_range (&old->node->locus, "originally defined here");
      //FIXME named_cond_free (nc);
      return NULL;
    }
  nc->idx = detcond_count++;
  return nc;
}

static int
condition_prepare (CFG_NODE *node, void *call_data, void **baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  int op;
  NAMED_COND *nc;
  char const *name;

  name = string_ptr (arg->v.string);
  arg = cfg_arg_next (arg);

  if (!arg)
    op = BOOL_AND;
  else
    {
      char const *opname = string_ptr (arg->v.string);
      if (c_strcasecmp (opname, "and") == 0)
	op = BOOL_AND;
      else if (c_strcasecmp (opname, "or") == 0)
	op = BOOL_OR;
      else
	{
	  conf_error_at_locus_range (&arg->locus,
				     "expected AND or OR, but found %s",
				     opname);
	  return -1;
	}
    }

  if ((nc = named_cond_new (name, op, node)) == NULL)
    return -1;

  *baseptr = nc->cond;

  return 0;
}

static CFG_TYPE cfg_type_condition = {
  .argdef = "sl?",
  .prepare = condition_prepare
};

/*
 * Eval "NAME"
 */
static int
eval_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  char const *name = string_ptr (arg->v.string);
  SERVICE_COND *cond = cfg_rcvr_ptr (&node->rcvr, baseptr);
  NAMED_COND *nc;

  if ((nc = named_cond_lookup (name)) == NULL)
    {
      conf_error_at_locus_range (&arg->locus, "%s: no such condition", name);
      return -1;
    }

  cond = service_cond_append (cond, COND_REF);
  cond->ref = nc->idx;

  return 0;
}

static CFG_TYPE cfg_type_eval = {
  .argdef = "s",
  .commit = eval_commit
};

/*
 * Listener operations.
 */

static LISTENER *
listener_alloc (POUND_DEFAULTS *dfl, struct locus_range *locus)
{
  LISTENER *lst;

  XZALLOC (lst);

  lst->mode = 0600;
  lst->sock = -1;
  lst->to = dfl->clnt_to;
  lst->rewr_loc = 1;
  lst->log_level = -1;
  lst->rewrite_errors = -1;
  lst->verb = 0;
  lst->header_options = dfl->header_options;
  lst->clnt_check = -1;
  lst->linebufsize = dfl->linebufsize;
  locus_range_init (&lst->locus);
  locus_range_copy (&lst->locus, locus);

  SLIST_INIT (&lst->rewrite[REWRITE_REQUEST]);
  SLIST_INIT (&lst->rewrite[REWRITE_RESPONSE]);
  SLIST_INIT (&lst->services);
  SLIST_INIT (&lst->ctx_head);
  return lst;
}

static int
find_listener_ident (LISTENER_HEAD *list_head, char const *name)
{
  LISTENER *lstn;
  SLIST_FOREACH (lstn, list_head, next)
    {
      if (lstn->name && strcmp (lstn->name, name) == 0)
	return 1;
    }
  return 0;
}

/*
 * The Control statement.
 */
static SERVICE *new_service (BALANCER_ALGO algo);

static void
control_listener_finalize (LISTENER *lst)
{
  SERVICE *svc;
  BACKEND *be;

  lst->verb = 1; /* Need PUT and DELETE methods */
  /* Register listener in the global listener list */
  SLIST_PUSH (&listeners, lst, next);

  /* Create service; there'll be only one backend so the balancing algorithm
     doesn't really matter. */
  svc = new_service (BALANCER_ALGO_RANDOM);
  svc->lstn = lst;
  locus_range_copy (&svc->locus, &lst->locus);

  /* Register service in the listener */
  SLIST_PUSH (&lst->services, svc, next);

  /* Create backend */
  be = xbackend_create (BE_CONTROL, 1, &lst->locus);
  be->service = svc;
  /* Register backend in service */
  balancer_add_backend (balancer_list_get_normal (&svc->balancers), be);
  service_recompute_pri_unlocked (svc, NULL, NULL);
}

static int
parse_control_address (struct addrinfo *addr, CFG_ARG *arg)
{
  struct sockaddr_un *sun;
  char const *str = string_ptr (arg->v.string);
  size_t len = strlen (str);

  if (len > UNIX_PATH_MAX)
    {
      conf_error_at_locus_range (&arg->locus, "UNIX path name too long");
      return -1;
    }

  len += offsetof (struct sockaddr_un, sun_path) + 1;
  sun = xmalloc (len);
  sun->sun_family = AF_UNIX;
  strcpy (sun->sun_path, str);
  unlink_at_exit (sun->sun_path);

  addr->ai_socktype = SOCK_STREAM;
  addr->ai_family = AF_UNIX;
  addr->ai_protocol = 0;
  addr->ai_addr = (struct sockaddr *) sun;
  addr->ai_addrlen = len;

  return 0;
}

/* Allocates a new control listener and returns it in *baseptr. */
static int
control_prepare (CFG_NODE *node, void *call_data, void **baseptr)
{
  LISTENER *lst = listener_alloc (call_data, &node->locus);
  *baseptr = lst;
  // FIXME: Prepare lst for freeing in case of error. This will require a
  // free_data method.
  return 0;
}

/* The Control statement:
 *    Control "SOCKET"
 */
static int
control_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  LISTENER *lst = baseptr;
  if (!cfg_arglist_empty (&node->arglist))
    {
      CFG_ARG *arg = cfg_arglist_first (&node->arglist);
      if (parse_control_address (&lst->addr, arg))
	{
	  // FIXME: listener_free
	  return -1;
	}
    }
  control_listener_finalize (lst);
  return 0;
}

static CFG_TYPE cfg_type_control = {
  .argdef = "s?",
  .prepare = control_prepare,
  .commit = control_commit
};

static int
socket_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  struct addrinfo *addr = cfg_rcvr_ptr (&node->rcvr, baseptr);
  return parse_control_address (addr, arg);
}

static int
file_mode_verify (CFG_NODE *node)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  if (arg->v.number & ~0777)
    {
      conf_error_at_locus_range (&arg->locus, "invalid file mode");
      return -1;
    }
  return 0;
}

/* Directives allowed for use in the Control section. */
static CFG_DEFN control_defn[] = {
  {
    .name = "Socket",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = socket_commit,
    .rcvr = {
      .off = offsetof (LISTENER, addr)
    }
  },
  {
    .name = "ChangeOwner",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_BOOL,
    .rcvr = {
      .off = offsetof (LISTENER, chowner)
    }
  },
  {
    .name = "Mode",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_INT,
    .verify = file_mode_verify,
    .rcvr = {
      .off = offsetof (LISTENER, mode)
    }
  },
  { NULL }
};

#define FLG_MASK(n) (1<<(n))

static int
get_file_option (CFG_ARG **argptr, CFG_ARG **file)
{
  CFG_ARG *arg = *argptr;
  CFG_ARG *filearg = NULL;
  CFG_ARG *farg;
  int c;
  int opt = 0;

  while ((c = cfg_arglist_getflag (arg, &farg, &arg)) > 0)
    {
      switch (c)
	{
	case FLG_FILE:
	case FLG_FILEWATCH:
	  if (filearg)
	    conf_error_at_locus_range (&farg->locus, "duplicate -file flag");
	  filearg = farg;
	}
      opt |= FLG_MASK (c);
    }

  if (opt & FLG_MASK (FLG_FILEWATCH))
    num_reserved_fds++;

  *argptr = arg;
  *file = filearg;

  return opt;
}

/*
 * ACL support
 */

/* Max. number of bytes in an inet address (suitable for both v4 and v6) */
#define MAX_INADDR_BYTES 16

typedef struct cidr
{
  int family;                           /* Address family */
  int len;                              /* Address length */
  unsigned char addr[MAX_INADDR_BYTES]; /* Network address */
  unsigned char mask[MAX_INADDR_BYTES]; /* Address mask */
  SLIST_ENTRY (cidr) next;              /* Link to next CIDR */
} CIDR;

/* Create a new ACL. */
static ACL *
new_acl (char const *name)
{
  ACL *acl;

  XZALLOC (acl);
  if (name)
    acl->name = xstrdup (name);
  else
    acl->name = NULL;
  SLIST_INIT (&acl->head);

  return acl;
}

/* Match cidr against inet address ap/len.  Return 0 on match, 1 otherwise. */
static int
cidr_match (CIDR *cidr, unsigned char *ap, size_t len)
{
  size_t i;

  if (cidr->len == len)
    {
      for (i = 0; i < len; i++)
	{
	  if (cidr->addr[i] != (ap[i] & cidr->mask[i]))
	    return 1;
	}
    }
  return 0;
}

/*
 * Split the inet address of SA to address pointer and length, suitable
 * for use with the above functions.  Store pointer in RET_PTR.  If
 * RET_PTR is not NULL, store the effective address family there.
 * Return address length in bytes, or -1 if SA address family is not
 * supported.
 */
int
sockaddr_bytes (struct sockaddr *sa, unsigned char **ret_ptr, int *ret_family)
{
  int len;
  int fml;
  struct in6_addr *in6p;

  switch (sa->sa_family)
    {
    case AF_INET:
      fml = AF_INET;
      len = 4;
      *ret_ptr = (unsigned char *) &(((struct sockaddr_in*)sa)->sin_addr.s_addr);
      break;

    case AF_INET6:
      in6p = &((struct sockaddr_in6*)sa)->sin6_addr;
      if (IN6_IS_ADDR_V4MAPPED (in6p))
	{
	  fml = AF_INET;
	  len = 4;
	  *ret_ptr = &in6p->s6_addr[12];
	}
      else
	{
	  fml = AF_INET6;
	  len = 16;
	  *ret_ptr = (unsigned char*) in6p;
	}
      break;

    default:
      return -1;
    }
  if (ret_family)
    *ret_family = fml;
  return len;
}

static int config_parse_acl_file (ACL *acl, char const *filename, WORKDIR *wd);

static int
dynacl_read (void *obj, char const *filename, WORKDIR *wd)
{
  return config_parse_acl_file (obj, filename, wd);
}

static void
dynacl_clear (void *obj)
{
  acl_clear (obj);
}

static int
dynacl_register (ACL *acl, char const *filename, struct locus_range const *loc)
{
  acl->watcher = watcher_register (acl, filename, loc,
				   dynacl_read, dynacl_clear);
  return acl->watcher == NULL;
}

/*
 * Match sockaddr SA against ACL.  Return 0 if it matches, 1 if it does not
 * and -1 on error (invalid address family).
 */
int
acl_match (ACL *acl, struct sockaddr *sa)
{
  CIDR *cidr;
  unsigned char *ap;
  size_t len;
  int family;
  int rc = 1;

  if ((len = sockaddr_bytes (sa, &ap, &family)) == -1)
    return -1;

  acl_lock (acl);
  SLIST_FOREACH (cidr, &acl->head, next)
    {
      if (cidr->family == family && cidr_match (cidr, ap, len) == 0)
	{
	  rc = 0;
	  break;
	}
    }
  acl_unlock (acl);

  return rc;
}

void
acl_clear (ACL *acl)
{
  struct cidr *cp;
  while ((cp = SLIST_FIRST (&acl->head)) != NULL)
    {
      SLIST_SHIFT (&acl->head, next);
      free (cp);
    }
}

void
acl_free (ACL *acl)
{
  if (acl)
    {
      acl_clear (acl);
      free (acl->name);
      // FIXME: what about watcher?
      free (acl);
    }
}

static void
masklen_to_netmask (unsigned char *buf, size_t len, size_t masklen)
{
  int i, cnt;

  cnt = masklen / 8;
  for (i = 0; i < cnt; i++)
    buf[i] = 0xff;
  if (i == MAX_INADDR_BYTES)
    return;
  cnt = 8 - masklen % 8;
  buf[i++] = (0xff >> cnt) << cnt;
  for (; i < MAX_INADDR_BYTES; i++)
    buf[i] = 0;
}

static int
parse_cidr_str (ACL *acl, char const *str, struct locus_range const *loc)
{
  char *mask;
  struct addrinfo hints, *res;
  unsigned long masklen;
  int rc;

  if ((mask = strchr (str, '/')) != NULL)
    {
      char *p;

      *mask++ = 0;

      errno = 0;
      masklen = strtoul (mask, &p, 10);
      if (errno || *p)
	{
	  conf_error_at_locus_range (loc, "invalid netmask");
	  return -1;
	}
    }

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_NUMERICHOST;

  if ((rc = getaddrinfo (str, NULL, &hints, &res)) == 0)
    {
      CIDR *cidr;
      int len, i;
      unsigned char *p;
      int family;

      if ((len = sockaddr_bytes (res->ai_addr, &p, &family)) == -1)
	{
	  conf_error_at_locus_range (loc, "unsupported address family");
	  return -1;
	}
      XZALLOC (cidr);
      cidr->family = family;
      cidr->len = len;
      memcpy (cidr->addr, p, len);
      if (!mask)
	masklen = len * 8;
      masklen_to_netmask (cidr->mask, cidr->len, masklen);
      /* Fix-up network address, just in case */
      for (i = 0; i < len; i++)
	cidr->addr[i] &= cidr->mask[i];
      SLIST_PUSH (&acl->head, cidr, next);
      freeaddrinfo (res);
    }
  else
    {
      conf_error_at_locus_range (loc, "invalid IP address: %s",
				 gai_strerror (rc));
      return -1;
    }
  return 0;
}

/*
 * List of named ACLs.
 * There shouldn't be many of them, so it's perhaps no use in implementing
 * more sophisticated data structures than a mere singly-linked list.
 */
static ACL_HEAD acl_list = SLIST_HEAD_INITIALIZER (acl_list);

/*
 * Return a pointer to the named ACL, or NULL if no ACL with such name is
 * found.
 */
static ACL *
acl_by_name (char const *name)
{
  ACL *acl;
  SLIST_FOREACH (acl, &acl_list, next)
    {
      if (strcmp (acl->name, name) == 0)
	break;
    }
  return acl;
}

/*
 * Read CIDRs from file FILENAME, resolved relative to the directory WD.
 * Store them in ACL.
 * Return the number of errors detected.
 */
static int
config_parse_acl_file (ACL *acl, char const *filename, WORKDIR *wd)
{
  FILE *fp;
  char buf[MAXBUF];
  struct locus_range loc;
  int rc;
  char *p;

  fp = fopen_wd (wd, filename);
  if (fp == NULL)
    return -1;

  locus_point_init (&loc.beg, filename, wd->name);
  locus_point_init (&loc.end, NULL, NULL);

  rc = 0;
  loc.beg.line--;
  while ((p = fgets (buf, sizeof buf, fp)) != NULL)
    {
      char *line;
      size_t len = strlen (p);

      loc.beg.line++;
      if (len == 0)
	continue;
      if (p[len-1] == '\n')
	len--;
      line = c_trimws (p, &len);
      if (len == 0 || *line == '#')
	continue;
      line[len] = 0;

      if (line[0] == '"' && line[len-1] == '"')
	{
	  line[--len] = 0;
	  line++;
	}

      if (parse_cidr_str (acl, line, &loc))
	rc++;
    }
  fclose (fp);
  locus_range_unref (&loc);
  return rc;
}

/* A wrapper over config_parse_acl_file. Adds error reporting. */
static int
parse_acl_file (ACL *acl, char const *filename, struct locus_range const *loc)
{
  WORKDIR *wd;
  char const *basename;
  int rc;

  if ((basename = filename_split_wd (filename, &wd)) == NULL)
    return -1;
  rc = config_parse_acl_file (acl, basename, wd);
  workdir_unref (wd);
  if (rc == -1)
    {
      if (errno == ENOENT)
	conf_error_at_locus_range (loc, "file %s does not exist", filename);
      else
	conf_error_at_locus_range (loc, "can't open %s: %s", filename,
				   strerror (errno));
      return -1;
    }
  else if (rc > 0)
    {
      conf_error_at_locus_range (loc, "errors reading %s", filename);
      return -1;
    }
  return 0;
}

/*
 * Commit function for an immediate ACL definition:
 *   ACL "NAME"
 *     CIDR
 *     ...
 *   End
 *
 * ACL name is in node->tag, and list of CIDRs is in node->arglist.
 */
static int
acldef_commit_imm (ACL *acl, CFG_ARG *arg)
{
  int rc = 0;
  for (; arg; arg = cfg_arg_next (arg))
    if (parse_cidr_str (acl, string_ptr (arg->v.string), &arg->locus))
      rc = 1;
  return rc;
}

/*
 * Commit function for referencing ACL definition:
 *   ACL "NAME" [-file|-filewatch] [FLAGS] "FILE"
 * Arguments:
 *   ACL
 */
static int
acldef_commit_ref (ACL *acl, CFG_NODE *node)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  CFG_ARG *filename = NULL;
  int opt;

  if ((opt = get_file_option (&arg, &filename)) == -1)
    return -1;

  if (arg)
    {
      /* Shouldn't happen */
      conf_error_at_locus_range (&arg->locus,
				 "internal error:"
				 " ACL reference not allowed here");
      abort ();
    }
  else
    {
      if (opt & FLG_MASK (FLG_FILEWATCH))
	{
	  if (dynacl_register (acl, string_ptr (filename->v.string),
			       &filename->locus))
	    return -1;
	}
      else if (parse_acl_file (acl, string_ptr (filename->v.string),
			       &filename->locus))
	return -1;
    }

  return 0;
}

/* Commit function for various named ACL forms. */
static int
acldef_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  char const *name = string_ptr (node->acl.tag);
  ACL *acl;
  int rc;

  if (acl_by_name (name))
    {
      conf_error_at_locus_range (&node->locus,
				 "ACL with that name already defined");
      return -1;
    }

  acl = new_acl (name);

  switch (node->acl.type)
    {
    case ACLT_IMM:
      rc = acldef_commit_imm (acl, cfg_arglist_first (&node->arglist));
      break;

    case ACLT_REF:
      rc = acldef_commit_ref (acl, node);
      break;

    default:
      conf_error_at_locus_range (&node->locus,
				 "internal error: malformed ACL node");
      abort ();
    }

  if (rc == 0)
    SLIST_PUSH (&acl_list, acl, next);
  else
    acl_free (acl);

  return rc;
}

static CFG_FLAG acl_flagdef[] = {
  { "file", FLG_FILE, 1 },
  { "filewatch", FLG_FILEWATCH, 1 },
  { NULL }
};

static CFG_TYPE cfg_type_named_acl = {
  .argdef = "[fls]+",
  .flagdef = acl_flagdef,
  .commit = acldef_commit
};

/*
 * ACL conditions have the following forms:
 *
 * ACL [-forwarded] "\n" ... End
 *   Creates and references an unnamed ACL.
 * ACL [-forwarded] "name"
 *   References a named ACL.
 * ACL [-forwarded] -file "name"
 * ACL [-forwarded] -filewatch "name"
 *   Read ACL from file.
 */
static int
acl_build (CFG_NODE *node, ACL **ret_acl, int *ret_fwd)
{
  ACL *acl;
  CFG_ARG *arg = cfg_arglist_first (&node->arglist), *nxt;
  CFG_ARG *flgarg, *filename = NULL;
  int c;
  int watch = 0;
  int fwd = 0;
  int rc = 0;

  while ((c = cfg_arglist_getflag (arg, &flgarg, &nxt)) != 0)
    {
      switch (c)
	{
	case FLG_FILE:
	  filename = flgarg;
	  break;

	case FLG_FILEWATCH:
	  filename = flgarg;
	  watch = 1;
	  break;

	case FLG_FWD:
	  fwd = 1;
	  break;
	}

      arg = nxt;
    }

  switch (node->acl.type)
    {
    case ACLT_IMM:
      acl = new_acl (NULL);
      rc = acldef_commit_imm (acl, arg);
      break;

    case ACLT_REF:
      if (filename)
	{
	  acl = new_acl (NULL);

	  if (watch)
	    {
	      if (dynacl_register (acl, string_ptr (filename->v.string),
				   &filename->locus))
		rc = -1;
	    }
	  else if (parse_acl_file (acl, string_ptr (filename->v.string),
				   &filename->locus))
	    rc = -1;
	}
      else if (arg)
	{
	  if ((acl = acl_by_name (string_ptr (arg->v.string))) == NULL)
	    {
	      conf_error_at_locus_range (&arg->locus, "no such ACL");
	      rc = -1;
	    }
	}
      else
	{
	  /* shouldn't happen */
	  conf_error_at_locus_range (&node->locus, "internal error");
	  abort ();
	}
    }

  if (rc == 0)
    {
      *ret_acl = acl;
      if (ret_fwd)
	*ret_fwd = fwd;
    }
  else
    acl_free (acl);

  return rc;
}

/* Commit function for any form of ACL condition. */
static int
aclcond_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  SERVICE_COND *cond = cfg_rcvr_ptr (&node->rcvr, baseptr);
  ACL *acl;
  int fwd;

  if (acl_build (node, &acl, &fwd))
    return -1;

  cond = service_cond_append (cond, COND_ACL);
  cond->acl.acl = acl;
  cond->acl.forwarded = fwd;

  return 0;
}

static CFG_FLAG aclcond_flagdef[] = {
  { "file", FLG_FILE, 1 },
  { "filewatch", FLG_FILEWATCH, 1 },
  { "forwarded", FLG_FWD },
  { NULL }
};

static CFG_TYPE cfg_type_aclcond = {
  .argdef = "f*s*",
  .flagdef = aclcond_flagdef,
  .commit = aclcond_commit
};

/*
 * TrustedIP lists.
 */

static int
trustedip_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  ACL **aclptr = cfg_rcvr_ptr (&node->rcvr, baseptr);
  return acl_build (node, aclptr, NULL);
}

static CFG_FLAG trustedip_flagdef[] = {
  { "file", FLG_FILE, 1 },
  { "filewatch", FLG_FILEWATCH, 1 },
  { NULL }
};

static CFG_TYPE cfg_type_trustedip = {
  .argdef = "f?s*",
  .flagdef = trustedip_flagdef,
  .commit = trustedip_commit
};

/*
 * String constants.
 */
#define HT_TYPE STRCONST
#define HT_NO_HASH_FREE
#define HT_NO_DELETE
#define HT_NO_FOREACH
#include "ht.h"

static STRCONST_HASH *strconst_tab;

static int
strconst_read (STRCONST *sc, char const *filename, WORKDIR *wd)
{
  char *s;
  size_t n;

  string_unref (sc->value);
  s = slurp (filename, wd, &sc->locus, &n);
  if (s == NULL)
    {
      sc->value = NULL;
      return -1;
    }
  if (sc->trim)
    n -= c_memrspn (s, CCTYPE_SPACE, n);
  sc->value = string_ninit (s, n);
  free (s);
  return 0;
}

static int
dynstrconst_read (void *obj, char const *filename, WORKDIR *wd)
{
  STRCONST *sc = obj;
  return strconst_read (sc, filename, wd);
}

static void
dynstrconst_clear (void *obj)
{
  STRCONST *sc = obj;
  sc->value = string_unref (sc->value);
}

static int
strconst_register (STRCONST *sc, char const *filename,
		   struct locus_range const *loc)
{
  sc->watcher = watcher_register (sc, filename, loc,
				  dynstrconst_read, dynstrconst_clear);
  return sc->watcher == NULL;
}

static STRCONST *
strconst_new (char const *name, struct locus_range const *loc)
{
  STRCONST *sc;

  XZALLOC (sc);
  sc->name = xstrdup (name);
  locus_range_init (&sc->locus);
  locus_range_copy (&sc->locus, loc);
  return sc;
}

static void
strconst_free (STRCONST *sc)
{
  free (sc->name);
  locus_range_unref (&sc->locus);
  string_unref (sc->value);
  free (sc);
}

/*
 * The Constant statement:
 *   Constant "NAME" "VALUE"
 *   Constant "NAME" -file|-filewatch FILE [-trim]
 */
static int
constant_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  STRCONST_HASH **hashptr = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *filename = NULL;
  int opt;
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  STRCONST *sc, *old;

  sc = strconst_new (string_ptr (arg->v.string), &arg->locus);
  arg = cfg_arg_next (arg);

  if ((opt = get_file_option (&arg, &filename)) == -1)
    {
      strconst_free (sc);
      return -1;
    }

  sc->trim = !!(opt & FLG_MASK (FLG_TRIM));

  if (filename)
    {
      if (arg)
	{
	  conf_error_at_locus_range (&arg->locus, "superfluous arguments");
	  strconst_free (sc);
	  return -1;
	}
      if (opt & FLG_MASK (FLG_FILEWATCH))
	{
	  if (strconst_register (sc, string_ptr (filename->v.string),
				 &filename->locus))
	    {
	      strconst_free (sc);
	      return -1;
	    }
	}
      else if (strconst_read (sc, string_ptr (filename->v.string),
			      get_include_wd ()))
	{
	  strconst_free (sc);
	  return -1;
	}
    }
  else if (!arg)
    {
      conf_error_at_locus_range (&node->locus, "required argument missing");
      strconst_free (sc);
      return -1;
    }
  else if (cfg_arg_next (arg))
    {
      conf_error_at_locus_range (&cfg_arg_next (arg)->locus,
				 "superfluous arguments");
      strconst_free (sc);
      return -1;
    }
  else
    {
      sc->value = string_ref (arg->v.string);
    }

  if (!*hashptr)
    *hashptr = STRCONST_HASH_NEW ();

  if ((old = STRCONST_INSERT (*hashptr, sc)) != NULL)
    {
      conf_error_at_locus_range (&sc->locus, "%s",
				 "warning: constant redefined");
      conf_error_at_locus_range (&old->locus, "%s",
				 "This is the place of the previous"
				 " definition");
      strconst_free (old);
    }

  return 0;
}

static CFG_FLAG constant_flagdef[] = {
  { "file", FLG_FILE, 1 },
  { "filewatch", FLG_FILEWATCH, 1 },
  { "trim", FLG_TRIM },
  { NULL }
};

static CFG_TYPE cfg_type_constant = {
  .argdef = "sf*s?",
  .flagdef = constant_flagdef,
  .commit = constant_commit
};

STRCONST *
strconst_lookup (STRCONST_HASH *hash, char const *name)
{
  STRCONST *sc = NULL;
  if (hash)
    {
      STRCONST key;
      key.name = (char*)name;
      sc = STRCONST_RETRIEVE (hash, &key);
    }
  return sc;
}

STRCONST *
pound_http_get_strconst (POUND_HTTP *phttp, char const *name)
{
  STRCONST *s;
  if ((s = strconst_lookup (phttp->svc->sctab, name)) == NULL)
    if ((s = strconst_lookup (phttp->lstn->sctab, name)) == NULL)
      s = strconst_lookup (strconst_tab, name);
  return s;
}

/*
 * The CombineHeaders section
 *   CombineHeaders
 *      HEADER
 *      ...
 *   End
 */
static int
comheaders_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  CFG_ARG *arg;
  CFG_ARG_FOREACH (arg, &node->arglist)
    combinable_header_add (string_ptr (arg->v.string));
  return 0;
}

/*
 * The Resolver section.
 */

/* ConfigFile "FILE" */
static int
commit_configfile (CFG_NODE *node, void *call_data, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  char **ptr = cfg_rcvr_ptr (&node->rcvr, baseptr);
  char *s;

  s = slurp (string_ptr (arg->v.string), get_include_wd (), &arg->locus, NULL);
  if (!s)
    return -1;
  *ptr = s;
  return 0;
}

/* Statements allowed for use in the Resolver section. */
static CFG_DEFN resolver_defn[] = {
  {
    .name = "ConfigFile",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = commit_configfile,
    .rcvr = {
      .off = offsetof (struct resolver_config, config_text)
    }
  },
  {
    .name = "ConfigText",
    .token = T_TEXT,
    .vtype = CFG_TYPE_STRING,
    .rcvr = {
      .off = offsetof (struct resolver_config, config_text)
    }
  },
  {
    .name = "Debug",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_BOOL,
    .rcvr = {
      .off = offsetof (struct resolver_config, debug)
    }
  },
  {
    .name = "CNAMEChain",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_UINT,
    .rcvr = {
      .off = offsetof (struct resolver_config, max_cname_chain)
    }
  },
  {
    .name = "RetryInterval",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_DURATION,
    .rcvr = {
      .off = offsetof (struct resolver_config, retry_interval)
    }
  },
  { NULL }
};

static char *resolv_conf_names[] = { "ConfigText", "ConfigFile", NULL };

/*
 * Prepare for committing the resolver settings. Verify if at most one
 * of ConfigFile or ConfigText is used. If both are used, emit a warning
 * and use the last one.
 * On success, store the resolver to *baseptr.
 */
static int
resolver_prepare (CFG_NODE *node, void *call_data, void **baseptr)
{
  POUND_DEFAULTS *dfl = call_data;
  CFG_NODE *prev;

  *baseptr = &dfl->resolver;

  prev = cfg_ast_locate_node (node->subtree, cfg_node_name_memberof,
			      resolv_conf_names);
  while (prev)
    {
      CFG_NODE *next;

      next = cfg_node_locate_next (prev, cfg_node_name_memberof,
				   resolv_conf_names);
      if (next)
	{
	  conf_error_at_locus_range (&next->locus,
				     "%s overrides prior %s",
				     next->defn->name, prev->defn->name);
	  conf_error_at_locus_range (&prev->locus,
				     "%s previosly defined here",
				     prev->defn->name);
	  DLIST_REMOVE (node->subtree, prev, link);
	  cfg_node_free (prev);
	  prev = next;
	}
      else
	prev = NULL;
    }

  return 0;
}

static int
resolver_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
#ifndef ENABLE_DYNAMIC_BACKENDS
  conf_error_at_locus_range (&node->locus,
			     "section ignored: "
			     "pound compiled without support "
			     "for dynamic backends");
#endif
  return 0;
}

static CFG_TYPE cfg_type_resolver = {
  .argdef = "",
  .prepare = resolver_prepare,
  .commit = resolver_commit
};

/*
 * Lua extensions.
 */
#ifdef ENABLE_LUA
extern CFG_DEFN pndlua_defn[];
#else
static int
nolua_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  conf_error_at_locus_range (&node->locus,
			     "this pound is compiled without support for Lua");
  return -1;
}
#endif

static int
luamatch_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  SERVICE_COND *cond =
    service_cond_append (cfg_rcvr_ptr (&node->rcvr, baseptr), COND_LUA);
  return pndlua_parse_closure (node, &cond->clua);
}

static CFG_TYPE cfg_type_luamatch = {
  .argdef = "s+",
  .commit = luamatch_commit
};

/* The deprecated HeadDeny statement. */
static int
head_deny_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  POUND_DEFAULTS *dfl = call_data;
  SERVICE_COND *cond =
    service_cond_append (cfg_rcvr_ptr (&node->rcvr, baseptr), COND_BOOL);
  cond->boolean.op = BOOL_NOT;
  return cond_matcher_commit_generic (node, cfg_arglist_first (&node->arglist),
				      cond, COND_HDR,
				      dfl->re_type, dfl->re_type,
				      GENPAT_MULTILINE | GENPAT_ICASE,
				      NULL);
}

static CFG_TYPE cond_type_simple = {
  .argdef = "f*s?",
  .flagdef = cond_re_flags,
  .commit = cond_matcher_commit_simple
};

static CFG_TYPE cond_type_simple_decode = {
  .argdef = "f*s",
  .flagdef = cond_re_decode_flags,
  .commit = cond_matcher_commit_simple
};

static CFG_TYPE cond_type_twoarg = {
  .argdef = "sf*s",
  .flagdef = cond_re_flags,
  .commit = cond_matcher_commit_twoarg
};

static CFG_TYPE cond_type_twoarg_decode = {
  .argdef = "sf*s",
  .flagdef = cond_re_decode_flags,
  .commit = cond_matcher_commit_twoarg
};

static CFG_TYPE cond_type_header = {
  .argdef = ".*",
  .flagdef = cond_re_flags,
  .commit = cond_header_commit
};

/* BasicAuth [-file|-filewatch] "FILE" */
static int
cond_basicauth_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  SERVICE_COND *cond =
    service_cond_append (cfg_rcvr_ptr (&node->rcvr, baseptr), COND_BASIC_AUTH);
  CFG_ARG *filename = NULL;
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  int opt;
  void *wt;

  if ((opt = get_file_option (&arg, &filename)) == -1)
    return -1;

  if (filename)
    {
      if (!(opt & FLG_MASK (FLG_FILEWATCH)))
	{
	  char const *basename;
	  WORKDIR *wd;
	  int ret = 0;

	  if ((basename = filename_split_wd (string_ptr (filename->v.string),
					     &wd))
	      == NULL)
	    ret = -1;
	  else
	    {
	      int rc = basic_auth_read (cond, basename, wd);
	      workdir_unref (wd);
	      if (rc == -1)
		{
		  if (errno == ENOENT)
		    conf_error_at_locus_range (&filename->locus,
					       "file %s does not exist",
					       string_ptr (filename->v.string));
		  else
		    conf_error_at_locus_range (&filename->locus,
					       "can't open %s: %s",
					       string_ptr (filename->v.string),
					       strerror (errno));
		  ret = -1;
		}
	    }
	  return ret;
	}
    }
  else if (arg)
    filename = arg;
  else
    {
      conf_error_at_locus_range (&node->locus,
				 "required argument missing");
      return -1;
    }

  wt = watcher_register (cond, string_ptr (filename->v.string),
			 &filename->locus,
			 basic_auth_read, basic_auth_clear);
  if (wt == NULL)
    return -1;
  return 0;
}

static CFG_TYPE cond_type_basicauth = {
  .argdef = "f?s?",
  .flagdef = acl_flagdef,
  .commit = cond_basicauth_commit
};

/*
 * TBF
 */

#ifndef UINT64_MAX
# define UINT64_MAX ((uint64_t)-1)
#endif

/*
 * Compute (v * d) / n with range checking.  On success, store the result
 * in retval and return 0.
 */
static int
mulf (unsigned long v, unsigned n, unsigned long d, uint64_t *retval)
{
  if (UINT64_MAX / n < v)
    {
      uint64_t e = (v - UINT64_MAX / n) * n;
      if (UINT64_MAX / n < (v - e))
	return -1;
      *retval = ((v - e) * n) / d + e / d;
    }
  else
    *retval = (v * n) / d;
  return 0;
}

static int
parse_rate (CFG_ARG *arg, uint64_t *ret_rate)
{
  unsigned long rate;
  unsigned long n = 1;
  char *p;
  enum { I_SEC, I_MSEC, I_USEC };
  int i = I_SEC;
  static struct kwtab intervals[] = {
    { "s",  I_SEC },
    { "ms", I_MSEC },
    { "us", I_USEC },
    { NULL }
  };
  static unsigned mul[] = {
    NANOSECOND,
    1000000,
    1000,
  };

  if (arg->type == T_NUMBER)
    {
      rate = arg->v.number;
    }
  else
    {
      errno = 0;
      rate = strtoul (string_ptr (arg->v.string), &p, 10);
      if (errno || rate == 0)
	{
	  conf_error_at_locus_range (&arg->locus, "bad unsigned number");
	  return -1;
	}
      else if (*p == '/')
	{
	  ++p;

	  if (c_isdigit (p[0]))
	    {
	      n = strtoul (p, &p, 10);
	      if (n == 0 || errno)
		{
		  conf_error_at_locus_range (&arg->locus,
					     "bad interval specifier");
		  return -1;
		}
	    }

	  if (kw_to_tok (intervals, p, 1, &i))
	    {
	      conf_error_at_locus_range (&arg->locus, "bad interval specifier");
	      return -1;
	    }
	}
      else if (*p != 0)
	{
	  conf_error_at_locus_range (&arg->locus, "invalid rate");
	  return -1;
	}
    }

  if (mulf (n, mul[i], rate, ret_rate))
    {
      conf_error_at_locus_range (&arg->locus,
				 "effective rate is out of range");
      return -1;
    }

  if (*ret_rate == 0)
    {
      conf_error_at_locus_range (&arg->locus, "effective rate is 0");
      return -1;
    }

  return 0;
}

/* TBF <KEY> <RATE> <BURST> */
static int
cond_tbf_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  SERVICE_COND *cond =
    service_cond_append (cfg_rcvr_ptr (&node->rcvr, baseptr), COND_TBF);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  uint64_t rate;
  unsigned maxtok;
  STRING *key;

  key = string_ref (arg->v.string);
  arg = cfg_arg_next (arg);

  if (parse_rate (arg, &rate))
    return -1;
  arg = cfg_arg_next (arg);

  if (cfg_assert_range (arg, 0, UINT_MAX))
    return -1;
  maxtok = arg->v.number;

  cond->tbf.key = key;
  cond->tbf.tbf = tbf_alloc (rate, maxtok);

  return 0;
}

static CFG_TYPE cond_type_tbf = {
  .argdef = "s[nl]n",
  .commit = cond_tbf_commit
};

/* Base conditions, useful in both request and response processing. */
static CFG_DEFN cond_base_defn[] = {
  {
    .name = "Header",
    .token = T_DIRECTIVE,
    .vtype = &cond_type_header,
    .data = (void *) (intptr_t) COND_HDR
  },
  {
    .name = "StringMatch",
    .token = T_DIRECTIVE,
    .vtype = &cond_type_twoarg,
    .data = (void *) (intptr_t) COND_STRING_MATCH
  },
  {
    .name = "LuaMatch",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_luamatch,
  },
  {
    .name = "Match",
    .token = T_SECTION,
    .vtype = &cfg_type_match,
    .ref = cond_base_defn
  },
  {
    .name = "NOT",
    .token = T_NOT,
    .vtype = &cfg_type_not,
    .ref = cond_base_defn
  },
  {
    .name = "Eval",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_eval
  },
  { NULL }
};

/* Full set of conditions, only for request processing. */
static CFG_DEFN cond_defn[] = {
  {
    .name = "ACL",
    .token = T_ACL,
    .vtype = &cfg_type_aclcond
  },
  {
    .name = "Method",
    .token = T_DIRECTIVE,
    .vtype = &cond_type_simple,
    .data = (void *) (intptr_t) COND_METHOD,
  },
  {
    .name = "URL",
    .token = T_DIRECTIVE,
    .vtype = &cond_type_simple,
    .data = (void *) (intptr_t) COND_URL,
  },
  {
    .name = "Path",
    .token = T_DIRECTIVE,
    .vtype = &cond_type_simple_decode,
    .data = (void *) (intptr_t) COND_PATH
  },
  {
    .name = "Query",
    .token = T_DIRECTIVE,
    .vtype = &cond_type_simple,
    .data = (void *) (intptr_t) COND_QUERY
  },
  {
    .name = "QueryParam",
    .token = T_DIRECTIVE,
    .vtype = &cond_type_twoarg_decode,
    .data = (void *) (intptr_t) COND_QUERY_PARAM
  },
  {
    .name = "Header",
    .token = T_DIRECTIVE,
    .vtype = &cond_type_header,
    .data = (void *) (intptr_t) COND_HDR
  },
  {
    .name = "HeadRequire",
    .type = KWT_ALIAS,
    .deprecated = 1
  },
  {
    .name = "HeadDeny",
    .token = T_DIRECTIVE,
    .vtype = &cond_type_simple,
    .commit = head_deny_commit,
    .deprecated = 1,
    .message = "use \"Not Header\" instead"
  },
  {
    .name = "Host",
    .token = T_DIRECTIVE,
    .vtype = &cond_type_simple,
    .commit = cond_host_commit,
  },
  {
    .name = "BasicAuth",
    .token = T_DIRECTIVE,
    .vtype = &cond_type_basicauth
  },
  {
    .name = "TBF",
    .token = T_DIRECTIVE,
    .vtype = &cond_type_tbf
  },
  {
    .name = "StringMatch",
    .token = T_DIRECTIVE,
    .vtype = &cond_type_twoarg,
    .data = (void *) (intptr_t) COND_STRING_MATCH
  },
  {
    .name = "Match",
    .token = T_SECTION,
    .vtype = &cfg_type_match,
    .ref = cond_defn
  },
  {
    .name = "NOT",
    .token = T_NOT,
    .vtype = &cfg_type_not,
    .ref = cond_defn
  },
  {
    .name = "ClientCert",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_CERT,
    .commit = clientcert_commit
  },
  {
    .name = "Eval",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_eval
  },
  {
    .name = "LuaMatch",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_luamatch,
  },
  { NULL }
};

static int check_eval_resp_usage (CFG_NODE *node, CFG_NODE **pair);
static int check_eval_resp_cb (CFG_NODE *node, void *key);

static int
not_resp_cond (CFG_NODE *node, void *key)
{
  CFG_NODE **pair = key;
  CFG_DEFN const *ref;
  CFG_RCVR rcv;

  if (node->defn->token == T_SECTION || node->defn->token == T_NOT)
    return cfg_ast_locate_node (node->subtree, not_resp_cond, key) != NULL;

  if (!locate_defn (cond_base_defn, node->defn->name, &ref, &rcv)
      && locate_defn (cond_defn, node->defn->name, &ref, &rcv))
    {
      if (pair)
	pair[1] = node;
      return 1;
    }

  if (c_strcasecmp (node->defn->name, "Eval") == 0)
    return check_eval_resp_cb (node, key);

  return 0;
}

static int
check_eval_resp_cb (CFG_NODE *node, void *key)
{
  CFG_NODE **pair = key;
  if (node->defn->token == T_DIRECTIVE &&
      c_strcasecmp (node->defn->name, "Eval") == 0)
    {
      CFG_ARG *arg = cfg_arglist_first (&node->arglist);
      NAMED_COND *nc;

      if ((nc = named_cond_lookup (string_ptr (arg->v.string))) == NULL)
	/* Error will be reported later */
	return 0;

      if (cfg_ast_locate_node (nc->node->subtree, not_resp_cond, pair))
	{
	  pair[0] = node;
	  return 1;
	}
    }
  switch (node->defn->token)
    {
    case T_SECTION:
    case T_NOT:
    case T_REWRITE:
      return check_eval_resp_usage (node, pair);
    }
  return 0;
}

/*
 * Recursively scan node->subtree in search of Evals referring to conditions
 * that cannot be used in Rewrite response. If none are found, return 0.
 * Otherwise, return 1 and fill pair as follows:
 *   pair[0]     The erroneous Eval
 *   pair[1]     The offending condition.
 */
static int
check_eval_resp_usage (CFG_NODE *node, CFG_NODE **pair)
{
  if (!node->subtree)
    return 0;
  return cfg_ast_locate_node (node->subtree, check_eval_resp_cb, pair) != NULL;
}

/*
 * The Rewrite section.
 */
static REWRITE_OP *
rewrite_op_alloc (REWRITE_OP_HEAD *head, enum rewrite_type type)
{
  REWRITE_OP *op;

  XZALLOC (op);
  op->type = type;
  SLIST_PUSH (head, op, next);

  return op;
}

static void rewrite_rule_free (REWRITE_RULE *rule);

static void
rewrite_op_free (REWRITE_OP *op)
{
  switch (op->type)
    {
    case REWRITE_REWRITE_RULE:
      rewrite_rule_free (op->v.rule);
      break;

    case REWRITE_HDR_DEL:
      genpat_free (op->v.hdrdel);
      break;

    case REWRITE_QUERY_PARAM_SET:
      free (op->v.qp.name);
      free (op->v.qp.value);
      break;

    case REWRITE_LUA:
      pndlua_closure_free (&op->v.lua);
      break;

    default:
      free (op->v.str);
    }
  free (op);
}

static void
rewrite_op_head_free (REWRITE_OP_HEAD *ophead)
{
  while (!SLIST_EMPTY (ophead))
    {
      REWRITE_OP *op = SLIST_FIRST (ophead);
      SLIST_SHIFT (ophead, next);
      rewrite_op_free (op);
    }
}

static REWRITE_RULE *
rewrite_rule_alloc (REWRITE_RULE_HEAD *head)
{
  REWRITE_RULE *rule;

  XZALLOC (rule);
  service_cond_init (&rule->cond, COND_BOOL);
  SLIST_INIT (&rule->ophead);

  if (head)
    SLIST_PUSH (head, rule, next);

  return rule;
}

static void
rewrite_rule_free (REWRITE_RULE *rule)
{
  if (rule)
    {
      service_cond_free (&rule->cond);
      rewrite_rule_free (rule->iffalse);
      rewrite_op_head_free (&rule->ophead);
    }
}

static REWRITE_RULE *
rewrite_rule_last_uncond (REWRITE_RULE_HEAD *head)
{
  if (!SLIST_EMPTY (head))
    {
      REWRITE_RULE *rw = SLIST_LAST (head);
      if (rw->cond.type == COND_BOOL && SLIST_EMPTY (&rw->cond.boolean.head))
	return rw;
    }

  return rewrite_rule_alloc (head);
}

enum {
  FLG_ENCODE = 1
};

static CFG_FLAG encode_flags[] = {
  { "encode", FLG_ENCODE },
  { NULL }
};

static void
gen_rewrite_op (CFG_NODE *node, REWRITE_OP_HEAD *head, enum rewrite_type type)
{
  REWRITE_OP *op = rewrite_op_alloc (head, type);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);

  op->encode = cfg_arglist_getflag (arg, NULL, &arg) == FLG_ENCODE;
  op->v.str = xstrdup (string_ptr (arg->v.string));
}

static int
service_reqmod_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  REWRITE_RULE *rule =
    rewrite_rule_last_uncond (cfg_rcvr_ptr (&node->rcvr, baseptr));
  gen_rewrite_op (node, &rule->ophead, (int)(intptr_t)node->defn->data);
  return 0;
}

static CFG_TYPE cfg_type_svc_reqmod_encode = {
  .argdef = "f?s",
  .flagdef = encode_flags,
  .commit = service_reqmod_commit
};

static CFG_TYPE cfg_type_svc_reqmod = {
  .argdef = "s",
  .commit = service_reqmod_commit
};

static int
rw_reqmod_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  gen_rewrite_op (node, cfg_rcvr_ptr (&node->rcvr, baseptr),
		  (int)(intptr_t)node->defn->data);
  return 0;
}

static CFG_TYPE cfg_type_rw_reqmod_encode = {
  .argdef = "f?s",
  .flagdef = encode_flags,
  .commit = rw_reqmod_commit
};

static CFG_TYPE cfg_type_rw_reqmod = {
  .argdef = "s",
  .commit = rw_reqmod_commit
};

/*
 * Generic pattern compiler, useful in deprecated conditional statements.
 */
static int
gen_regex_compat (CFG_ARG *arg, GENPAT *regex, int dfl_re_type, int flags)
{
  struct match_param match_param = MATCH_PARAM_INITIALIZER;
  int rc;
  int gp_type = dfl_re_type;

  if (parse_match_mode (arg, dfl_re_type, &gp_type, &flags, &match_param,
			&arg))
    return -1;

  rc = genpat_compile (regex, gp_type, string_ptr (arg->v.string), flags);
  if (rc)
    {
      conf_regcomp_error (&arg->locus, *regex, NULL);
      genpat_free (*regex);
      *regex = NULL;
      return -1;
    }
  return 0;
}

static int
gen_delete_header_commit (CFG_NODE *node, POUND_DEFAULTS *dfl,
			  REWRITE_OP_HEAD *head)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  REWRITE_OP *op = rewrite_op_alloc (head, REWRITE_HDR_DEL);

  XZALLOC (op->v.hdrdel);
  return gen_regex_compat (arg, &op->v.hdrdel, dfl->re_type,
			   (dfl->ignore_case ? GENPAT_ICASE : 0));
}

/* DeleteHeader [FLAGS] "PAT", used from a Service section. */
static int
service_delete_header_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  REWRITE_RULE *rule =
    rewrite_rule_last_uncond (cfg_rcvr_ptr (&node->rcvr, baseptr));
  return gen_delete_header_commit (node, call_data, &rule->ophead);
}

static CFG_TYPE cfg_type_svc_delete_header = {
  .argdef = "f*s",
  .flagdef = cond_re_flags,
  .commit = service_delete_header_commit
};

/* DeleteHeader used from a Rewrite section. */
static int
rw_delete_header_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  return gen_delete_header_commit (node, call_data,
				   cfg_rcvr_ptr (&node->rcvr, baseptr));
}

static CFG_TYPE cfg_type_rw_delete_header = {
  .argdef = "f*s",
  .flagdef = cond_re_flags,
  .commit = rw_delete_header_commit
};

/* DeleteQuery, used from a Service section. */
static int
service_delete_query_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  REWRITE_RULE *rule =
    rewrite_rule_last_uncond (cfg_rcvr_ptr (&node->rcvr, baseptr));
  rewrite_op_alloc (&rule->ophead, REWRITE_QUERY_DELETE);
  return 0;
}

/* DeleteQuery, used from a Rewrite section. */
static int
rw_delete_query_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  rewrite_op_alloc (cfg_rcvr_ptr (&node->rcvr, baseptr), REWRITE_QUERY_DELETE);
  return 0;
}

static int
gen_setqp_commit (CFG_NODE *node, REWRITE_OP_HEAD *head)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  REWRITE_OP *op = rewrite_op_alloc (head, REWRITE_QUERY_PARAM_SET);

  op->v.qp.name = xstrdup (string_ptr (arg->v.string));
  arg = cfg_arg_next (arg);

  op->encode = cfg_arglist_getflag (arg, NULL, &arg) == FLG_ENCODE;

  if (arg)
    op->v.qp.value = xstrdup (string_ptr (arg->v.string));

  return 0;
}

/*
 * The SetQueryParam statement used in a Service section.
 *
 * SetQueryParam "NAME" [-encode] "VALUE"
 * SetQueryParam "NAME"
 */
static int
service_setqp_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  REWRITE_RULE *rule =
    rewrite_rule_last_uncond (cfg_rcvr_ptr (&node->rcvr, baseptr));
  return gen_setqp_commit (node, &rule->ophead);
}

static CFG_TYPE cfg_type_svc_setqp = {
  .argdef = "sf?s?",
  .flagdef = encode_flags,
  .commit = service_setqp_commit
};

/* SetQueryParam statement used in a Rewrite section. */
static int
rw_setqp_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  return gen_setqp_commit (node, cfg_rcvr_ptr (&node->rcvr, baseptr));
}

static CFG_TYPE cfg_type_rw_setqp = {
  .argdef = "sf?s?",
  .flagdef = encode_flags,
  .commit = rw_setqp_commit
};

/*
 * LuaModify "ARG" ...
 */
static int
service_lua_modify_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  REWRITE_RULE *rule =
    rewrite_rule_last_uncond (cfg_rcvr_ptr (&node->rcvr, baseptr));
  REWRITE_OP *op = rewrite_op_alloc (&rule->ophead, REWRITE_LUA);
  return pndlua_parse_closure (node, &op->v.lua);
}

static CFG_TYPE cfg_type_svc_lua_modify = {
  .argdef = "s+",
  .commit = service_lua_modify_commit
};

static int
rw_lua_modify_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  REWRITE_OP *op = rewrite_op_alloc (cfg_rcvr_ptr (&node->rcvr, baseptr),
				     REWRITE_LUA);
  return pndlua_parse_closure (node, &op->v.lua);
}

static CFG_TYPE cfg_type_rw_lua_modify = {
  .argdef = "s+",
  .commit = rw_lua_modify_commit
};

/* Minimal set of request modification statements for use in Rewrite sections.
 */
static CFG_DEFN rw_mod_base[] = {
  {
    .name = "SetHeader",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_rw_reqmod,
    .data = (void*)(intptr_t) REWRITE_HDR_SET,
  },
  {
    .name = "DeleteHeader",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_rw_delete_header,
  },
  {
    .name = "LuaModify",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_rw_lua_modify,
  },
  { NULL }
};

/* Extended set of request modification statements for use in Rewrite sections.
 */
static CFG_DEFN rw_mod_ext[] = {
  {
    .name = "SetURL",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_rw_reqmod,
    .data = (void*)(intptr_t) REWRITE_URL_SET,
  },
  {
    .name = "SetPath",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_rw_reqmod_encode,
    .data = (void*)(intptr_t) REWRITE_PATH_SET,
  },
  {
    .name = "SetQuery",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_rw_reqmod,
    .data = (void*)(intptr_t) REWRITE_QUERY_SET,
  },
  {
    .name = "DeleteQuery",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_OPT_BOOL,
    .commit = rw_delete_query_commit,
  },
  {
    .name = "SetQueryParam",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_rw_setqp,
  },
  { NULL }
};

/* Modification statements allowed for use in Rewrite response sections. */
static CFG_DEFN rw_resp_defn[] = {
  {
    .name = "",
    .type = KWT_SOFTREF,
    .ref = cond_base_defn,
    .rcvr = {
      .off = offsetof (REWRITE_RULE, cond),
    }
  },
  {
    .name = "",
    .type = KWT_SOFTREF,
    .ref = rw_mod_base,
    .rcvr = {
      .off = offsetof (REWRITE_RULE, ophead),
    }
  },
  {
    .name = "Else",
    .token = T_ELSE,
    .ref = rw_resp_defn,
  },
  { NULL }
};

/* Modification statements allowed for use in Rewrite request sections. */
static CFG_DEFN rw_req_defn[] = {
  {
    .name = "",
    .type = KWT_SOFTREF,
    .ref = cond_defn,
    .rcvr = {
      .off = offsetof (REWRITE_RULE, cond),
    }
  },
  {
    .name = "",
    .type = KWT_SOFTREF,
    .ref = rw_mod_base,
    .rcvr = {
      .off = offsetof (REWRITE_RULE, ophead),
    }
  },
  {
    .name = "",
    .type = KWT_SOFTREF,
    .ref = rw_mod_ext,
    .rcvr = {
      .off = offsetof (REWRITE_RULE, ophead),
    }
  },
  {
    .name = "Else",
    .token = T_ELSE,
    .ref = rw_req_defn,
  },
  { NULL }
};

/* Selector for the two Rewrite flavors. */
static CFG_DEFN rw_defn[] = {
  {
    .name = "request",
    .type = KWT_TABREF,
    .ref  = rw_req_defn
  },
  {
    .name = "response",
    .type = KWT_TABREF,
    .ref  = rw_resp_defn
  },
  { NULL }
};

struct rwclosure
{
  REWRITE_RULE *prev;
  REWRITE_RULE *rule;
};

static int
rewrite_branch_prepare (CFG_NODE *node, void *call_data, void **baseptr)
{
  struct rwclosure *clos = *baseptr;

  if (clos->prev)
    {
      clos->rule = rewrite_rule_alloc (NULL);
      clos->prev->iffalse = clos->rule;
    }
  clos->prev = clos->rule;

  *baseptr = clos->rule;

  return 0;
}

static CFG_TYPE cfg_type_rewrite_branch = {
  .prepare = rewrite_branch_prepare
};

static int
service_rewrite_prepare (CFG_NODE *node, void *call_data, void **baseptr)
{
  REWRITE_RULE_HEAD *rw = cfg_rcvr_ptr (&node->rcvr, *baseptr);
  struct rwclosure *clos;

  assert (node->rwtarget == REWRITE_REQUEST ||
	  node->rwtarget == REWRITE_RESPONSE);

  if (node->rwtarget == REWRITE_RESPONSE)
    {
      CFG_NODE *pair[2];
      if (check_eval_resp_usage (node, pair))
	{
	  conf_error_at_locus_range (&pair[0]->locus,
				     "eval refers to a condition that cannot"
				     " be used in Rewrite response");
	  conf_error_at_locus_range (&pair[1]->locus,
				     "this is the location of the"
				     " offending statement");
	  return -1;
	}
    }

  XZALLOC (clos);
  clos->rule = rewrite_rule_alloc (&rw[node->rwtarget]);
  node->data = clos;

  *baseptr = clos;

  return 0;
}

static CFG_TYPE cfg_type_svc_rewrite = {
  .prepare = service_rewrite_prepare,
};

/*
 * Service operations.
 */

/* Return 1 if a service with the given NAME exists in SVC_HEAD. */
static int
find_service_ident (SERVICE_HEAD *svc_head, char const *name)
{
  SERVICE *svc;
  SLIST_FOREACH (svc, svc_head, next)
    {
      if (svc->name && strcmp (svc->name, name) == 0)
	return 1;
    }
  return 0;
}

/* Create a new service, using balancing algorithm ALGO. */
static SERVICE *
new_service (BALANCER_ALGO algo)
{
  SERVICE *svc;

  XZALLOC (svc);

  service_cond_init (&svc->cond, COND_BOOL);
  DLIST_INIT (&svc->balancers);

  svc->sess_type = SESS_NONE;
  pthread_mutex_init (&svc->mut, &mutex_attr_recursive);
  svc->balancer_algo = algo;
  svc->rewrite_errors = -1;
  locus_range_init (&svc->locus);

  DLIST_INIT (&svc->be_rem_head);
  pthread_cond_init (&svc->be_rem_cond, NULL);

  return svc;
}

/* Prepare the Service section. */
static int
svc_prepare (CFG_NODE *node, void *call_data, void **baseptr)
{
  POUND_DEFAULTS *dfl = (POUND_DEFAULTS*) call_data;
  SERVICE_HEAD *head = cfg_rcvr_ptr (&node->rcvr, *baseptr);
  SERVICE *svc;

  svc = new_service (dfl->balancer_algo);
  locus_range_copy (&svc->locus, &node->locus);
  if (!cfg_arglist_empty (&node->arglist))
    {
      CFG_ARG *arg = cfg_arglist_first (&node->arglist);
      char const *tag = string_ptr (arg->v.string);

      if (find_service_ident (head, tag))
	{
	  conf_error_at_locus_range (&arg->locus,
				     "service name is not unique");
	  return -1;
	}
      svc->name = xstrdup (tag);
    }

  if ((svc->sessions = session_table_new ()) == NULL)
    {
      /* FIXME: service_free (svc) */
      conf_error_at_locus_range (&node->locus, "session_table_new failed");
      return -1;
    }

  *baseptr = svc;

  /* FIXME: Instead of this, assign svc to node->data and provide
     vtype->free_data so that it gets freed in case of errors. */
  SLIST_PUSH (head, svc, next);

  return 0;
}

static CFG_TYPE cfg_type_service = {
  .argdef = "s?",
  .prepare = svc_prepare
};

/* The deprecated IgnoreCase statement, used in the Service section. */
static int
svc_ignorecase_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  POUND_DEFAULTS *dfl = (POUND_DEFAULTS*) call_data;
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  dfl->ignore_case = arg->v.number;
  return 0;
}

/* Statements allowed for use in Service sections. */
static CFG_DEFN svc_defn[] = {
  {
    .name = "",
    .type = KWT_SOFTREF,
    .ref = cond_defn,
    .rcvr = {
      .off = offsetof (SERVICE, cond),
    }
  },
  {
    .name = "Backend",
    .token = T_SECTION,
    .vtype = &cfg_type_service_backend,
    .ref = service_backend_defn,
    .rcvr = {
      .off = offsetof (SERVICE, balancers)
    }
  },
  {
    .name = "UseBackend",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = service_use_backend_commit,
    .rcvr = {
      .off = offsetof (SERVICE, balancers)
    }
  },
  {
    .name = "Emergency",
    .token = T_SECTION,
    .vtype = &cfg_type_service_emergency,
    .ref = service_backend_defn,
    .rcvr = {
      .off = offsetof (SERVICE, balancers)
    }
  },
  {
    .name = "Redirect",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_service_redirect,
    .rcvr = {
      .off = offsetof (SERVICE, balancers)
    }
  },
  {
    .name = "Error",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_service_error,
    .rcvr = {
      .off = offsetof (SERVICE, balancers)
    }
  },
  {
    .name = "SendFile",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = &service_sendfile_commit,
    .rcvr = {
      .off = offsetof (SERVICE, balancers)
    }
  },
  {
    .name = "Success",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_NULL,
    .commit = service_success_commit,
    .rcvr = {
      .off = offsetof (SERVICE, balancers)
    }
  },
  {
    .name = "Metrics",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_NULL,
    .commit = service_metrics_commit,
    .rcvr = {
      .off = offsetof (SERVICE, balancers)
    }
  },
  {
    .name = "Control",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_NULL,
    .commit = service_control_commit,
    .rcvr = {
      .off = offsetof (SERVICE, balancers)
    }
  },
  {
    .name = "RewriteErrors",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_BOOL,
    .rcvr = {
      .off = offsetof (SERVICE, rewrite_errors)
    }
  },
  {
    .name = "LuaBackend",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_luabackend,
    .rcvr = {
      .off = offsetof (SERVICE, balancers)
    }
  },
  {
    .name = "Session",
    .token = T_SECTION,
    .vtype = &cfg_type_service_session,
    .ref = service_session_defn
  },
  {
    .name = "Balancer",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_balancer,
    .rcvr = {
      .off = offsetof (SERVICE, balancer_algo)
    }
  },
  {
    .name = "ForwardedHeader",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .rcvr = {
      .off = offsetof (SERVICE, forwarded_header)
    }
  },
  {
    .name = "TrustedIP",
    .token = T_TRUSTEDIP,
    .vtype = &cfg_type_trustedip,
    .rcvr = {
      .off = offsetof (SERVICE, trusted_ips)
    }
  },
  {
    .name = "LogSuppress",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_log_suppress,
    .rcvr = {
      .off = offsetof (SERVICE, log_suppress_mask)
    }
  },
  {
    .name = "Constant",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_constant,
    .rcvr = {
      .off = offsetof (SERVICE, sctab)
    }
  },
  {
    .name = "Disabled",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_BOOL,
    .rcvr = {
      .off = offsetof (SERVICE, disabled)
    }
  },
  {
    .name = "FallThrough",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_OPT_BOOL,
    .rcvr = {
      .off = offsetof (SERVICE, fall_through)
    }
  },

  /* Set* statements */
  {
    .name = "SetURL",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_svc_reqmod,
    .data = (void*)(intptr_t) REWRITE_URL_SET,
    .rcvr = {
      .off = offsetof (SERVICE, rewrite)
    }
  },
  {
    .name = "SetPath",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_svc_reqmod_encode,
    .data = (void*)(intptr_t) REWRITE_PATH_SET,
    .rcvr = {
      .off = offsetof (SERVICE, rewrite)
    }
  },
  {
    .name = "SetQuery",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_svc_reqmod,
    .data = (void*)(intptr_t) REWRITE_QUERY_SET,
    .rcvr = {
      .off = offsetof (SERVICE, rewrite)
    }
  },
  {
    .name = "SetHeader",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_svc_reqmod,
    .data = (void*)(intptr_t) REWRITE_HDR_SET,
    .rcvr = {
      .off = offsetof (SERVICE, rewrite)
    }
  },
  {
    .name = "DeleteHeader",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_svc_delete_header,
    .rcvr = {
      .off = offsetof (SERVICE, rewrite)
    }
  },
  {
    .name = "DeleteQuery",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_OPT_BOOL,
    .commit = service_delete_query_commit,
    .rcvr = {
      .off = offsetof (SERVICE, rewrite)
    }
  },
  {
    .name = "SetQueryParam",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_svc_setqp,
    .rcvr = {
      .off = offsetof (SERVICE, rewrite)
    }
  },
  {
    .name = "LuaModify",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_svc_lua_modify,
    .rcvr = {
      .off = offsetof (SERVICE, rewrite)
    }
  },
  {
    .name = "ContentCapture",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_SIZE,
    .rcvr = {
      .off = offsetof (SERVICE, capture_size)
    }
  },
  {
    .name = "Rewrite",
    .token = T_REWRITE,
    .vtype = &cfg_type_svc_rewrite,
    .ref = rw_defn,
    .rcvr = {
      .off = offsetof (SERVICE, rewrite)
    }
  },
  {
    .name = "IgnoreCase",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_BOOL,
    .commit = svc_ignorecase_commit,
    .deprecated = 1,
    .message = "use the -icase matching directive flag to request case-insensitive comparison"
  },
  { NULL }
};

/*
 * Listeners
 */
static int
socketfrom_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  LISTENER *lst = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  char const *sockname = string_ptr (arg->v.string);
  struct sockaddr_un *sun;
  size_t len;

  len = strlen (sockname);
  if (len > UNIX_PATH_MAX)
    {
      conf_error_at_locus_range (&arg->locus, "UNIX path name too long");
      return -1;
    }

  len += offsetof (struct sockaddr_un, sun_path) + 1;
  sun = xmalloc (len);
  sun->sun_family = AF_UNIX;
  strcpy (sun->sun_path, sockname);

  lst->addr.ai_socktype = SOCK_STREAM;
  lst->addr.ai_family = AF_UNIX;
  lst->addr.ai_protocol = 0;
  lst->addr.ai_addr = (struct sockaddr *) sun;
  lst->addr.ai_addrlen = len;

  lst->socket_from = 1;

  return 0;
}

static CFG_DEFN listener_address_common[] = {
  {
    .name = "Address",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_LAZY_STRING,
    .rcvr = {
      .off = offsetof (LISTENER, addr_str)
    }
  },
  {
    .name = "Port",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_PORT_STRING,
    .rcvr = {
      .off = offsetof (LISTENER, port_str)
    }
  },
  {
    .name = "SocketFrom",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = socketfrom_commit
  },
  { NULL }
};

/* XHTTP <N> */
static int
xhttp_commit (CFG_NODE *node, void *unused, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);

  if (cfg_assert_range (arg, 0, 3))
    return -1;

  *(int*) cfg_rcvr_ptr (&node->rcvr, baseptr) = arg->v.number;
  return 0;
}

/* CheckURL "PAT" */
static int
checkurl_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  LISTENER *lst = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  POUND_DEFAULTS *dfl = call_data;

  if (lst->url_pat)
    {
      conf_error_at_locus_range (&node->locus, "CheckURL multiple pattern");
      return -1;
    }

  return gen_regex_compat (arg, &lst->url_pat, dfl->re_type,
			   (dfl->ignore_case ? GENPAT_ICASE : 0));
}

/* ErrorFile CODE "FILENAME" */
static int
errorfile_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  struct http_errmsg **http_err = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  int status;

  if (arg->v.number > INT_MAX ||
      (status = http_status_to_pound (arg->v.number)) == -1)
    {
      conf_error_at_locus_range (&arg->locus, "unsupported status code");
      return -1;
    }

  if (!http_err[status])
    XZALLOC (http_err[status]);

  return parse_http_errmsg (http_err[status], cfg_arg_next (arg));
}

/* MaxRequest <N> */
static CFG_TYPE cfg_type_errorfile = {
  .argdef = "ns",
  .commit = errorfile_commit
};

/*
 * Support for backward-compatible HeaderRemove and HeadRemove directives.
 */
static int
headerremove_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  POUND_DEFAULTS *dfl = call_data;
  REWRITE_RULE *rule =
    rewrite_rule_last_uncond (cfg_rcvr_ptr (&node->rcvr, baseptr));
  REWRITE_OP *op = rewrite_op_alloc (&rule->ophead, REWRITE_HDR_DEL);
  XZALLOC (op->v.hdrdel);
  return gen_regex_compat (cfg_arglist_first (&node->arglist),
			   &op->v.hdrdel, dfl->re_type,
			   GENPAT_ICASE | GENPAT_MULTILINE);
}

/* RewriteLocation <N> */
static int
rewritelocation_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);

  if (cfg_assert_range (arg, 0, 3))
    return -1;

  *(int*) cfg_rcvr_ptr (&node->rcvr, baseptr) = arg->v.number;
  return 0;
}

/* ACME <DIR> */
static int
acme_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  SERVICE_HEAD *head = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  char const *dir = string_ptr (arg->v.string);
  SERVICE *svc;
  BACKEND *be;
  SERVICE_COND *cond;
  struct stat st;
  int rc;
  static char sp_acme[] = "^/\\.well-known/acme-challenge/(.+)";
  int fd;
  WORKDIR *wd = get_include_wd ();

  if (fstatat (wd ? wd->fd : AT_FDCWD, dir, &st, 0))
    {
      conf_error_at_locus_range (&arg->locus, "can't stat %s: %s",
				 dir, strerror (errno));
      return -1;
    }
  if (!S_ISDIR (st.st_mode))
    {
      conf_error_at_locus_range (&arg->locus, "%s is not a directory", dir);
      return -1;
    }
  if ((fd = open_wd (wd, dir, O_RDONLY | O_NONBLOCK | O_DIRECTORY, 0)) == -1)
    {
      conf_error_at_locus_range (&arg->locus, "can't open: %s",
				 strerror (errno));
      return -1;
    }

  /* Create service; there'll be only one backend so the balancing algorithm
     doesn't really matter. */
  svc = new_service (BALANCER_ALGO_RANDOM);

  /* Create a URL matcher */
  cond = service_cond_append (&svc->cond, COND_URL);
  rc = genpat_compile (&cond->re, GENPAT_POSIX, sp_acme, 0);
  if (rc)
    {
      conf_regcomp_error (&node->locus, cond->re, NULL);
      /* FIXME: service_free (svc) */
      return -1;
    }

  locus_range_init (&svc->locus);
  locus_range_copy (&svc->locus, &node->locus);

  /* Create ACME backend */
  be = xbackend_create (BE_ACME, 1, &node->locus);
  be->service = svc;
  be->priority = 1;
  be->v.acme.wd = fd;

  /* Register backend in service */
  balancer_add_backend (balancer_list_get_normal (&svc->balancers), be);
  service_recompute_pri_unlocked (svc, NULL, NULL);

  /* Register service in the listener */
  SLIST_PUSH (head, svc, next);

  return 0;
}

/* Statements allowed for use in both ListenHTTP and ListenHTTPS sections. */
static CFG_DEFN http_common[] = {
  {
    .name = "",
    .type = KWT_TABREF,
    .ref = listener_address_common
  },
  {
    .name = "xHTTP",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_INT,
    .commit = xhttp_commit,
    .rcvr = {
      .off = offsetof (LISTENER, verb)
    }
  },
  {
    .name = "Client",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_DURATION,
    .rcvr = {
      .off = offsetof (LISTENER, to)
    }
  },
  {
    .name = "CheckURL",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = checkurl_commit
  },
  {
    .name = "ErrorFile",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_errorfile,
    .rcvr = {
      .off = offsetof (LISTENER, http_err)
    }
  },
  {
    .name = "MaxRequest",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_CONTENT_LENGTH,
    .rcvr = {
      .off = offsetof (LISTENER, max_req_size)
    }
  },
  {
    .name = "MaxURI",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_SIZE,
    .rcvr = {
      .off = offsetof (LISTENER, max_uri_length)
    }
  },
  {
    .name = "Rewrite",
    .token = T_REWRITE,
    .vtype = &cfg_type_svc_rewrite,
    .ref = rw_defn,
    .rcvr = {
      .off = offsetof (LISTENER, rewrite)
    }
  },
  {
    .name = "RewriteErrors",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_BOOL,
    .rcvr = {
      .off = offsetof (LISTENER, rewrite_errors)
    }
  },
  {
    .name = "SetHeader",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_svc_reqmod,
    .data = (void*)(intptr_t) REWRITE_HDR_SET,
    .rcvr = {
      .off = offsetof (LISTENER, rewrite)
    }
  },
  {
    .name = "HeaderAdd",
    .type = KWT_ALIAS,
    .deprecated = 1
  },
  {
    .name = "AddHeader",
    .type = KWT_ALIAS,
    .deprecated = 1
  },
  {
    .name = "DeleteHeader",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_svc_delete_header,
    .rcvr = {
      .off = offsetof (LISTENER, rewrite)
    }
  },
  {
    .name = "HeaderRemove",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = headerremove_commit,
    .rcvr = {
      .off = offsetof (LISTENER, rewrite)
    },
    .deprecated = 1,
    .message = "use \"DeleteHeader\" instead"
  },
  {
    .name = "HeadRemove",
    .type = KWT_ALIAS,
    .deprecated = 1,
    .message = "use \"DeleteHeader\" instead"
  },
  {
    .name = "SetURL",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_svc_reqmod,
    .data = (void*)(intptr_t) REWRITE_URL_SET,
    .rcvr = {
      .off = offsetof (LISTENER, rewrite)
    }
  },
  {
    .name = "SetPath",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_svc_reqmod_encode,
    .data = (void*)(intptr_t) REWRITE_PATH_SET,
    .rcvr = {
      .off = offsetof (LISTENER, rewrite)
    }
  },
  {
    .name = "DeleteQuery",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_OPT_BOOL,
    .commit = service_delete_query_commit,
    .rcvr = {
      .off = offsetof (LISTENER, rewrite)
    }
  },
  {
    .name = "SetQuery",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_svc_reqmod,
    .data = (void*)(intptr_t) REWRITE_QUERY_SET,
    .rcvr = {
      .off = offsetof (LISTENER, rewrite)
    }
  },
  {
    .name = "SetQueryParam",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_svc_setqp,
    .rcvr = {
      .off = offsetof (LISTENER, rewrite)
    }
  },
  {
    .name = "LuaModify",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_svc_lua_modify,
    .rcvr = {
      .off = offsetof (LISTENER, rewrite)
    }
  },
  {
    .name = "HeaderOption",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_headeroptions,
    .rcvr = {
      .off = offsetof (LISTENER, header_options)
    }
  },
  {
    .name = "RewriteLocation",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_UINT,
    .commit = rewritelocation_commit,
    .rcvr = {
      .off = offsetof (LISTENER, rewr_loc)
    }
  },
  {
    .name = "RewriteDestination",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_BOOL,
    .rcvr = {
      .off = offsetof (LISTENER, rewr_dest)
    }
  },
  {
    .name = "LogLevel",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_loglevel,
    .rcvr = {
      .off = offsetof (LISTENER, log_level)
    }
  },
  {
    .name = "ForwardedHeader",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .rcvr = {
      .off = offsetof (LISTENER, forwarded_header)
    }
  },
  {
    .name = "TrustedIP",
    .token = T_TRUSTEDIP,
    .vtype = &cfg_type_trustedip,
    .rcvr = {
      .off = offsetof (LISTENER, trusted_ips)
    }
  },
  {
    .name = "Service",
    .token = T_SECTION,
    .vtype = &cfg_type_service,
    .ref = svc_defn,
    .rcvr = {
      .off = offsetof (LISTENER, services)
    }
  },
  {
    .name = "LineBufferSize",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_SIZE,
    .rcvr = {
      .off = offsetof (LISTENER, linebufsize),
    }
  },
  {
    .name = "Constant",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_constant,
    .rcvr = {
      .off = offsetof (LISTENER, sctab)
    }
  },
  { NULL }
};

/*
 * Deprecated ErrN statements.
 */
static int
errN_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  struct http_errmsg **http_err = cfg_rcvr_ptr (&node->rcvr, baseptr);
  if (!*http_err)
    XZALLOC (*http_err);
  return parse_http_errmsg (*http_err, cfg_arglist_first (&node->arglist));
}

static CFG_DEFN http_deprecated[] = {
  {
    .name = "Err400",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = errN_commit,
    .rcvr = {
      .off = offsetof (LISTENER, http_err[HTTP_STATUS_BAD_REQUEST]),
    },
    .deprecated = 1,
    .message = "use \"ErrorFile 400\" instead"
  },
  {
    .name = "Err401",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = errN_commit,
    .rcvr = {
      .off = offsetof (LISTENER, http_err[HTTP_STATUS_UNAUTHORIZED]),
    },
    .deprecated = 1,
    .message = "use \"ErrorFile 401\" instead"
  },
  {
    .name = "Err403",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = errN_commit,
    .rcvr = {
      .off = offsetof (LISTENER, http_err[HTTP_STATUS_FORBIDDEN]),
    },
    .deprecated = 1,
    .message = "use \"ErrorFile 403\" instead"
  },
  {
    .name = "Err404",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = errN_commit,
    .rcvr = {
      .off = offsetof (LISTENER, http_err[HTTP_STATUS_NOT_FOUND]),
    },
    .deprecated = 1,
    .message = "use \"ErrorFile 404\" instead"
  },
  {
    .name = "Err413",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = errN_commit,
    .rcvr = {
      .off = offsetof (LISTENER, http_err[HTTP_STATUS_PAYLOAD_TOO_LARGE]),
    },
    .deprecated = 1,
    .message = "use \"ErrorFile 413\" instead"
  },
  {
    .name = "Err414",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = errN_commit,
    .rcvr = {
      .off = offsetof (LISTENER, http_err[HTTP_STATUS_URI_TOO_LONG]),
    },
    .deprecated = 1,
    .message = "use \"ErrorFile 414\" instead"
  },
  {
    .name = "Err500",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = errN_commit,
    .rcvr = {
      .off = offsetof (LISTENER, http_err[HTTP_STATUS_INTERNAL_SERVER_ERROR]),
    },
    .deprecated = 1,
    .message = "use \"ErrorFile 500\" instead"
  },
  {
    .name = "Err501",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = errN_commit,
    .rcvr = {
      .off = offsetof (LISTENER, http_err[HTTP_STATUS_NOT_IMPLEMENTED]),
    },
    .deprecated = 1,
    .message = "use \"ErrorFile 501\" instead"
  },
  {
    .name = "Err503",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = errN_commit,
    .rcvr = {
      .off = offsetof (LISTENER, http_err[HTTP_STATUS_SERVICE_UNAVAILABLE]),
    },
    .deprecated = 1,
    .message = "use \"ErrorFile 503\" instead"
  },
  { NULL }
};


/* Statements allowed in ListenHTTP */
static CFG_DEFN lst_http_defn[] = {
  {
    .name = "",
    .type = KWT_TABREF,
    .ref = http_common
  },
  {
    .name = "",
    .type = KWT_TABREF,
    .ref = http_deprecated
  },
  {
    .name = "ACME",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = acme_commit,
    .rcvr = {
      .off = offsetof (LISTENER, services)
    }
  },
  { NULL }
};

/*
 * ListenHTTPS support.
 */
#define general_name_string(n) \
	xstrndup ((char*)ASN1_STRING_get0_data (n->d.dNSName),	\
		 ASN1_STRING_length (n->d.dNSName) + 1)

static void
get_subjectaltnames (X509 *x509, POUND_CTX *pc, size_t san_max)
{
  STACK_OF (GENERAL_NAME) * san_stack =
    (STACK_OF (GENERAL_NAME) *) X509_get_ext_d2i (x509, NID_subject_alt_name,
						  NULL, NULL);
  char **result;

  if (san_stack == NULL)
    return;
  while (sk_GENERAL_NAME_num (san_stack) > 0)
    {
      GENERAL_NAME *name = sk_GENERAL_NAME_pop (san_stack);
      switch (name->type)
	{
	case GEN_DNS:
	  if (pc->subjectAltNameCount == san_max)
	    pc->subjectAltNames = x2nrealloc (pc->subjectAltNames,
					      &san_max,
					      sizeof (pc->subjectAltNames[0]));
	  pc->subjectAltNames[pc->subjectAltNameCount++] = general_name_string (name);
	  break;

	default:
	  logmsg (LOG_INFO, "unsupported subjectAltName type encountered: %i",
		  name->type);
	}
      GENERAL_NAME_free (name);
    }

  sk_GENERAL_NAME_pop_free (san_stack, GENERAL_NAME_free);
  if (pc->subjectAltNameCount
      && (result = realloc (pc->subjectAltNames,
			    pc->subjectAltNameCount * sizeof (pc->subjectAltNames[0]))) != NULL)
    pc->subjectAltNames = result;
}

static int
load_ca_certs (SSL_CTX *ctx, BIO *in)
{
  X509 *ca;
  int rc;
  unsigned long err;

  rc = SSL_CTX_clear_chain_certs (ctx);
  if (!rc)
    return 0;

  while ((ca = PEM_read_bio_X509 (in, NULL, NULL, NULL)) != NULL)
    {
      rc = SSL_CTX_add0_chain_cert (ctx, ca);
      if (!rc)
	{
	  X509_free (ca);
	  return rc;
	}
    }

  err = ERR_peek_last_error ();
  if (ERR_GET_LIB (err) == ERR_LIB_PEM
      && ERR_GET_REASON (err) == PEM_R_NO_START_LINE)
    ERR_clear_error ();
  else
    rc = 0;            /* some real error */
  return rc;
}

static int
load_certificate_chain (SSL_CTX *ctx, BIO *in)
{
  int rc = 0;
  X509 *x = NULL;

  ERR_clear_error ();

  x = PEM_read_bio_X509_AUX (in, NULL, NULL, NULL);
  if (x)
    {
      rc = SSL_CTX_use_certificate (ctx, x);
      if (ERR_peek_error () != 0)
	rc = 0;

      if (rc)
	rc = load_ca_certs (ctx, in);

      X509_free (x);
    }

  return rc;
}

static int
load_private_key (SSL_CTX *ctx, BIO *in)
{
  int rc;
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey (in, NULL, NULL, NULL);
  if (!pkey)
    return 0;
  rc = SSL_CTX_use_PrivateKey (ctx, pkey);
  EVP_PKEY_free (pkey);
  return rc;
}

static int
load_san (POUND_CTX *pc, BIO *bio, struct locus_range const *loc)
{
  int i;
  size_t san_max = 0;
  X509 *x509;
  X509_NAME *xname;

  x509 = PEM_read_bio_X509 (bio, NULL, NULL, NULL);

  if (!x509)
    {
      conf_error_at_locus_range (loc, "could not get certificate subject");
      return -1;
    }

  pc->subjectAltNameCount = 0;
  pc->subjectAltNames = NULL;
  san_max = 0;

  /* Extract server name */
  xname = X509_get_subject_name (x509);
  for (i = -1;
       (i = X509_NAME_get_index_by_NID (xname, NID_commonName, i)) != -1;)
    {
      X509_NAME_ENTRY *entry = X509_NAME_get_entry (xname, i);
      ASN1_STRING *value;
      char *str = NULL;
      value = X509_NAME_ENTRY_get_data (entry);
      if (ASN1_STRING_to_UTF8 ((unsigned char **)&str, value) >= 0)
	{
	  if (pc->server_name == NULL)
	    pc->server_name = str;
	  else
	    {
	      if (pc->subjectAltNameCount == san_max)
		pc->subjectAltNames = x2nrealloc (pc->subjectAltNames,
						  &san_max,
						  sizeof (pc->subjectAltNames[0]));
	      pc->subjectAltNames[pc->subjectAltNameCount++] = str;
	    }
	}
    }

  get_subjectaltnames (x509, pc, san_max);
  X509_free (x509);

  if (pc->server_name == NULL)
    {
      conf_error_at_locus_range (loc, "no CN in certificate subject name");
      return -1;
    }

  return 0;
}

static int
pound_ctx_load_cert (POUND_CTX *pc, BIO *bio, char const *filename,
		     struct locus_range const *loc)
{
  if ((pc->ctx = SSL_CTX_new (SSLv23_server_method ())) == NULL)
    {
      conf_openssl_error (loc, NULL, "SSL_CTX_new");
      return -1;
    }

  if (load_certificate_chain (pc->ctx, bio) != 1)
    {
      conf_openssl_error (loc, filename, "can't load certificate chain");
      return -1;
    }

  BIO_seek (bio, 0);

  if (load_private_key (pc->ctx, bio) != 1)
    {
      conf_openssl_error (loc, filename, "can't load private keys");
      return -1;
    }
  if (SSL_CTX_check_private_key (pc->ctx) != 1)
    {
      conf_openssl_error (loc, filename, "SSL_CTX_check_private_key");
      return -1;
    }

  BIO_seek (bio, 0);

  return load_san (pc, bio, loc);
}

void
pound_ctx_free (POUND_CTX *pc)
{
  size_t i;

  if (pc->ctx)
    SSL_CTX_free (pc->ctx);
  if (pc->server_name)
    OPENSSL_free (pc->server_name);

  for (i = 0; i < pc->subjectAltNameCount; i++)
    OPENSSL_free (pc->subjectAltNames[i]);

  free (pc->subjectAltNames);
  free (pc);
}

static int
load_cert_wd (WORKDIR *wd, char const *filename,
	      struct locus_range const *loc, LISTENER *lst)
{
  POUND_CTX *pc;
  int fd;
  BIO *bio;
  int rc;

  fd = open_wd (wd, filename, O_RDONLY, 0);
  if (fd == -1)
    {
      conf_error_at_locus_range (loc, "can't open %s: %s", filename,
				 strerror (errno));
      return -1;
    }

  bio = BIO_new_fd (fd, BIO_CLOSE);
  if (!bio)
    {
      conf_error_at_locus_range (loc, "BIO_new_fd failed");
      return -1;
    }

  XZALLOC (pc);

  rc = pound_ctx_load_cert (pc, bio, filename, loc);

  BIO_free (bio);

  if (rc == 0)
    SLIST_PUSH (&lst->ctx_head, pc, next);
  else
    pound_ctx_free (pc);

  return rc;
}

static int
try_cert_wd (WORKDIR *wd, char const *filename,
	     struct locus_range const *loc, LISTENER *lst)
{
  struct stat st;
  int rc = 0;

  if (fstatat (wd->fd, filename, &st, 0))
    {
      conf_error_at_locus_range (loc,
				 "%s: stat error: %s",
				 filename, strerror (errno));
      rc = -1;
    }
  else if (S_ISREG (st.st_mode))
    rc = load_cert_wd (wd, filename, loc, lst);
  else
    conf_error_at_locus_range (loc,
			       "warning: "
			       "ignoring %s: not a regular file",
			       filename);
  return rc;
}

static DIR *
opendir_wd (WORKDIR *wd, char const *name)
{
  DIR *dir;
  int fd = open_wd (wd, name, O_DIRECTORY | O_RDONLY | O_NDELAY, 0);
  if (fd == -1)
    return NULL;
  dir = fdopendir (fd);
  if (!dir)
    {
      int ec = errno;
      close (fd);
      errno = ec;
    }
  return dir;
}

/* Cert "FILE" */
static int
cert_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  LISTENER *lst = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  char const *certname = string_ptr (arg->v.string);
  struct stat st;
  int rc = 0;
  WORKDIR *wd = get_include_wd ();

  if (fstatat (wd ? wd->fd : AT_FDCWD, certname, &st, 0) == 0)
    {
      if (S_ISREG (st.st_mode))
	rc = load_cert_wd (wd, certname, &arg->locus, lst);
      else if (S_ISDIR (st.st_mode))
	{
	  DIR *dp;
	  struct dirent *ent;

	  dp = opendir_wd (wd, certname);
	  if (dp == NULL)
	    {
	      conf_error_at_locus_range (&arg->locus,
					 "%s: error opening directory: %s",
					 certname,
					 strerror (errno));
	      return -1;
	    }

	  wd = workdir_get (certname);
	  if (wd == NULL)
	    {
	      conf_error_at_locus_range (&arg->locus,
					 "%s: error opening directory: %s",
					 certname,
					 strerror (errno));
	      closedir (dp);
	      return -1;
	    }

	  while ((ent = readdir (dp)) != NULL)
	    {
	      if (strcmp (ent->d_name, ".") == 0 ||
		  strcmp (ent->d_name, "..") == 0)
		continue;

	      if ((rc = try_cert_wd (wd, ent->d_name, &node->locus, lst)) != 0)
		break;
	    }
	  closedir (dp);
	  workdir_free (wd);
	}
      else
	{
	  conf_error_at_locus_range (&arg->locus,
				     "%s: not a regular file or directory",
				     certname);
	  rc = -1;
	}
    }
  else if (errno == ENOENT)
    {
      glob_t glob;
      rc = globat (wd->fd, certname, GLOB_ERR | GLOB_MARK, NULL, &glob);
      if (rc == 0)
	{
	  size_t i;

	  for (i = 0; i < glob.gl_pathc; i++)
	    {
	      if ((rc = try_cert_wd (wd, glob.gl_pathv[i],
				     &arg->locus, lst)) != 0)
		break;
	    }
	  globfree(&glob);
	}
      else
	{
	  if (rc != GLOB_NOMATCH)
	    conf_error_at_locus_range (&arg->locus, "glob error: %s",
				       globstrerror (rc));
	  else
	    conf_error_at_locus_range (&arg->locus, "%s: stat error: %s",
				       certname, strerror (ENOENT));
	  return -1;
	}
    }
  else
    {
      conf_error_at_locus_range (&arg->locus, "%s: stat error: %s",
				 certname, strerror (errno));
      return -1;
    }

  return rc;
}

static int
verify_OK (int pre_ok, X509_STORE_CTX *ctx)
{
  return 1;
}

#ifdef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
static int
SNI_server_name (SSL *ssl, int *dummy, POUND_CTX_HEAD *ctx_head)
{
  const char *server_name;
  POUND_CTX *pc;

  if ((server_name = SSL_get_servername (ssl, TLSEXT_NAMETYPE_host_name)) == NULL)
    return SSL_TLSEXT_ERR_NOACK;

  /* logmsg(LOG_DEBUG,
     "Received SSL SNI Header for servername %s", servername); */

  SSL_set_SSL_CTX (ssl, NULL);
  SLIST_FOREACH (pc, ctx_head, next)
    {
      if (fnmatch (pc->server_name, server_name, 0) == 0)
	{
	  /* logmsg(LOG_DEBUG, "Found cert for %s", servername); */
	  SSL_set_SSL_CTX (ssl, pc->ctx);
	  return SSL_TLSEXT_ERR_OK;
	}
      else if (pc->subjectAltNameCount > 0 && pc->subjectAltNames != NULL)
	{
	  int i;

	  for (i = 0; i < pc->subjectAltNameCount; i++)
	    {
	      if (fnmatch ((char *) pc->subjectAltNames[i], server_name, 0) ==
		  0)
		{
		  SSL_set_SSL_CTX (ssl, pc->ctx);
		  return SSL_TLSEXT_ERR_OK;
		}
	    }
	}
    }

  /* logmsg(LOG_DEBUG, "No match for %s, default used", server_name); */
  SSL_set_SSL_CTX (ssl, SLIST_FIRST (ctx_head)->ctx);
  return SSL_TLSEXT_ERR_OK;
}
#endif

/* ClientCert MODE [DEPTH] */
static int
lst_clientcert_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  LISTENER *lst = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  int depth;
  POUND_CTX *pc;

  if (cfg_assert_range (arg, 0, 3))
    return -1;

  if (lst->clnt_check > 0)
    {
      if ((arg = cfg_arg_next (arg)) != NULL)
	{
	  if (cfg_assert_range (arg, 0, 9))
	    return -1;
	  depth = arg->v.number;
	}
      else
	depth = 9;
    }
  else if ((arg = cfg_arg_next (arg)) != NULL)
    conf_error_at_locus_range (&arg->locus, "superfluous argument ignored");

  switch (lst->clnt_check)
    {
    case 0:
      /* don't ask */
      SLIST_FOREACH (pc, &lst->ctx_head, next)
	SSL_CTX_set_verify (pc->ctx, SSL_VERIFY_NONE, NULL);
      break;

    case 1:
      /* ask but OK if no client certificate */
      SLIST_FOREACH (pc, &lst->ctx_head, next)
	{
	  SSL_CTX_set_verify (pc->ctx,
			      SSL_VERIFY_PEER |
			      SSL_VERIFY_CLIENT_ONCE, NULL);
	  SSL_CTX_set_verify_depth (pc->ctx, depth);
	}
      break;

    case 2:
      /* ask and fail if no client certificate */
      SLIST_FOREACH (pc, &lst->ctx_head, next)
	{
	  SSL_CTX_set_verify (pc->ctx,
			      SSL_VERIFY_PEER |
			      SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	  SSL_CTX_set_verify_depth (pc->ctx, depth);
	}
      break;

    case 3:
      /* ask but do not verify client certificate */
      SLIST_FOREACH (pc, &lst->ctx_head, next)
	{
	  SSL_CTX_set_verify (pc->ctx,
			      SSL_VERIFY_PEER |
			      SSL_VERIFY_CLIENT_ONCE, verify_OK);
	  SSL_CTX_set_verify_depth (pc->ctx, depth);
	}
      break;
    }
  return 0;
}

static CFG_TYPE cfg_type_lst_clientcert = {
  .argdef = "nn?",
  .commit = lst_clientcert_commit
};

/* Disable <PROTO> */
static int
lst_disable_proto_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  int *opt = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  int n;

  static struct kwtab kwtab[] = {
    { "SSLv2", SSL_OP_NO_SSLv2 },
    { "SSLv3", SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 },
#ifdef SSL_OP_NO_TLSv1
    { "TLSv1", SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 },
#endif
#ifdef SSL_OP_NO_TLSv1_1
    { "TLSv1_1", SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
		 SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 },
#endif
#ifdef SSL_OP_NO_TLSv1_2
    { "TLSv1_2", SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
		 SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
		 SSL_OP_NO_TLSv1_2 },
#endif
    { NULL }
  };

  if (kw_to_tok (kwtab, string_ptr (arg->v.string), 1, &n))
    {
      conf_error_at_locus_range (&arg->locus, "unrecognized protocol name");
      return -1;
    }
  *opt |= n;
  return 0;
}

/* SSLHonorCipherOrder <BOOL> */
static int
honor_cipher_order_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  LISTENER *lst = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);

  if (arg->v.number)
    {
      lst->ssl_op_enable |= SSL_OP_CIPHER_SERVER_PREFERENCE;
      lst->ssl_op_disable &= ~SSL_OP_CIPHER_SERVER_PREFERENCE;
    }
  else
    {
      lst->ssl_op_disable |= SSL_OP_CIPHER_SERVER_PREFERENCE;
      lst->ssl_op_enable &= ~SSL_OP_CIPHER_SERVER_PREFERENCE;
    }
  return 0;
}

/* SSLAllowClientRenegotiation <N> */
static int
alloc_client_reneg_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  LISTENER *lst = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);

  if (cfg_assert_range (arg, 0, 2))
    return -1;

  lst->allow_client_reneg = arg->v.number;

  if (lst->allow_client_reneg == 2)
    {
      lst->ssl_op_enable |= SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
      lst->ssl_op_disable &= ~SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
    }
  else
    {
      lst->ssl_op_disable |= SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
      lst->ssl_op_enable &= ~SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
    }

  return 0;
}

/* CAList "FILENAME" */
static int
calist_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  LISTENER *lst = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  STACK_OF (X509_NAME) *cert_names;
  POUND_CTX *pc;

  if ((cert_names = SSL_load_client_CA_file (string_ptr (arg->v.string)))
       == NULL)
    {
      conf_openssl_error (&arg->locus, NULL, "SSL_load_client_CA_file");
      return -1;
    }

  SLIST_FOREACH (pc, &lst->ctx_head, next)
    SSL_CTX_set_client_CA_list (pc->ctx, cert_names);

  return 0;
}

/* VerifyList "FILENAME" */
static int
verifylist_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  LISTENER *lst = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  char const *str = string_ptr (arg->v.string);
  POUND_CTX *pc;

  SLIST_FOREACH (pc, &lst->ctx_head, next)
    if (SSL_CTX_load_verify_locations (pc->ctx, str, NULL) != 1)
      {
	conf_openssl_error (&node->locus, str,
			    "SSL_CTX_load_verify_locations");
	return -1;
      }
  return 0;
}

/* CRList "FILENAME" */
static int
crlist_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  LISTENER *lst = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);
  char const *str = string_ptr (arg->v.string);
  X509_STORE *store;
  X509_LOOKUP *lookup;
  POUND_CTX *pc;

  SLIST_FOREACH (pc, &lst->ctx_head, next)
    {
      store = SSL_CTX_get_cert_store (pc->ctx);
      if ((lookup = X509_STORE_add_lookup (store, X509_LOOKUP_file ()))
	  == NULL)
	{
	  conf_openssl_error (&node->locus, NULL, "X509_STORE_add_lookup");
	  return -1;
	}

      if (X509_load_crl_file (lookup, str, X509_FILETYPE_PEM) != 1)
	{
	  conf_openssl_error (&node->locus, str, "X509_load_crl_file failed");
	  return -1;
	}

      X509_STORE_set_flags (store,
			    X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
    }

  return 0;
}

/* NoHTTPS11 <N> */
static int
nohttps11_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  LISTENER *lst = cfg_rcvr_ptr (&node->rcvr, baseptr);
  CFG_ARG *arg = cfg_arglist_first (&node->arglist);

  if (cfg_assert_range (arg, 0, 2))
    return -1;
  lst->noHTTPS11 = arg->v.number;
  return 0;
}

/* Statements allowed in ListenHTTPS sections. */
static CFG_DEFN lst_https_defn[] = {
  {
    .name = "",
    .type = KWT_TABREF,
    .ref = http_common
  },
  {
    .name = "",
    .type = KWT_TABREF,
    .ref = http_deprecated
  },
  {
    .name = "Cert",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = cert_commit
  },
  {
    .name = "ClientCert",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_lst_clientcert
  },
  {
    .name = "Disable",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_LAZY_STRING,
    .commit = lst_disable_proto_commit,
    .rcvr = {
      .off = offsetof (LISTENER, ssl_op_enable)
    }
  },
  {
    .name = "Ciphers",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_lst_ciphers
  },
  {
    .name = "SSLHonorCipherOrder",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_BOOL,
    .commit = honor_cipher_order_commit
  },
  {
    .name = "SSLAllowClientRenegotiation",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_INT,
    .commit = alloc_client_reneg_commit
  },
  {
    .name = "CAlist",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = calist_commit
  },
  {
    .name = "VerifyList",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = verifylist_commit
  },
  {
    .name = "CRLlist",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = crlist_commit
  },
  {
    .name = "NoHTTPS11",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = nohttps11_commit
  },
  { NULL }
};

#if 0
/* Names of the statements that require the presence of the Cert statement.
 */
static char *cert_deps[] = {
  "ClientCert",
  "Disable",
  "Ciphers",
  "CAList",
  "VerifyList",
  "CRlist"
};
#endif

/* If Cert statement is present in node, move it to the start of the
   subtree and return 0.  Otherwise, return -1.
 */
static int
lst_https_reorder (CFG_NODE *node)
{
  CFG_NODE *np;
  int rc = -1;

  np = cfg_ast_locate_node (node->subtree, cfg_node_name_eq, "Cert");
  if (np)
    {
      rc = 0;
      cfg_ast_remove (node->subtree, np);
      cfg_ast_prepend (node->subtree, np);
    }
  return rc;
}

static int
lst_prepare (CFG_NODE *node, void *call_data, void **baseptr)
{
  POUND_DEFAULTS *dfl = (POUND_DEFAULTS*) call_data;
  LISTENER_HEAD *list_head = cfg_rcvr_ptr (&node->rcvr, *baseptr);
  LISTENER *lst;

  if ((lst = listener_alloc (dfl, &node->locus)) == NULL)
    return -1;

  if (!cfg_arglist_empty (&node->arglist))
    {
      CFG_ARG *arg = cfg_arglist_first (&node->arglist);
      char const *tag = string_ptr (arg->v.string);

      if (find_listener_ident (list_head, tag))
	{
	  conf_error_at_locus_range (&node->locus,
				     "listener name is not unique");
	  return -1;
	}
      lst->name = xstrdup (tag);
    }

  SLIST_PUSH (list_head, lst, next);

  *baseptr = lst;

  return 0;
}

static int
lst_https_prepare (CFG_NODE *node, void *call_data, void **baseptr)
{
  LISTENER *lst;

  if (lst_https_reorder (node))
    {
      conf_error_at_locus_range (&node->locus, "no certificates for HTTPS;"
				 " use Cert statement to load some");
      return -1;
    }
  if (lst_prepare (node, call_data, baseptr))
    return -1;
  lst = *baseptr;

  lst->ssl_op_enable = SSL_OP_ALL;
#ifdef  SSL_OP_NO_COMPRESSION
  lst->ssl_op_enable |= SSL_OP_NO_COMPRESSION;
#endif
  lst->ssl_op_disable =
    SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | SSL_OP_LEGACY_SERVER_CONNECT |
    SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;

  return 0;
}

/*
 * For each certificate used in ClientCert condition from COND, invoke
 * function CB with the certificate and DATA as its arguments.
 *
 * Return 0 if all calls returned 0, otherwise return the value returned from
 * the first failed call.
 *
 * If CB is NULL, return 1 if at least one ClientCert was found, and 0
 * otherwise.
 */
static int
foreach_client_cert (SERVICE_COND *cond, int (*cb) (X509 *, void *),
		     void *data)
{
  int rc = 0;

  switch (cond->type)
    {
    case COND_CLIENT_CERT:
      if (cb)
	rc = cb (cond->x509, data);
      else
	rc = 1;
      break;

    case COND_BOOL:
      {
	SERVICE_COND *subcond;
	SLIST_FOREACH (subcond, &cond->boolean.head, next)
	  {
	    if ((rc = foreach_client_cert (subcond, cb, data)) != 0)
	      break;
	  }
      }
      break;

    default:
      break;
    }
  return rc;
}

/*
 * If at least one ClientCert condition is used in S_HEAD, print error
 * text MSG and return 1.  Otherwise, return 0.
 */
static int
forbid_ssl_usage (SERVICE_HEAD *s_head, char const *msg)
{
  SERVICE *svc;
  SLIST_FOREACH (svc, s_head, next)
    {
      if (foreach_client_cert (&svc->cond, NULL, NULL))
	{
	  conf_error_at_locus_range (&svc->locus, "%s", msg);
	  return 1;
	}
    }
  return 0;
}

static int
resolve_listener_address (LISTENER *lst, char *defsrv)
{
  if (lst->addr.ai_addr == NULL)
    {
      struct addrinfo hints, *res, *ptr;
      char *service;
      int rc;

      memset (&hints, 0, sizeof (hints));
      hints.ai_family = AF_UNSPEC;
      hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
      hints.ai_socktype = SOCK_STREAM;
      service = lst->port_str ? lst->port_str : defsrv;
      rc = getaddrinfo (lst->addr_str, service, &hints, &res);
      if (rc != 0)
	{
	  conf_error_at_locus_range (&lst->locus, "bad listener address: %s",
				     gai_strerror (rc));
	  return -1;
	}

      ptr = res;
      /* Prefer in6addr_any over INADDR_ANY. */
      if (ptr->ai_family == AF_INET &&
	  ((struct sockaddr_in*)ptr->ai_addr)->sin_addr.s_addr == INADDR_ANY &&
	  ptr->ai_next != NULL &&
	  ptr->ai_next->ai_family == AF_INET6 &&
	  memcmp (&((struct sockaddr_in6*)ptr->ai_next->ai_addr)->sin6_addr,
		  &in6addr_any, sizeof (in6addr_any)) == 0)
	ptr = ptr->ai_next;

      lst->addr = *ptr;
      lst->addr.ai_next = NULL;
      lst->addr.ai_addr = xmalloc (ptr->ai_addrlen);
      memcpy (lst->addr.ai_addr, ptr->ai_addr, ptr->ai_addrlen);
      freeaddrinfo (res);
    }
  return 0;
}

static int
client_cert_cb (X509 *x509, void *data)
{
  LISTENER *lst = data;
  POUND_CTX *pc;

  SLIST_FOREACH (pc, &lst->ctx_head, next)
    {
      X509_STORE *store = SSL_CTX_get_cert_store (pc->ctx);
      if (X509_STORE_add_cert (store, x509) != 1)
	{
	  conf_openssl_error (NULL, NULL, "X509_STORE_add_cert");
	  return -1;
	}
    }
  lst->verify = 1;
  return 0;
}

static int
flush_service_client_cert (LISTENER *lst)
{
  SERVICE *svc;

  SLIST_FOREACH (svc, &lst->services, next)
    {
      if (foreach_client_cert (&svc->cond, client_cert_cb, lst))
	return -1;
    }
  if (lst->verify == 1)
    {
      if (lst->clnt_check != -1)
	{
	  conf_error_at_locus_range (&lst->locus,
				     "ClientCert in ListenHTTPS"
				     " conflicts with that in Service");
	  return -1;
	}
      else
	{
	  POUND_CTX *pc;
	  SLIST_FOREACH (pc, &lst->ctx_head, next)
	    {
	      SSL_CTX_set_verify (pc->ctx,
				  SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
				  verify_OK);
	    }
	  lst->clnt_check = 3;
	}
    }
  return 0;
}

/*
 * For all services defined in listener, set its lstn field to point to the
 * listener.
 */
static void
listener_service_backlink (LISTENER *lstn)
{
  SERVICE *svc;
  SLIST_FOREACH (svc, &lstn->services, next)
    svc->lstn = lstn;
}

/* Commit function for ListenHTTP and ListenHHTPS sections */
static int
lst_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  LISTENER *lst = baseptr;

  if (resolve_listener_address (lst, PORT_HTTP_STR))
    return -1;

  listener_service_backlink (lst);

  if (SLIST_EMPTY (&lst->ctx_head) &&
      forbid_ssl_usage (&lst->services,
			"use of SSL features in ListenHTTP sections"
			" is forbidden"))
    return -1;

  if (lst->max_uri_length > lst->linebufsize)
    lst->max_uri_length = lst->linebufsize;

  return 0;
}

static int
lst_https_commit (CFG_NODE *node, void *call_data, void *baseptr)
{
  LISTENER *lst = baseptr;
  struct stringbuf sb;
  POUND_CTX *pc;

  if (lst_commit (node, call_data, lst))
    return -1;
  if (flush_service_client_cert (lst))
    return -1;

#ifdef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
  if (!SLIST_EMPTY (&lst->ctx_head))
    {
      SSL_CTX *ctx = SLIST_FIRST (&lst->ctx_head)->ctx;
      if (!SSL_CTX_set_tlsext_servername_callback (ctx, SNI_server_name)
	  || !SSL_CTX_set_tlsext_servername_arg (ctx, &lst->ctx_head))
	{
	  conf_openssl_error (NULL, NULL, "can't set SNI callback");
	  return -1;
	}
    }
#endif

  xstringbuf_init (&sb);
  SLIST_FOREACH (pc, &lst->ctx_head, next)
    {
      SSL_CTX_set_app_data (pc->ctx, lst);
      SSL_CTX_set_mode (pc->ctx, SSL_MODE_AUTO_RETRY);
      SSL_CTX_set_options (pc->ctx, lst->ssl_op_enable);
      SSL_CTX_clear_options (pc->ctx, lst->ssl_op_disable);
      stringbuf_reset (&sb);
      stringbuf_printf (&sb, "%d-Pound-%ld", getpid (), random ());
      SSL_CTX_set_session_id_context (pc->ctx, (unsigned char *) sb.base,
				      sb.len);
      POUND_SSL_CTX_init (pc->ctx);
      SSL_CTX_set_info_callback (pc->ctx, SSLINFO_callback);
    }
  stringbuf_free (&sb);

  return 0;
}

static CFG_TYPE cfg_type_listener = {
  .argdef = "s?",
  .prepare = lst_prepare,
  .commit = lst_commit
};

static CFG_TYPE cfg_type_listener_https = {
  .argdef = "s?",
  .prepare = lst_https_prepare,
  .commit = lst_https_commit
};

/*
 * The Tunnel section.
 */
static CFG_DEFN tunnel_backend_defn[] = {
  {
    .name = "Address",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_LAZY_STRING,
    .rcvr = {
      .off = offsetof (BACKEND, v.mtx.hostname)
    }
  },
  {
    .name = "Port",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_PORT,
    .rcvr = {
      .off = offsetof (BACKEND, v.mtx.port)
    }
  },
  {
    .name = "TimeOut",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_DURATION,
    .rcvr = {
      .off = offsetof (BACKEND, v.mtx.to)
    }
  },
  {
    .name = "ConnTO",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_DURATION,
    .rcvr = {
      .off = offsetof (BACKEND, v.mtx.conn_to)
    }
  },
  {
    .name = "Disabled",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_BOOL,
    .rcvr = {
      .off = offsetof (BACKEND, disabled)
    }
  },
  { NULL }
};

static int
tunnel_backend_prepare (CFG_NODE *node, void *call_data, void **baseptr)
{
  LISTENER *lst = *baseptr;
  SERVICE *svc;
  BACKEND *be;

  svc = new_service (BALANCER_ALGO_RANDOM);
  locus_range_copy (&svc->locus, &node->locus);

  be = backend_init (node, call_data);
  if (!be)
    return -1;

  be->service = svc;
  be->priority = 1;

  /* Register backend in service */
  balancer_add_backend (balancer_list_get_normal (&svc->balancers), be);
  service_recompute_pri_unlocked (svc, NULL, NULL);

  /* Register service in the listener */
  SLIST_PUSH (&lst->services, svc, next);

  *baseptr = be;

  return 0;
}

static CFG_TYPE cfg_type_tunnel_backend = {
  .prepare = tunnel_backend_prepare
};

static CFG_DEFN lst_tunnel_defn[] = {
  {
    .name = "",
    .type = KWT_TABREF,
    .ref = listener_address_common
  },
  {
    .name = "Backend",
    .token = T_SECTION,
    .vtype = &cfg_type_tunnel_backend,
    .ref = tunnel_backend_defn,
  },
  { NULL }
};

static int
lst_tunnel_prepare (CFG_NODE *node, void *call_data, void **baseptr)
{
  LISTENER *lst;
  CFG_NODE *bn0, *bn;

  bn0 = cfg_ast_locate_node (node->subtree, cfg_node_name_eq, "Backend");
  if (!bn0)
    {
      conf_error_at_locus_range (&node->locus, "no backend defined");
      return -1;
    }
  bn = cfg_node_locate_next (bn0, cfg_node_name_eq, "Backend");
  if (bn)
    {
      conf_error_at_locus_range (&bn->locus, "backend redefined");
      conf_error_at_locus_range (&bn0->locus, "previous definition was here");
      return -1;
    }

  if (lst_prepare (node, call_data, (void**)&lst))
    return -1;
  lst->tunnel = 1;

  *baseptr = lst;

  return 0;
}

static CFG_TYPE cfg_type_tunnel = {
  .argdef = "s?",
  .prepare = lst_tunnel_prepare,
  .commit = lst_commit
};

/*
 * Top-level (global scope) configuration statements.
 */
static CFG_DEFN top_level_defn[] = {
  {
    .name = "IncludeDir",
    .token = T_INCLUDEDIR,
    .vtype = CFG_TYPE_STRING,
    /* This one is handled in the grammar directly. The node will never be
       committed directly. */
  },
  {
    .name = "User",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
  },
  {
    .name = "Group",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
  },
  {
    .name = "RootJail",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
  },
  {
    .name = "Daemon",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_BOOL,
  },
  {
    .name = "Supervisor",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_BOOL,
  },
  {
    .name = "WorkerMinCount",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_UINT,
    .rcvr = {
      .data = &worker_min_count
    },
    .verify = verify_range_positive_int,
  },
  {
    .name = "WorkerMaxCount",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_UINT,
    .rcvr = {
      .data = &worker_max_count
    },
    .verify = verify_range_positive_int,
  },
  {
    .name = "Threads",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_UINT,
    .commit = cfg_threads_commit,
    .verify = verify_range_positive_int,
  },
  {
    .name = "WorkerIdleTimeout",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_DURATION,
    .rcvr = {
      .data = &worker_idle_timeout
    },
  },
  {
    .name = "WorkerStackSize",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_SIZE,
    .rcvr = {
      .data = &worker_stack_size
    },
  },
  {
    .name = "ConnectionQueueSize",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_UINT,
    .commit = cfg_connqsize_commit,
    .verify = verify_range_nonnegative_int,
  },
  {
    .name = "ReserveFD",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_reserve_fd,
  },
  {
    .name = "Grace",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_DURATION,
    .rcvr = {
      .data = &grace
    },
  },
  {
    .name = "LogFacility",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_logfacility,
    .rcvr = {
      .off = offsetof (POUND_DEFAULTS, facility)
    },
  },
  {
    .name = "LogLevel",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_loglevel,
    .rcvr = {
      .off = offsetof (POUND_DEFAULTS, log_level)
    },
  },
  {
    .name = "LogFormat",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_logformat,
  },
  {
    .name = "LogTag",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .rcvr = {
      .data = &syslog_tag
    },
  },
  {
    .name = "Alive",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_DURATION,
    .rcvr = {
      .data = &alive_to
    },
  },
  {
    .name = "Client",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_DURATION,
    .rcvr = {
      .off = offsetof (POUND_DEFAULTS, clnt_to)
    },
  },
  {
    .name = "TimeOut",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_DURATION,
    .rcvr = {
      .off = offsetof (POUND_DEFAULTS, be_to)
    },
  },
  {
    .name = "WSTimeOut",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_DURATION,
    .rcvr = {
      .off = offsetof (POUND_DEFAULTS, ws_to)
    },
  },
  {
    .name = "ConnTO",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_DURATION,
    .rcvr = {
      .off = offsetof (POUND_DEFAULTS, be_connto)
    },
  },
  {
    .name = "Balancer",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_balancer,
    .rcvr = {
      .off = offsetof (POUND_DEFAULTS, balancer_algo)
    },
  },
  {
    .name = "HeaderOption",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_headeroptions,
    .rcvr = {
      .off = offsetof (POUND_DEFAULTS, header_options)
    },
  },
  {
    .name = "ECDHCurve",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_IGNORED,
    .deprecated = 1,
    .message = "this setting is no longer used"
  },
  {
    .name = "SSLEngine",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .commit = commit_sslengine,
  },
  {
    .name = "Anonymise",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_OPT_BOOL,
    .rcvr = {
      .data = &anonymise
    },
  },
  {
    .name = "Anonymize",
    .type = KWT_ALIAS
  },
  {
    .name = "PidFile",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .rcvr = {
      .data = &pid_name
    },
  },
  {
    .name = "BackendStats",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_BOOL,
    .rcvr = {
      .data = &enable_backend_stats
    },
  },
  {
    .name = "ForwardedHeader",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_STRING,
    .rcvr = {
      .data = &forwarded_header
    },
  },
  {
    .name = "WatcherTTL",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_DURATION,
    .rcvr = {
      .data = &watcher_ttl
    },
  },
  {
    .name = "LineBufferSize",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_SIZE,
    .rcvr = {
      .off = offsetof (POUND_DEFAULTS, linebufsize),
    },
  },
  {
    .name = "RegexType",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_LITERAL,
    .commit = &commit_regex_type,
    .rcvr = {
      .off = offsetof (POUND_DEFAULTS, re_type),
    },
  },

  {
    .name = "Backend",
    .token = T_SECTION,
    .vtype = &cfg_type_named_backend,
    .ref = common_backend_defn,
    .rcvr = {
      .off = offsetof (POUND_DEFAULTS, named_backend_table)
    }
  },
  {
    .name = "Control",
    .token = T_CONTROL,
    .vtype = &cfg_type_control,
    .ref = control_defn
  },
  {
    .name = "CombineHeaders",
    .token = T_COMHEADERS,
    .vtype = CFG_TYPE_ANY,
    .commit = comheaders_commit
  },

  {
    .name = "Resolver",
    .token = T_SECTION,
    .vtype = &cfg_type_resolver,
    .ref = resolver_defn
  },

  {
    .name = "Constant",
    .token = T_DIRECTIVE,
    .vtype = &cfg_type_constant,
    .rcvr = {
      .data = &strconst_tab
    }
  },
  {
    .name = "ACL",
    .token = T_ACL,
    .vtype = &cfg_type_named_acl
  },
  {
    .name = "TrustedIP",
    .token = T_TRUSTEDIP,
    .vtype = &cfg_type_trustedip,
    .rcvr = {
      .data = &trusted_ips
    }
  },
  {
    .name = "Condition",
    .token = T_SECTION,
    .vtype = &cfg_type_condition,
    .ref = cond_defn
  },
  {
    .name = "Lua",
    .token = T_SECTION,
#ifdef ENABLE_LUA
    .ref = pndlua_defn,
#else
    .commit = nolua_commit
#endif
  },
  {
    .name = "Service",
    .token = T_SECTION,
    .vtype = &cfg_type_service,
    .ref = svc_defn,
    .rcvr = {
      .data = &services
    }
  },
  {
    .name = "ListenHTTP",
    .token = T_SECTION,
    .vtype = &cfg_type_listener,
    .ref = lst_http_defn,
    .rcvr = {
      .data = &listeners
    }
  },
  {
    .name = "ListenHTTPS",
    .token = T_SECTION,
    .vtype = &cfg_type_listener_https,
    .ref = lst_https_defn,
    .rcvr = {
      .data = &listeners
    }
  },
  {
    .name = "Tunnel",
    .token = T_SECTION,
    .vtype = &cfg_type_tunnel,
    .ref = lst_tunnel_defn,
    .rcvr = {
      .data = &listeners
    }
  },
  /* Backward compatibility. */
  {
    .name = "IgnoreCase",
    .token = T_DIRECTIVE,
    .vtype = CFG_TYPE_BOOL,
    .rcvr = {
      .off = offsetof (POUND_DEFAULTS, ignore_case),
    },
    .deprecated = 1,
    .message = "use the -icase matching directive flag to request case-insensitive comparison"
  },
  { NULL }
};

static int
str_is_ipv4 (const char *addr)
{
  int c;
  int dot_count;
  int digit_count;

  dot_count = 0;
  digit_count = 0;
  for (; (c = *addr) != 0; addr++)
    {
      if (c == '.')
	{
	  if (++dot_count > 4)
	    return 0;
	  digit_count = 0;
	}
      else if (!(c_isdigit (c) && ++digit_count <= 3))
	return 0;
    }

  return dot_count == 3;
}

static int
str_is_ipv6 (const char *addr)
{
  int c;
  int col_count = 0; /* Number of colons */
  int dcol = 0;      /* Did we encounter a double-colon? */
  int dig_count = 0; /* Number of digits in the last group */

  for (; (c = *addr) != 0; addr++)
    {
      if (!c_isascii (c))
	return 0;
      else if (c_isxdigit (c))
	{
	  if (++dig_count > 4)
	    return 0;
	}
      else if (c == ':')
	{
	  if (col_count && dig_count == 0 && ++dcol > 1)
	    return 0;
	  if (++col_count > 7)
	    return 0;
	  dig_count = 0;
	}
      else
	return 0;
    }
  return col_count == 7 || dcol;
}

static int
str_is_ip (const char *addr)
{
  int c;
  int dot = 0;
  for (; (c = *addr) != 0 && c_isascii (c); addr++)
    {
      if (!c_isascii (c))
	break;
      else if (c_isxdigit (c))
	return str_is_ipv6 (addr);
      else if (c == dot)
	return str_is_ipv4 (addr);
      else if (c_isdigit (c))
	dot = '.';
      else
	break;
    }
  return 0;
}

/*
 * If ipstr is an IPv4-mapped IPv6 address, return 1 and store pointer
 * to the beginning of plain IPv4 part in memory location pointed to by
 * ipv4. Otherwise, return 0 and store there ipstr itself.
 */
int
ipv4mapped (char const *ipstr, char **ipv4)
{
  static char pfx[] = "::ffff:";
  static size_t npfx = sizeof(pfx) - 1;
  if (ipstr && strncmp (pfx, ipstr, npfx) == 0 && str_is_ipv4 (ipstr + npfx))
    {
      *ipv4 = (char *)ipstr + npfx;
      return 1;
    }
  else
    *ipv4 = (char *)ipstr;
  return 0;
}
/*
 * Finalize backends.
 */
struct be_setup_closure
{
  /* Input */
  NAMED_BACKEND_TABLE *be_tab;
  SERVICE *svc;        /* Service. */
  BALANCER *bal;       /* Balancer. */

  /* Output */
  int be_count;        /* Number of backends processed. */
  int be_class;        /* Backend class mask. */
  int err;             /* Errors encountered or not. */
};

static void
be_setup_closure_init (struct be_setup_closure *cp,
		       NAMED_BACKEND_TABLE *tab,
		       SERVICE *svc, BALANCER *bal)
{
  memset (cp, 0, sizeof *cp);
  cp->be_tab = tab;
  cp->svc = svc;
  cp->bal = bal;
}

static int backend_resolve (BACKEND *be);

static int
backend_finalize (BACKEND *be, NAMED_BACKEND_TABLE *tab)
{
  if (be->be_type == BE_BACKEND_REF)
    {
      NAMED_BACKEND *nb;

      nb = named_backend_retrieve (tab, be->v.be_name);
      if (!nb)
	{
	  conf_error_at_locus_range (&be->locus,
				     "named backend %s is not declared",
				     be->v.be_name);
	  return -1;
	}
      free (be->v.be_name);
      be->be_type = BE_MATRIX;
      be->v.mtx = nb->bemtx;
      /* Hostname will be freed after resolving backend to be_regular.
	 FIXME: use STRING? */
      be->v.mtx.hostname = xstrdup (be->v.mtx.hostname);
      if (be->priority == -1)
	be->priority = nb->priority;
      if (be->disabled == -1)
	be->disabled = nb->disabled;
    }

  if (be->be_type == BE_MATRIX)
    {
      if (!be->v.mtx.hostname)
	{
	  conf_error_at_locus_range (&be->locus, "%s",
				     "Backend missing Address declaration");
	  return -1;
	}

      if (be->v.mtx.hostname[0] == '/' || str_is_ip (be->v.mtx.hostname))
	be->v.mtx.resolve_mode = bres_immediate;

      if (be->v.mtx.port == 0)
	{
	  be->v.mtx.port = htons (be->v.mtx.ctx == NULL ? PORT_HTTP : PORT_HTTPS);
	}
      else if (be->v.mtx.hostname[0] == '/')
	{
	  conf_error_at_locus_range (&be->locus,
				     "Port is not applicable to this address family");
	  return -1;
	}

      if (be->v.mtx.resolve_mode == bres_immediate)
	{
	  if (backend_resolve (be))
	    return -1;
	}
      else
	{
#ifdef ENABLE_DYNAMIC_BACKENDS
	  if (feature_is_set (FEATURE_DNS))
	    {
	      backend_matrix_init (be);
	    }
	  else
	    {
	      conf_error_at_locus_range (&be->locus,
					 "Dynamic backend creation is not "
					 "available: disabled by -Wno-dns");
	      return 1;
	    }
#else
	  conf_error_at_locus_range (&be->locus,
				     "Dynamic backend creation is not "
				     "available: pound compiled without "
				     "support for dynamic backends");
	  return 1;

#endif
	}
    }
  return 0;
}

#define BE_MASK(n) (1<<(n))
#define BX_(x)  ((x) - (((x)>>1)&0x77777777)			\
		 - (((x)>>2)&0x33333333)			\
		 - (((x)>>3)&0x11111111))
#define BITCOUNT(x)     (((BX_(x)+(BX_(x)>>4)) & 0x0F0F0F0F) % 255)

static void
cb_be_setup (BACKEND *be, void *data)
{
  struct be_setup_closure *clos = data;

  if (backend_finalize (be, clos->be_tab))
    {
      be->disabled = 1;
      clos->err = 1;
      return;
    }

  clos->be_count++;
  clos->be_class |= BE_MASK (be->be_type);
  be->service = clos->svc;
  if (be->priority > PRI_MAX)
    {
      conf_error_at_locus_range (&be->locus,
				 "backend priority out of allowed"
				 " range; reset to max. %d",
				 PRI_MAX);
      be->priority = PRI_MAX;
    }
}

void
backend_matrix_to_regular (struct be_matrix *mtx, struct addrinfo *addr,
			   struct be_regular *reg)
{
  memset (reg, 0, sizeof (*reg));
  reg->addr = *addr;

  switch (reg->addr.ai_family)
    {
    case AF_INET:
      ((struct sockaddr_in *)reg->addr.ai_addr)->sin_port = mtx->port;
      break;

    case AF_INET6:
      ((struct sockaddr_in6 *)reg->addr.ai_addr)->sin6_port = mtx->port;
      break;
    }

  reg->alive = 1;
  reg->to = mtx->to;
  reg->conn_to = mtx->conn_to;
  reg->ws_to = mtx->ws_to;
  reg->ctx = mtx->ctx;
  reg->servername = mtx->servername;
}

static int
backend_resolve (BACKEND *be)
{
  struct addrinfo addr;
  struct be_regular reg;
  char *hostname = be->v.mtx.hostname;

  if (get_host (hostname, &addr, be->v.mtx.family))
    {
      /* if we can't resolve it, assume this is a UNIX domain socket */
      struct sockaddr_un *sun;
      size_t len = strlen (hostname);
      if (len > UNIX_PATH_MAX)
	{
	  conf_error_at_locus_range (&be->locus, "%s",
				     "UNIX path name too long");
	  return -1;
	}

      len += offsetof (struct sockaddr_un, sun_path) + 1;
      sun = xmalloc (len);
      sun->sun_family = AF_UNIX;
      strcpy (sun->sun_path, hostname);

      addr.ai_socktype = SOCK_STREAM;
      addr.ai_family = AF_UNIX;
      addr.ai_protocol = 0;
      addr.ai_addr = (struct sockaddr *) sun;
      addr.ai_addrlen = len;
    }

  backend_matrix_to_regular (&be->v.mtx, &addr, &reg);
  free (hostname);
  be->v.reg = reg;
  be->be_type = BE_REGULAR;
  backend_refcount_init (be);
  return 0;
}

/*
 * Finalize services.
 */
static int
service_finalize (SERVICE *svc, void *data)
{
  BALANCER *bal;
  unsigned be_count = 0;
  NAMED_BACKEND_TABLE *tab = data;

  DLIST_FOREACH (bal, &svc->balancers, link)
    {
      struct be_setup_closure be_setup;
      bal->algo = svc->balancer_algo;
      be_setup_closure_init (&be_setup, tab, svc, bal);
      balancer_recompute_pri_unlocked (bal, cb_be_setup, &be_setup);
      if (be_setup.err)
	return -1;

      if (be_setup.be_count > 1)
	{
	  if (be_setup.be_class & ~(BE_MASK (BE_REGULAR) |
				    BE_MASK (BE_MATRIX) |
				    BE_MASK (BE_REDIRECT)))
	    {
	      conf_error_at_locus_range (&svc->locus,
			  "%s",
			  BITCOUNT (be_setup.be_class) == 1
			    ? "multiple backends of this type are not allowed"
			    : "service mixes backends of different types");
	      return -1;
	    }

	  if (be_setup.be_class & BE_MASK (BE_REDIRECT))
	    {
	      conf_error_at_locus_range (&svc->locus,
			  "warning: %s",
			  (be_setup.be_class & (BE_MASK (BE_REGULAR) |
						BE_MASK (BE_MATRIX)))
			     ? "service mixes regular and redirect backends"
			     : "service uses multiple redirect backends");
	      conf_error_at_locus_range (&svc->locus,
			  "%s",
			  "see section \"DEPRECATED FEATURES\" in pound(8)");
	    }
	}

      be_count += be_setup.be_count;
    }

  if (svc->fall_through)
    {
      if (be_count)
	{
	  conf_error_at_locus_range (&svc->locus,
				     "backends defined in"
				     " a FallThrough service");
	  return -1;
	}
      if (!SLIST_EMPTY (&svc->rewrite[REWRITE_RESPONSE]))
	{
	  conf_error_at_locus_range (&svc->locus,
				     "Rewrite response defined in"
				     " a FallThrough service");
	  return -1;
	}
    }
  else if (be_count == 0)
    {
      conf_error_at_locus_range (&svc->locus, "%s",
				 "warning: no backends defined");
    }

  service_lb_init (svc);

  return 0;
}

static int
postprocess (POUND_DEFAULTS *dfl, int nosyslog)
{
  if (forbid_ssl_usage (&services,
			"use of SSL features in top-level sections"
			" is forbidden"))
    return -1;
#ifdef ENABLE_DYNAMIC_BACKENDS
  resolver_set_config (&dfl->resolver);
#endif
  if (foreach_service (service_finalize, &dfl->named_backend_table))
    return -1;

  named_cond_finish ();

  if (pndlua_init ())
    return -1;

  if (worker_min_count > worker_max_count)
    abend (NULL, "WorkerMinCount is greater than WorkerMaxCount");
  if (!nosyslog)
    log_facility = dfl->facility;
  log_level = dfl->log_level;

  return 0;
}

static int
parser_finish (int keepwd)
{
  workdir_unref (include_wd);
  if (include_wd && include_wd->refcount == 0)
    include_wd = NULL;
  /* Remove unreferenced wd's and resolve CWD */
  return workdir_cleanup (keepwd);
}

int
parse_config_file (char const *filename, int nosyslog)
{
  CFG_AST *ast;
  int rc = -1;
  POUND_DEFAULTS pound_defaults = {
    .log_level = DEFAULT_LOG_LEVEL,
    .facility = LOG_DAEMON,
    .clnt_to = 10,
    .be_to = 15,
    .ws_to = 600,
    .be_connto = 15,
    .ignore_case = 0,
    .re_type = GENPAT_POSIX,
    .header_options = HDROPT_FORWARDED_HEADERS | HDROPT_SSL_HEADERS,
    .balancer_algo = BALANCER_ALGO_RANDOM,
    .resolver = RESOLVER_CONFIG_INITIALIZER,
    .linebufsize = MAXBUF
  };

  named_backend_table_init (&pound_defaults.named_backend_table);
  compile_canned_formats ();

  rewrite_branch_defn.vtype = &cfg_type_rewrite_branch;

  ast = cfg_parse_tree (filename, NULL, top_level_defn);
  if (ast)
    {
      rc = cfg_ast_finalize (ast, &pound_defaults, &pound_defaults);
      cfg_ast_free (ast);
    }

  if (rc == 0)
    rc = postprocess (&pound_defaults, nosyslog);

  named_backend_table_free (&pound_defaults.named_backend_table);

  parser_finish (root_jail || daemonize);

  return rc;
}
