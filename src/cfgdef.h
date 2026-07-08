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

#ifndef _POUND_CFGDEF_H
#define  _POUND_CFGDEF_H 1
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <glob.h>
#include "list.h"
#include "mem.h"
#include "assert.h"

typedef struct
{
  unsigned refcnt;
  size_t len;
  char str[1];
} STRING;

static inline STRING *
string_ref (STRING *s)
{
  if (s) s->refcnt++;
  return s;
}

static inline STRING *
string_unref (STRING *sp)
{
  if (sp && --sp->refcnt == 0)
    {
      free (sp);
      return NULL;
    }
  return sp;
}

static inline STRING *
string_alloc (size_t n)
{
  STRING *s = string_ref (xcalloc (1, sizeof (STRING) + n));
  s->len = n;
  return s;
}

static inline STRING *
string_ninit (char const *s, size_t n)
{
  STRING *str = string_alloc (n);
  memcpy (str->str, s, n);
  str->str[n] = 0;
  return str;
}

static inline STRING *
string_init (char const *s)
{
  return s ? string_ninit (s, strlen (s)) : NULL;
}

static inline size_t
string_len (STRING const *s)
{
  return s ? s->len : 0;
}

static inline char const *
string_ptr (STRING const *s)
{
  return s ? s->str : NULL;
}

static inline int
string_eq (STRING const *a, STRING const *b)
{
  return (a == NULL) ? a == b : strcmp (string_ptr (a), string_ptr (b)) == 0;
}

/*
 * Keyword table and lookups it in.
 */
struct kwtab
{
  char const *name;
  int tok;
};

int kwn_to_tok (struct kwtab *kwt, char const *name, size_t len,
		int ci, int *retval);
int kw_to_tok (struct kwtab *kwt, char const *name, int ci, int *retval);
char const *kw_to_str (struct kwtab *kwt, int t);

/* Locations in the source file */
struct locus_point
{
  STRING *filename;
  int line;
  int col;
};

#define LOCUS_POINT_INITIALIZER { NULL, 1, 0 }

struct locus_range
{
  struct locus_point beg, end;
};

#define LOCUS_RANGE_INITIALIZER \
  { LOCUS_POINT_INITIALIZER, LOCUS_POINT_INITIALIZER }

void locus_point_init (struct locus_point *pt, char const *filename,
		       char const *dir);

static inline void
locus_point_ref (struct locus_point *pt)
{
  string_ref (pt->filename);
}

static inline void
locus_point_unref (struct locus_point *pt)
{
  pt->filename = string_unref (pt->filename);
}

static inline void
locus_point_copy (struct locus_point *dst, struct locus_point const *src)
{
  if (dst->filename != src->filename)
    string_unref (dst->filename);
  *dst = *src;
  string_ref (dst->filename);
}

static inline void
locus_range_init_ext (struct locus_range *rng, char const *file,
		      char const *dir)
{
  locus_point_init (&rng->beg, file, dir);
  rng->end = rng->beg;
  locus_point_ref (&rng->beg);
}

static inline void
locus_range_init (struct locus_range *rng)
{
  locus_point_init (&rng->beg, NULL, NULL);
  locus_point_init (&rng->end, NULL, NULL);
}

static inline void
locus_range_copy (struct locus_range *dst, struct locus_range const *src)
{
  locus_point_copy (&dst->beg, &src->beg);
  locus_point_copy (&dst->end, &src->end);
}

static inline void
locus_range_ref (struct locus_range *r)
{
  locus_point_ref (&r->beg);
  locus_point_ref (&r->end);
}

static inline void
locus_range_unref (struct locus_range *r)
{
  locus_point_unref (&r->beg);
  locus_point_unref (&r->end);
}

void locus_point_print (FILE *fp, struct locus_point const *p);
void locus_range_print (FILE *fp, struct locus_range const *r);


/*
 * Locus formatting and error messaging.
 */
extern void (*cfg_error_msg) (char const *msg);

struct stringbuf;
void stringbuf_format_locus_point (struct stringbuf *sb,
				   struct locus_point const *loc);
void stringbuf_format_locus_range (struct stringbuf *sb,
				   struct locus_range const *range);
void vconf_error_at_locus_range (struct locus_range const *loc,
				 char const *fmt, va_list ap);
void conf_error_at_locus_range (struct locus_range const *loc,
				char const *fmt, ...);
void vconf_error_at_locus_point (struct locus_point const *loc,
				 char const *fmt, va_list ap);
void conf_error_at_locus_point (struct locus_point const *loc,
				char const *fmt, ...);
void conf_error (char const *fmt, ...);

char const *argdef_string (char const *, char **);
char const *token_string (int t);
int yylex (void);

#define YYLLOC_DEFAULT(Current, Rhs, N)				    \
  do								    \
    {								    \
      if (N)							    \
	{							    \
	  (Current).beg = YYRHSLOC(Rhs, 1).beg;			    \
	  (Current).end = YYRHSLOC(Rhs, N).end;			    \
	}							    \
      else							    \
	{							    \
	  (Current).beg = YYRHSLOC(Rhs, 0).end;			    \
	  (Current).end = (Current).beg;			    \
	}							    \
    } while (0)

#define YY_LOCATION_PRINT(File, Loc) locus_range_print (File, &(Loc))

enum deprecation_mode
  {
    DEPREC_OK,
    DEPREC_WARN,
    DEPREC_ERR
  };

extern enum deprecation_mode cfg_deprecation_mode;

/*
 * Working directory support.
 */
typedef struct workdir
{
  DLIST_ENTRY (workdir) link;
  int refcount;
  int fd;
  char name[1];
} WORKDIR;

static inline WORKDIR *
workdir_ref (WORKDIR *wd)
{
  wd->refcount++;
  return wd;
}

static inline void
workdir_unref (WORKDIR *wd)
{
  if (wd)
    {
      wd->refcount--;
    }
}

WORKDIR *workdir_get (char const *name);
int workdir_free (WORKDIR *wd);
int workdir_cleanup (int keepwd);

/* Read in entire file and return its contents as string. */
char *slurp (char const *filename, WORKDIR *wd,
	     struct locus_range const *locus, size_t *len);

void set_include_wd (WORKDIR *wd);
WORKDIR *get_include_wd (void);
int open_wd (WORKDIR *wd, const char *filename, int flags, mode_t mode);
FILE *fopen_wd (WORKDIR *wd, const char *filename);
FILE *fopen_include (const char *filename);
char *filename_resolve (const char *filename);
void fopen_error (int pri, int ec, WORKDIR *wd, const char *filename,
		  struct locus_range const *loc);

int globat (int wd, const char *restrict pattern, int flags,
	    int (*errfunc)(const char *epath, int eerrno),
	    glob_t *restrict pglob);
char const *globstrerror (int rc);

int cfg_open_input (const char *filename, struct locus_range *loc);
int cfg_lex_done (void);
int cfg_lex_init (char const *filename, char const *dir);
int cfg_lex_preproc (char const *filename);

typedef struct cfg_type CFG_TYPE;
typedef struct cfg_rcvr CFG_RCVR;
typedef struct cfg_flag CFG_FLAG;
typedef struct cfg_defn CFG_DEFN;
typedef struct cfg_arg  CFG_ARG;
typedef DLIST_HEAD(,cfg_arg) CFG_ARG_HEAD;
typedef struct cfg_node CFG_NODE;
typedef DLIST_HEAD(,cfg_node) CFG_AST;

enum cfg_keyword_type
  {
    KWT_REG,          /* Regular keyword */
    KWT_ALIAS,        /* Alias to another keyword */
    KWT_TABREF,       /* Reference to another table */
    KWT_SOFTREF,      /* Same as above, but overrides data/off pair of it. */
  };

struct cfg_rcvr
{
  void *data;
  size_t off;
};

static inline void *
cfg_rcvr_ptr (CFG_RCVR *rcvr, void *data)
{
  if (rcvr->data)
    data = rcvr->data;
  return (char*)data + rcvr->off;
}

#include "cfg-gram.h"

struct cfg_flag
{
  char *name;
  int code;
  int has_arg;
};

/*
 * Argument definition reminder:
 *   a         string or literal (for address and port)
 *   b         boolean
 *   f         flag
 *   l         literal
 *   n         number
 *   s         string
 *   .         any of the above
 *
 * Type class:
 *   [C...]    where C is any of type letters above.
 *
 * Each letter or class can be followed by one of the following qualifiers:
 *   ?                 argument is optional;
 *   *                 zero or more arguments of that type;
 *   +                 one or more arguments of that type;
 *   N (decimal digit) N arguments of that type;
 */

struct cfg_type
{
  char *argdef;       /* Argument signature. */
  CFG_FLAG *flagdef;  /* Allowed flags. */
  int (*prepare) (CFG_NODE *, void *, void **);
  int (*commit) (CFG_NODE *, void *, void *);
  void (*free_data) (void *);
};

/* Definition of a configuration entity. */
struct cfg_defn
{
  char *name;        /* Keyword. */
  CFG_TYPE *vtype;   /* Value type. */
  CFG_RCVR rcvr;     /* Receiver. */
  int token;         /* Token type. */
  enum cfg_keyword_type type;  /* Entry type. */

  /* For sections, or type KWT_TABREF or KWT_SOFTREF. */
  CFG_DEFN *ref;

  CFG_FLAG *flagdef;  /* Allowed flags. When present, they override those from
			 vtype. */
  void *data;         /* Definition-specific data. */

  int (*verify) (CFG_NODE *);
  int (*commit) (CFG_NODE *, void *, void *);

  /* For deprecated statements: */
  int deprecated;    /* Whether the statement is deprecated. */
  char *message;     /* Deprecation message. For KWT_ALIAS it can be NULL,
			in which case a default message will be generated. */
};

struct cfg_arg
{
  int type;
  struct locus_range locus;
  YYSTYPE v;
  DLIST_ENTRY (cfg_arg) link;
};

#define CFG_ARG_FOREACH(arg, arglist) DLIST_FOREACH(arg, arglist, link)

static inline int
cfg_arglist_empty (CFG_ARG_HEAD *alist)
{
  return alist == NULL || DLIST_EMPTY (alist);
}

static inline void
cfg_arglist_remove_head (CFG_ARG_HEAD *alist)
{
  if (alist)
    DLIST_REMOVE_HEAD (alist, link);
}

#define cfg_arglist_init DLIST_INIT
#define cfg_arglist_append(alist, arg) DLIST_INSERT_TAIL(alist, arg, link)
#define cfg_arglist_concat(alist, blist) DLIST_CONCAT(alist, blist, link)

static inline CFG_ARG *
cfg_arglist_first (CFG_ARG_HEAD *arglist)
{
  return arglist ? DLIST_FIRST (arglist) : NULL;
}

static inline CFG_ARG *
cfg_arglist_last (CFG_ARG_HEAD *arglist)
{
  return arglist ? DLIST_LAST (arglist) : NULL;
}

static inline CFG_ARG *
cfg_arglist_shift (CFG_ARG_HEAD *arglist)
{
  CFG_ARG *arg = cfg_arglist_first (arglist);
  if (arg)
    cfg_arglist_remove_head (arglist);
  return arg;
}

static inline CFG_ARG *
cfg_arg_next (CFG_ARG *arg)
{
  return DLIST_NEXT (arg, link);
}

int lex_argcmp (char const *argdef, CFG_ARG_HEAD *arg_head,
		char const **expdef, CFG_ARG **errarg);
void arg_mismatch_error (char const *argdef, CFG_ARG *arg,
			 struct locus_range const *loc);

CFG_ARG *cfg_arg_alloc (int type, struct locus_range *locus);
void cfg_arg_free (CFG_ARG *arg);
void cfg_arglist_free (CFG_ARG_HEAD *list);

int cfg_arglist_getflag (CFG_ARG *arg, CFG_ARG **flarg, CFG_ARG **nextarg);

int cfg_assert_range (CFG_ARG *arg, unsigned long min, unsigned long max);

CFG_FLAG *cfg_flag_find (char const *name, size_t len);


enum acl_type
  {
    ACLT_REF,         /* ACL referencing another ACL or disk file. */
    ACLT_IMM,         /* Immediate ACL definition. */
  };

struct cfg_node
{
  CFG_DEFN const *defn;         /* Node definition. */
  CFG_RCVR rcvr;                /* Receiver. */
  struct locus_range locus;     /* Location in the config. */
  CFG_ARG_HEAD arglist;         /* Arguments. */
  DLIST_ENTRY (cfg_node) link;  /* Links to nodes on the same level. */
  CFG_AST *subtree;             /* Subtree, for sections. */
  void *data;                   /* Opaque node-specific data. */
  union
  {
    struct
    {
      enum acl_type type;
      STRING *tag;
    } acl;                      /* ACL (TrustedIP) */
    int rwtarget;               /* Rewrite */
  };
};

CFG_NODE *cfg_node_alloc (CFG_DEFN const *defn, CFG_RCVR const *rcvr,
			  struct locus_point *beg,
			  struct locus_point *end);
void cfg_node_free (CFG_NODE *node);
CFG_AST *cfg_ast_alloc (void);
void cfg_ast_free (CFG_AST *ast);

static inline void
cfg_ast_append (CFG_AST *ast, CFG_NODE *node)
{
  DLIST_INSERT_TAIL (ast, node, link);
}

static inline void
cfg_ast_prepend (CFG_AST *ast, CFG_NODE *node)
{
  DLIST_INSERT_HEAD (ast, node, link);
}

static inline void
cfg_ast_concat (CFG_AST *a, CFG_AST *b)
{
  DLIST_CONCAT (a, b, link);
}

static inline void
cfg_ast_remove (CFG_AST *ast, CFG_NODE *node)
{
  DLIST_REMOVE (ast, node, link);
}

CFG_AST *cfg_parse_tree (char const *filename, char const *dir,
			 CFG_DEFN *parsetab);

int cfg_ast_verify (CFG_AST *ast);
int cfg_ast_commit (CFG_AST *ast, void *baseptr, void *data);
static inline int
cfg_ast_finalize (CFG_AST *ast, void *baseptr, void *data)
{
  return cfg_ast_verify (ast) || cfg_ast_commit (ast, baseptr, data);
}
CFG_NODE *cfg_ast_locate_node (CFG_AST *ast, int (*eqf) (CFG_NODE *, void *),
			       void *key);
CFG_NODE *cfg_node_locate_next (CFG_NODE *node,
				int (*eqf) (CFG_NODE *, void *), void *key);
int cfg_node_defn_eq (CFG_NODE *node, void *key);
int cfg_node_name_eq (CFG_NODE *node, void *key);
int cfg_node_name_memberof (CFG_NODE *node, void *nameset);
int cfg_node_name_not_memberof (CFG_NODE *node, void *nameset);

enum
  {
    LOOKUP_OK,
    LOOKUP_NOTFOUND,
    LOOKUP_ERROR
  };

void cfg_defn_push (CFG_DEFN const *defn);
void cfg_defn_pop (void);
int cfg_defn_lookup (char const *name, CFG_DEFN const **ret_defn,
		     CFG_RCVR *rcvr);
CFG_DEFN const *locate_defn (CFG_DEFN const *tab, char const *name,
			     CFG_DEFN const **ref, CFG_RCVR *rcvr);

enum
  {
    CFG_DEBUG_LEX = 0x1,
    CFG_DEBUG_GRAM = 0x2,
    CFG_DEBUG_AST = 0x4
  };

extern int cfg_debug;
extern size_t preproc_argc;
extern char **preproc_argv;

extern CFG_DEFN rewrite_branch_defn;

/* Configuration data types. */
extern struct cfg_type cfg_type_string;
#define CFG_TYPE_STRING (&cfg_type_string)
extern struct cfg_type cfg_type_lazy_string;
#define CFG_TYPE_LAZY_STRING (&cfg_type_lazy_string)
extern struct cfg_type cfg_type_literal;
#define CFG_TYPE_LITERAL (&cfg_type_literal)
extern struct cfg_type cfg_type_bool;
#define CFG_TYPE_BOOL (&cfg_type_bool)
extern struct cfg_type cfg_type_opt_bool;
#define CFG_TYPE_OPT_BOOL (&cfg_type_opt_bool)
extern struct cfg_type cfg_type_int;
#define CFG_TYPE_INT (&cfg_type_int)
extern struct cfg_type cfg_type_uint;
#define CFG_TYPE_UINT (&cfg_type_uint)
extern struct cfg_type cfg_type_duration;
#define CFG_TYPE_DURATION (&cfg_type_duration)
extern struct cfg_type cfg_type_size;
#define CFG_TYPE_SIZE (&cfg_type_size)
extern struct cfg_type cfg_type_content_length;
#define CFG_TYPE_CONTENT_LENGTH (&cfg_type_content_length)
extern struct cfg_type cfg_type_port;
#define CFG_TYPE_PORT (&cfg_type_port)
extern struct cfg_type cfg_type_port_string;
#define CFG_TYPE_PORT_STRING (&cfg_type_port_string)
extern struct cfg_type cfg_type_cert;
#define CFG_TYPE_CERT (&cfg_type_cert)
extern struct cfg_type cfg_type_ignored;
#define CFG_TYPE_IGNORED (&cfg_type_ignored)
extern struct cfg_type cfg_type_null;
#define CFG_TYPE_NULL (&cfg_type_null)
extern struct cfg_type cfg_type_any;
#define CFG_TYPE_ANY (&cfg_type_any)

enum
  {
    F_OFF,
    F_ON,
    F_DFL
  };

struct pound_feature
{
  char *name;
  char *descr;
  int enabled;
  void (*setfn) (char const *, int, char const *);
};

void feature_init (struct pound_feature *ftab);
int feature_set (char const *name);
int feature_is_set (int f);
void features_print (FILE *fp);

void set_debug_feature (char const *fname, int enabled, char const *val);

void skip_eol (void);

#endif
