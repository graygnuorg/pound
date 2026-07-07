/*
 * Pound - the reverse-proxy load-balancer        -*- c -*-
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
%top{
#include <config.h>
#include "pound.h"
#include "cfgdef.h"
#include "extern.h"
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include "cfg-gram.h"
}
%{
struct locus_range curloc;
int in_stmt;
static int nl_injected;

#define YY_INPUT(buf,result,max_size)				\
  do								\
    {								\
      size_t n = fread (buf, 1, max_size, yyin);		\
      if (n == 0)						\
	{							\
	  if (!nl_injected)					\
	    {							\
	      buf[0] = '\n';					\
	      n = 1;						\
	      nl_injected = 1;					\
	    }							\
	}							\
      else							\
	nl_injected = buf[n-1] == '\n';				\
      result = n;						\
    }								\
  while (0)

#define YY_USER_ACTION  { locus_advance (yytext, yyleng); }

static inline void
locus_newline (size_t n)
{
  curloc.end.line += n;
  curloc.end.col = 1;
}

static inline void
locus_advance (char const *str, int len)
{
  int i;
  for (i = 0; i < len; i++)
    {
      switch (str[i])
	{
	case '\t':
	  curloc.end.col += 8; //FIXME
	  break;
	case '\n':
	  locus_newline (1);
	  break;
	default:
	  curloc.end.col++;
	}
    }
}

static inline void
locus_reset (void)
{
  curloc.beg = curloc.end;
}

static inline int
tok (int c)
{
  if (c == T_NL)
    {
      yylloc.beg = curloc.end;
      yylloc.beg.line--;
      yylloc.beg.col = 0;
      yylloc.end = yylloc.beg;
    }
  else
    {
      yylloc = curloc;
      yylloc.end.col--;
    }
  locus_reset ();
  return c;
}

static struct stringbuf sb;

#define new_string string_ninit

static inline void
string_begin (void)
{
  stringbuf_reset (&sb);
}

static inline void
string_add (char const *str, size_t len)
{
  stringbuf_add (&sb, str, len);
}

static inline STRING *
string_end (void)
{
  return new_string (stringbuf_value (&sb), stringbuf_len (&sb));
}

static inline int
flag_token_type (CFG_FLAG const *flg)
{
  if (flg->has_arg)
    {
      if (strcmp (flg->name, "file") == 0 ||
	  strcmp (flg->name, "filewatch") == 0)
	return T_FILEFLAG;
      else
	return T_FLAGARG;
    }
  return T_FLAG;
}
%}
%option case-insensitive
WS [ \t]+
IDENT [a-zA-Z_][a-zA-Z0-9_]*
%x STR TEXT
%%
    /* Comments and whitespace. */
#.*\n                  { in_stmt = 0; return tok (T_NL); }
{WS}                   locus_reset ();
\\\n                   ;
\n+                    { in_stmt = 0; return tok (T_NL); }
    /* Strings */
\"[^\n\\\"]*\"         {
  yylval.string = new_string (yytext + 1, yyleng - 2);
  return tok (T_STRING);
}
\"[^\n\\\"]*\\[\\\"]   {
  BEGIN (STR);
  string_begin ();
  string_add (yytext + 1, yyleng - 3);
  string_add (yytext + yyleng - 1, 1);
}
\"[^\n\\\"]*\\[^\\\"]  {
  struct locus_range loc = curloc;
  loc.beg.col = loc.end.col-2;
  conf_error_at_locus_range (&loc,
			     "unrecognized escape sequence");
  BEGIN (STR);
  string_begin ();
  string_add (yytext + 1, yyleng - 1);
}
\"[^\n\\\"]*\n  {
  conf_error_at_locus_point (&curloc.end,
			     "unexpected newline in string");
  in_stmt = 0;
  return tok (T_BOGUS);
}
<STR>{
  [^\n\\\"]*\"           {
    string_add (yytext, yyleng - 1);
    yylval.string = string_end ();
    BEGIN (INITIAL);
    return tok (T_STRING);
  }
  [^\n\\\"]*\\[\\\"]  {
    string_add (yytext, yyleng - 2);
    string_add (yytext + yyleng - 1, 1);
  }
  [^\n\\\"]*\\[^\\\"] {
	 conf_error_at_locus_point (&curloc.end,
				    "unrecognized escape character");
	 string_add (yytext, yyleng - 2);
	 string_add (yytext + yyleng - 1, 1);
  }
  [^\n\\\"]*\n {
	 BEGIN (INITIAL);
	 conf_error_at_locus_point (&curloc.end,
				    "unexpected newline in string");
	 in_stmt = 0;
	 return tok (T_BOGUS);
  }
}
    /* Numbers. */
[0-9]+/[ \t\n] {
  yylval.number = strtoul (yytext, NULL, 0);
  return tok (T_NUMBER);
}
    /* Flags. */
-{IDENT} {
  CFG_FLAG *flg = cfg_flag_find (yytext + 1, yyleng - 1);
  if (flg)
    {
      yylval.flag = flg;
      return tok (flag_token_type (flg));
    }
  else
    {
      conf_error ("%s", "unrecognized flag");
      yylval.flag = NULL;
      return tok (T_FLAG);
    }
}
    /* Special keywords. */
"End"                  return tok (T_END);
"Include"              return tok (T_INCLUDE);
    /* Boolean values. */
"on"|"true"|"yes"      { yylval.boolean = 1; return tok (T_BOOLEAN); }
"off"|"false"|"no"     { yylval.boolean = 0; return tok (T_BOOLEAN); }
    /* Keywords and literals. */
{IDENT} {
  if (in_stmt)
    {
      yylval.string = new_string (yytext, yyleng);
      return tok (T_LITERAL);
    }
  switch (cfg_defn_lookup (yytext, &yylval.defn.defn, &yylval.defn.rcvr))
    {
    case LOOKUP_OK:
      if (yylval.defn.defn->token != T_NOT)
	in_stmt = 1;
      return tok (yylval.defn.defn->token);

    case LOOKUP_NOTFOUND:
      yylval.string = new_string (yytext, yyleng);
      return tok (T_LITERAL);

    case LOOKUP_ERROR:
      return T_BOGUS;
    }
}
[^ \t\n\\\"]+  {
  yylval.string = new_string (yytext, yyleng);
  return tok (T_LITERAL);
}
.      {
  if (c_isgraph (yytext[0]))
    conf_error ("stray character '%c'", yytext[0]);
  else
    conf_error ("stray character %03o", yytext[0]);
  return tok (T_BOGUS);
}
<TEXT>{
[ \t]+end[ \t]*$ {
  yyless (0);
  BEGIN (INITIAL);
  yylval.string = string_end ();
  return tok (T_LITERAL);
}
[^\n]*\n {
  string_add (yytext, yyleng);
 }
}
%%
void
conf_error (char const *fmt, ...)
{
  va_list ap;
  struct locus_range loc = curloc;
  if (loc.end.col > loc.beg.col)
    loc.end.col--;
  va_start (ap, fmt);
  vconf_error_at_locus_range (&loc, fmt, ap);
  va_end (ap);
}

void
begin_text (void)
{
  BEGIN (TEXT);
  string_begin ();
}

void
locus_point_init (struct locus_point *pt, char const *filename,
		  char const *dir)
{
  if (filename)
    {
      size_t dlen = (dir && filename[0] != '/') ? strlen (dir) : 0;
      char *p;
      pt->filename = string_alloc (strlen (filename) +
				   (dlen ? (dlen + 1) : 0));
      p = pt->filename->str;
      if (dlen > 0)
	{
	  memcpy (p, dir, dlen);
	  p += dlen;
	  *p++ = '/';
	}
      strcpy (p, filename);
    }
  else
    pt->filename = NULL;
  pt->line = 1;
  pt->col = 1;
}

static inline int
locus_point_same_file (struct locus_point const *a,
		       struct locus_point const *b)
{
  return string_eq (a->filename, b->filename);
}

void
locus_point_print (FILE *fp, struct locus_point const *p)
{
  if (p->filename)
    {
      fprintf (fp, "%s:%d", string_ptr (p->filename), p->line);
      if (p->col)
	fprintf (fp, ".%d", p->col);
    }
}

void
locus_range_print (FILE *fp, struct locus_range const *r)
{
  locus_point_print (fp, &r->beg);
  if (r->end.filename)
    {
      if (!locus_point_same_file (&r->beg, &r->end))
	{
	  fputc ('-', fp);
	  locus_point_print (fp, &r->end);
	}
      else if (r->beg.line != r->end.line)
	{
	  fputc ('-', fp);
	  fprintf (fp, "%d", r->end.line);
	  if (r->end.col)
	    fprintf (fp, ".%d", r->end.col);
	}
      else if (r->beg.col && r->beg.col != r->end.col)
	{
	  fputc ('-', fp);
	  fprintf (fp, "%d", r->end.col);
	}
    }
}


/* Input context. */
struct inctx
{
  struct inctx *prev;             /* Previous context on stack. */
  YY_BUFFER_STATE buf;            /* Lex buffer state. */
  ino_t ino;
  dev_t dev;
  struct locus_range locus;       /* Current location */
  WORKDIR *wd;
  glob_t *glob;
  size_t idx;
};

static struct inctx *input_ctx;
static ino_t cur_ino;
static dev_t cur_dev;

static void
inctx_push (void)
{
  if (YY_CURRENT_BUFFER)
    {
      struct inctx *ctx;
      XZALLOC (ctx);

      ctx->prev = input_ctx;
      ctx->buf = YY_CURRENT_BUFFER;
      ctx->ino = cur_ino;
      ctx->dev = cur_dev;
      ctx->locus = curloc;
      locus_range_ref (&curloc);
      input_ctx = ctx;
    }
}

static char const *
next_name (void)
{
  if (input_ctx && input_ctx->glob)
    {
      while (input_ctx->idx < input_ctx->glob->gl_pathc)
	{
	  char const *name = input_ctx->glob->gl_pathv[input_ctx->idx++];
	  if (name[strlen(name)-1] != '/')
	    return name;
	}
    }
  return NULL;
}

static int
inctx_pop (void)
{
  struct inctx *ctx = input_ctx;

  if (!ctx)
    {
      fclose (yyin);
      return 1;
    }

  input_ctx = ctx->prev;
  if (YY_CURRENT_BUFFER != ctx->buf)
    {
      fclose (yyin);
      yy_delete_buffer (YY_CURRENT_BUFFER);
      yy_switch_to_buffer (ctx->buf);
    }
  cur_ino = ctx->ino;
  cur_dev = ctx->dev;
  curloc = ctx->locus;
  locus_range_unref (&curloc);

  if (ctx->glob)
    {
      globfree (ctx->glob);
      free (ctx->glob);
    }
  free (ctx);

  return 0;
}

static struct inctx *
inctx_locate (struct stat *st)
{
  struct inctx *ctx;

  for (ctx = input_ctx; ctx; ctx = ctx->prev)
    {
      if (ctx->dev == st->st_dev && ctx->ino == st->st_ino)
	break;
    }
  return ctx;
}

int
yywrap (void)
{
  do
    {
      char const *name;
      if ((name = next_name ()) != NULL)
	return cfg_open_input (name, &input_ctx->locus);
      if (inctx_pop ())
	return 1;
    }
  while (input_ctx && input_ctx->glob);
  return 0;
}

/*
 * Interface functions.
 */
int
cfg_open_input (const char *filename, struct locus_range *loc)
{
  struct stat st;
  WORKDIR *wd =  get_include_wd ();
  struct inctx *ctx;

  if (fstatat (wd->fd, filename, &st, 0))
    {
      if (errno == ENOENT)
	{
	  int rc;
	  glob_t *glob;
	  XZALLOC (glob);
	  rc = globat (wd->fd, filename, GLOB_ERR | GLOB_MARK, NULL, glob);
	  if (rc == 0)
	    {
	      char const *name;

	      inctx_push ();
	      input_ctx->glob = glob;
	      input_ctx->wd = wd;
	      input_ctx->idx = 0;
	      if ((name = next_name ()) != NULL &&
		  cfg_open_input (name, &input_ctx->locus) == 0)
		return 0;
	      inctx_pop ();
	    }
	  else if (rc != GLOB_NOMATCH)
	    {
	      conf_error ("glob error: %s", globstrerror (rc));
	      return -1;
	    }
	  errno = ENOENT;
	}

      if (filename[0] == '/')
	conf_error ("can't stat %s: %s", filename, strerror (errno));
      else
	conf_error ("can't stat %s/%s: %s", wd->name, filename,
		    strerror (errno));
      return -1;
    }
  else
    {
      inctx_push ();
      if ((ctx = inctx_locate (&st)) != NULL)
	{
	  ctx = ctx->prev;
	  if (ctx)
	    {
	      conf_error ("%s already included", filename);
	      conf_error_at_locus_range (&ctx->locus,
					 "here is the location of original"
					 " inclusion");
	    }
	  else
	    conf_error ("%s: main configuration file cannot be included",
			filename);
	  inctx_pop ();
	  return -1;
	}
    }

  if ((yyin = fopen_include (filename)) == 0)
    {
      conf_error ("can't open %s: %s", filename, strerror (errno));
      inctx_pop ();
      return -1;
    }

  yy_switch_to_buffer (yy_create_buffer (yyin, YY_BUF_SIZE));
  cur_ino = st.st_ino;
  cur_dev = st.st_dev;
  locus_range_init_ext (&curloc, filename,
			(wd->fd != AT_FDCWD) ? wd->name : NULL);

  return 0;
}

int
cfg_lex_done (void)
{
  stringbuf_free (&sb);
  return 0;
}

int
cfg_lex_init (char const *filename, char const *dir)
{
  int rc;

  yyset_debug (cfg_debug & CFG_DEBUG_LEX);

  if ((include_wd = workdir_get (dir)) == NULL)
    {
      conf_error ("can't open cwd: %s", strerror (errno));
      return -1;
    }

  rc = cfg_open_input (filename, NULL);

  xstringbuf_init (&sb);

  /* Make sure an attempt to open include_dir will be made if needed. */
  workdir_unref (include_wd);
  include_wd = NULL;

  return rc;
}

char const *
argcode_string (int c)
{
  switch (c)
    {
    case 'a':
      return "string or literal";
    case 'b':
      return "boolean";
    case 'f':
      return "flag";
    case 'l':
      return "literal";
    case 'n':
      return "number";
    case 's':
      return "string";
    case '.':
      return "any type";
    case 0:
      return "end of argument list";
    }
  return "UNDEFINED";
}

static inline int
is_argtype (int c)
{
  return strchr ("abfnls.", c) != NULL;
}

char const *
argdef_string (char const *s, char **ptr)
{
  if (*s != '[' && s[1] != '?' && s[1] != '*')
    {
      *ptr = NULL;
      s = argcode_string (*s);
    }
  else
    {
      struct stringbuf sb;
      xstringbuf_init (&sb);
      while (*s)
	{
	  if (*s == '[')
	    {
	      s++;
	      for (;;)
		{
		  stringbuf_add_string (&sb, argcode_string (*s));
		  s++;
		  assert (*s != 0);
		  if (*s == ']')
		    break;
		  stringbuf_add_string (&sb, " or ");
		}
	      s++;
	    }
	  else
	    {
	      stringbuf_add_string (&sb, argcode_string (*s));
	      s++;
	    }
	  if (*s == '?' || *s == '*')
	    {
	      s++;
	      if (*s)
		stringbuf_add_string (&sb, " or ");
	      else
		{
		  stringbuf_add_string (&sb, " or end of list");
		  break;
		}
	    }
	  else
	    break;
	}

      s = stringbuf_finish (&sb);
      *ptr = (char *) s;
    }

  return s;
}

char const *
token_string (int t)
{
  switch (t)
    {
    case T_BOOLEAN:
      return "boolean";
    case T_FLAG:
      return "flag";
    case T_LITERAL:
      return "literal";
    case T_NUMBER:
      return "number";
    case T_STRING:
      return "string";
    }
  return "UNKNOWN";
}
/*
 * Table-driven parsing
 */
static int
typeq (int type, CFG_ARG *arg)
{
  int eq = 0;

  switch (type)
    {
    case 'a':
      eq = arg->type == T_STRING || arg->type == T_LITERAL;
      break;

    case 'b':
      if (arg->type == T_NUMBER)
	eq = arg->v.number == 0 || arg->v.number == 1;
      else
	eq = arg->type == T_BOOLEAN;
      break;

    case 'f':
      eq = arg->type == T_FLAG;
      break;

    case 'l':
      eq = arg->type == T_LITERAL;
      break;

    case 'n':
      eq = arg->type == T_NUMBER;
      break;

    case 's':
      eq = arg->type == T_STRING;
      break;

    case '.':
      eq = 1;
      break;

    default:
      abort ();
    }

  return eq;
}

static int
typeqs (char const *def, CFG_ARG *arg, char const **defnext, CFG_ARG **argnext)
{
  int rc = 0;
  if (*def == '[')
    {
      for (def++; !(*def == ']' || *def == 0); def++)
	if ((rc = typeq (*def, arg)) != 0)
	  break;
      for (; !(*def == ']' || *def == 0); def++)
	;
      assert(*def == ']');
    }
  else
    rc = typeq (*def, arg);

  if (rc)
    {
      if (arg->type == T_FLAG && arg->v.flag->has_arg)
	arg = cfg_arg_next (arg);
      *argnext = cfg_arg_next (arg);
    }
  else
    *argnext = arg;

  if (defnext)
    *defnext = def + 1;

  return rc;
}

static int
argruncmp (char const *def, CFG_ARG *arg,
	   char const **defnext, CFG_ARG **argnext)
{
  char const *dn = *defnext;
  int ok = typeqs (def, arg, &dn, &arg);
  switch (*dn)
    {
    case '*':
      *defnext = dn + 1;
      if (ok)
	{
	  while (arg && typeqs (def, arg, NULL, &arg))
	    ;
	  *argnext = arg;
	}
      else
	ok = 1;
      break;
    case '?':
      *defnext = dn + 1;
      if (ok)
	*argnext = arg;
      ok = 1;
      break;
    case '+':
      if (ok)
	{
	  while (arg && typeqs (def, arg, NULL, &arg))
	    ;
	  *defnext = dn + 1;
	  *argnext = arg;
	}
      break;
    case '2': case '3': case '4': case '5':
    case '6': case '7': case '8': case '9':
      {
	int n = *dn-'0';
	for (; arg && n > 1; n--)
	  if (!(ok = typeqs (def, arg, NULL, &arg)))
	    break;
	if (ok)
	  *defnext = dn + 1;
	*argnext = arg;
      }
      break;
    case '1':
      dn++;
      /* fallthrough */
    default:
      if (ok)
	{
	  *defnext = dn;
	  *argnext = arg;
	}
    }
  return !ok;
}

int
lex_argcmp (char const *argdef, CFG_ARG_HEAD *arg_head,
	    char const **expdef, CFG_ARG **errarg)
{
  char const *startdef = argdef;
  CFG_ARG *arg = cfg_arglist_first (arg_head);
  int rc;

  if (!argdef)
    argdef = "";
  else if (strcmp (argdef, ".*") == 0)
    {
      *expdef = "";
      *errarg = NULL;
      return 0;
    }

  for (;;)
    {
      if (*argdef == 0)
	{
	  rc = arg != NULL;
	  break;
	}
      else if (arg == NULL)
	{
	  if (!*argdef)
	    rc = 0;
	  else
	    {
	      rc = 1;
	      while (*argdef)
		{
		  if (*argdef == '[')
		    {
		      argdef = strchr (argdef, ']');
		      assert (argdef != NULL);
		    }
		  argdef++;
		  if (*argdef == '?' || *argdef == '*')
		    {
		      if (!*++argdef)
			{
			  rc = 0;
			  break;
			}
		    }
		  else
		    break;
		}
	    }
	  break;
	}
      else if ((rc = argruncmp (argdef, arg, &argdef, &arg)) != 0)
	break;
    }

  if (rc)
    {
      /* Adjust expdef */
      while (argdef > startdef && (argdef[-1] == '?' || argdef[-1] == '*'))
	{
	  --argdef;
	  if (argdef > startdef && *--argdef == ']')
	    while (argdef > startdef && *--argdef != '[')
	      ;
	}
    }
  *expdef = argdef;
  *errarg = arg;
  return rc;
}

static inline int
iswild (char const *p)
{
  return p[0] == '*' && p[1] == 0;
}

/*
 * Find in TAB an entry describing the keyword NAME.  If the keyword is an
 * alias to another one, return the aliased keyword, and place in *REF a
 * pointer to the entry describing the alias.  Otherwise, initialize *REF to
 * NULL.
 *
 * Upon successful return, return the receiver data in the memory location
 * pointed to by rcvr.
 */
CFG_DEFN const *
locate_defn (CFG_DEFN const *tab, char const *name,
	     CFG_DEFN const **ref, CFG_RCVR *rcvr)
{
  CFG_DEFN const *p;

  *ref = NULL;
  p = tab;
  for (; p->name; p++)
    {
      if (p->type == KWT_TABREF)
	{
	  CFG_DEFN const *result = locate_defn (p->ref, name, ref, rcvr);
	  if (result)
	    return result;
	}
      else if (p->type == KWT_SOFTREF)
	{
	  CFG_DEFN const *result = locate_defn (p->ref, name, ref, rcvr);
	  if (result)
	    {
	      *rcvr = p->rcvr;
	      return result;
	    }
	}
      else if (c_strcasecmp (p->name, name) == 0 || iswild (p->name))
	{
	  *ref = p;
	  if (p->type == KWT_ALIAS)
	    {
	      while (p > tab && p->type == KWT_ALIAS)
		p--;
	      assert (p->type == KWT_REG);
	    }
	  *rcvr = p->rcvr;
	  return p;
	}
    }
  return NULL;
}

typedef struct defnstk
{
  CFG_DEFN const *defn;
  SLIST_ENTRY(defnstk) prev;
} DEFNSTK;

static SLIST_HEAD(,defnstk) defn_head =
  SLIST_HEAD_INITIALIZER (defn_head);

void
cfg_defn_push (CFG_DEFN const *defn)
{
  DEFNSTK *ent;
  XZALLOC (ent);
  ent->defn = defn;
  SLIST_INSERT_HEAD (&defn_head, ent, prev);
}

void
cfg_defn_pop (void)
{
  DEFNSTK *ent = SLIST_FIRST (&defn_head);
  SLIST_REMOVE_HEAD (&defn_head, prev);
  free (ent);
}

enum deprecation_mode cfg_deprecation_mode = DEPREC_WARN;

int
cfg_defn_lookup (char const *name, CFG_DEFN const **ret_defn, CFG_RCVR *rcvr)
{
  DEFNSTK *tos = SLIST_FIRST (&defn_head);
  CFG_DEFN const *ent, *ref;

  if (tos)
    {
      if ((ent = locate_defn (tos->defn, name, &ref, rcvr)) != NULL)
	{
	  if (ref && ref->deprecated)
	    {
	      switch (cfg_deprecation_mode)
		{
		case DEPREC_OK:
		  break;

		case DEPREC_WARN:
		  if (ent->message)
		    conf_error ("warning: deprecated statement, %s",
				ref->message);
		  else
		    conf_error ("warning: deprecated statement,"
				" use \"%s\" instead", ent->name);
		  break;

		case DEPREC_ERR:
		  if (ent->message)
		    conf_error ("deprecated statement, %s", ref->message);
		  else
		    conf_error ("deprecated statement,"
				" use \"%s\" instead", ent->name);
		  return LOOKUP_ERROR;
		}
	    }
	  *ret_defn = ent;
	  return LOOKUP_OK;
	}
    }

  return LOOKUP_NOTFOUND;
}

static CFG_FLAG *
flagdef_find (CFG_FLAG *def, char const *name, size_t len)
{
  if (def)
    for (; def->name; def++)
      {
	if (strlen (def->name) == len && memcmp (def->name, name, len) == 0)
	  return def;
      }
  return NULL;
}

CFG_FLAG *
cfg_flag_find (char const *name, size_t len)
{
  DEFNSTK *tos = SLIST_FIRST (&defn_head);
  CFG_DEFN const *defn = tos->defn;
  return flagdef_find (defn->flagdef ? defn->flagdef : defn->vtype->flagdef,
		       name, len);
}

void
skip_eol (void)
{
  int c;
  while ((c = input ()) > 0)
    {
      if (c == '\n')
	{
	  unput (c);
	  break;
	}
    }
}
