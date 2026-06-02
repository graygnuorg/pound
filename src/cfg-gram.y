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

%{
#include <config.h>
#include "pound.h"
#include "cfgdef.h"
#include "cfg-gram.h"

int cfg_debug;
static int cfg_err;
static CFG_AST *cfg_result;

static inline CFG_AST *
cfg_stmtlist_init (CFG_NODE *node)
{
  CFG_AST *ast = cfg_ast_alloc ();
  if (node)
    DLIST_INSERT_TAIL (ast, node, link);
  return ast;
}

static inline CFG_AST *
cfg_stmtlist_add (CFG_AST *ast, CFG_NODE *node)
{
  if (node)
    DLIST_INSERT_TAIL (ast, node, link);
  return ast;
}

void
arg_mismatch_error (char const *argdef, CFG_ARG *arg,
		    struct locus_range const *loc)
{
  cfg_err++;
  if (argdef == 0)
    conf_error_at_locus_range (&arg->locus, "extra arguments");
  else if (arg == NULL)
    conf_error_at_locus_range (loc, "not enough arguments");
  else
    {
      char *ptr;
      conf_error_at_locus_range (&arg->locus,
				 "argument type mismatch: "
				 "expected %s, but found %s",
				 argdef_string (argdef, &ptr),
				 token_string (arg->type));
      free (ptr);
    }
}

static inline CFG_NODE *
cfg_gen_node (CFG_DEFN const *defn, CFG_RCVR const *rcvr,
	      CFG_ARG_HEAD *arglist, CFG_AST *subtree,
	      struct locus_point *beg, struct locus_point *end)
{
  CFG_NODE *node = cfg_node_alloc (defn, rcvr, beg, end);
  CFG_ARG *arg;
  char const *argdef;

  if (defn->vtype && lex_argcmp (defn->vtype->argdef, arglist, &argdef, &arg))
    {
      arg_mismatch_error (argdef, arg, &node->locus);
      cfg_node_free (node);
      return NULL;
    }

  if (arglist)
    {
      node->arglist = *arglist;
      cfg_arglist_init (arglist);
    }
  node->subtree = subtree;
  return node;
}

static CFG_DEFN *
find_rewrite_defn (CFG_DEFN *defn, char const *id)
{
  for (; defn->name; defn++)
    {
      if (defn->type == KWT_TABREF && c_strcasecmp (defn->name, id) == 0)
	return defn->ref;
    }
  abort ();
}

CFG_DEFN rewrite_branch_defn = {
  .name = "rewrite/else",
  .vtype = CFG_TYPE_IGNORED,
  .token = T_SECTION,
};

static CFG_NODE *
new_rewrite_node (CFG_AST *ast, struct locus_range *loc)
{
  CFG_NODE *node;
  CFG_RCVR rcvr = { NULL, 0 };

  node = cfg_node_alloc (&rewrite_branch_defn, &rcvr, &loc->beg, &loc->end);
  node->subtree = ast;
  return node;
}

void yyerror(char const *s);
void begin_text (void);

%}

%token <defn> T_CONTROL    "Control"
%token <defn> T_ACL        "ACL"
%token <defn> T_TRUSTEDIP  "TrustedIP"
%token <defn> T_NOT        "Not"
%token <defn> T_DIRECTIVE  "directive"
%token <defn> T_SECTION    "section start"
%token <defn> T_COMHEADERS "CombineHeaders"
%token <defn> T_REWRITE    "Rewrite"
%token <defn> T_ELSE       "Else"
%token <defn> T_TEXT       "textual section"

%token T_INCLUDE           "Include"
%token T_INCLUDEDIR        "Includedir"
%token T_END               "End"

%token <string> T_STRING   "quoted string"
%token <string> T_LITERAL  "literal"
%token <flag> T_FLAG T_FLAGARG T_FILEFLAG
%token <number> T_NUMBER   "number"
%token <boolean> T_BOOLEAN "boolean"

%token T_NL                "newline"
%token T_BOGUS

%type <defn> control_kw
%type <defn> not_kw
%type <defn> section_kw acl_kw trustedip_kw directive_kw
%type <rewrite> rewrite_begin
%type <subtree> opt_stmtlist stmtlist
%type <subtree> toplist rwelse
%type <node> topstmt stmt opt_stmt section textstmt
%type <node> acldef trustedip control comheaders directive
%type <node> negation
%type <node> aclcond
%type <node> rewrite
%type <node> includedir
%type <string> tag
%type <arg> arg string
%type <string> opt_lit
%type <arglist> arglist opt_arglist stringlist opt_stringlist singlestring
%type <arglist> flag flags opt_flags fileflag fileflags

%expect 3
%define parse.error custom
%locations
%code requires {
# define YYLTYPE struct locus_range
}
%union {
  STRING *string;
  char *text;
  unsigned long number;
  int boolean;
  struct
  {
    CFG_DEFN const *defn;
    CFG_RCVR rcvr;
  } defn;
  struct
  {
    CFG_DEFN const *defn;
    CFG_RCVR rcvr;
    int target;
  } rewrite;
  CFG_ARG *arg;
  CFG_ARG_HEAD arglist;
  CFG_NODE *node;
  CFG_AST *subtree;
  CFG_FLAG *flag;
};

%%
input       : /* empty */
	      {
		cfg_result = cfg_stmtlist_init (NULL);
	      }
	    | toplist
	      {
		cfg_result = $1;
	      }
	    ;

toplist     : topstmt
	      {
		$$ = cfg_stmtlist_init ($1);
	      }
	    | toplist topstmt
	      {
		$$ = cfg_stmtlist_add ($1, $2);
	      }
	    ;

topstmt     : T_NL
	      {
		$$ = NULL;
	      }
	    | stmt
	    | control
	    | comheaders
	    | acldef
	    | includedir
	    ;

section     : section_kw opt_arglist T_NL opt_stmtlist endsec T_NL
	      {
		$$ = cfg_gen_node ($1.defn, &$1.rcvr, &$2, $4,
				   &@1.beg, &@5.end);
	      }
	    ;

section_kw  : T_SECTION
	      {
		cfg_defn_push ($1.defn->ref);
	      }
	    ;

opt_stmtlist: /* empty */
	      {
		$$ = cfg_ast_alloc ();
	      }
	    | stmtlist
	    ;

stmtlist    : opt_stmt
	      {
		$$ = cfg_stmtlist_init ($1);
	      }
	    | stmtlist opt_stmt
	      {
		$$ = cfg_stmtlist_add ($1, $2);
	      }
	    ;

opt_stmt    : T_NL
	      {
		$$ = NULL;
	      }
	    | stmt
	    | error { skip_eol (); } T_NL
	      {
		yyclearin;
		yyerrok;
		cfg_err++;
		$$ = NULL;
	      }
	    ;

stmt        : directive
	    | textstmt
	    | section
	    | rewrite
	    | negation
	    | aclcond
	    | trustedip
	    ;

directive   : directive_kw opt_arglist nl
	      {
		$$ = cfg_gen_node ($1.defn, &$1.rcvr, &$2, NULL,
				   &@1.beg, &@2.end);
	      }
	    | directive_kw error { skip_eol (); } nl
	      {
		yyclearin;
		yyerrok;
		cfg_err++;
		$$ = NULL;
	      }
	    | include
	      {
		$$ = NULL;
	      }
	    ;

directive_kw: T_DIRECTIVE
	      {
		cfg_defn_push ($1.defn);
	      }
	    ;

includedir  : T_INCLUDEDIR T_STRING T_NL
	      {
		WORKDIR *wd;
		/* Make sure current include directory is open. */
		get_include_wd ();
		/* Open new include directory. */
		if ((wd = workdir_get (string_ptr ($2))) == NULL)
		  {
		    conf_error_at_locus_range (&@2,
					       "can't open directory %s: %s",
					       string_ptr ($2),
					       strerror (errno));
		    YYERROR;
		  }
		/* Set it up. */
		set_include_wd (wd);
		$$ = NULL;
	      }
	    ;

include     : T_INCLUDE T_STRING T_NL
	      {
		if (cfg_open_input (string_ptr ($2), &@2))
		  YYERROR;
	      }
	    ;

textstmt    : T_TEXT T_NL { begin_text (); } T_LITERAL T_END T_NL
	      {
		CFG_ARG_HEAD arglist;
		CFG_ARG *arg = cfg_arg_alloc (T_STRING, &@4);
		arg->v.string = $4;
		cfg_arglist_init (&arglist);
		cfg_arglist_append (&arglist, arg);
		$$ = cfg_gen_node ($1.defn, &$1.rcvr, &arglist, NULL,
				   &@1.beg, &@4.end);
	      }

endsec      : T_END
	      {
		cfg_defn_pop ();
	      }
	    ;

nl          : T_NL
	      {
		cfg_defn_pop ();
	      }
	    ;

/*
 * Top-level control statement.
 */
control     : T_CONTROL arglist T_NL
	      {

		$$ = cfg_gen_node ($1.defn, &$1.rcvr, &$2, NULL,
				   &@1.beg, &@2.end);
	      }
	    | control_kw T_NL stmtlist endsec T_NL
	      {
		$$ = cfg_gen_node ($1.defn, &$1.rcvr, NULL, $3,
				   &@1.beg, &@4.end);
	      }
	    | control_kw error { skip_eol (); } nl
	      {
		yyclearin;
		yyerrok;
		cfg_err++;
		$$ = NULL;
	      }
	    ;

control_kw  : T_CONTROL
	      {
		cfg_defn_push ($1.defn->ref);
	      }
	    ;
/*
 * The Rewrite statement.
 */
rewrite     : rewrite_begin T_NL opt_stmtlist rwelse endsec T_NL
	      {
		CFG_NODE *node;
		CFG_AST *ast = $4 ? $4 : cfg_ast_alloc ();

		cfg_ast_prepend (ast, new_rewrite_node ($3, &@3));

		DLIST_FOREACH (node, ast, link)
		  node->rwtarget = $1.target;

		$$ = cfg_gen_node ($1.defn, &$1.rcvr, NULL,
				   ast, &@1.beg, &@5.end);
		$$->rwtarget = $1.target;
	      }
	    | rewrite_begin error { skip_eol (); } nl
	      {
		yyclearin;
		yyerrok;
		cfg_err++;
		$$ = NULL;
	      }
	    ;

rewrite_begin : T_REWRITE opt_lit
	      {
		CFG_DEFN *defn;
		int target;
		char const *id;
		if ($2)
		  {
		    id = string_ptr ($2);
		    if (c_strcasecmp (id, "response") == 0)
		      target = REWRITE_RESPONSE;
		    else if (c_strcasecmp (id, "request") == 0)
		      target = REWRITE_REQUEST;
		    else
		      {
			conf_error_at_locus_range (&@2,
						   "expected response or request");
			YYERROR;
		      }
		  }
		else
		  {
		    id = "request";
		    target = REWRITE_REQUEST;
		  }

		defn = find_rewrite_defn ($1.defn->ref, id);
		cfg_defn_push (defn);

		$$.defn = $1.defn;
		$$.rcvr = $1.rcvr;
		$$.target = target;
	      }
	    ;

rwelse      : /* empty */
	      {
		$$ = NULL;
	      }
	    | T_ELSE T_NL opt_stmtlist rwelse
	      {
		$$ = $4 ? $4 : cfg_ast_alloc ();
		cfg_ast_prepend ($$, new_rewrite_node ($3, &@3));
	      }
	    ;

/*
 * Negation
 */
negation    : not_kw stmt
	      {
		CFG_AST *ast;
		cfg_defn_pop ();
		ast = cfg_ast_alloc ();
		cfg_ast_append (ast, $2);
		$$ = cfg_gen_node ($1.defn, &$1.rcvr, NULL, ast,
				   &@1.beg, &@2.end);
	      }
	    ;

not_kw      : T_NOT
	      {
		cfg_defn_push ($1.defn->ref);
	      }
	    ;

/*
 * comheaders
 */
comheaders  : T_COMHEADERS T_NL opt_stringlist T_END T_NL
	      {
		$$ = cfg_gen_node ($1.defn, &$1.rcvr, &$3, NULL,
				   &@1.beg, &@4.end);
	      }
	    ;

/*
 * ACL definitions.
 */
acldef      : acl_kw tag T_NL opt_stringlist endsec T_NL
	      {
		$$ = cfg_gen_node ($1.defn, &$1.rcvr, &$4, NULL,
				   &@1.beg, &@4.end);
		if ($$)
		  {
		    $$->acl.type = ACLT_IMM;
		    $$->acl.tag = string_ref ($2);
		  }
	      }
	    | acl_kw tag fileflags nl
	      {
		$$ = cfg_gen_node ($1.defn, &$1.rcvr, &$3, NULL,
				   &@1.beg, &@3.end);
		if ($$)
		  {
		    $$->acl.type = ACLT_REF;
		    $$->acl.tag = string_ref ($2);
		  }
	      }
	    | acl_kw error { skip_eol (); } nl
	      {
		yyclearin;
		yyerrok;
		cfg_err++;
		$$ = NULL;
	      }
	    ;

acl_kw      : T_ACL
	      {
		cfg_defn_push ($1.defn);
	      }
	    ;

trustedip   : trustedip_kw fileflags nl
	      {
		$$ = cfg_gen_node ($1.defn, &$1.rcvr, &$2, NULL,
				   &@1.beg, &@2.end);
		if ($$)
		  $$->acl.type = ACLT_REF;
	      }
	    | trustedip_kw singlestring nl
	      {
		$$ = cfg_gen_node ($1.defn, &$1.rcvr, &$2, NULL,
				   &@1.beg, &@2.end);
		if ($$)
		  $$->acl.type = ACLT_REF;
	      }
	    | trustedip_kw T_NL opt_stringlist endsec T_NL
	      {
		$$ = cfg_gen_node ($1.defn, &$1.rcvr, &$3, NULL,
				   &@1.beg, &@4.end);
		if ($$)
		  $$->acl.type = ACLT_IMM;
	      }
	    | trustedip_kw error { skip_eol (); } nl
	      {
		yyclearin;
		yyerrok;
		cfg_err++;
		$$ = NULL;
	      }
	    ;

trustedip_kw: T_TRUSTEDIP
	      {
		cfg_defn_push ($1.defn);
	      }
	    ;

/*
 * ACL condition takes three forms:
 *
 * 1. ACL [-forwarded] "\n" ... End
 *   Creates and references an unnamed ACL.
 * 2. ACL [-forwarded] "name"
 *   References a named ACL.
 * 3. ACL [-forwarded] -file "name" [-forwarded]
 *    ACL [-forwarded] -filewatch "name" [-forwarded]
 *   Reads ACL from file.
 *
 * The forms 2 and 3 would be syntactically indistinguishable for a LALR(1)
 * parser, should each of the above flags be represented by T_FLAG token.
 * Therefore, a special token T_FILEFLAG is introduced for -file and
 * -filewatch. A list of flags containing at least one such token will produce
 * the "fileflags" non-terminal, whereas lists containing none of such will
 * produce "flags". This helps discern the two forms.
 */
aclcond     : acl_kw opt_flags T_NL opt_stringlist endsec T_NL
	      {
		DLIST_CONCAT (&$2, &$4, link);
		$$ = cfg_gen_node ($1.defn, &$1.rcvr, &$2, NULL,
				   &@1.beg, &@5.end);
		if ($$)
		  $$->acl.type = ACLT_IMM;
	      }
	    | acl_kw opt_flags tag nl
	      {
		CFG_ARG *arg = cfg_arg_alloc (T_STRING, &@3);
		arg->v.string = $3;
		cfg_arglist_append (&$2, arg);
		$$ = cfg_gen_node ($1.defn, &$1.rcvr, &$2, NULL,
				   &@1.beg, &@3.end);
		if ($$)
		  $$->acl.type = ACLT_REF;
	      }
	    | acl_kw fileflags nl
	      {
		$$ = cfg_gen_node ($1.defn, &$1.rcvr, &$2, NULL,
				   &@1.beg, &@2.end);
		if ($$)
		  $$->acl.type = ACLT_REF;
	      }
	    ;

/* Other rules */
tag         : T_STRING
	    ;

opt_flags   : /* empty */
	      {
		DLIST_INIT (&$$);
	      }
	    | flags
	    ;

flags       : flag
	    | flags flag
	      {
		DLIST_CONCAT (&$1, &$2, link);
		$$ = $1;
	      }
	    ;

flag        : T_FLAG
	      {
		DLIST_INIT (&$$);
		if ($1)
		  {
		    CFG_ARG *arg = cfg_arg_alloc (T_FLAG, &@1);
		    arg->v.flag = $1;
		    DLIST_INSERT_TAIL (&$$, arg, link);
		  }
	      }
	    | T_FLAGARG arg
	      {
		CFG_ARG *arg = cfg_arg_alloc (T_FLAG, &@1);
		arg->v.flag = $1;
		DLIST_INIT (&$$);
		DLIST_INSERT_TAIL (&$$, arg, link);
		DLIST_INSERT_TAIL (&$$, $2, link);
	      }
	    ;

fileflags   : fileflag
	    | flags fileflag
	      {
		DLIST_CONCAT (&$1, &$2, link);
		$$ = $1;
	      }
	    | fileflags flags
	      {
		DLIST_CONCAT (&$1, &$2, link);
		$$ = $1;
	      }
	    ;

fileflag    : T_FILEFLAG arg
	      {
		CFG_ARG *arg = cfg_arg_alloc (T_FLAG, &@1);
		arg->v.flag = $1;
		DLIST_INIT (&$$);
		DLIST_INSERT_TAIL (&$$, arg, link);
		DLIST_INSERT_TAIL (&$$, $2, link);
	      }
	    ;

opt_lit     : /* empty */
	      {
		$$ = NULL;
	      }
	    | T_LITERAL
	    ;

opt_stringlist: /* empty */
	      {
		DLIST_INIT (&$$);
	      }
	    | stringlist
	    ;

stringlist  : string
	      {
		DLIST_INIT (&$$);
		if ($1)
		  DLIST_INSERT_TAIL (&$$, $1, link);
	      }
	    | stringlist string
	      {
		if ($2)
		  DLIST_INSERT_TAIL (&$1, $2, link);
		$$ = $1;
	      }
	    ;

string      : T_NL
	      {
		$$ = NULL;
	      }
	    | T_STRING T_NL
	      {
		$$ = cfg_arg_alloc (T_STRING, &@1);
		$$->v.string = $1;
	      }
	    | T_LITERAL T_NL
	      {
		/* NOTE: This differs from 4.22 and earlier: literals are
		   allowed here.
		 */
		$$ = cfg_arg_alloc (T_STRING, &@1);
		$$->v.string = $1;
	      }
	    | include
	      {
		$$ = NULL;
	      }
	    ;

singlestring: T_STRING
	      {
		CFG_ARG *arg = cfg_arg_alloc (T_STRING, &@1);
		arg->v.string = $1;
		cfg_arglist_init (&$$);
		cfg_arglist_append (&$$, arg);
	      }
	    ;

opt_arglist : /* empty */
	      {
		DLIST_INIT (&$$);
	      }
	    | arglist
	    ;

arglist     : arg
	      {
		cfg_arglist_init (&$$);
		cfg_arglist_append (&$$, $1);
	      }
	    | flag
	    | fileflag
	    | arglist arg
	      {
		cfg_arglist_append (&$1, $2);
		$$ = $1;
	      }
	    | arglist flag
	      {
		cfg_arglist_concat (&$1, &$2);
		$$ = $1;
	      }
	    | arglist fileflag
	      {
		cfg_arglist_concat (&$1, &$2);
		$$ = $1;
	      }
	    ;

arg         : T_STRING
	      {
		$$ = cfg_arg_alloc (T_STRING, &@1);
		$$->v.string = $1;
	      }
	    | T_LITERAL
	      {
		$$ = cfg_arg_alloc (T_LITERAL, &@1);
		$$->v.string = $1;
	      }
	    | T_NUMBER
	      {
		$$ = cfg_arg_alloc (T_NUMBER, &@1);
		$$->v.number = $1;
	      }
	    | T_BOOLEAN
	      {
		$$ = cfg_arg_alloc (T_BOOLEAN, &@1);
		$$->v.boolean = $1;
	      }
	    ;
%%
void
yyerror (char const *msg)
{
  conf_error_at_locus_range (&yylloc, "%s", msg);
  cfg_err++;
}

static const char *
symname (yysymbol_kind_t sym)
{
  switch (sym)
    {
    case YYSYMBOL_T_FLAG:
    case YYSYMBOL_T_FLAGARG:
    case YYSYMBOL_T_FILEFLAG:
      return "flag";

    default:
      return yysymbol_name (sym);
    }
}

extern int in_stmt;

static int
yyreport_syntax_error (const yypcontext_t *ctx)
{
  yysymbol_kind_t lookahead = yypcontext_token (ctx);

  cfg_err++;

  if (lookahead == YYSYMBOL_T_BOGUS)
    /* An error message must have already been issued. */
    return 0;

  if (progname)
    fprintf (stderr, "%s: ", progname);
  locus_range_print (stderr, yypcontext_location (ctx));
  fputs (": ", stderr);

  if (lookahead == YYSYMBOL_YYEOF)
    fprintf (stderr, "unexpected end of file");
  else if (!in_stmt)
    {
      if (lookahead == YYSYMBOL_T_LITERAL)
	fprintf (stderr, "unrecognized keyword");
      else
	fprintf (stderr, "expected directive or section keyword, but found %s",
		 symname (lookahead));
    }
  else
    {
      enum { MAXTOKEN = 4 };
      yysymbol_kind_t exp[MAXTOKEN];
      int i, n = yypcontext_expected_tokens (ctx, exp, MAXTOKEN);
      if (n < 0)
	return n;
      else if (n)
	{
	  for (i = 0; i < n; i++)
	    fprintf (stderr, "%s %s",
		     i == 0 ? ": expected" : " or",
		     symname (exp[i]));
	  fprintf (stderr, ", but found %s",  symname (lookahead));
	}
      else
	fprintf (stderr, "unexpected %s", symname (lookahead));
    }
  fprintf (stderr, "\n");
  return 0;
}

CFG_ARG *
cfg_arg_alloc (int type, struct locus_range *locus)
{
  CFG_ARG *arg;

  XZALLOC (arg);
  arg->type = type;
  locus_range_init (&arg->locus);
  locus_range_copy (&arg->locus, locus);
  return arg;
}

void
cfg_arg_free (CFG_ARG *arg)
{
  if (!arg)
    return;
  switch (arg->type)
    {
    case T_STRING:
    case T_LITERAL:
      string_unref (arg->v.string);
      break;

    default:
      break;
    }
  locus_range_unref (&arg->locus);
  free (arg);
}

void
cfg_arglist_free (CFG_ARG_HEAD *list)
{
  CFG_ARG *arg;
  while ((arg = cfg_arglist_shift (list)) != NULL)
    cfg_arg_free (arg);
}

CFG_NODE *
cfg_node_alloc (CFG_DEFN const *defn, CFG_RCVR const *rcvr,
		struct locus_point *beg,
		struct locus_point *end)
{
  CFG_NODE *node;
  XZALLOC (node);
  node->defn = defn;
  node->rcvr = *rcvr;
  locus_range_init (&node->locus);
  locus_point_copy (&node->locus.beg, beg);
  locus_point_copy (&node->locus.end, end);
  return node;
}

void
cfg_node_free (CFG_NODE *node)
{
  if (node)
    {
      if (node->defn->token == T_ACL)
	string_unref (node->acl.tag);
      cfg_arglist_free (&node->arglist);
      cfg_ast_free (node->subtree);
      if (node->data)
	{
	  if (node->defn->vtype->free_data)
	    node->defn->vtype->free_data (node->data);
	  else
	    free (node->data);
	}
      locus_range_unref (&node->locus);
      free (node);
    }
}

CFG_AST *
cfg_ast_alloc (void)
{
  CFG_AST *ast;
  XZALLOC (ast);
  DLIST_INIT (ast);
  return ast;
}

void
cfg_ast_free (CFG_AST *ast)
{
  CFG_NODE *node;
  if (!ast)
    return;
  while ((node = DLIST_FIRST (ast)) != NULL)
    {
      DLIST_REMOVE_HEAD (ast, link);
      cfg_node_free (node);
    }
  free (ast);
}

CFG_AST *
cfg_parse_tree (char const *filename, char const *dir, CFG_DEFN *parsetab)
{
  int rc;
  if (cfg_lex_init (filename, dir))
    return NULL;
  cfg_defn_push (parsetab);
  yydebug = !!(cfg_debug & CFG_DEBUG_GRAM);
  cfg_err = 0;
  cfg_result = NULL;
  rc = yyparse () || cfg_err;
  cfg_defn_pop ();
  cfg_lex_done ();
  if (rc)
    {
      cfg_ast_free (cfg_result);
      cfg_result = NULL;
    }
  return cfg_result;
}
