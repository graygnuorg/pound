#include <stdarg.h>
#include <stddef.h>

/* Locations in the source file */
struct locus_point
{
  char const *filename;
  int line;
  int col;
};

struct locus_range
{
  struct locus_point beg, end;
};

struct locus_range *last_token_locus_range (void);

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
WORKDIR *get_include_wd_at_locus_range (struct locus_range *locus);
static inline WORKDIR *get_include_wd (void)
{
  return get_include_wd_at_locus_range (last_token_locus_range ());
}

/* Token types: */
enum
  {
    T__BASE = 256,
    T_IDENT = T__BASE, /* Identifier */
    T_NUMBER,          /* Decimal number */
    T_STRING,          /* Quoted string */
    T_LITERAL,         /* Unquoted literal */
    T__END,
    T_ERROR = T__END,  /* Erroneous or malformed token */
  };

typedef unsigned TOKENMASK;

#define T_BIT(t) ((TOKENMASK)1<<((t)-T__BASE))
#define T_MASK_ISSET(m,t) ((m) & T_BIT(t))
#define T_ANY 0 /* any token, including newline */
/* Unquoted character sequence */
#define T_UNQ (T_BIT (T_IDENT) | T_BIT (T_NUMBER) | T_BIT (T_LITERAL))

/*
 * Buffer size for token buffer used as input to token_mask_str.  This takes
 * into account only T_.* types above, as returned by token_type_str.
 *
 * Be sure to update this constant if you change anything above.
 */
#define MAX_TOKEN_BUF_SIZE 45

/* Token structure */
struct token
{
  int type;
  char *str;
  struct locus_range locus;
};


/*
 * Token manipulation functions.
 */
char const *token_type_str (unsigned type);
size_t token_mask_str (TOKENMASK mask, char *buf, size_t size);

/*
 * Keyword table and lookups it in.
 */
struct kwtab
{
  char const *name;
  int tok;
};

int kw_to_tok (struct kwtab *kwt, char const *name, int ci, int *retval);
char const *kw_to_str (struct kwtab *kwt, int t);

/*
 * Locus formatting.
 */
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

#define conf_error(fmt, ...)						\
  conf_error_at_locus_range (last_token_locus_range (), fmt, __VA_ARGS__)

struct token *gettkn_expect_mask (int expect);
struct token *gettkn_expect (int type);
struct token *gettkn_any (void);
void putback_tkn (struct token *tok);

enum
  {
    CFGPARSER_OK,
    CFGPARSER_OK_NONL,
    CFGPARSER_FAIL,
    CFGPARSER_END
  };

typedef int (*CFGPARSER) (void *, void *);

enum keyword_type
  {
    KWT_REG,          /* Regular keyword */
    KWT_ALIAS,        /* Alias to another keyword */
    KWT_TABREF,       /* Reference to another table */
    KWT_SOFTREF,      /* Same as above, but overrides data/off pair of it. */
  };

typedef struct cfg_parser_table
{
  char *name;        /* The keyword. */
  CFGPARSER parser;  /* Parser function. */
  void *data;        /* Data pointer to pass to parser in its first
			parameter. */
  size_t off;        /* Offset data by this number of bytes before passing. */

  enum keyword_type type;  /* Entry type. */

  /* For KWT_TABREF & KWT_SOFTREF */
  struct cfg_parser_table *ref;

  /* For deprecated statements: */
  int deprecated;    /* Whether the statement is deprecated. */
  char *message;     /* Deprecation message. For KWT_ALIAS it can be NULL,
			in which case a default message will be generated. */
} CFGPARSER_TABLE;

enum deprecation_mode
  {
    DEPREC_OK,
    DEPREC_WARN,
    DEPREC_ERR
  };

int cfgparser (CFGPARSER_TABLE *ptab,
	       void *call_data, void *section_data,
	       int single_statement,
	       enum deprecation_mode handle_deprecated,
	       struct locus_range *retrange);

static inline int
cfgparser_loop (CFGPARSER_TABLE *ptab,
		void *call_data, void *section_data,
		enum deprecation_mode handle_deprecated,
		struct locus_range *retrange)
{
  return cfgparser (ptab, call_data, section_data, 0, handle_deprecated, retrange);
}

int cfg_parse_end (void *call_data, void *section_data);
int cfg_parse_include (void *call_data, void *section_data);
int cfg_parse_includedir (void *call_data, void *section_data);
int cfg_int_set_one (void *call_data, void *section_data);
int cfg_assign_string (void *call_data, void *section_data);
int cfg_assign_string_from_file (void *call_data, void *section_data);
int cfg_assign_bool (void *call_data, void *section_data);
int cfg_assign_unsigned (void *call_data, void *section_data);
int cfg_assign_int (void *call_data, void *section_data);
int cfg_assign_mode (void *call_data, void *section_data);

int cfg_assign_int_range (int *dst, int min, int max);
int cfg_assign_int_enum (int *dst, struct token *tok, struct kwtab *kwtab,
			 char *what);
int cfg_assign_log_facility (void *call_data, void *section_data);

#define cfg_assign_timeout cfg_assign_unsigned

int cfgparser_open (char const *filename, char const *wd);
int cfgparser_finish (int keepwd);
int cfgparser_parse (char const *filename, char const *wd,
		     CFGPARSER_TABLE *tab,
		     void *section_data,
		     enum deprecation_mode handle_deprecated, int keepwd);
struct cfginput;

int cfg_read_to_end (struct cfginput *input, char **ptr);

extern struct cfginput *cur_input;
extern void (*cfg_error_msg) (char const *msg);
extern char const *include_dir;
extern WORKDIR *include_wd;
