#include "pound.h"
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

struct pound_regex
{
  pcre2_code *code;
  size_t nsub;
  char *errmsg;
  size_t erroff;
};

int
regex_compile (POUND_REGEX *retval, const char *pattern, int pflags)
{
  struct pound_regex *pre;
  int flags = 0;
  int error_code;

  if (pflags & POUND_REGEX_ICASE)
    flags |= PCRE2_CASELESS;
  if (pflags & POUND_REGEX_MULTILINE)
    flags |= PCRE2_MULTILINE;

  XZALLOC (pre);
  *retval = pre;
  pre->code = pcre2_compile ((PCRE2_SPTR8) pattern, strlen (pattern), flags,
			     &error_code, &pre->erroff, NULL);
  if (pre->code == NULL)
    {
      size_t errsize = 32;
      int rc;

      pre->errmsg = malloc (errsize);
      if (!pre->errmsg)
	return -1;

      while ((rc = pcre2_get_error_message (error_code, (PCRE2_UCHAR*) pre->errmsg, errsize)) ==
	     PCRE2_ERROR_NOMEMORY)
	{
	  char *p = mem2nrealloc (pre->errmsg, &errsize, 1);
	  if (!p)
	    break;
	  pre->errmsg = p;
	}

      return -1;
    }
  else
    {
      uint32_t nsub;
      if (pcre2_pattern_info (pre->code, PCRE2_INFO_CAPTURECOUNT, &nsub))
	nsub = 0;
      else
	nsub++;
      pre->nsub = nsub;
    }

  return 0;
}

void
regex_free (POUND_REGEX pre)
{
  if (pre)
    {
      pcre2_code_free (pre->code);
      free (pre->errmsg);
      free (pre);
    }
}

char const *
regex_error (POUND_REGEX pre, size_t *off)
{
  *off = pre->erroff;
  return pre->errmsg;
}

size_t
regex_num_submatch (POUND_REGEX pre)
{
  return pre->nsub;
}

int
regex_exec (POUND_REGEX pre, const char *subj, size_t n, POUND_REGMATCH *prm)
{
  int rc;
  PCRE2_SIZE *ovector;
  size_t i, j;
  pcre2_match_data *md;

  md = pcre2_match_data_create_from_pattern (pre->code, NULL);
  if (!md)
    return -1;

  rc = pcre2_match (pre->code, (PCRE2_SPTR8)subj, strlen (subj), 0, 0, md, NULL);
  if (rc < 0)
    {
      pcre2_match_data_free (md);
      return rc;
    }

  if (n > rc)
    n = rc;

  ovector = pcre2_get_ovector_pointer (md);
  for (i = j = 0; i < n; i++, j += 2)
    {
      prm[i].rm_so = ovector[j];
      prm[i].rm_eo = ovector[j+1];
    }

  pcre2_match_data_free (md);
  return 0;
}
