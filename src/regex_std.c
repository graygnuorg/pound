/*
 * Pound - the reverse-proxy load-balancer
 * Copyright (C) 2023-2024 Sergey Poznyakoff
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
#include <regex.h>

struct pound_regex
{
  regex_t re;
  char *errmsg;
};

int
regex_compile (POUND_REGEX *retval, const char *pattern, int pflags)
{
  struct pound_regex *pre;
  int flags = REG_EXTENDED;
  int rc;

  if (pflags & POUND_REGEX_ICASE)
    flags |= REG_ICASE;
  if (pflags & POUND_REGEX_MULTILINE)
    flags |= REG_NEWLINE;
  
  XZALLOC (pre);
  *retval = pre;
  if ((rc = regcomp (&pre->re, pattern, flags)) != 0)
    {
      char errbuf[128];
      regerror (rc, &pre->re, errbuf, sizeof (errbuf));
      pre->errmsg = xstrdup (errbuf);
    }
  return rc;
}

char const *
regex_error (POUND_REGEX pre, size_t *off)
{
  *off = 0;
  return pre->errmsg;
}

int
regex_exec (POUND_REGEX pre, const char *subj, size_t n, POUND_REGMATCH *prm)
{
  int rc;
  regmatch_t *rm = NULL;

  if (n > 0)
    {
      rm = calloc (n, sizeof (rm[0]));
      if (rm == NULL)
	return -1;
      if (n > pre->re.re_nsub + 1)
	n = pre->re.re_nsub + 1;
    }

  if ((rc = regexec (&pre->re, subj, n, rm, 0)) == 0)
    {
      size_t i;
      for (i = 0; i < n; i++)
	{
	  prm[i].rm_so = rm[i].rm_so;
	  prm[i].rm_eo = rm[i].rm_eo;
	}
    }
  free (rm);
  return rc == REG_NOMATCH;
}

size_t
regex_num_submatch (POUND_REGEX pre)
{
  return pre->re.re_nsub + 1;
}

void
regex_free (POUND_REGEX pre)
{
  if (pre)
    {
      regfree (&pre->re);
      free (pre->errmsg);
      free (pre);
    }
}
