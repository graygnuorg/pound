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
#if HAVE_PCRE_H
# include <pcre.h>
#elif HAVE_PCRE_PCRE_H
# include <pcre/pcre.h>
#else
#  error "You have libpcre, but the header files are missing. Use --disable-pcre"
#endif

struct pound_regex
{
  pcre *pcre;
  size_t nsub;
  char const *errmsg;
  int erroff;
};

int
regex_compile (POUND_REGEX *retval, const char *pattern, int pflags)
{
  struct pound_regex *pre;
  int flags = 0;
  int nsub;

  if (pflags & POUND_REGEX_ICASE)
    flags |= PCRE_CASELESS;
  if (pflags & POUND_REGEX_MULTILINE)
    flags |= PCRE_MULTILINE;

  XZALLOC (pre);
  *retval = pre;
  pre->pcre = pcre_compile (pattern, flags, &pre->errmsg, &pre->erroff, 0);

  if (pre->pcre == NULL)
    return -1;

  if (pcre_fullinfo (pre->pcre, NULL, PCRE_INFO_CAPTURECOUNT, &nsub))
    nsub = 0;
  else
    nsub++;
  pre->nsub = nsub;

  return 0;
}

char const *
regex_error (POUND_REGEX pre, size_t *off)
{
  *off = pre->erroff;
  return pre->errmsg;
}

int
regex_exec (POUND_REGEX pre, const char *subj, size_t n, POUND_REGMATCH *prm)
{
  int rc;
  int ovsize;
  int *ovector;

  ovsize = pre->nsub * 3;
  ovector = calloc (ovsize, sizeof (ovector[0]));
  if (!ovector)
    return -1;

  rc = pcre_exec (pre->pcre, 0, subj, strlen (subj), 0, 0, ovector, ovsize);
  if (rc > 0)
    {
      size_t i, j;

      /* Collect captured substrings */
      if (n > rc)
	n = rc;

      for (i = j = 0; i < n; i++, j += 2)
	{
	  prm[i].rm_so = ovector[j];
	  prm[i].rm_eo = ovector[j+1];
	}
    }
  free (ovector);

  return rc < 0;
}

size_t
regex_num_submatch (POUND_REGEX pre)
{
  return pre->nsub;
}

void
regex_free (POUND_REGEX pre)
{
  if (pre)
    {
      pcre_free (pre->pcre);
      free (pre);
    }
}
