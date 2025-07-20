/* This file is part of Pound.
   Copyright (C) 2012-2025 Sergey Poznyakoff.
 
   Pound is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.
 
   Pound is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with Pound.  If not, see <http://www.gnu.org/licenses/>. */

#include <string.h>
#include "cctype.h"

char lctab[] = {
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,
	-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,  0,  0,  0,  0,  0
};

static inline int
lc (char c)
{
  if (c >= 0 && c < sizeof(lctab))
    c += lctab[(int)c];
  return c;
}

int
c_strncasecmp (char const *a, char const *b, size_t n)
{
  size_t i;

  for (i = 0; i < n; i++)
    {
      int c = lc (a[i]) - lc (b[i]);
      if (c || a[i] == 0 || b[i] == 0)
	return c;
    }
  return 0;
}

int
c_strcasecmp (char const *a, char const *b)
{
  while (*a)
    {
      if (*b == 0)
	return *(unsigned char*)a;
      else
	{
	  int c = lc (*a++) - lc (*b++);
	  if (c)
	    return c;
	}
    }
  return - *(unsigned char*)b;
}

int cc_tab[CC_TAB_MAX] = {
  /* 000 */ CCTYPE_CNTRL,
  /* 001 */ CCTYPE_CNTRL,
  /* 002 */ CCTYPE_CNTRL,
  /* 003 */ CCTYPE_CNTRL,
  /* 004 */ CCTYPE_CNTRL,
  /* 005 */ CCTYPE_CNTRL,
  /* 006 */ CCTYPE_CNTRL,
  /* 007 */ CCTYPE_CNTRL,
  /* 010 */ CCTYPE_CNTRL,
  /* \t  */ CCTYPE_CNTRL|CCTYPE_SPACE|CCTYPE_BLANK,
  /* \n  */ CCTYPE_CNTRL|CCTYPE_SPACE,
  /* \v  */ CCTYPE_CNTRL|CCTYPE_SPACE,
  /* \f  */ CCTYPE_CNTRL|CCTYPE_SPACE,
  /* \r  */ CCTYPE_CNTRL|CCTYPE_SPACE,
  /* 016 */ CCTYPE_CNTRL,
  /* 017 */ CCTYPE_CNTRL,
  /* 020 */ CCTYPE_CNTRL,
  /* 021 */ CCTYPE_CNTRL,
  /* 022 */ CCTYPE_CNTRL,
  /* 023 */ CCTYPE_CNTRL,
  /* 024 */ CCTYPE_CNTRL,
  /* 025 */ CCTYPE_CNTRL,
  /* 026 */ CCTYPE_CNTRL,
  /* 027 */ CCTYPE_CNTRL,
  /* 030 */ CCTYPE_CNTRL,
  /* 031 */ CCTYPE_CNTRL,
  /* 032 */ CCTYPE_CNTRL,
  /* 033 */ CCTYPE_CNTRL,
  /* 034 */ CCTYPE_CNTRL,
  /* 035 */ CCTYPE_CNTRL,
  /* 036 */ CCTYPE_CNTRL,
  /* 037 */ CCTYPE_CNTRL,
  /* ' ' */ CCTYPE_PRINT|CCTYPE_SPACE|CCTYPE_BLANK,
  /* !   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* "   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* #   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* $   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* %   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* &   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* '   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* (   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* )   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* *   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* +   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* ,   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT, 
  /* -   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* .   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* /   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* 0   */ CCTYPE_DIGIT|CCTYPE_GRAPH|CCTYPE_PRINT,
  /* 1   */ CCTYPE_DIGIT|CCTYPE_GRAPH|CCTYPE_PRINT,
  /* 2   */ CCTYPE_DIGIT|CCTYPE_GRAPH|CCTYPE_PRINT,
  /* 3   */ CCTYPE_DIGIT|CCTYPE_GRAPH|CCTYPE_PRINT,
  /* 4   */ CCTYPE_DIGIT|CCTYPE_GRAPH|CCTYPE_PRINT,
  /* 5   */ CCTYPE_DIGIT|CCTYPE_GRAPH|CCTYPE_PRINT,
  /* 6   */ CCTYPE_DIGIT|CCTYPE_GRAPH|CCTYPE_PRINT,
  /* 7   */ CCTYPE_DIGIT|CCTYPE_GRAPH|CCTYPE_PRINT,
  /* 8   */ CCTYPE_DIGIT|CCTYPE_GRAPH|CCTYPE_PRINT,
  /* 9   */ CCTYPE_DIGIT|CCTYPE_GRAPH|CCTYPE_PRINT,
  /* :   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* ;   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* <   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* =   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* >   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* ?   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* @   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* A   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER|CCTYPE_XLETR,
  /* B   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER|CCTYPE_XLETR,
  /* C   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER|CCTYPE_XLETR,
  /* D   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER|CCTYPE_XLETR,
  /* E   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER|CCTYPE_XLETR,
  /* F   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER|CCTYPE_XLETR,
  /* G   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* H   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* I   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* J   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* K   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* L   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* M   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* N   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* O   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* P   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* Q   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* R   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* S   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* T   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* U   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* V   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* W   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* X   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* Y   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* Z   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_UPPER,
  /* [   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* \   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* ]   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* ^   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* _   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* `   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* a   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT|CCTYPE_XLETR,
  /* b   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT|CCTYPE_XLETR,
  /* c   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT|CCTYPE_XLETR,
  /* d   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT|CCTYPE_XLETR,
  /* e   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT|CCTYPE_XLETR,
  /* f   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT|CCTYPE_XLETR,
  /* g   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* h   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* i   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* j   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* k   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* l   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* m   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* n   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* o   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* p   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* q   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* r   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* s   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* t   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* u   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* v   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* w   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* x   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* y   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* z   */ CCTYPE_ALPHA|CCTYPE_GRAPH|CCTYPE_LOWER|CCTYPE_PRINT,
  /* {   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* |   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* }   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* ~   */ CCTYPE_GRAPH|CCTYPE_PRINT|CCTYPE_PUNCT,
  /* 177 */ CCTYPE_CNTRL
};

size_t
c_memspn (char const *str, int class, size_t len)
{
  size_t i;
  for (i = 0; i < len && c_isascii (str[i]) &&
	 (cc_tab[(unsigned)str[i]] & class); i++)
    ;
  return i;
}

size_t
c_memrspn (char const *str, int class, size_t len)
{
  size_t i = len;
  while (i > 0 && c_isascii (str[--i]) &&
	 (cc_tab[(unsigned)str[i]] & class));
  return len-i;
}

size_t
c_memcspn (char const *str, int class, size_t len)
{
  size_t i;
  for (i = 0; i < len && c_isascii (str[i]) &&
	 !(cc_tab[(unsigned)str[i]] & class); i++)
    ;
  return i;
}

size_t
c_memrcspn (char const *str, int class, size_t len)
{
  size_t i = len;
  while (i > 0 && c_isascii (str[--i]) &&
	 !(cc_tab[(unsigned)str[i]] & class));
  return len-i;
}

size_t
c_trimrws (char const *str, size_t len)
{
  return (len == 0)
    ? 0
    : len - c_memrspn (str, CCTYPE_BLANK, len) + 1;
}

char *
c_trimlws (char const *str, size_t *plen)
{
  size_t n, k;
  if (!plen)
    {
      k = strlen (str);
      plen = &k;
    }
  n = c_memspn (str, CCTYPE_BLANK, *plen);
  *plen -= n;
  return (char*) str + n;
}

char *
c_trimws (char const *str, size_t *plen)
{
  size_t n;
  if (!plen)
    {
      n = strlen (str);
      plen = &n;
    }
  *plen = c_trimrws (str, *plen);
  return c_trimlws (str, plen);
}
