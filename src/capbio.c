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
#include <config.h>
#include <string.h>
#include <assert.h>
#include "capbio.h"

struct capture_bio_st
{
  BIO *mem;
  size_t cap;
  size_t len;
  int trnc;
};

static int
cap_new (BIO *b)
{
  struct capture_bio_st *cp = malloc (sizeof (*cp));
  if (!cp)
    return 0;
  cp->mem = BIO_new (BIO_s_mem ());
  cp->cap = -1;
  cp->len = 0;
  cp->trnc = 0;
  BIO_set_data (b, cp);
  BIO_set_init (b, 1);
  return 1;
}

static int
cap_free (BIO *b)
{
  struct capture_bio_st *cp;
  
  if (b == NULL)
    return 0;

  cp = BIO_get_data (b);
  if (cp)
    {
      BIO_free (cp->mem);
      free (cp);
    }
  
  BIO_set_data (b, NULL);
  BIO_set_init (b, 0);
  return 1;
}

static int
cap_write_ex (BIO *b, const char *buf, size_t size, size_t *in_size)
{
  struct capture_bio_st *cp = BIO_get_data (b);
  BIO *next = BIO_next (b);
  size_t n, i;

  if (!BIO_write_ex (next, buf, size, &n))
    return 0;

  *in_size = n;

  for (i = 0; i < n; )
    {
      size_t s = n - i, m;
      if (cp->cap != (size_t)-1 && s > (m = cp->cap - cp->len))
	s = m;
      if (s == 0)
	{
	  cp->trnc = 1;
	  break;
	}
      if (!BIO_write_ex (cp->mem, buf + i, s, &m))
	{
	  cp->cap = cp->len;
	  break;
	}
      i += m;
      cp->len += m;
    }

  return 1;
}

static int
cap_puts (BIO *b, const char *str)
{
  size_t m;

  if (!BIO_write_ex (b, str, strlen (str), &m))
    return 0;
  return m;
}

static long
cap_ctrl (BIO *b, int cmd, long lval, void *pval)
{
  struct capture_bio_st *cp = BIO_get_data (b);

  switch (cmd)
    {
    case BIO_CTLR_CAPTURE_SET_CAP:
      cp->cap = lval;
      break;

    case BIO_CTLR_CAPTURE_GET_CAP:
      *(size_t*) pval = cp->cap;
      break;

    case BIO_CTLR_CAPTURE_GET_LEN:
      *(size_t*) pval = cp->len;
      break;

    case BIO_CTLR_CAPTURE_GET_PTR:
      return BIO_get_mem_data (cp->mem, pval);

    case BIO_CTLR_CAPTURE_GET_TRNC:
      return cp->trnc;

    default:
      return BIO_ctrl (BIO_next(b), cmd, lval, pval);
    }
  return 1;
}

const BIO_METHOD *
BIO_f_capture (void)
{
  static BIO_METHOD *cap;

  if (!cap)
    {
      int n = BIO_get_new_index ();
      assert(n != -1);
      
      cap = BIO_meth_new (n | BIO_TYPE_FILTER, "capture");
      assert(cap != NULL);

      BIO_meth_set_write_ex (cap, cap_write_ex);
      BIO_meth_set_puts (cap, cap_puts);
      BIO_meth_set_create (cap, cap_new);
      BIO_meth_set_destroy (cap, cap_free);
      BIO_meth_set_ctrl (cap, cap_ctrl);
    }
  return cap;
}

BIO *
bio_new_capture (size_t cap)
{
  BIO *b = BIO_new (BIO_f_capture ());
  BIO_ctrl (b, BIO_CTLR_CAPTURE_SET_CAP, cap, NULL);
  return b;
}
