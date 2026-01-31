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

static int
sink_write_ex (BIO *b, const char *buf, size_t size, size_t *in_size)
{
  *in_size = size;
  return 1;
}

static int
sink_puts (BIO *b, const char *str)
{
  return strlen (str);
}

static long
sink_ctrl (BIO *b, int cmd, long lval, void *pval)
{
  long ret;

  switch (cmd)
    {
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
      ret = 1;
      break;

    default:
      ret = 0;
    }
  return ret;
}
      
const BIO_METHOD *
BIO_f_sink (void)
{
  static BIO_METHOD *sink;

  if (!sink)
    {
      int n = BIO_get_new_index ();
      if (n == -1)
	return NULL;

      sink = BIO_meth_new (n | BIO_TYPE_FILTER, "sink");
      if (sink == NULL)
	return NULL;

      BIO_meth_set_write_ex (sink, sink_write_ex);
      BIO_meth_set_puts (sink, sink_puts);
      BIO_meth_set_ctrl (sink, sink_ctrl);
    }
  return sink;
}

BIO *
bio_new_sink (void)
{
  return BIO_new (BIO_f_sink ());
}


