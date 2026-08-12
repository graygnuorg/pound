/*
 * Beacon (settable condition) support for pound.
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
#include "pound.h"

struct beacon
{
  char *name;
  int enabled;
  pthread_mutex_t mut;
  struct locus_range locus;
};

#define HT_TYPE POUND_BEACON
#define HT_NO_FOREACH_SAFE 1
#include "ht.h"

static POUND_BEACON_HASH *beacon_hash;

POUND_BEACON *
pound_beacon_locate (char const *name)
{
  POUND_BEACON *bp = NULL;
  if (beacon_hash)
    {
      POUND_BEACON key = { (char *) name };
      bp = POUND_BEACON_RETRIEVE (beacon_hash, &key);
    }
  return bp;
}

int
pound_beacon_declare (char const *name, int enabled,
		      struct locus_range const *locus,
		      struct locus_range *ret)
{
  POUND_BEACON *bp, *old;

  if (!beacon_hash)
    beacon_hash = POUND_BEACON_HASH_NEW ();
  bp = xmalloc (sizeof (*bp) + strlen (name) + 1);
  bp->name = (char*) (bp + 1);
  strcpy (bp->name, name);
  bp->enabled = enabled;
  pthread_mutex_init (&bp->mut, NULL);
  locus_range_init (&bp->locus);
  locus_range_copy (&bp->locus, locus);
  if ((old = POUND_BEACON_INSERT (beacon_hash, bp)) != NULL)
    {
      locus_range_unref (&bp->locus);
      pthread_mutex_destroy (&bp->mut);
      free (bp);
      locus_range_init (ret);
      locus_range_copy (ret, &old->locus);
      return -1;
    }
  return 0;
}

int
pound_beacon_get (POUND_BEACON *bp)
{
  int val;
  if (!bp)
    return -1;
  pthread_mutex_lock (&bp->mut);
  val = bp->enabled;
  pthread_mutex_unlock (&bp->mut);
  return val;
}

int
pound_beacon_set (char const *name, int val)
{
  POUND_BEACON *bp = pound_beacon_locate (name);

  if (!bp)
    return -1;
  pthread_mutex_lock (&bp->mut);
  bp->enabled = val;
  pthread_mutex_unlock (&bp->mut);
  return 0;
}

struct beacon_serializer_info
{
  struct json_value *obj;
  int err;
};

static void
beacon_serializer (POUND_BEACON *bp, void *data)
{
  struct beacon_serializer_info *info = data;
  if (info->err)
    return;
  pthread_mutex_lock (&bp->mut);
  info->err = json_object_set (info->obj, bp->name,
			       json_new_bool (bp->enabled));
  pthread_mutex_unlock (&bp->mut);
}

int
pound_beacon_serialize (struct json_value *obj, char const *name)
{
  int rc = 0;
  struct json_value *val = json_new_object ();
  if (!val)
    return HTTP_STATUS_INTERNAL_SERVER_ERROR;
  if (name)
    {
      POUND_BEACON *bp = pound_beacon_locate (name);
      if (bp)
	{
	  struct beacon_serializer_info info = { val, 0 };
	  beacon_serializer (bp, &info);
	  if (info.err)
	    rc = HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
      else
	rc = HTTP_STATUS_NOT_FOUND;
    }
  else
    {
      if (beacon_hash)
	{
	  struct beacon_serializer_info info = { val, 0 };
	  POUND_BEACON_FOREACH (beacon_hash, beacon_serializer, &info);
	  if (info.err)
	    rc = HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
    }

  if (rc)
    json_value_free (val);
  else
    rc = json_object_set (obj, "beacons", val);

  return rc;
}
