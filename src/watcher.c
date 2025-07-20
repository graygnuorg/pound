/*
 * Pound - the reverse-proxy load-balancer
 * Copyright (C) 2025 Sergey Poznyakoff
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
#include "extern.h"
#include "watcher.h"

unsigned watcher_ttl = 180;

static void watcher_stat (struct watcher *watcher);
static void watcher_read_unlocked (struct watcher *watcher);

void
watcher_log (int pri, struct watcher *watcher, char const *fmt, ...)
{
  va_list ap;
  struct stringbuf sb;
  struct locus_point pt;

  xstringbuf_init (&sb);
  stringbuf_format_locus_range (&sb, &watcher->locus);
  stringbuf_add_string (&sb, ": ");

  locus_point_init (&pt, watcher->filename,
		    watcher->wd ? watcher->wd->name : NULL);
  stringbuf_add_string (&sb, string_ptr (pt.filename));
  locus_point_unref (&pt);
  stringbuf_add_string (&sb, ": ");

  va_start (ap, fmt);
  stringbuf_vprintf (&sb, fmt, ap);
  va_end (ap);
  logmsg (pri, "%s", stringbuf_value (&sb));
  stringbuf_free (&sb);
}

static void
job_watcher_check (enum job_ctl ctl, void *arg, const struct timespec *ts)
{
  struct watcher *watcher = arg;
  if (ctl == job_ctl_run)
    {
      time_t mtime;

      pthread_rwlock_wrlock (&watcher->rwl);
      mtime = watcher->mtime;
      watcher_stat (watcher);
      if (watcher->mtime > mtime)
	{
	  if (mtime == 0)
	    watcher_log (LOG_INFO, watcher, "file restored");
	  watcher_read_unlocked (watcher);
	}
      else if (watcher->mtime == 0)
	{
	  if (mtime)
	    {
	      watcher_log (LOG_INFO, watcher, "file removed");
	      watcher->clear (watcher->obj);
	    }
	}
      pthread_rwlock_unlock (&watcher->rwl);
      job_enqueue_after (watcher_ttl, job_watcher_check, watcher);
    }
}

WATCHPOINT_HEAD watch_head;

void
watchpoint_free (struct watchpoint *wp)
{
  free (wp);
}

void
watchpoint_set_compat_mode (struct watchpoint *wp)
{
  // FIXME: Remove existing watcher
  wp->watcher->mode = WATCHER_COMPAT;
  wp->watcher->mtime = 0;
  watcher_stat (wp->watcher);
  job_enqueue_after (watcher_ttl, job_watcher_check, wp->watcher);
}

static void
watcher_stat (struct watcher *watcher)
{
  struct stat st;
  watcher->mtime = 0;
  if (fstatat (watcher->wd->fd, watcher->filename, &st, 0))
    {
      if (errno != ENOENT)
	watcher_log (LOG_ERR, watcher, "can't stat: %s", strerror (errno));
    }
  else
    watcher->mtime = st.st_mtime;
}

static inline void
watcher_open_error (struct watcher *watcher, int ec)
{
  watcher_log (LOG_ERR, watcher, "can't open file: %s", strerror (ec));
}

static void
watcher_read_unlocked (struct watcher *watcher)
{
  watcher_log (LOG_INFO, watcher, "re-reading");
  watcher->clear (watcher->obj);
  if (watcher->read (watcher->obj, watcher->filename, watcher->wd) == -1)
    watcher_open_error (watcher, errno);
}

void
watcher_reread (struct watcher *watcher)
{
  pthread_rwlock_wrlock (&watcher->rwl);
  watcher_read_unlocked (watcher);
  pthread_rwlock_unlock (&watcher->rwl);
}

char const *
filename_split_str (char const *filename, char **dir)
{
  char *p = strrchr (filename, '/');
  if (dir)
    {
      if (p)
	*dir = xstrndup (filename, p - filename);
      else
	*dir = NULL;
    }
  return p ? p + 1 : filename;
}

char const *
filename_split_wd (char const *filename, WORKDIR **wdp)
{
  char const *name;
  WORKDIR *wd;

  if (filename[0] == '/')
    {
      char *dir;
      name = filename_split_str (filename, &dir);
      if ((wd = workdir_get (dir)) == NULL)
	{
	  logmsg (LOG_ERR, "can't open directory %s: %s",
		  dir, strerror (errno));
	  free (dir);
	  return NULL;
	}
      free (dir);
    }
  else
    {
      if ((wd = get_include_wd ()) == NULL)
	return NULL;
      workdir_ref (wd);
      name = filename;
    }
  *wdp = wd;
  return name;
}

void
watcher_lock (struct watcher *dp)
{
  if (dp)
    pthread_rwlock_rdlock (&dp->rwl);
}

void
watcher_unlock (struct watcher *dp)
{
  if (dp)
    pthread_rwlock_unlock (&dp->rwl);
}

struct watcher *
watcher_register (void *obj, char const *filename,
		  struct locus_range const *loc,
		  int (*read) (void *, char *, WORKDIR *),
		  void (*clear) (void *))
{
  struct watchpoint *wp;
  char const *basename;
  int rc;
  enum watcher_mode mode;

  XZALLOC (wp);
  wp->wd = -1;
  wp->type = WATCH_FILE;
  XZALLOC (wp->watcher);
  wp->watcher->obj = obj;
  wp->watcher->read = read;
  wp->watcher->clear = clear;

  basename = filename_split_wd (filename, &wp->watcher->wd);
  if (!basename)
    {
      conf_error_at_locus_range (loc, "can't register watcher");
      free (wp);
      return NULL;
    }
  wp->watcher->filename = xstrdup (basename);
  locus_range_init (&wp->watcher->locus);
  locus_range_copy (&wp->watcher->locus, loc);
  pthread_rwlock_init (&wp->watcher->rwl, NULL);

  rc = wp->watcher->read (wp->watcher->obj, wp->watcher->filename,
			 wp->watcher->wd);
  if (rc == -1)
    {
      if (errno == ENOENT)
	{
	  watcher_log (LOG_WARNING, wp->watcher, "file does not exist");
	  mode = WATCHER_NOFILE;
	}
      else
	{
	  watcher_open_error (wp->watcher, errno);
	  watchpoint_free (wp);
	  return NULL;
	}
    }
  else
    mode = WATCHER_EXISTS;

  watchpoint_set_mode (wp, mode);

  DLIST_PUSH (&watch_head, wp, link);

  return wp->watcher;
}
