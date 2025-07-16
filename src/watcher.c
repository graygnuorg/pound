#include "pound.h"
#include "extern.h"

unsigned watcher_ttl = 180;

struct watchpoint;

enum watcher_mode
  {
    WATCHER_EXISTS,    /* File exists and is monitored. */
    WATCHER_NOFILE,    /* File does not exist, its directory is monitored. */
    WATCHER_COMPAT     /* Compatibility mode. */
  };

static void watchpoint_set_mode (struct watchpoint *wp, enum watcher_mode);

struct watcher
{
  enum watcher_mode mode;
  void *obj;
  int (*read) (void *, char *, WORKDIR *);
  void (*clear) (void *);
  WORKDIR *wd;                /* Working directory. */
  char *filename;             /* Filename relative to wd. */
  struct locus_range locus;
  pthread_rwlock_t rwl;       /* Locker. */
  time_t mtime;               /* File mtime.  Used if inotify is
				 not available. */
};

static void watcher_stat (struct watcher *watcher);
static void watcher_read (struct watcher *watcher);

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
	    conf_error_at_locus_range (&watcher->locus, "%s restored",
				       watcher->filename);
	  watcher_read (watcher);
	}
      else if (watcher->mtime == 0)
	{
	  if (mtime)
	    {
	      conf_error_at_locus_range (&watcher->locus, "%s removed",
					 watcher->filename);
	      watcher->clear (watcher->obj);
	    }
	}
      pthread_rwlock_unlock (&watcher->rwl);
      job_enqueue_after (watcher_ttl, job_watcher_check, watcher);
    }
}

enum
  {
    WATCH_FILE,
    WATCH_DIR
  };

struct watchpoint
{
  int type;
  int wd;
  DLIST_ENTRY (watchpoint) link;
  union
  {
    struct watcher *watcher;
    struct
    {
      WORKDIR *wd;
      size_t nref;
    } wdir;
  };
};

static DLIST_HEAD (,watchpoint) watch_head;

static void
watchpoint_free (struct watchpoint *wp)
{
  free (wp);
}

static void
watchpoint_set_compat_mode (struct watchpoint *wp)
{
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
	conf_error_at_locus_range (&watcher->locus,
				   "%s: can't stat: %s",
				   watcher->filename,
				   strerror (errno));
    }
  else
    watcher->mtime = st.st_mtime;
}

static void
watcher_open_error (struct watcher *watcher, int ec)
{
  struct locus_point pt = LOCUS_POINT_INITIALIZER;

  locus_point_init (&pt, watcher->filename, watcher->wd->name);
  conf_error_at_locus_range (&watcher->locus, "can't open file %s: %s",
			     string_ptr (pt.filename), strerror (ec));
  locus_point_unref (&pt);
}

static void
watcher_read (struct watcher *watcher)
{
  conf_error_at_locus_range (&watcher->locus, "re-reading %s",
			     watcher->filename);
  watcher->clear (watcher->obj);
  if (watcher->read (watcher->obj, watcher->filename, watcher->wd) == -1)
    watcher_open_error (watcher, errno);
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
	mode = WATCHER_NOFILE;
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

#ifdef WITH_INOTIFY
#include <sys/inotify.h>

static int ifd;

static void
watchpoint_set_mode (struct watchpoint *wp, enum watcher_mode mode)
{
  wp->watcher->mode = mode;
}

static void
workdir_set_compat_mode (WORKDIR *wd)
{
  struct watchpoint *wp;
  DLIST_FOREACH (wp, &watch_head, link)
    {
      if (wp->type == WATCH_FILE && wp->watcher->wd == wd)
	watchpoint_set_compat_mode (wp);
    }
}

static void watchpoint_remove (struct watchpoint *wp);

static void
watchpoints_disable (void)
{
  struct watchpoint *wp, *tmp;
  DLIST_FOREACH_SAFE (wp, tmp, &watch_head, link)
    {
      switch (wp->type)
	{
	case WATCH_FILE:
	  inotify_rm_watch (ifd, wp->wd);
	  wp->wd = -1;
	  watchpoint_set_compat_mode (wp);
	  break;

	case WATCH_DIR:
	  watchpoint_remove (wp);
	}
    }
}

static struct watchpoint *
watchpoint_locate (int wd)
{
  struct watchpoint *wp;
  DLIST_FOREACH (wp, &watch_head, link)
    {
      if (wp->wd == wd)
	return wp;
    }
  return NULL;
}

static struct watchpoint *
watchpoint_locate_file (WORKDIR *wdir, char const *filename)
{
  struct watchpoint *wp;
  DLIST_FOREACH (wp, &watch_head, link)
    {
      if (wp->type == WATCH_FILE &&
	  wp->watcher->mode == WATCHER_NOFILE &&
	  wp->watcher->wd == wdir &&
	  strcmp (wp->watcher->filename, filename) == 0)
	return wp;
    }
  return NULL;
}

static void
watchpoint_set (struct watchpoint *wp)
{
  struct locus_point pt;

  switch (wp->type)
    {
    case WATCH_FILE:
      locus_point_init (&pt, wp->watcher->filename, wp->watcher->wd->name);
      wp->wd = inotify_add_watch (ifd, string_ptr (pt.filename),
				  IN_CLOSE_WRITE);
      locus_point_unref (&pt);
      break;

    case WATCH_DIR:
      wp->wd = inotify_add_watch (ifd, wp->wdir.wd->name,
				  IN_CREATE | IN_MOVED_TO);
      break;
    }
}

static struct watchpoint *
watchpoint_locate_dir (WORKDIR *wd)
{
  struct watchpoint *wp;
  DLIST_FOREACH (wp, &watch_head, link)
    {
      if (wp->type == WATCH_DIR && wp->wdir.wd == wd)
	{
	  wp->wdir.nref++;
	  return wp;
	}
    }
  XZALLOC (wp);
  wp->type = WATCH_DIR;
  wp->wdir.wd = wd;
  wp->wdir.nref = 1;
  watchpoint_set (wp);
  DLIST_PUSH (&watch_head, wp, link);
  return wp;
}

static void
watchpoint_remove (struct watchpoint *wp)
{
  DLIST_REMOVE (&watch_head, wp, link);
  if (wp->wd != -1)
    {
      inotify_rm_watch (ifd, wp->wd);
      wp->wd = -1;
    }
  watchpoint_free (wp);
}

static void
watchpoint_dir_unref (struct watchpoint *wp)
{
  if (--wp->wdir.nref == 0)
    watchpoint_remove (wp);
}

static void
watcher_reread (struct watcher *watcher)
{
  pthread_rwlock_wrlock (&watcher->rwl);
  watcher_read (watcher);
  pthread_rwlock_unlock (&watcher->rwl);
}

static void
process_event (struct inotify_event *ep)
{
  struct watchpoint *wp;

  if (ep->mask & IN_Q_OVERFLOW)
    logmsg (LOG_NOTICE, "event queue overflow");

  wp = watchpoint_locate (ep->wd);
  if (!wp)
    {
      if (!(ep->mask & IN_IGNORED))
	{
	  if (ep->len > 0)
	    logmsg (LOG_NOTICE, "ignoring unrecognized event %#x for %s",
		    ep->mask, ep->name);
	  else
	    logmsg (LOG_NOTICE, "ignoring unrecognized event %#x", ep->mask);
	}
      return;
    }

  if (ep->mask & IN_IGNORED)
    {
      wp->wd = -1;
      switch (wp->type)
	{
	case WATCH_FILE:
	  conf_error_at_locus_range (&wp->watcher->locus, "file removed");
	  wp->watcher->clear (wp->watcher->obj);
	  wp->watcher->mode = WATCHER_NOFILE;
	  watchpoint_locate_dir (wp->watcher->wd);
	  break;

	case WATCH_DIR:
	  logmsg (LOG_NOTICE, "%s: directory removed", wp->wdir.wd->name);
	  workdir_set_compat_mode (wp->wdir.wd);
	  watchpoint_remove (wp);
	  break;
	}
      return;
    }

  if (ep->mask & (IN_CREATE | IN_MOVED_TO))
    {
      struct watchpoint *awp = watchpoint_locate_file (wp->wdir.wd, ep->name);
      if (awp)
	{
	  conf_error_at_locus_range (&awp->watcher->locus, "%s restored",
				     awp->watcher->filename);
	  awp->watcher->mode = WATCHER_EXISTS;
	  watchpoint_set (awp);
	  watchpoint_dir_unref (wp);
	  watcher_reread (awp->watcher);
	}
    }
  else if (ep->mask & IN_CLOSE_WRITE)
    watcher_reread (wp->watcher);
}

static void
watcher_cleanup (void *arg)
{
  watchpoints_disable ();
  close (ifd);
}

static void *
thr_watcher (void *arg)
{
  char buffer[4096];
  struct inotify_event *ep;
  size_t size;
  ssize_t rdbytes;

  pthread_cleanup_push (watcher_cleanup, NULL);
  while (1)
    {
      rdbytes = read (ifd, buffer, sizeof (buffer));
      if (rdbytes == -1)
	{
	  if (errno == EINTR)
	    continue;
	  logmsg (LOG_CRIT, "inotify read failed: %s", strerror (errno));
	  break;
	}
      ep = (struct inotify_event *) buffer;

      while (rdbytes)
	{
	  if (ep->wd >= 0)
	    process_event (ep);
	  size = sizeof (*ep) + ep->len;
	  ep = (struct inotify_event *) ((char*) ep + size);
	  rdbytes -= size;
	}
    }
  pthread_cleanup_pop (1);
  return NULL;
}

int
watcher_setup (void)
{
  struct watchpoint *wp;
  pthread_t tid;

  if (DLIST_EMPTY (&watch_head))
    return 0;

  ifd = inotify_init ();
  if (ifd == -1)
    {
      logmsg (LOG_CRIT, "inotify_init: %s", strerror (errno));
      return -1;
    }

  DLIST_FOREACH (wp, &watch_head, link)
    {
      if (wp->type == WATCH_DIR)
	continue;
      switch (wp->watcher->mode)
	{
	case WATCHER_EXISTS:
	  watchpoint_set (wp);
	  break;

	case WATCHER_NOFILE:
	  watchpoint_locate_dir (wp->watcher->wd);
	  break;

	case WATCHER_COMPAT:
	  /* Shouldn't happen. */
	  break;
	}
    }

  pthread_create (&tid, &thread_attr_detached, thr_watcher, NULL);
  return 0;
}
#else
static void
watchpoint_set_mode (struct watchpoint *wp, enum watcher_mode mode)
{
  watchpoint_set_compat_mode (wp);
}

int
watcher_setup (void)
{
  return 0;
}
#endif
