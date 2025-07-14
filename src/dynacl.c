#include "pound.h"
#include "extern.h"

unsigned dynacl_ttl = 180;

struct watchpoint;

enum dynacl_mode
  {
    DYNACL_EXISTS,    /* File exists and is monitored. */
    DYNACL_NOFILE,    /* File does not exist, its directory is monitored. */
    DYNACL_COMPAT     /* Compatibility mode. */
  };

static void watchpoint_set_mode (struct watchpoint *wp, enum dynacl_mode);

struct dynacl
{
  enum dynacl_mode mode;
  ACL *acl;
  WORKDIR *wd;                /* Working directory. */
  char *filename;             /* Filename relative to wd. */
  struct locus_range locus;
  pthread_rwlock_t rwl;       /* Locker. */
  time_t mtime;               /* File mtime.  Used if inotify is
				 not available. */
};

static void dynacl_stat (struct dynacl *dynacl);
static void dynacl_read (struct dynacl *dynacl);

static void
job_dynacl_check (enum job_ctl ctl, void *arg, const struct timespec *ts)
{
  struct dynacl *dynacl = arg;
  if (ctl == job_ctl_run)
    {
      time_t mtime;
      
      pthread_rwlock_wrlock (&dynacl->rwl);
      mtime = dynacl->mtime;
      dynacl_stat (dynacl);
      if (dynacl->mtime > mtime)
	{
	  if (mtime == 0)
	    conf_error_at_locus_range (&dynacl->locus, "%s restored",
				       dynacl->filename);
	  dynacl_read (dynacl);
	}
      else if (dynacl->mtime == 0)
	{
	  if (mtime)
	    {
	      conf_error_at_locus_range (&dynacl->locus, "%s removed",
					 dynacl->filename);
	      acl_clear (dynacl->acl);
	    }
	}
      pthread_rwlock_unlock (&dynacl->rwl);
      job_enqueue_after (dynacl_ttl, job_dynacl_check, dynacl);
    }
}


void
acl_lock (ACL *acl)
{
  if (acl_is_dynamic (acl))
    pthread_rwlock_rdlock (&acl->dynacl->rwl);
}

void
acl_unlock (ACL *acl)
{
  if (acl_is_dynamic (acl))
    pthread_rwlock_unlock (&acl->dynacl->rwl);
}

enum
  {
    WATCH_ACL,
    WATCH_DIR
  };

struct watchpoint
{
  int type;
  int wd;
  DLIST_ENTRY (watchpoint) link;
  union
  {
    struct dynacl dynacl;
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
  switch (wp->type)
    {
    case WATCH_ACL:
      free (wp->dynacl.filename);
      locus_range_unref (&wp->dynacl.locus);
      pthread_rwlock_destroy (&wp->dynacl.rwl);
      break;

    case WATCH_DIR:
      break;
    }
  free (wp);
}

static void
watchpoint_set_compat_mode (struct watchpoint *wp)
{
  wp->dynacl.mode = DYNACL_COMPAT;
  wp->dynacl.mtime = 0;
  dynacl_stat (&wp->dynacl);
  job_enqueue_after (dynacl_ttl, job_dynacl_check, &wp->dynacl);
}

static void
dynacl_stat (struct dynacl *dynacl)
{
  struct stat st;
  dynacl->mtime = 0;
  if (fstatat (dynacl->wd->fd, dynacl->filename, &st, 0))
    {
      if (errno != ENOENT)
	conf_error_at_locus_range (&dynacl->locus,
				   "%s: can't stat: %s",
				   dynacl->filename,
				   strerror (errno));
    }
  else
    dynacl->mtime = st.st_mtime;
}

static void
dynacl_open_error (struct dynacl *dynacl, int ec)
{
  struct locus_point pt = LOCUS_POINT_INITIALIZER;

  locus_point_init (&pt, dynacl->filename, dynacl->wd->name);
  conf_error_at_locus_range (&dynacl->locus, "can't open file %s: %s",
			     string_ptr (pt.filename), strerror (ec));
  locus_point_unref (&pt);
}

static void
dynacl_read (struct dynacl *dynacl)
{
  conf_error_at_locus_range (&dynacl->locus, "re-reading %s",
			     dynacl->filename);
  acl_clear (dynacl->acl);
  if (config_parse_acl_file (dynacl->acl, dynacl->filename, dynacl->wd) == -1)
    dynacl_open_error (dynacl, errno);
}

static char const *
filename_split (char const *filename, char **dir)
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

int
dynacl_register (ACL *acl, char const *filename, struct locus_range *loc)
{
  struct watchpoint *wp;
  char const *basename;
  char *dir;
  int rc;
  enum dynacl_mode mode;

  XZALLOC (wp);
  wp->wd = -1;
  wp->type = WATCH_ACL;
  wp->dynacl.acl = acl;

  basename = filename_split (filename, &dir);
  if ((wp->dynacl.wd = workdir_get (dir)) == NULL)
    {
      conf_error_at_locus_range (loc,
				 "can't open directory %s: %s",
				 dir,
				 strerror (errno));
      free (dir);
      free (wp);
      return -1;
    }
  free (dir);
  wp->dynacl.filename = xstrdup (basename);
  locus_range_init (&wp->dynacl.locus);
  locus_range_copy (&wp->dynacl.locus, loc);
  pthread_rwlock_init (&wp->dynacl.rwl, NULL);

  rc = config_parse_acl_file (acl, wp->dynacl.filename, wp->dynacl.wd);
  if (rc == -1)
    {
      if (errno == ENOENT)
	mode = DYNACL_NOFILE;
      else
	{
	  dynacl_open_error (&wp->dynacl, errno);
	  watchpoint_free (wp);
	  return -1;
	}
    }
  else
    mode = DYNACL_EXISTS;

  watchpoint_set_mode (wp, mode);
  acl->dynacl = &wp->dynacl;

  DLIST_PUSH (&watch_head, wp, link);

  return 0;
}

#ifdef WITH_INOTIFY
#include <sys/inotify.h>

static int ifd;

static void
watchpoint_set_mode (struct watchpoint *wp, enum dynacl_mode mode)
{
  wp->dynacl.mode = mode;
}

static void
workdir_set_compat_mode (WORKDIR *wd)
{
  struct watchpoint *wp;
  DLIST_FOREACH (wp, &watch_head, link)
    {
      if (wp->type == WATCH_ACL && wp->dynacl.wd == wd)
	watchpoint_set_compat_mode (wp);
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
      if (wp->type == WATCH_ACL &&
	  wp->dynacl.mode == DYNACL_NOFILE &&
	  wp->dynacl.wd == wdir &&
	  strcmp (wp->dynacl.filename, filename) == 0)
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
    case WATCH_ACL:
      locus_point_init (&pt, wp->dynacl.filename, wp->dynacl.wd->name);
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
dynacl_reread (struct dynacl *dynacl)
{
  pthread_rwlock_wrlock (&dynacl->rwl);
  dynacl_read (dynacl);
  pthread_rwlock_unlock (&dynacl->rwl);
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
	case WATCH_ACL:
	  conf_error_at_locus_range (&wp->dynacl.locus, "file removed");
	  wp->dynacl.mode = DYNACL_NOFILE;
	  watchpoint_locate_dir (wp->dynacl.wd);
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
      conf_error_at_locus_range (&awp->dynacl.locus, "%s restored",
				 awp->dynacl.filename);
      awp->dynacl.mode = DYNACL_EXISTS;
      watchpoint_set (awp);
      watchpoint_dir_unref (wp);
    }
  else if (ep->mask & IN_CLOSE_WRITE)
    dynacl_reread (&wp->dynacl);
}

static void
dynacl_cleanup (void *arg)
{
  close (ifd);
}

static void *
thr_dynacl (void *arg)
{
  char buffer[4096];
  struct inotify_event *ep;
  size_t size;
  ssize_t rdbytes;

  pthread_cleanup_push (dynacl_cleanup, NULL);
  while (1)
    {
      rdbytes = read (ifd, buffer, sizeof (buffer));
      if (rdbytes == -1)
	{
	  if (errno == EINTR)
	    continue;
	  logmsg (LOG_CRIT, "inotify read failed: %s", strerror (errno));
	  close (ifd);//FIXME
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
dynacl_setup (void)
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
      switch (wp->dynacl.mode)
	{
	case DYNACL_EXISTS:
	  watchpoint_set (wp);
	  break;

	case DYNACL_NOFILE:
	  watchpoint_locate_dir (wp->dynacl.wd);
	  break;

	case DYNACL_COMPAT:
	  /* Shouldn't happen. */
	  break;
	}
    }

  pthread_create (&tid, &thread_attr_detached, thr_dynacl, NULL);
  return 0;
}
#else
static void
watchpoint_set_mode (struct watchpoint *wp, enum dynacl_mode mode)
{
  watchpoint_set_compat_mode (wp);
}

int
dynacl_setup (void)
{
  struct watchpoint *wp;
  DLIST_FOREACH (wp, &watch_head, link)
    {
      if (wp->type == WATCH_ACL)
	job_enqueue_after (dynacl_ttl, job_dynacl_check, &wp->dynacl);
    }
  return 0;
}
#endif
