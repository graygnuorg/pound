/*
 * Pound - the reverse-proxy load-balancer
 * Copyright (C) 2002-2010 Apsis GmbH
 *
 * This file is part of Pound.
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Contact information:
 * Apsis GmbH
 * P.O.Box
 * 8707 Uetikon am See
 * Switzerland
 * EMail: roseg@apsis.ch
 */

#include "pound.h"
#include "extern.h"

/*
 * Compare two timespecs
 */
static inline int
timespec_cmp (struct timespec const *a, struct timespec const *b)
{
  if (a->tv_sec < b->tv_sec)
    return -1;
  if (a->tv_sec > b->tv_sec)
    return 1;
  if (a->tv_nsec < b->tv_nsec)
    return -1;
  if (a->tv_nsec > b->tv_nsec)
    return 1;
  return 0;
}

/*
 * basic hashing function, based on fmv
 */
static unsigned long
session_hash (const SESSION *e)
{
  unsigned long res;
  char *k;

  k = e->key;
  res = 2166136261;
  while (*k)
    res = ((res ^ *k++) * 16777619) & 0xFFFFFFFF;
  return res;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static IMPLEMENT_LHASH_HASH_FN (session, SESSION)
#endif

static int
session_cmp (const SESSION *d1, const SESSION *d2)
{
  return strcmp (d1->key, d2->key);
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static IMPLEMENT_LHASH_COMP_FN (session, SESSION)
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
# define SESSION_HASH_NEW() lh_SESSION_new (session_hash, session_cmp)
# define SESSION_INSERT(tab, node) lh_SESSION_insert (tab, node)
# define SESSION_RETRIEVE(tab, node) lh_SESSION_retrieve (tab, node)
# define SESSION_DELETE(tab, node) lh_SESSION_delete (tab, node)
#else /* OPENSSL_VERSION_NUMBER >= 0x10000000L */
# define SESSION_HASH_NEW() LHM_lh_new (SESSION, session)
# define SESSION_INSERT(tab, node) LHM_lh_insert (SESSION, tab, node)
# define SESSION_RETRIEVE(tab, node) LHM_lh_retrieve (SESSION, tab, node)
# define SESSION_DELETE(tab, node) LHM_lh_delete (SESSION, tab, node)
#endif

SESSION_TABLE *
session_table_new (void)
{
  SESSION_TABLE *st;
  XZALLOC (st);
  if ((st->hash = SESSION_HASH_NEW ()) == NULL)
    xnomem ();
  DLIST_INIT (&st->head);
  return st;
}

static inline void
session_link_at_tail (SESSION_TABLE *tab, SESSION *sess)
{
  DLIST_INSERT_TAIL (&tab->head, sess, link);
}

static inline void
session_unlink (SESSION_TABLE *tab, SESSION *sess)
{
  DLIST_REMOVE (&tab->head, sess, link);
}

static void
session_free (SESSION *sess)
{
  free (sess);
}

/*
 * Periodic job to remove expired sessions within the given service (passed
 * as the DATA argument),  Sessions within the session table are ordered
 * by their expiration time.  The expire_sessions cronjob is normally scheduled
 * to the expiration time of the first session in the list, i.e. the least
 * recently used one.
 *
 * Before returning, the function rearms the periodic job if necessary.
 */
static void
expire_sessions (void *data)
{
  SERVICE *svc = data;
  SESSION_TABLE *tab = svc->sessions;
  SESSION *sess = DLIST_FIRST (&tab->head);

  if (sess)
    {
      pthread_mutex_lock (&svc->mut);
      SESSION_DELETE (tab->hash, sess);
      session_unlink (tab, sess);
      session_free (sess);

      if (!DLIST_EMPTY (&tab->head))
	job_enqueue_unlocked (&DLIST_FIRST (&tab->head)->expire, expire_sessions, svc);
      pthread_mutex_unlock (&svc->mut);
    }
}

static void
service_rearm_expire_sessions (SERVICE *svc)
{
  SESSION *sess = DLIST_FIRST (&svc->sessions->head);
  if (sess)
    job_rearm (&sess->expire, expire_sessions, svc);
  /*
   * If the session list is empty, the scheduled job remains unchanged.
   * It will eventually fire, call expire_sessions, which will do nothing
   * and be removed from the queue.
   */
}

/*
 * Promote the given session by updating its expiration time and
 * moving it to the end of the session list.  Re-schedule the expiration
 * periodic job accordingly.
 *
 * The service mutex must be locked.
 */
static void
service_session_promote (SERVICE *svc, SESSION *sess)
{
  SESSION_TABLE *tab = svc->sessions;
  session_unlink (tab, sess);
  clock_gettime (CLOCK_REALTIME, &sess->expire);
  sess->expire.tv_sec += svc->sess_ttl;
  session_link_at_tail (tab, sess);
  service_rearm_expire_sessions (svc);
}

/*
 * Add a new key/backend pair to the session table of SVC.  If this is
 * going to be the the first session in the session list, schedule the
 * expiration job.
 *
 * The service mutex must be locked.
 */
static void
service_session_add (SERVICE *svc, const char *key, BACKEND *be)
{
  SESSION_TABLE *tab = svc->sessions;
  SESSION *t, *old;
  size_t keylen = strlen (key);

  if ((t = malloc (sizeof (SESSION) + keylen + 1)) == NULL)
    {
      logmsg (LOG_WARNING, "service_session_add() content malloc");
      return;
    }
  t->key = (char*)(t + 1);
  strcpy (t->key, key);
  t->backend = be;
  clock_gettime (CLOCK_REALTIME, &t->expire);
  t->expire.tv_sec += svc->sess_ttl;
  if ((old = SESSION_INSERT (tab->hash, t)) != NULL)
    {
      session_free (old);
      logmsg (LOG_WARNING, "service_session_add() DUP");
    }
  session_link_at_tail (tab, t);
  if (DLIST_NEXT (DLIST_FIRST (&tab->head), link) == 0)
    job_enqueue (&t->expire, expire_sessions, svc);
}

/*
 * Look up the service session table for the given key.  If found,
 * return the corresponding backend and promote the session.
 *
 * The service mutex must be locked.
 */
static BACKEND *
service_session_find (SERVICE *svc, char *const key)
{
  SESSION_TABLE *tab = svc->sessions;
  SESSION t, *res;

  t.key = key;
  if ((res = SESSION_RETRIEVE (tab->hash, &t)) != NULL)
    {
      service_session_promote (svc, res);
      return res->backend;
    }
  return NULL;
}

/*
 * Delete from the service session table a session corresponding to the
 * given key.
 *
 * The service mutex must be locked.
 */
static void
service_session_remove_by_key (SERVICE *svc, char *const key)
{
  SESSION_TABLE *tab = svc->sessions;
  SESSION t, *res;

  t.key = key;
  if ((res = SESSION_DELETE (tab->hash, &t)) != NULL)
    {
      int first = DLIST_FIRST (&tab->head) == res;
      session_unlink (tab, res);
      session_free (res);
      if (first)
	service_rearm_expire_sessions (svc);
    }
  return;
}

/*
 * Remove from the service session table all sessions with the given backend
 *
 * The service mutex must be locked.
 */
static void
service_session_remove_by_backend (SERVICE *svc, BACKEND *be)
{
  SESSION_TABLE *tab = svc->sessions;
  SESSION *sess, *tmp, *first;

  first = DLIST_FIRST (&tab->head);
  DLIST_FOREACH_SAFE (sess, tmp, &tab->head, link)
    {
      if (sess->backend == be)
	{
	  SESSION_DELETE (tab->hash, sess);
	  session_unlink (tab, sess);
	  session_free (sess);
	}
    }
  if (first != DLIST_FIRST (&tab->head))
    service_rearm_expire_sessions (svc);
}

/*
 * Log an error to the syslog or to stderr
 */
void
vlogmsg (const int priority, const char *fmt, va_list ap)
{
  if (log_facility == -1 || print_log)
    {
      FILE *fp = (priority == LOG_INFO || priority == LOG_DEBUG)
		     ? stdout : stderr;
      if (progname)
	fprintf (fp, "%s: ", progname);
      vfprintf (fp, fmt, ap);
      fputc ('\n', fp);
    }
  else
    {
      struct stringbuf sb;
      stringbuf_init (&sb);
      stringbuf_vprintf (&sb, fmt, ap);
      syslog (priority, "%s", stringbuf_value (&sb));
      stringbuf_free (&sb);
    }
  return;
}

void
logmsg (const int priority, const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  vlogmsg (priority, fmt, ap);
  va_end (ap);
}

/*
 * Translate inet/inet6 address/port into a string
 */
char *
addr2str (char *res, int res_len, const struct addrinfo *addr, int no_port)
{
  int n;
  char *ptr = res;

  if (res == NULL || res_len <= 0 || addr == NULL)
    return NULL;

  ptr[res_len - 1] = 0;
  --res_len;

  if (addr->ai_family == AF_UNIX)
    {
      struct sockaddr_un *sun = (struct sockaddr_un *)addr->ai_addr;
      n = addr->ai_addrlen - offsetof (struct sockaddr_un, sun_path);
      if (n > res_len)
	n = res_len;
      strncpy (ptr, sun->sun_path, n);
      if (ptr[n-1] != 0 && n < res_len)
	ptr[n] = 0;
    }
  else
    {
      char hostbuf[NI_MAXHOST];
      char portbuf[NI_MAXSERV];

      int rc = getnameinfo (addr->ai_addr, addr->ai_addrlen,
			    hostbuf, sizeof (hostbuf),
			    portbuf, sizeof (portbuf),
			    NI_NUMERICHOST | NI_NUMERICSERV);

      if (rc)
	{
	  logmsg (LOG_ERR, "getnameinfo: %s", gai_strerror (rc));
	  strncpy (ptr, "(UNKNOWN)", res_len);
	}
      else
	{
	  if (addr->ai_family == AF_INET6)
	    snprintf (ptr, res_len+1, "[%s]", hostbuf);
	  else
	    strncpy (ptr, hostbuf, res_len);

	  n = strlen (ptr);
	  ptr += n;
	  res_len -= n;

	  if (!no_port)
	    {
	      if (res_len)
		{
		  *ptr++ = ':';
		  res_len--;
		  strncpy (ptr, portbuf, res_len);
		}
	    }
	}
    }
  return res;
}

/*
 * Parse a URL, possibly decoding hexadecimal-encoded characters
 */
int
cpURL (char *res, char *src, int len)
{
  int state;
  char *kp_res;

  for (kp_res = res, state = 0; len > 0; len--)
    switch (state)
      {
      case 1:
	if (*src >= '0' && *src <= '9')
	  {
	    *res = *src++ - '0';
	    state = 2;
	  }
	else if (*src >= 'A' && *src <= 'F')
	  {
	    *res = *src++ - 'A' + 10;
	    state = 2;
	  }
	else if (*src >= 'a' && *src <= 'f')
	  {
	    *res = *src++ - 'a' + 10;
	    state = 2;
	  }
	else
	  {
	    *res++ = '%';
	    *res++ = *src++;
	    state = 0;
	  }
	break;

      case 2:
	if (*src >= '0' && *src <= '9')
	  {
	    *res = *res * 16 + *src++ - '0';
	    res++;
	    state = 0;
	  }
	else if (*src >= 'A' && *src <= 'F')
	  {
	    *res = *res * 16 + *src++ - 'A' + 10;
	    res++;
	    state = 0;
	  }
	else if (*src >= 'a' && *src <= 'f')
	  {
	    *res = *res * 16 + *src++ - 'a' + 10;
	    res++;
	    state = 0;
	  }
	else
	  {
	    *res++ = '%';
	    *res++ = *(src - 1);
	    *res++ = *src++;
	    state = 0;
	  }
	break;

      default:
	if (*src != '%')
	  *res++ = *src++;
	else
	  {
	    src++;
	    state = 1;
	  }
	break;
      }
  if (state > 0)
    *res++ = '%';
  if (state > 1)
    *res++ = *(src - 1);
  *res = '\0';
  return res - kp_res;
}

/*
 * Parse a header
 * return a code and possibly content in the arg
 */
int
check_header (const char *header, char *const content)
{
  regmatch_t matches[4];
  static struct
  {
    char header[32];
    int len;
    int val;
  } hd_types[] =
  {
    {"Transfer-encoding", 17, HEADER_TRANSFER_ENCODING},
    {"Content-length", 14, HEADER_CONTENT_LENGTH},
    {"Connection", 10, HEADER_CONNECTION},
    {"Location", 8, HEADER_LOCATION},
    {"Content-location", 16, HEADER_CONTLOCATION},
    {"Host", 4, HEADER_HOST},
    {"Referer", 7, HEADER_REFERER},
    {"User-agent", 10, HEADER_USER_AGENT},
    {"Destination", 11, HEADER_DESTINATION},
    {"Expect", 6, HEADER_EXPECT},
    {"Upgrade", 7, HEADER_UPGRADE},
    {"", 0, HEADER_OTHER},
  };
  int i;

  if (!regexec (&HEADER, header, 4, matches, 0))
    {
      for (i = 0; hd_types[i].len > 0; i++)
	if ((matches[1].rm_eo - matches[1].rm_so) == hd_types[i].len
	    && strncasecmp (header + matches[1].rm_so, hd_types[i].header,
			    hd_types[i].len) == 0)
	  {
	    /* we know that the original header was read into a buffer of size MAXBUF, so no overflow */
	    strncpy (content, header + matches[2].rm_so,
		     matches[2].rm_eo - matches[2].rm_so);
	    content[matches[2].rm_eo - matches[2].rm_so] = '\0';
	    return hd_types[i].val;
	  }
      return HEADER_OTHER;
    }
  else
    return HEADER_ILLEGAL;
}

static void
submatch_init (struct submatch *sm)
{
  sm->matchn = 0;
  sm->matchmax = 0;
  sm->matchv = NULL;
}

static int
submatch_realloc (struct submatch *sm, regex_t const *re)
{
  size_t n = re->re_nsub + 1;
  if (n > sm->matchmax)
    {
      regmatch_t *p = realloc (sm->matchv, n * sizeof (p[0]));
      if (!p)
	return -1;
      sm->matchmax = n;
      sm->matchv = p;
    }
  sm->matchn = n;
  return 0;
}

void
submatch_free (struct submatch *sm)
{
  free (sm->matchv);
  submatch_init (sm);
}

static void
submatch_reset (struct submatch *sm)
{
  sm->matchn = 0;
}

static int
match_headers (char **const headers, regex_t const *re)
{
  int i, found;

  for (i = found = 0; i < MAXHEADERS-1 && !found; i++)
    {
      if (headers[i])
	found = regexec (re, headers[i], 0, NULL, 0) == 0;
    }
  return found;
}

static int
match_cond (const SERVICE_COND *cond, struct sockaddr *srcaddr,
	    const char *request, char **const headers,
	    struct submatch *sm)
{
  int res = 1;
  SERVICE_COND *subcond;

  switch (cond->type)
    {
    case COND_ACL:
      res = acl_match (cond->acl, srcaddr) == 0;
      break;

    case COND_URL:
      if (submatch_realloc (sm, &cond->re))
	{
	  logmsg (LOG_ERR, "memory allocation failed");
	  return 0;
	}
      res = regexec (&cond->re, request, sm->matchn, sm->matchv, 0) == 0;
      break;

    case COND_HDR:
      res = match_headers (headers, &cond->re);
      break;

    case COND_BOOL:
      submatch_reset (sm);
      if (cond->bool.op == BOOL_NOT)
	{
	  subcond = SLIST_FIRST (&cond->bool.head);
	  res = ! match_cond (subcond, srcaddr, request, headers, sm);
	}
      else
	{
	  SLIST_FOREACH (subcond, &cond->bool.head, next)
	    {
	      res = match_cond (subcond, srcaddr, request, headers, sm);
	      if ((cond->bool.op == BOOL_AND) ? (res == 0) : (res == 1))
		break;
	    }
	}
      break;
    }

  return res;
}

static int
match_service (const SERVICE *svc, struct sockaddr *srcaddr,
	       const char *request, char **const headers,
	       struct submatch *sm)
{
  return match_cond (&svc->cond, srcaddr, request, headers, sm);
}

/*
 * Find the right service for a request
 */
SERVICE *
get_service (const LISTENER * lstn, struct sockaddr *srcaddr,
	     const char *request, char **const headers,
	     struct submatch *sm)
{
  SERVICE *svc;

  SLIST_FOREACH (svc, &lstn->services, next)
    {
      if (svc->disabled)
	continue;
      if (match_service (svc, srcaddr, request, headers, sm))
	return svc;
    }

  /* try global services */
  SLIST_FOREACH (svc, &services, next)
    {
      if (svc->disabled)
	continue;
      if (match_service (svc, srcaddr, request, headers, sm))
	return svc;
    }

  /* nothing matched */
  return NULL;
}

/*
 * extract the session key for a given request
 */
static int
get_REQUEST (char *res, const SERVICE * svc, const char *request)
{
  int n, s;
  regmatch_t matches[4];

  if (regexec (&svc->sess_start, request, 4, matches, 0))
    {
      res[0] = '\0';
      return 0;
    }
  s = matches[0].rm_eo;
  if (regexec (&svc->sess_pat, request + s, 4, matches, 0))
    {
      res[0] = '\0';
      return 0;
    }
  if ((n = matches[1].rm_eo - matches[1].rm_so) > KEY_SIZE)
    n = KEY_SIZE;
  strncpy (res, request + s + matches[1].rm_so, n);
  res[n] = '\0';
  return 1;
}

static int
get_HEADERS (char *res, const SERVICE * svc, char **const headers)
{
  int i, n, s;
  regmatch_t matches[4];

  /* this will match SESS_COOKIE, SESS_HEADER and SESS_BASIC */
  res[0] = '\0';
  for (i = 0; i < (MAXHEADERS - 1); i++)
    {
      if (headers[i] == NULL)
	continue;
      if (regexec (&svc->sess_start, headers[i], 4, matches, 0))
	continue;
      s = matches[0].rm_eo;
      if (regexec (&svc->sess_pat, headers[i] + s, 4, matches, 0))
	continue;
      if ((n = matches[1].rm_eo - matches[1].rm_so) > KEY_SIZE)
	n = KEY_SIZE;
      strncpy (res, headers[i] + s + matches[1].rm_so, n);
      res[n] = '\0';
    }
  return res[0] != '\0';
}

/*
 * Pick a random back-end from a candidate list
 */
static BACKEND *
rand_backend (BACKEND_HEAD *head, int pri)
{
  BACKEND *be;
  SLIST_FOREACH (be, head, next)
    {
      if (!be->alive || be->disabled)
	continue;
      if ((pri -= be->priority) < 0)
	break;
    }
  return be;
}

/*
 * return a back-end based on a fixed hash value
 * this is used for session_ttl < 0
 *
 * WARNING: the function may return different back-ends
 * if the target back-end is disabled or not alive
 */
static BACKEND *
hash_backend (BACKEND_HEAD *head, int abs_pri, char *key)
{
  unsigned long hv;
  BACKEND *res, *tb;
  int pri;

  hv = 2166136261;
  while (*key)
    hv = ((hv ^ *key++) * 16777619) & 0xFFFFFFFF;
  pri = hv % abs_pri;
  SLIST_FOREACH (tb, head, next)
    if ((pri -= tb->priority) < 0)
      break;
  if (!tb)
    /* should NEVER happen */
    return NULL;
  for (res = tb; !res->alive || res->disabled;)
    {
      res = SLIST_NEXT (res, next);
      if (res == NULL)
	res = SLIST_FIRST (head);
      if (res == tb)
	/* NO back-end available */
	return NULL;
    }
  return res;
}

/*
 * Find the right back-end for a request
 */
BACKEND *
get_backend (SERVICE * const svc, const struct addrinfo * from_host,
	     const char *request, char **const headers)
{
  BACKEND *res;
  char key[KEY_SIZE + 1];
  int ret_val, no_be;

  if ((ret_val = pthread_mutex_lock (&svc->mut)) != 0)
    logmsg (LOG_WARNING, "get_backend() lock: %s", strerror (ret_val));

  no_be = (svc->tot_pri <= 0);

  switch (svc->sess_type)
    {
    case SESS_NONE:
      /* choose one back-end randomly */
      res = no_be ? svc->emergency : rand_backend (&svc->backends,
						   random () % svc->tot_pri);
      break;

    case SESS_IP:
      addr2str (key, sizeof (key), from_host, 1);
      if (svc->sess_ttl < 0)
	res = no_be ? svc->emergency
		     : hash_backend (&svc->backends, svc->abs_pri, key);
      else if ((res = service_session_find (svc, key)) == NULL)
	{
	  if (no_be)
	    res = svc->emergency;
	  else
	    {
	      /* no session yet - create one */
	      res = rand_backend (&svc->backends, random () % svc->tot_pri);
	      service_session_add (svc, key, res);
	    }
	}
      break;

    case SESS_URL:
    case SESS_PARM:
      if (get_REQUEST (key, svc, request))
	{
	  if (svc->sess_ttl < 0)
	    res = no_be ? svc->emergency
			: hash_backend (&svc->backends, svc->abs_pri, key);
	  else if ((res = service_session_find (svc, key)) == NULL)
	    {
	      if (no_be)
		res = svc->emergency;
	      else
		{
		  /* no session yet - create one */
		  res = rand_backend (&svc->backends, random () % svc->tot_pri);
		  service_session_add (svc, key, res);
		}
	    }
	}
      else
	{
	  res = no_be ? svc->emergency
		      : rand_backend (&svc->backends, random () % svc->tot_pri);
	}
      break;
    default:
      /* this works for SESS_BASIC, SESS_HEADER and SESS_COOKIE */
      if (get_HEADERS (key, svc, headers))
	{
	  if (svc->sess_ttl < 0)
	    res = no_be ? svc->emergency
			: hash_backend (&svc->backends, svc->abs_pri, key);
	  else if ((res = service_session_find (svc, key)) == NULL)
	    {
	      if (no_be)
		res = svc->emergency;
	      else
		{
		  /* no session yet - create one */
		  res = rand_backend (&svc->backends, random () % svc->tot_pri);
		  service_session_add (svc, key, res);
		}
	    }
	}
      else
	{
	  res = no_be ? svc->emergency
		      : rand_backend (&svc->backends, random () % svc->tot_pri);
	}
      break;
    }
  if ((ret_val = pthread_mutex_unlock (&svc->mut)) != 0)
    logmsg (LOG_WARNING, "get_backend() unlock: %s", strerror (ret_val));

  return res;
}

/*
 * (for cookies/header only) possibly create session based on response headers
 */
void
upd_session (SERVICE *const svc, char **const headers, BACKEND * const be)
{
  char key[KEY_SIZE + 1];
  int ret_val;

  if (svc->sess_type != SESS_HEADER && svc->sess_type != SESS_COOKIE)
    return;
  if ((ret_val = pthread_mutex_lock (&svc->mut)) != 0)
    logmsg (LOG_WARNING, "upd_session() lock: %s", strerror (ret_val));
  if (get_HEADERS (key, svc, headers))
    if (service_session_find (svc, key) == NULL)
      service_session_add (svc, key, be);
  if ((ret_val = pthread_mutex_unlock (&svc->mut)) != 0)
    logmsg (LOG_WARNING, "upd_session() unlock: %s", strerror (ret_val));
  return;
}

static void touch_be (void *data);

/*
 * mark a backend host as dead/disabled; remove its sessions if necessary
 *  disable_only == 1:  mark as disabled
 *  disable_only == 0:  mark as dead, remove sessions
 *  disable_only == -1:  mark as enabled
 */
void
kill_be (SERVICE *svc, BACKEND *be, const int disable_mode)
{
  BACKEND *b;
  int ret_val;
  char buf[MAXBUF];

  if ((ret_val = pthread_mutex_lock (&svc->mut)) != 0)
    logmsg (LOG_WARNING, "kill_be() lock: %s", strerror (ret_val));
  svc->tot_pri = 0;
  SLIST_FOREACH (b, &svc->backends, next)
    {
      if (b == be)
	{
	  switch (disable_mode)
	    {
	    case BE_DISABLE:
	      b->disabled = 1;
	      str_be (buf, sizeof (buf), b);
	      logmsg (LOG_NOTICE, "(%"PRItid") Backend %s disabled",
		      POUND_TID (),
		      buf);
	      break;

	    case BE_KILL:
	      b->alive = 0;
	      str_be (buf, sizeof (buf), b);
	      logmsg (LOG_NOTICE, "(%"PRItid") Backend %s dead (killed)",
		      POUND_TID (), buf);
	      service_session_remove_by_backend (svc, be);
	      job_enqueue_after (alive_to, touch_be, be);
	      break;

	    case BE_ENABLE:
	      str_be (buf, sizeof (buf), b);
	      logmsg (LOG_NOTICE, "(%"PRItid") Backend %s enabled",
		      POUND_TID (),
		      buf);
	      b->disabled = 0;
	      break;

	    default:
	      logmsg (LOG_WARNING, "kill_be(): unknown mode %d", disable_mode);
	      break;
	    }
	}
      if (b->alive && !b->disabled)
	svc->tot_pri += b->priority;
    }
  if ((ret_val = pthread_mutex_unlock (&svc->mut)) != 0)
    logmsg (LOG_WARNING, "kill_be() unlock: %s", strerror (ret_val));
  return;
}

/*
 * Search for a host name, return the addrinfo for it
 */
int
get_host (char *const name, struct addrinfo *res, int ai_family)
{
  struct addrinfo *chain, *ap;
  struct addrinfo hints;
  int ret_val;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = ai_family;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_CANONNAME |
		    (feature_is_set (FEATURE_DNS) ? 0 : AI_NUMERICHOST);
  if ((ret_val = getaddrinfo (name, NULL, &hints, &chain)) == 0)
    {
      for (ap = chain; ap != NULL; ap = ap->ai_next)
	if (ap->ai_socktype == SOCK_STREAM)
	  break;
      if (ap == NULL)
	{
	  freeaddrinfo (chain);
	  return EAI_NONAME;
	}
      *res = *ap;
      if ((res->ai_addr = malloc (ap->ai_addrlen)) == NULL)
	{
	  freeaddrinfo (chain);
	  return EAI_MEMORY;
	}
      memcpy (res->ai_addr, ap->ai_addr, ap->ai_addrlen);
      freeaddrinfo (chain);
    }
  return ret_val;
}

/*
 * Find if a redirect needs rewriting
 * In general we have two possibilities that require it:
 * (1) if the redirect was done to the correct location with the wrong port
 * (2) if the redirect was done to the back-end rather than the listener
 */
int
need_rewrite (const int rewr_loc, char *const location, char *const path,
	      const char *v_host, const LISTENER * lstn, const BACKEND * be)
{
  struct addrinfo addr;
  struct sockaddr_in in_addr, be_addr;
  struct sockaddr_in6 in6_addr, be6_addr;
  regmatch_t matches[4];
  char *proto, *host, *port, *cp, buf[MAXBUF];

  /* check if rewriting is required at all */
  if (rewr_loc == 0)
    return 0;

  /* applies only to INET/INET6 back-ends */
  if (be->addr.ai_family != AF_INET && be->addr.ai_family != AF_INET6)
    return 0;

  /* split the location into its fields */
  if (regexec (&LOCATION, location, 4, matches, 0))
    return 0;
  proto = location + matches[1].rm_so;
  host = location + matches[2].rm_so;
  if (location[matches[3].rm_so] == '/')
    matches[3].rm_so++;
  /* path is guaranteed to be large enough */
  strcpy (path, location + matches[3].rm_so);
  location[matches[1].rm_eo] = location[matches[2].rm_eo] = '\0';
  if ((port = strchr (host, ':')) != NULL)
    *port++ = '\0';

  /*
   * Check if the location has the same address as the listener or the back-end
   */
  memset (&addr, 0, sizeof (addr));
  if (get_host (host, &addr, be->addr.ai_family))
    return 0;

  /*
   * compare the back-end
   */
  if (addr.ai_family != be->addr.ai_family)
    {
      free (addr.ai_addr);
      return 0;
    }
  if (addr.ai_family == AF_INET)
    {
      memcpy (&in_addr, addr.ai_addr, sizeof (in_addr));
      memcpy (&be_addr, be->addr.ai_addr, sizeof (be_addr));
      if (port)
	in_addr.sin_port = (in_port_t) htons (atoi (port));
      else if (!strcasecmp (proto, "https"))
	in_addr.sin_port = (in_port_t) htons (443);
      else
	in_addr.sin_port = (in_port_t) htons (80);
      /*
       * check if the Location points to the back-end
       */
      if (memcmp (&be_addr.sin_addr.s_addr, &in_addr.sin_addr.s_addr,
		  sizeof (in_addr.sin_addr.s_addr)) == 0
	  && memcmp (&be_addr.sin_port, &in_addr.sin_port,
		     sizeof (in_addr.sin_port)) == 0)
	{
	  free (addr.ai_addr);
	  return 1;
	}
    }
  else				/* AF_INET6 */
    {
      memcpy (&in6_addr, addr.ai_addr, sizeof (in6_addr));
      memcpy (&be6_addr, be->addr.ai_addr, sizeof (be6_addr));
      if (port)
	in6_addr.sin6_port = (in_port_t) htons (atoi (port));
      else if (!strcasecmp (proto, "https"))
	in6_addr.sin6_port = (in_port_t) htons (443);
      else
	in6_addr.sin6_port = (in_port_t) htons (80);
      /*
       * check if the Location points to the back-end
       */
      if (memcmp (&be6_addr.sin6_addr.s6_addr, &in6_addr.sin6_addr.s6_addr,
		  sizeof (in6_addr.sin6_addr.s6_addr)) == 0
	  && memcmp (&be6_addr.sin6_port, &in6_addr.sin6_port,
		     sizeof (in6_addr.sin6_port)) == 0)
	{
	  free (addr.ai_addr);
	  return 1;
	}
    }

  /*
   * compare the listener
   */
  if (rewr_loc != 1 || addr.ai_family != lstn->addr.ai_family)
    {
      free (addr.ai_addr);
      return 0;
    }
  memset (buf, '\0', sizeof (buf));
  strncpy (buf, v_host, sizeof (buf) - 1);
  if ((cp = strchr (buf, ':')) != NULL)
    *cp = '\0';
  if (addr.ai_family == AF_INET)
    {
      memcpy (&be_addr, lstn->addr.ai_addr, sizeof (be_addr));
      /*
       * check if the Location points to the Listener but with the wrong
       * port or protocol
       */
      if ((memcmp (&be_addr.sin_addr.s_addr, &in_addr.sin_addr.s_addr,
		   sizeof (in_addr.sin_addr.s_addr)) == 0
	   || strcasecmp (host, buf) == 0)
	  &&
	  (memcmp (&be_addr.sin_port, &in_addr.sin_port,
		   sizeof (in_addr.sin_port)) != 0
	   || strcasecmp (proto,
			  !SLIST_EMPTY (&lstn->ctx_head) ? "https" : "http")))
	{
	  free (addr.ai_addr);
	  return 1;
	}
    }
  else
    {
      memcpy (&be6_addr, lstn->addr.ai_addr, sizeof (be6_addr));
      /*
       * check if the Location points to the Listener but with the wrong
       * port or protocol
       */
      if ((memcmp (&be6_addr.sin6_addr.s6_addr, &in6_addr.sin6_addr.s6_addr,
		   sizeof (in6_addr.sin6_addr.s6_addr)) == 0
	   || strcasecmp (host, buf) == 0)
	  &&
	  (memcmp (&be6_addr.sin6_port, &in6_addr.sin6_port,
		   sizeof (in6_addr.sin6_port)) != 0
	   || strcasecmp (proto,
			  !SLIST_EMPTY (&lstn->ctx_head) ? "https" : "http")))
	{
	  free (addr.ai_addr);
	  return 1;
	}
    }

  free (addr.ai_addr);
  return 0;
}

/*
 * Non-blocking connect(). Does the same as connect(2) but ensures
 * it will time-out after a much shorter time period SERVER_TO
 */
int
connect_nb (const int sockfd, const struct addrinfo *serv_addr, const int to)
{
  int flags, res, error;
  socklen_t len;
  struct pollfd p;

  if ((flags = fcntl (sockfd, F_GETFL, 0)) < 0)
    {
      logmsg (LOG_WARNING, "(%"PRItid") connect_nb: fcntl GETFL failed: %s",
	      POUND_TID (), strerror (errno));
      return -1;
    }
  if (fcntl (sockfd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      logmsg (LOG_WARNING, "(%"PRItid") connect_nb: fcntl SETFL failed: %s",
	      POUND_TID (), strerror (errno));
      return -1;
    }

  error = 0;
  if ((res = connect (sockfd, serv_addr->ai_addr, serv_addr->ai_addrlen)) < 0)
    if (errno != EINPROGRESS)
      {
	logmsg (LOG_WARNING, "(%"PRItid") connect_nb: connect failed: %s",
		POUND_TID (), strerror (errno));
	return -1;
      }

  if (res == 0)
    {
      /* connect completed immediately (usually localhost) */
      if (fcntl (sockfd, F_SETFL, flags) < 0)
	{
	  logmsg (LOG_WARNING, "(%"PRItid") connect_nb: fcntl reSETFL failed: %s",
		  POUND_TID (), strerror (errno));
	  return -1;
	}
      return 0;
    }

  memset (&p, 0, sizeof (p));
  p.fd = sockfd;
  p.events = POLLOUT;
  if ((res = poll (&p, 1, to * 1000)) != 1)
    {
      if (res == 0)
	{
	  /* timeout */
	  logmsg (LOG_WARNING, "(%"PRItid") connect_nb: poll timed out",
		  POUND_TID ());
	  errno = ETIMEDOUT;
	}
      else
	logmsg (LOG_WARNING, "(%"PRItid") connect_nb: poll failed: %s",
		POUND_TID (), strerror (errno));
      return -1;
    }

  /* socket is writeable == operation completed */
  len = sizeof (error);
  if (getsockopt (sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
    {
      logmsg (LOG_WARNING, "(%"PRItid") connect_nb: getsockopt failed: %s",
	      POUND_TID (), strerror (errno));
      return -1;
    }

  /* restore file status flags */
  if (fcntl (sockfd, F_SETFL, flags) < 0)
    {
      logmsg (LOG_WARNING, "(%"PRItid") connect_nb: fcntl reSETFL failed: %s",
	      POUND_TID (), strerror (errno));
      return -1;
    }

  if (error)
    {
      /* getsockopt() shows an error */
      errno = error;
      logmsg (LOG_WARNING, "(%"PRItid") connect_nb: error after getsockopt: %s",
	      POUND_TID (), strerror (errno));
      return -1;
    }

  /* really connected */
  return 0;
}

enum
  {
    BACKEND_OK,
    BACKEND_DEAD,
    BACKEND_ERR,
  };

static int
backend_probe (BACKEND *be)
{
  int sock;
  int family;
  int rc;

  switch (be->addr.ai_family)
    {
    case AF_INET:
      family = PF_INET;
      break;

    case AF_INET6:
      family = PF_INET6;
      break;

    case AF_UNIX:
      family = PF_UNIX;
      break;

    default:
      errno = EINVAL;
      return BACKEND_ERR;
    }

  if ((sock = socket (family, SOCK_STREAM, 0)) < 0)
    return BACKEND_ERR;

  rc = connect_nb (sock, &be->addr, be->conn_to);
  shutdown (sock, 2);
  close (sock);

  return rc == 0 ? BACKEND_OK : BACKEND_DEAD;
}

/*
 * Periodic job: check if the backend passed as argument is alive.
 * If so, return it to the pool of backends.  Otherwise, reschedule
 * itself for alive_to seconds later.
 */
static void
touch_be (void *data)
{
  BACKEND *be = data;
  char buf[MAXBUF];

  if (!be->alive)
    {
      if (backend_probe (be) == BACKEND_OK)
	{
	  be->alive = 1;
	  str_be (buf, sizeof (buf), be);
	  logmsg (LOG_NOTICE, "Backend %s resurrect", buf);
	  if (!be->disabled)
	    {
	      pthread_mutex_lock (&be->service->mut);
	      be->service->tot_pri += be->priority;
	      pthread_mutex_unlock (&be->service->mut);
	    }
	}
      else
	job_enqueue_after_unlocked (alive_to, touch_be, be);
    }
}

#if ! SET_DH_AUTO
static pthread_mutex_t RSA_mut;	/* mutex for RSA keygen */
static RSA *RSA512_keys[N_RSA_KEYS];	/* ephemeral RSA keys */
static RSA *RSA1024_keys[N_RSA_KEYS];	/* ephemeral RSA keys */

/*
 * return a pre-generated RSA key
 */
static RSA *
RSA_tmp_callback ( /* not used */ SSL * ssl, /* not used */ int is_export,
		  int keylength)
{
  RSA *res;
  int ret_val;

  if ((ret_val = pthread_mutex_lock (&RSA_mut)) != 0)
    logmsg (LOG_WARNING, "RSA_tmp_callback() lock: %s", strerror (ret_val));
  res = (keylength <= 512) ? RSA512_keys[rand () % N_RSA_KEYS]
			   : RSA1024_keys[rand () % N_RSA_KEYS];
  if ((ret_val = pthread_mutex_unlock (&RSA_mut)) != 0)
    logmsg (LOG_WARNING, "RSA_tmp_callback() unlock: %s", strerror (ret_val));
  return res;
}

static int
generate_key (RSA ** ret_rsa, unsigned long bits)
{
  int rc = 0;
  RSA *rsa;

  rsa = RSA_new ();
  if (rsa)
    {
      BIGNUM *bne = BN_new ();
      if (BN_set_word (bne, RSA_F4))
	rc = RSA_generate_key_ex (rsa, bits, bne, NULL);
      BN_free (bne);
      if (rc)
	*ret_rsa = rsa;
      else
	RSA_free (rsa);
    }
  return rc;
}

/*
 * Periodically regenerate ephemeral RSA keys
 * runs every T_RSA_KEYS seconds
 */
static void
do_RSAgen (void *unused)
{
  int n, ret_val;
  RSA *t_RSA512_keys[N_RSA_KEYS];
  RSA *t_RSA1024_keys[N_RSA_KEYS];

  /* Re-arm the job */
  job_enqueue_after_unlocked (T_RSA_KEYS, do_RSAgen, NULL);

  for (n = 0; n < N_RSA_KEYS; n++)
    {
      /* FIXME: Error handling */
      generate_key (&t_RSA512_keys[n], 512);
      generate_key (&t_RSA1024_keys[n], 1024);
    }
  if ((ret_val = pthread_mutex_lock (&RSA_mut)) != 0)
    logmsg (LOG_WARNING, "thr_RSAgen() lock: %s", strerror (ret_val));
  for (n = 0; n < N_RSA_KEYS; n++)
    {
      RSA_free (RSA512_keys[n]);
      RSA512_keys[n] = t_RSA512_keys[n];
      RSA_free (RSA1024_keys[n]);
      RSA1024_keys[n] = t_RSA1024_keys[n];
    }
  if ((ret_val = pthread_mutex_unlock (&RSA_mut)) != 0)
    logmsg (LOG_WARNING, "thr_RSAgen() unlock: %s", strerror (ret_val));
}

#include    "dh.h"
static DH *DH512_params, *DHALT_params;

static DH *
DH_tmp_callback ( /* not used */ SSL * s, /* not used */ int is_export,
		 int keylength)
{
  return keylength == 512 ? DH512_params : DHALT_params;
}

/*
 * initialise RSA_mut and keys
 */
void
init_rsa (void)
{
  int n;

  /*
   * Pre-generate ephemeral RSA keys
   */
  for (n = 0; n < N_RSA_KEYS; n++)
    {
      if (!generate_key (&RSA512_keys[n], 512))
	{
	  logmsg (LOG_WARNING, "RSA_generate(%d, 512) failed", n);
	  return;
	}
      if (!generate_key (&RSA1024_keys[n], 1024))
	{
	  logmsg (LOG_WARNING, "RSA_generate(%d, 1024) failed", n);
	  return;
	}
    }
  /* pthread_mutex_init() always returns 0 */
  pthread_mutex_init (&RSA_mut, NULL);

  DH512_params = get_dh512 ();
#if DH_LEN == 1024
  DHALT_params = get_dh1024 ();
#else
  DHALT_params = get_dh2048 ();
#endif
  return;
}

#ifndef OPENSSL_NO_ECDH
static int EC_nid = NID_X9_62_prime256v1;
#endif

int
set_ECDHCurve (char *name)
{
  int n;

  if ((n = OBJ_sn2nid (name)) == 0)
    return -1;
  EC_nid = n;
  return 0;
}

void
POUND_SSL_CTX_init (SSL_CTX *ctx)
{
  SSL_CTX_set_tmp_rsa_callback (ctx, RSA_tmp_callback);
  SSL_CTX_set_tmp_dh_callback (ctx, DH_tmp_callback);
#ifndef OPENSSL_NO_ECDH
  /* This generates a EC_KEY structure with no key, but a group defined */
  EC_KEY *ecdh;
  if ((ecdh = EC_KEY_new_by_curve_name (EC_nid)) == NULL)
    {
      logmsg (LOG_ERR, "Unable to generate temp ECDH key");
      exit (1);
    }
  SSL_CTX_set_tmp_ecdh (ctx, ecdh);
  SSL_CTX_set_options (ctx, SSL_OP_SINGLE_ECDH_USE);
  EC_KEY_free (ecdh);
#endif
}
#else /* SET_DH_AUTO == 1 */
void
POUND_SSL_CTX_init (SSL_CTX *ctx)
{
  SSL_CTX_set_dh_auto (ctx, 1);
}
#endif

/* Periodic jobs */
typedef struct job
{
  struct timespec ts;
  void (*func) (void *);
  void *data;
  DLIST_ENTRY (job) link;
} JOB;

typedef DLIST_HEAD (,job) JOB_HEAD;
static JOB_HEAD job_head = DLIST_HEAD_INITIALIZER (job_head);
static pthread_mutex_t job_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t job_cond = PTHREAD_COND_INITIALIZER;

static JOB *
job_alloc (struct timespec const *ts, void (*func) (void *), void *data)
{
  JOB *job;

  XZALLOC (job);
  job->ts = *ts;
  job->func = func;
  job->data = data;
  return job;
}

static void
job_arm_unlocked (JOB *job)
{
  JOB *t;

  DLIST_FOREACH (t, &job_head, link)
    {
      if (timespec_cmp (&job->ts, &t->ts) < 0)
	break;
    }

  DLIST_INSERT_BEFORE (&job_head, t, job, link);

  if (DLIST_PREV (job, link) == NULL)
    pthread_cond_broadcast (&job_cond);
}

void
job_enqueue_unlocked (struct timespec const *ts, void (*func) (void *), void *data)
{
  job_arm_unlocked (job_alloc (ts, func, data));
}

void
job_enqueue (struct timespec const *ts, void (*func) (void *), void *data)
{
  pthread_mutex_lock (&job_mutex);
  job_enqueue_unlocked (ts, func, data);
  pthread_mutex_unlock (&job_mutex);
}

void
job_enqueue_after_unlocked (unsigned t, void (*func) (void *), void *data)
{
  struct timespec ts;
  clock_gettime (CLOCK_REALTIME, &ts);
  ts.tv_sec += t;
  job_enqueue_unlocked (&ts, func, data);
}

void
job_enqueue_after (unsigned t, void (*func) (void *), void *data)
{
  pthread_mutex_lock (&job_mutex);
  job_enqueue_after_unlocked (t, func, data);
  pthread_mutex_unlock (&job_mutex);
}

void
job_rearm_unlocked (struct timespec *ts, void (*func) (void *), void *data)
{
  JOB *job, *tmp;

  DLIST_FOREACH_SAFE (job, tmp, &job_head, link)
    {
      if (job->func == func && job->data == data)
	{
	  DLIST_REMOVE (&job_head, job, link);
	  job->ts = *ts;
	  job_arm_unlocked (job);
	  return;
	}
    }
  job_arm_unlocked (job_alloc (ts, func, data));
}

void
job_rearm (struct timespec *ts, void (*func) (void *), void *data)
{
  pthread_mutex_lock (&job_mutex);
  job_rearm_unlocked (ts, func, data);
  pthread_mutex_unlock (&job_mutex);
}

static void
timer_cleanup (void *ptr)
{
  pthread_mutex_unlock (&job_mutex);
}

/*
 * run periodic functions:
 */
void *
thr_timer (void *arg)
{
  /* Seed the job queue */
#if ! SET_DH_AUTO
  init_rsa ();
  job_enqueue_after (T_RSA_KEYS, do_RSAgen, NULL);
#endif

  pthread_mutex_lock (&job_mutex);
  pthread_cleanup_push (timer_cleanup, NULL);

  for (;;)
    {
      int rc;
      JOB *job;

      if (DLIST_EMPTY (&job_head))
	{
	  pthread_cond_wait (&job_cond, &job_mutex);
	  continue;
	}

      job = DLIST_FIRST (&job_head);

      rc = pthread_cond_timedwait (&job_cond, &job_mutex, &job->ts);
      if (rc == 0)
	continue;
      if (rc != ETIMEDOUT)
	{
	  logmsg (LOG_CRIT, "unexpected error from pthread_cond_timedwait: %s",
		  strerror (errno));
	  exit (1);
	}

      if (job != DLIST_FIRST (&job_head))
	/* Job was removed or its time changed */
	continue;

      DLIST_SHIFT (&job_head, link);

      job->func (job->data);
      free (job);
    }
  pthread_cleanup_pop (1);
}

typedef struct
{
  int control_sock;
  BACKEND_HEAD *backends;
} DUMP_ARG;

static void
dump_session (int control_sock, SESSION *t, BACKEND_HEAD * const backends)
{
  BACKEND *be, *bep = t->backend;
  int n_be, sz;

  n_be = 0;
  SLIST_FOREACH (be, backends, next)
    {
      if (be == bep)
	break;
      n_be++;
    }
  if (!be)
    /* should NEVER happen */
    n_be = 0;
  if (write (control_sock, t, sizeof (SESSION)) == -1)
    {
      logmsg (LOG_ERR, "%s:%d: %s() write: %s", __FILE__, __LINE__, __func__,
	      strerror (errno));
      return;
    }
  if (write (control_sock, &n_be, sizeof (n_be)) == -1)
    {
      logmsg (LOG_ERR, "%s:%d: %s() write: %s", __FILE__, __LINE__, __func__,
	      strerror (errno));
      return;
    }
  sz = strlen (t->key);
  if (write (control_sock, &sz, sizeof (sz)) == -1)
    {
      logmsg (LOG_ERR, "%s:%d: %s() write: %s", __FILE__, __LINE__, __func__,
	      strerror (errno));
      return;
    }
  if (write (control_sock, t->key, sz) == -1)
    {
      logmsg (LOG_ERR, "%s:%d: %s() write: %s", __FILE__, __LINE__, __func__,
	      strerror (errno));
      return;
    }
}

/*
 * write sessions to the control socket
 */
static void
dump_session_table (const int control_sock, SESSION_TABLE *const tab,
		    BACKEND_HEAD * const backends)
{
  SESSION *sess;

  if (tab)
    DLIST_FOREACH (sess, &tab->head, link)
      dump_session (control_sock, sess, backends);
}

/*
 * given a command, select a listener
 */
static LISTENER *
sel_lstn (const CTRL_CMD * cmd)
{
  LISTENER *lstn;
  int i = 0;

  if (cmd->listener < 0)
    return NULL;
  SLIST_FOREACH (lstn, &listeners, next)
    {
      if (i == cmd->listener)
	return lstn;
      i++;
    }
  return lstn;
}

/*
 * given a command, select a service
 */
static SERVICE *
sel_svc (const CTRL_CMD *cmd)
{
  SERVICE_HEAD *head;
  SERVICE *svc;
  LISTENER *lstn;
  int i;

  if (cmd->listener < 0)
    {
      head = &services;
    }
  else
    {
      if ((lstn = sel_lstn (cmd)) == NULL)
	return NULL;
      head = &lstn->services;
    }
  i = 0;
  SLIST_FOREACH (svc, head, next)
    {
      if (i == cmd->service)
	return svc;
      i++;
    }
  return NULL;
}

/*
 * given a command, select a back-end
 */
static BACKEND *
sel_be (const CTRL_CMD * cmd)
{
  BACKEND *be;
  SERVICE *svc;
  int i;

  if ((svc = sel_svc (cmd)) == NULL)
    return NULL;
  i = 0;
  SLIST_FOREACH (be, &svc->backends, next)
    {
      if (i == cmd->backend)
	break;
      i++;
    }
  return be;
}

static int
do_list (int ctl)
{
  int n;
  LISTENER *lstn, dummy_lstn;
  SERVICE *svc, dummy_svc;
  BACKEND *be, dummy_be;
  SESSION dummy_sess;
  int rc;

  memset (&dummy_lstn, 0, sizeof (dummy_lstn));
  dummy_lstn.disabled = -1;
  memset (&dummy_svc, 0, sizeof (dummy_svc));
  dummy_svc.disabled = -1;
  memset (&dummy_be, 0, sizeof (dummy_be));
  dummy_be.disabled = -1;
  memset (&dummy_sess, 0, sizeof (dummy_sess));
  dummy_sess.backend = NULL;

  n = get_thr_qlen ();
  if (write (ctl, (void *) &n, sizeof (n)) == -1)
    return -1;
  SLIST_FOREACH (lstn, &listeners, next)
    {
      if (write (ctl, (void *) lstn, sizeof (LISTENER)) == -1)
	return -1;
      if (write (ctl, lstn->addr.ai_addr, lstn->addr.ai_addrlen) == -1)
	return -1;
      SLIST_FOREACH (svc, &lstn->services, next)
	{
	  if (write (ctl, (void *) svc, sizeof (SERVICE)) == -1)
	    return -1;
	  SLIST_FOREACH (be, &svc->backends, next)
	    {
	      if (write (ctl, (void *) be, sizeof (BACKEND)) == -1)
		return -1;
	      if (write (ctl, be->addr.ai_addr, be->addr.ai_addrlen) == -1)
		return -1;
	    }
	  if (write (ctl, (void *) &dummy_be, sizeof (BACKEND)) == -1)
	    return -1;
	  if ((rc = pthread_mutex_lock (&svc->mut)) != 0)
	    logmsg (LOG_WARNING, "thr_control() lock: %s", strerror (rc));
	  else
	    {
	      dump_session_table (ctl, svc->sessions, &svc->backends);
	      if ((rc = pthread_mutex_unlock (&svc->mut)) != 0)
		logmsg (LOG_WARNING, "thr_control() unlock: %s",
			strerror (rc));
	    }
	  if (write (ctl, (void *) &dummy_sess, sizeof (SESSION)) == -1)
	    return -1;
	}
      if (write (ctl, (void *) &dummy_svc, sizeof (SERVICE)) == -1)
	return -1;
    }

  if (write (ctl, (void *) &dummy_lstn, sizeof (LISTENER)) == -1)
    return -1;

  SLIST_FOREACH (svc, &services, next)
    {
      if (write (ctl, (void *) svc, sizeof (SERVICE)) == -1)
	return -1;
      SLIST_FOREACH (be, &svc->backends, next)
	{
	  if (write (ctl, (void *) be, sizeof (BACKEND)) == -1 ||
	      write (ctl, be->addr.ai_addr, be->addr.ai_addrlen) == -1)
	    return -1;
	}
      if (write (ctl, (void *) &dummy_be, sizeof (BACKEND)) == -1)
	return -1;

      if ((rc = pthread_mutex_lock (&svc->mut)) != 0)
	logmsg (LOG_WARNING, "thr_control() lock: %s", strerror (rc));
      else
	{
	  dump_session_table (ctl, svc->sessions, &svc->backends);
	  if ((rc = pthread_mutex_unlock (&svc->mut)) != 0)
	    logmsg (LOG_WARNING, "thr_control() unlock: %s", strerror (rc));
	}
      if (write (ctl, (void *) &dummy_sess, sizeof (SESSION)) == -1)
	return -1;
    }
  if (write (ctl, (void *) &dummy_svc, sizeof (SERVICE)) == -1)
    return -1;
  return 0;
}

/*
 * The controlling thread
 * listens to client requests and calls the appropriate functions
 */
void *
thr_control (void *arg)
{
  CTRL_CMD cmd;
  int ctl, rc;
  LISTENER *lstn;
  SERVICE *svc;
  BACKEND *be;

  /* just to be safe */
  if (control_sock < 0)
    return NULL;
  for (;;)
    {
      struct sockaddr sa;
      socklen_t len = sizeof (sa);
      struct pollfd polls;

      polls.fd = control_sock;
      polls.events = POLLIN | POLLPRI;
      polls.revents = 0;
      if (poll (&polls, 1, -1) < 0)
	{
	  logmsg (LOG_WARNING, "thr_control() poll: %s", strerror (errno));
	  continue;
	}
      if ((ctl = accept (control_sock, &sa, &len)) < 0)
	{
	  logmsg (LOG_WARNING, "thr_control() accept: %s", strerror (errno));
	  continue;
	}
      if (read (ctl, &cmd, sizeof (cmd)) != sizeof (cmd))
	{
	  logmsg (LOG_WARNING, "thr_control() read: %s", strerror (errno));
	  continue;
	}
      switch (cmd.cmd)
	{
	case CTRL_LST:
	  /* logmsg(LOG_INFO, "thr_control() list"); */
	  if (do_list (ctl))
	    {
	      logmsg (LOG_ERR, "do_list: write: %s", strerror (errno));
	    }
	  break;

	case CTRL_EN_LSTN:
	  if ((lstn = sel_lstn (&cmd)) == NULL)
	    logmsg (LOG_INFO, "thr_control() bad listener %d", cmd.listener);
	  else
	    lstn->disabled = 0;
	  break;

	case CTRL_DE_LSTN:
	  if ((lstn = sel_lstn (&cmd)) == NULL)
	    logmsg (LOG_INFO, "thr_control() bad listener %d", cmd.listener);
	  else
	    lstn->disabled = 1;
	  break;

	case CTRL_EN_SVC:
	  if ((svc = sel_svc (&cmd)) == NULL)
	    logmsg (LOG_INFO, "thr_control() bad service %d/%d", cmd.listener,
		    cmd.service);
	  else
	    svc->disabled = 0;
	  break;

	case CTRL_DE_SVC:
	  if ((svc = sel_svc (&cmd)) == NULL)
	    logmsg (LOG_INFO, "thr_control() bad service %d/%d", cmd.listener,
		    cmd.service);
	  else
	    svc->disabled = 1;
	  break;

	case CTRL_EN_BE:
	  if ((svc = sel_svc (&cmd)) == NULL)
	    {
	      logmsg (LOG_INFO, "thr_control() bad service %d/%d",
		      cmd.listener, cmd.service);
	      break;
	    }
	  if ((be = sel_be (&cmd)) == NULL)
	    logmsg (LOG_INFO, "thr_control() bad backend %d/%d/%d",
		    cmd.listener, cmd.service, cmd.backend);
	  else
	    kill_be (svc, be, BE_ENABLE);
	  break;

	case CTRL_DE_BE:
	  if ((svc = sel_svc (&cmd)) == NULL)
	    {
	      logmsg (LOG_INFO, "thr_control() bad service %d/%d",
		      cmd.listener, cmd.service);
	      break;
	    }
	  if ((be = sel_be (&cmd)) == NULL)
	    logmsg (LOG_INFO, "thr_control() bad backend %d/%d/%d",
		    cmd.listener, cmd.service, cmd.backend);
	  else
	    kill_be (svc, be, BE_DISABLE);
	  break;

	case CTRL_ADD_SESS:
	  if ((svc = sel_svc (&cmd)) == NULL)
	    {
	      logmsg (LOG_INFO, "thr_control() bad service %d/%d",
		      cmd.listener, cmd.service);
	      break;
	    }
	  if ((be = sel_be (&cmd)) == NULL)
	    {
	      logmsg (LOG_INFO, "thr_control() bad back-end %d/%d",
		      cmd.listener, cmd.service);
	      break;
	    }
	  if ((rc = pthread_mutex_lock (&svc->mut)) != 0)
	    logmsg (LOG_WARNING, "thr_control() add session lock: %s",
		    strerror (rc));
	  service_session_add (svc, cmd.key, be);
	  if ((rc = pthread_mutex_unlock (&svc->mut)) != 0)
	    logmsg (LOG_WARNING,
		    "thoriginalfiler_control() add session unlock: %s",
		    strerror (rc));
	  break;

	case CTRL_DEL_SESS:
	  if ((svc = sel_svc (&cmd)) == NULL)
	    {
	      logmsg (LOG_INFO, "thr_control() bad service %d/%d",
		      cmd.listener, cmd.service);
	      break;
	    }
	  if ((rc = pthread_mutex_lock (&svc->mut)) != 0)
	    logmsg (LOG_WARNING, "thr_control() del session lock: %s",
		    strerror (rc));
	  service_session_remove_by_key (svc, cmd.key);
	  if ((rc = pthread_mutex_unlock (&svc->mut)) != 0)
	    logmsg (LOG_WARNING, "thr_control() del session unlock: %s",
		    strerror (rc));
	  break;

	default:
	  logmsg (LOG_WARNING, "thr_control() unknown command");
	  break;
	}
      close (ctl);
    }
}

#ifndef SSL3_ST_SR_CLNT_HELLO_A
# define SSL3_ST_SR_CLNT_HELLO_A (0x110|SSL_ST_ACCEPT)
#endif
#ifndef SSL23_ST_SR_CLNT_HELLO_A
# define SSL23_ST_SR_CLNT_HELLO_A (0x210|SSL_ST_ACCEPT)
#endif

void
SSLINFO_callback (const SSL * ssl, int where, int rc)
{
  RENEG_STATE *reneg_state;

  /* Get our thr_arg where we're tracking this connection info */
  if ((reneg_state = (RENEG_STATE *) SSL_get_app_data (ssl)) == NULL)
    return;

  /*
   * If we're rejecting renegotiations, move to ABORT if Client Hello
   * is being read.
   */
  if ((where & SSL_CB_ACCEPT_LOOP) && *reneg_state == RENEG_REJECT)
    {
      int state;

      state = SSL_get_state (ssl);
      if (state == SSL3_ST_SR_CLNT_HELLO_A
	  || state == SSL23_ST_SR_CLNT_HELLO_A)
	{
	  *reneg_state = RENEG_ABORT;
	  logmsg (LOG_WARNING, "rejecting client initiated renegotiation");
	}
    }
  else if (where & SSL_CB_HANDSHAKE_DONE && *reneg_state == RENEG_INIT)
    {
      // Reject any followup renegotiations
      *reneg_state = RENEG_REJECT;
    }
}
