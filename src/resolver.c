/*
 * DNS resolver for pound.
 * Copyright (C) 2024 Sergey Poznyakoff
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
#include <adns.h>
#include <assert.h>
#include "resolver.h"

/* Global parameters. */
static struct resolver_config conf;

void
resolver_set_config (struct resolver_config *newcfg)
{
  conf = *newcfg;
}

static struct dns_response *
dns_response_alloc (enum dns_resp_type type, size_t count)
{
  struct dns_response *resp;

  if ((resp = calloc (1, sizeof (*resp))) != NULL)
    {
      if ((resp->addr = calloc (count, sizeof (resp->addr[0]))) != NULL)
	{
	  resp->type = type;
	  resp->count = count;
	}
      else
	{
	  free (resp);
	  resp = NULL;
	}
    }
  return resp;
}

void
dns_response_free (struct dns_response *resp)
{
  switch (resp->type)
    {
    case dns_resp_addr:
      free (resp->addr);
      break;

    case dns_resp_srv:
      free (resp->srv);
      break;

    case dns_resp_none:
      break;
    }
  free (resp);
}

#define DEFAULT_QFLAGS \
	(adns_qf_cname_loose | \
	 adns_qf_quoteok_query | \
	 adns_qf_quoteok_cname | \
	 adns_qf_quoteok_anshost)

static void
dns_log_cb (adns_state ads, void *logfndata, const char *fmt, va_list ap)
{
  struct stringbuf *sb = logfndata;
  int rc = stringbuf_vprintf (sb, fmt, ap);
  if (rc)
    stringbuf_reset (sb);
  else
    {
      char *p = memchr (stringbuf_value (sb), '\n', stringbuf_len (sb));
      if (p != NULL)
	{
	  *p++ = 0;
	  logmsg (LOG_ERR, "%s", stringbuf_value (sb));
	  stringbuf_consume (sb, p - stringbuf_value (sb));
	}
    }
}

static pthread_key_t dns_state_key;
static pthread_once_t dns_state_key_once = PTHREAD_ONCE_INIT;

struct thread_dns_state
{
  adns_state state;
  struct stringbuf sb;
};

static void
dns_state_free (void *f)
{
  if (f)
    {
      struct thread_dns_state *s = f;
      adns_finish (s->state);
      stringbuf_free (&s->sb);
      free (f);
    }
}

static void
dns_state_key_create (void)
{
  pthread_key_create (&dns_state_key, dns_state_free);
}

static char *
slurp_file (char const *filename)
{
  struct stat st;
  char *buf;
  int fd;
  int pos;
  int err;
  
  if (stat (filename, &st))
    return NULL;

  if (st.st_size > ((size_t)~0))
    {
      errno = E2BIG;
      return NULL;
    }
  
  if ((buf = calloc (1, st.st_size + 1)) == NULL)
    return NULL;

  err = 0;
  if ((fd = open (filename, O_RDONLY)) == -1)
    {
      err = errno;
    }
  else
    {
      for (pos = 0; pos < st.st_size; )
	{
	  int n = read (fd, buf + pos, st.st_size - pos);
	  if (n == 0)
	    break;
	  if (n == -1)
	    {
	      err = errno;
	      break;
	    }
	  pos += n;
	}
      close (fd);
    }
  if (err)
    {
      free (buf);
      buf = NULL;
      errno = err;
    }
  return buf;
}

static struct thread_dns_state *
dns_state_create (void)
{
  int flags = adns_if_nosigpipe;
  struct thread_dns_state *ds;

  ds = calloc (1, sizeof (*ds));
  if (!ds)
    lognomem ();
  else
    {
      int rc;
      char *conftext = NULL;

      if (conf.debug)
	flags |= adns_if_debug;
      stringbuf_init_log (&ds->sb);
      if (conf.config_file)
	{
	  conftext = slurp_file (conf.config_file);
	  if (conftext == NULL)
	    {
	      logmsg (LOG_ERR, "%s: %s",
		      conf.config_file,
		      (errno == E2BIG) ? "file too big" : strerror (errno));
	    }
	}
      rc = adns_init_logfn (&ds->state, flags, conftext,
			    dns_log_cb, &ds->sb);
      free (conftext);
      if (rc)
	{
	  logmsg (LOG_ERR, "can't initialize DNS state: %s", strerror (rc));
	  stringbuf_free (&ds->sb);
	  free (ds);
	  ds = NULL;
	}
    }
  return ds;
}

static adns_state *
dns_get_state (void)
{
  struct thread_dns_state *state;

  pthread_once (&dns_state_key_once, dns_state_key_create);
  state = pthread_getspecific (dns_state_key);
  if (!state)
    {
      state = dns_state_create ();
      if (!state)
	exit (1);
      pthread_setspecific (dns_state_key, state);
    }
  return &state->state;
}

/* Table of correspondence between ADNS status codes and dns status.
   Values are increased by 1 to be able to tell whether the entry is
   initialized or not. */
int adns_to_dns_tab[] = {
#define STAT(s) ((s)+1)
  [adns_s_ok]                  = STAT (dns_success),

  [adns_s_nomemory]            = STAT (dns_failure),
  [adns_s_unknownrrtype]       = STAT (dns_failure),
  [adns_s_systemfail]          = STAT (dns_failure),

  /* remotely induced errors, detected locally */
  [adns_s_timeout]             = STAT (dns_temp_failure),
  [adns_s_allservfail]         = STAT (dns_temp_failure),
  [adns_s_norecurse]           = STAT (dns_temp_failure),
  [adns_s_invalidresponse]     = STAT (dns_failure),
  [adns_s_unknownformat]       = STAT (dns_failure),

  /* remotely induced errors), reported by remote server to us */
  [adns_s_rcodeservfail]       = STAT (dns_not_found),
  [adns_s_rcodeformaterror]    = STAT (dns_not_found),
  [adns_s_rcodenotimplemented] = STAT (dns_not_found),
  [adns_s_rcoderefused]        = STAT (dns_not_found),
  [adns_s_rcodeunknown]        = STAT (dns_not_found),

  /* remote configuration errors */
  [adns_s_inconsistent]        = STAT (dns_not_found),
  [adns_s_prohibitedcname]     = STAT (dns_not_found),
  [adns_s_answerdomaininvalid] = STAT (dns_not_found),
  [adns_s_answerdomaintoolong] = STAT (dns_not_found),
  [adns_s_invaliddata]         = STAT (dns_not_found),

  /* permanent problems with the query */
  [adns_s_querydomainwrong]    = STAT (dns_failure),
  [adns_s_querydomaininvalid]  = STAT (dns_failure),
  [adns_s_querydomaintoolong]  = STAT (dns_failure),

  /* permanent errors */
  [adns_s_nxdomain]            = STAT (dns_not_found),
  [adns_s_nodata]              = STAT (dns_not_found),
#undef STAT
};

/* Convert ADNS status code E to DNS status. */
static int
adns_to_dns_status (int e)
{
  /* If it is negative, fail right away */
  if (e < 0)
    return dns_failure;
  /* Look up in table. */
  if (e < sizeof (adns_to_dns_tab) / sizeof (adns_to_dns_tab[0]))
    {
      int r;

      if ((r = adns_to_dns_tab[e]) > 0)
		return r - 1;
    }
  /*
   * If not found in table, use adns_s_max_ constants to decide the
   * error class.
   */
  if (e < adns_s_max_localfail)
    return dns_failure;
  if (e < adns_s_max_remotefail)
    return dns_not_found;
  if (e < adns_s_max_tempfail)
    return dns_temp_failure;
  if (e < adns_s_max_misconfig)
    return dns_not_found;
  if (e < adns_s_max_misquery)
    return dns_not_found;
  return dns_not_found;
}

static int
errno_to_dns_status (int e)
{
  switch (e)
    {
    case 0:
      return dns_success;
    case EAGAIN:
#ifdef EINPROGRESS
    case EINPROGRESS:
#endif
#ifdef ETIMEDOUT
    case ETIMEDOUT:
#endif
      return dns_temp_failure;
    default:
      break;
    }
  return dns_failure;
}

typedef struct
{
  char name[1];
} CNAME_REF;

extern unsigned long strhash_ci (const char *c, size_t len);

static unsigned long
CNAME_REF_hash (const CNAME_REF *cp)
{
  return strhash_ci (cp->name, strlen (cp->name));
}

static int
CNAME_REF_cmp (const CNAME_REF *a, const CNAME_REF *b)
{
  return strcasecmp (a->name, b->name);
}

#define HT_TYPE CNAME_REF
#define HT_TYPE_HASH_FN_DEFINED 1
#define HT_TYPE_CMP_FN_DEFINED 1
#define HT_NO_DELETE
#include "ht.h"

static int
cname_install (CNAME_REF_HASH *hash, unsigned *n, char const *name)
{
  CNAME_REF *rec, *old;

  rec = malloc (sizeof (*rec));
  if (rec == NULL)
    return errno;
  strcpy (rec->name, name);
  if ((old = CNAME_REF_INSERT (hash, rec)) != NULL)
    {
      free (rec);
      return EEXIST;
    }
  ++*n;
  return 0;
}

/*
 * dns_query - look up a label NAME of RR type TYPE in the DNS.  Follow
 * CNAME chains of up to dns_max_cname_chain elements.  In other respects
 * the behavior is the same as that of adns_synchronous.
 *
 * FIXME: in the presence of a CNAME chain, this function does two
 * extra lookups, compared with the hypothetical libresolv implementation.
 * This is due to the specifics of libadns.
 */
static int
dns_query (const char *name, adns_rrtype type, adns_answer **ans_ret)
{
  adns_state *state = dns_get_state();
  adns_answer *ans = NULL, *cnans = NULL;
  int rc;

  /*
   * First, look up the requested RR type.  If the actual record is
   * a CNAME pointing to the requested RR, this will be handled by
   * adns due to adns_qf_cname_loose flag in DEFAULT_QFLAGS.
   *
   * If it is a CNAME pointing to a CNAME, this will result in the
   * first extra lookup (see FIXME above).
   */
  rc = adns_synchronous (*state, name, type, DEFAULT_QFLAGS, &ans);
  if (rc == 0 && ans->status == adns_s_prohibitedcname
      && conf.max_cname_chain > 1)
    {
      CNAME_REF_HASH *hash = CNAME_REF_HASH_NEW ();
      unsigned cname_count = 0;

      /* Record the queried name, first. */
      if ((rc = cname_install (hash, &cname_count, name)) == 0)
	{
	  /* Follow the CNAME chain. */
	  while (cname_count - 1 <= conf.max_cname_chain)
	    {
	      if ((rc = adns_synchronous (*state, name, adns_r_cname,
					  DEFAULT_QFLAGS, &cnans)))
		break;
	      if (cnans->status == adns_s_ok)
		{
		  /*
		   * CNAME found. Record it and continue.
		   */
		  rc = cname_install (hash, &cname_count, cnans->rrs.str[0]);
		  free (cnans);
		  if (rc)
		    {
		      if (rc == EEXIST)
			/*
			 * Loop detected.  The returned ans retains the
			 * adns_s_prohibitedcname status.
			 */
			rc = 0;
		      break;
		    }
		}
	      else if (cnans->status == adns_s_nodata)
		{
		  /*
		   * RR found, but has a different type.
		   * Look up the requested type using the last
		   * recorded name.  This accounts for second
		   * extra lookup.
		   */
		  free (cnans);
		  rc = adns_synchronous (*state, name, type, DEFAULT_QFLAGS, &ans);
		  break;
		}
	      else
		{
		  /*
		   * Another error.  Replace original answer with
		   * the last one.
		   */
		  free (ans);
		  ans = cnans;
		  break;
		}
	    }
	  CNAME_REF_HASH_FREE (hash);
	}
    }
  if (rc == 0)
    *ans_ret = ans;
  else
    free (ans);
  return adns_to_dns_status (rc);
}

static int
dns_lookup_internal (char const *name, int family, struct dns_response **presp)
{
  adns_answer *ans = NULL;
  int rr_type;
  int err, rc;
  struct dns_response *resp;
  
  switch (family)
    {
    case AF_INET:
      rr_type = adns_r_a;
      break;

    case AF_INET6:
      rr_type = adns_r_aaaa;
      break;

    default:
      abort (); // FIXME
    }

  err = dns_query (name, rr_type, &ans);
  if (err != 0)
    {
      rc = errno_to_dns_status (err);
      if (rc != dns_not_found)
	logmsg (LOG_ERR, "Querying for %s records of %s: %s",
		rr_type == adns_r_a ? "A" : "AAAA",
		name,
		strerror (err));
      return rc;
    }
  if (ans->status != adns_s_ok)
    {
      rc = adns_to_dns_status (ans->status);
      if (rc != dns_not_found)
	logmsg (LOG_ERR, "Querying for %s records of %s: %s",
		rr_type == adns_r_a ? "A" : "AAAA",
		name,
		adns_strerror (ans->status));
      
      free (ans);
      return rc;
    }

  rc = dns_success;
  resp = dns_response_alloc (dns_resp_addr, ans->nrrs);
  if (!resp)
    {
      lognomem ();
      rc = dns_failure;
    }
  else
    {
      if (ans->nrrs > 0)
	{
	  int i;

	  resp->expires = ans->expires;
	  for (i = 0; i < ans->nrrs; i++)
	    {
	      switch (family)
		{
		case AF_INET:
		  resp->addr[i].s_in.sin_family = AF_INET;
		  resp->addr[i].s_in.sin_port = 0;
		  resp->addr[i].s_in.sin_addr = ans->rrs.inaddr[i];
		  break;
		  
		case AF_INET6:
		  resp->addr[i].s_in6.sin6_family = AF_INET6;
		  resp->addr[i].s_in6.sin6_port = 0;
		  resp->addr[i].s_in6.sin6_addr = ans->rrs.in6addr[i];
		}
	    }
	}
    }

  free (ans);
  *presp = resp;
  return rc;
}

int
dns_lookup (char const *name, int family, struct dns_response **presp)
{
  int rc;
  struct dns_response *r4 = NULL, *r6 = NULL;
  
  switch (family)
    {
    case AF_INET:
    case AF_INET6:
      return dns_lookup_internal (name, family, presp);

    case AF_UNSPEC:
      break;

    default:
      abort();
    }

  rc = dns_lookup_internal (name, AF_INET, &r4);
  switch (dns_lookup_internal (name, AF_INET6, &r6))
    {
    case dns_success:
      rc = 0;
      break;

    case dns_not_found:
      if (rc != dns_success)
	return dns_not_found;
      break;

    case dns_temp_failure:
      if (rc != dns_success)
	return rc;

    case dns_failure:
      if (rc != dns_success)
	return dns_failure;
    }

  if (r4 == NULL)
    *presp = r6;
  else if (r6 == NULL)
    *presp = r4;
  else
    {
      struct dns_response *resp = dns_response_alloc (dns_resp_addr,
						      r4->count + r6->count);
      if (resp)
	{
	  int i, j;
	  resp->expires = r4->expires < r6->expires ? r4->expires : r6->expires;

	  for (i = j = 0; j < r4->count; i++, j++)
	    resp->addr[i] = r4->addr[j];
	  for (j = 0; j < r6->count; i++, j++)
	    resp->addr[i] = r6->addr[j];
	}
      *presp = resp;

      dns_response_free (r4);
      dns_response_free (r6);
    }
  return rc;
}
    
void
dns_addr_to_addrinfo (union dns_addr *da, struct addrinfo *ai)
{
  memset (ai, 0, sizeof (*ai));
  ai->ai_socktype = SOCK_STREAM;
  ai->ai_family = da->sa.sa_family;
  switch (da->sa.sa_family)
    {
    case AF_INET:
      ai->ai_addrlen = sizeof (struct sockaddr_in);
      break;
      
    case AF_INET6:
      ai->ai_addrlen = sizeof (struct sockaddr_in6);
      break;
      
    default:
      abort ();
    }
  ai->ai_addr = (struct sockaddr *) da;
}

static void service_matrix_update_backends (SERVICE *svc, BACKEND *mtx,
					    struct dns_response *resp);
static void job_resolver (void *arg, const struct timespec *ts);

/* Before calling, lock be->service! */
int
backend_matrix_init (BACKEND *be)
{
  int rc;
  struct dns_response *resp;
  struct timespec ts;
  
  rc = dns_lookup (be->v.mtx.hostname, be->v.mtx.family, &resp);
  switch (rc)
    {
    case dns_success:
      service_matrix_update_backends (be->service, be, resp);
      dns_response_free (resp);
      break;

    case dns_not_found:
    case dns_temp_failure:
      clock_gettime (CLOCK_REALTIME, &ts);
      ts.tv_sec += be->v.mtx.retry_interval
	              ? be->v.mtx.retry_interval : conf.retry_interval;
      ts.tv_nsec = 0;
      job_enqueue (&ts, job_resolver, be);
      break;
      
    case dns_failure:
      //FIXME
      return 1;
    }
  return 0;
}  

static void
job_resolver (void *arg, const struct timespec *ts)
{
  BACKEND *be = arg;
  backend_matrix_init (be);
}

unsigned long
djb_hash (const unsigned char *str, int length)
{
  unsigned long hash = 5381;
  int i;
  for (i = 0; i < length; i++, str++)
    hash = ((hash << 5) + hash) + (*str);
  return hash;
}

static unsigned long
BACKEND_hash (const BACKEND *b)
{
  unsigned char *p;
  int len = sockaddr_bytes (b->v.reg.addr.ai_addr, &p);
  return djb_hash (p, len);
}

static int
BACKEND_cmp (const BACKEND *a, const BACKEND *b)
{
  unsigned char *ap, *bp;
  int al = sockaddr_bytes (a->v.reg.addr.ai_addr, &ap);
  int bl = sockaddr_bytes (b->v.reg.addr.ai_addr, &bp);
  if (al != bl)
    return 1;
  return memcmp (ap, bp, al);
}

#define HT_TYPE BACKEND
#define HT_TYPE_HASH_FN_DEFINED 1
#define HT_TYPE_CMP_FN_DEFINED 1
#include "ht.h"

struct backend_table
{
  BACKEND_HASH *hash;
};

BACKEND_TABLE 
backend_table_new (void)
{
  BACKEND_TABLE bt = malloc (sizeof (*bt));
  if (!bt)
    lognomem ();
  else
    bt->hash = BACKEND_HASH_NEW ();
  return bt;
}

static inline BACKEND *
init_key (BACKEND *key, union dns_addr *addr)
{
  dns_addr_to_addrinfo (addr, &key->v.reg.addr);
  return key;
}

BACKEND *
backend_table_lookup (BACKEND_TABLE bt, union dns_addr *addr)
{
  BACKEND key;
  return BACKEND_RETRIEVE (bt->hash, init_key (&key, addr));
}

BACKEND *
backend_table_delete (BACKEND_TABLE bt, BACKEND *be)
{
  return BACKEND_DELETE (bt->hash, be);
}

void
backend_table_insert (BACKEND_TABLE bt, BACKEND *be)
{
  BACKEND_INSERT (bt->hash, be);
}

static inline void
backend_table_foreach (BACKEND_TABLE bt, void (*fn)(BACKEND *, void *),
		       void *data)
{
  BACKEND_FOREACH_SAFE (bt->hash, fn, data);
}

static void
backend_mark (BACKEND *be, void *data)
{
  pthread_mutex_lock (&be->mut);
  be->mark = *(int*)data;
  pthread_mutex_unlock (&be->mut);
}

static void
backend_sweep (BACKEND *be, void *data)
{ 
  BACKEND_TABLE tab = data;
  pthread_mutex_lock (&be->mut);
  if (be->mark)
    {
      assert (be->refcount > 0);
      /* Mark backend as disabled so it won't get more requests. */
      be->disabled = 1;
      /* Remove any sessions associated with it. */
      service_session_remove_by_backend (be->service, be);
      /*
       * Remove backend from the hash table, but don't schedule removal from
       * the list unless its decremented refcount is 0.  If not (that means
       * the backend is in use by one or more sessions), removal will be
       * scheduled later by backend_unref, when its refcount reaches zero.
       */
      backend_table_delete (tab, be);
      be->refcount--;
      if (be->refcount == 0)
	{
	  backend_schedule_removal (be);
	}
      be->mark = 0;
    }
  pthread_mutex_unlock (&be->mut);
}

static void
service_matrix_update_backends (SERVICE *svc, BACKEND *mtx,
				struct dns_response *resp)
{
  int i;
  int mark = 1;
  size_t n;
  struct timespec ts;

  if (mtx->disabled)
    return;
  
  /* Mark all generated backends. */
  backend_table_foreach (mtx->v.mtx.betab, backend_mark, &mark);
  
  mark = 0;
  switch (mtx->v.mtx.resolve_mode)
    {
    case bres_first:
      n = resp->count > 0 ? 1 : 0;
      break;

    case bres_all:
      n = resp->count;
      break;

    default:
      /* should not happen: bres_immediate handled elsewhere. */
      abort ();
    }
  
  for (i = 0; i < n; i++)
    {
      BACKEND *be = backend_table_lookup (mtx->v.mtx.betab, &resp->addr[i]);
      if (be)
	{
	  /* Backend didn't change.  Clear mark. */
	  backend_mark (be, &mark);
	}
      else
	{
	  struct addrinfo ai;
	  void *p;

	  /* Generate new backend. */
	  be = calloc (1, sizeof (*be));
	  if (!be)
	    {
	      lognomem ();
	      break;
	    }

	  dns_addr_to_addrinfo (&resp->addr[i], &ai);
	  p = malloc (ai.ai_addrlen);
	  if (!p)
	    {
	      lognomem ();
	      free (be);
	      break;
	    }
	  memcpy (p, ai.ai_addr, ai.ai_addrlen);
	  ai.ai_addr = p;
      	  backend_matrix_to_regular (&mtx->v.mtx, &ai, &be->v.reg);
	  be->service = mtx->service;
	  be->locus = mtx->locus;
	  be->locus_str = mtx->locus_str;
	  be->be_type = BE_REGULAR;
	  be->priority = mtx->priority;
	  be->disabled = mtx->disabled;
	  pthread_mutex_init (&be->mut, NULL);
	  be->refcount = 1;

	  /* Add it to the list of service backends and to the hash table. */
	  DLIST_PUSH (&svc->backends, be, link);
	  backend_table_insert (mtx->v.mtx.betab, be);
	}
    }

  /* Remove all unreferenced backends. */
  backend_table_foreach (mtx->v.mtx.betab, backend_sweep, mtx->v.mtx.betab);

  /* Reschedule next update. */
  ts.tv_sec = resp->expires + 1;
  ts.tv_nsec = 0;
  job_enqueue (&ts, job_resolver, mtx);
}

void
backend_matrix_disable (BACKEND *be, int disable_mode)
{
  if (disable_mode == BE_ENABLE)
    {
      if (be->disabled)
	{
	  be->disabled = 0;
	  pthread_mutex_lock (&be->service->mut);
	  backend_matrix_init (be);
	  pthread_mutex_unlock (&be->service->mut);
	}
    }
  else
    {
      /* For matrix backends, BE_DISABLE and BE_KILL are the same. */
      /* Mark all generated backends and remove associated sessions. */
      int mark = 1;
      backend_table_foreach (be->v.mtx.betab, backend_mark, &mark);
      /* Unreference all backends. */
      backend_table_foreach (be->v.mtx.betab, backend_sweep, be->v.mtx.betab);
      /* Mark matrix as disabled. */
      be->disabled = 1;
    }
}
