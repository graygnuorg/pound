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
#include "extern.h"
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
  int i;

  switch (resp->type)
    {
    case dns_resp_addr:
      free (resp->addr);
      break;

    case dns_resp_srv:
      for (i = 0; i < resp->count; i++)
	free (resp->srv[i].host);
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
      char *p;
      while ((p = memchr (stringbuf_value (sb), '\n', stringbuf_len (sb))))
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

      if (conf.debug)
	flags |= adns_if_debug;
      stringbuf_init_log (&ds->sb);
      rc = adns_init_logfn (&ds->state, flags, conf.config_text,
			    dns_log_cb, &ds->sb);
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
dns_generic_lookup (char const *name, adns_rrtype rrtype, char const *rrname,
		    int (*conv) (int, struct dns_response *, adns_answer *),
		    struct dns_response **presp)
{
  adns_answer *ans = NULL;
  int err, rc;
  struct dns_response *resp;
  enum dns_resp_type resp_type;

  switch (rrtype)
    {
    case adns_r_a:
    case adns_r_aaaa:
      resp_type = dns_resp_addr;
      break;

    case adns_r_srv_raw:
      resp_type = dns_resp_srv;
      break;

    default:
      abort ();
    }

  err = dns_query (name, rrtype, &ans);
  if (err != 0)
    {
      rc = errno_to_dns_status (err);
      if (rc != dns_not_found)
	logmsg (LOG_ERR, "Querying for %s records of %s: %s",
		rrname,
		name,
		strerror (err));
      return rc;
    }
  if (ans->status != adns_s_ok)
    {
      rc = adns_to_dns_status (ans->status);
      if (rc != dns_not_found)
	logmsg (LOG_ERR, "Querying for %s records of %s: %s",
		rrname,
		name,
		adns_strerror (ans->status));

      free (ans);
      return rc;
    }
  if (ans->nrrs == 0)
    {
      free (ans);
      return dns_not_found;
    }

  rc = dns_success;
  resp = dns_response_alloc (resp_type, ans->nrrs);
  if (!resp)
    {
      lognomem ();
      rc = dns_failure;
    }
  else
    {
      int i;

      resp->expires = ans->expires;
      for (i = 0; i < ans->nrrs; i++)
	{
	  if (conv (i, resp, ans))
	    {
	      resp->count = i;
	      dns_response_free (resp);
	      resp = NULL;
	      rc = dns_failure;
	      break;
	    }
	}
    }
  free (ans);
  *presp = resp;
  return rc;
}

static int
rr_a_conv (int i, struct dns_response *resp, adns_answer *ans)
{
  resp->addr[i].s_in.sin_family = AF_INET;
  resp->addr[i].s_in.sin_port = 0;
  resp->addr[i].s_in.sin_addr = ans->rrs.inaddr[i];
  return 0;
}

static int
rr_aaaa_conv (int i, struct dns_response *resp, adns_answer *ans)
{
  resp->addr[i].s_in6.sin6_family = AF_INET6;
  resp->addr[i].s_in6.sin6_port = 0;
  resp->addr[i].s_in6.sin6_addr = ans->rrs.in6addr[i];
  return 0;
}

static int
dns_generic_addr_lookup (char const *name, int family,
			 struct dns_response **presp)
{
  int rr_type;
  char const *rr_name;
  int (*rr_conv) (int, struct dns_response *, adns_answer *);

  switch (family)
    {
    case AF_INET:
      rr_type = adns_r_a;
      rr_name = "A";
      rr_conv = rr_a_conv;
      break;

    case AF_INET6:
      rr_type = adns_r_aaaa;
      rr_name = "AAAA";
      rr_conv = rr_aaaa_conv;
      break;

    default:
      abort (); // FIXME
    }

  return dns_generic_lookup (name, rr_type, rr_name, rr_conv, presp);
}

int
dns_addr_lookup (char const *name, int family, struct dns_response **presp)
{
  int rc;
  struct dns_response *r4 = NULL, *r6 = NULL;

  switch (family)
    {
    case AF_INET:
    case AF_INET6:
      return dns_generic_addr_lookup (name, family, presp);

    case AF_UNSPEC:
      break;

    default:
      abort();
    }

  rc = dns_generic_addr_lookup (name, AF_INET, &r4);
  switch (dns_generic_addr_lookup (name, AF_INET6, &r6))
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

	  *presp = resp;
	}
      else
	rc = dns_failure;

      dns_response_free (r4);
      dns_response_free (r6);
    }
  return rc;
}

static int
rr_srv_conv (int i, struct dns_response *resp, adns_answer *ans)
{
  resp->srv[i].priority = ans->rrs.srvraw[i].priority;
  resp->srv[i].weight = ans->rrs.srvraw[i].weight;
  resp->srv[i].port = ans->rrs.srvraw[i].port;
  if ((resp->srv[i].host = xstrdup (ans->rrs.srvraw[i].host)) == NULL)
    {
      lognomem ();
      return 1;
    }
  return 0;
}

static int
srv_cmp (void const *a, void const *b)
{
  struct dns_srv const *asrv = a;
  struct dns_srv const *bsrv = b;
  int rc = asrv->priority - bsrv->priority;
  if (rc == 0)
    {
      rc = bsrv->weight - asrv->weight;
      if (rc == 0)
	rc = strcasecmp (asrv->host, bsrv->host);
    }
  return rc;
}

int
dns_srv_lookup (char const *name, struct dns_response **presp)
{
  struct dns_response *resp;
  int rc = dns_generic_lookup (name, adns_r_srv_raw, "SRV", rr_srv_conv, &resp);
  if (rc == dns_success)
    {
      qsort (resp->srv, resp->count, sizeof (resp->srv[0]), srv_cmp);
      *presp = resp;
    }
  return rc;
}

static void
get_negative_expire_time (struct timespec *ts, BACKEND *be)
{
  clock_gettime (CLOCK_REALTIME, ts);
  ts->tv_sec += be->v.mtx.retry_interval
		      ? be->v.mtx.retry_interval : conf.retry_interval;
}

static struct dns_response *
dns_not_found_response_alloc (enum dns_resp_type type, BACKEND *be)
{
  struct dns_response *resp;

  if ((resp = calloc (1, sizeof (*resp))) != NULL)
    {
      struct timespec ts;
      
      resp->type = type;
      resp->count = 0;
      get_negative_expire_time (&ts, be);
      resp->expires = ts.tv_sec;
    }
  return resp;
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

static void service_matrix_addr_update_backends (SERVICE *svc, BACKEND *mtx,
						 struct dns_response *resp,
						 int locked);
static void service_matrix_srv_update_backends (SERVICE *svc, BACKEND *mtx,
						struct dns_response *resp);
static void job_resolver (enum job_ctl ctl, void *arg,
			  const struct timespec *ts);
static void start_backend_removal (SERVICE *svc);

int
backend_matrix_addr_init (BACKEND *be, int locked)
{
  int rc = 0;
  struct dns_response *resp;
  struct timespec ts;

  switch (dns_addr_lookup (be->v.mtx.hostname, be->v.mtx.family, &resp))
    {
    case dns_not_found:
      resp = dns_not_found_response_alloc (dns_resp_addr, be);
      if (!resp)
	{
	  rc = 1;
	  break;
	}
      /* fall through */
    case dns_success:
      service_matrix_addr_update_backends (be->service, be, resp, locked);
      dns_response_free (resp);
      break;

    case dns_temp_failure:
      get_negative_expire_time (&ts, be);
      job_enqueue (&ts, job_resolver, be);
      break;

    case dns_failure:
      //FIXME
      rc = 1;
    }
  return rc;
}

int
backend_matrix_srv_init (BACKEND *be)
{
  int rc = 0;
  struct dns_response *resp;
  struct timespec ts;

  switch (dns_srv_lookup (be->v.mtx.hostname, &resp))
    {
    case dns_not_found:
      resp = dns_not_found_response_alloc (dns_resp_srv, be);
      if (!resp)
	{
	  rc = 1;
	  break;
	}
      /* fall through */
    case dns_success:
      service_matrix_srv_update_backends (be->service, be, resp);
      dns_response_free (resp);
      break;

    case dns_temp_failure:
      get_negative_expire_time (&ts, be);
      job_enqueue (&ts, job_resolver, be);
      break;

    case dns_failure:
      //FIXME
      rc = 1;
    }
  return rc;
}

int
backend_matrix_init (BACKEND *be)
{
  int rc = -1;

  switch (be->v.mtx.resolve_mode)
    {
    case bres_first:
    case bres_all:
      rc = backend_matrix_addr_init (be, 0);
      break;

    case bres_srv:
      rc = backend_matrix_srv_init (be);
      break;

    default:
      abort ();
    }
  return rc;
}

static void
job_resolver (enum job_ctl ctl, void *arg, const struct timespec *ts)
{
  BACKEND *be = arg;
  if (ctl == job_ctl_run)
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
  if (b->be_type == BE_REGULAR)
    {
      unsigned char *p;
      int len = sockaddr_bytes (b->v.reg.addr.ai_addr, &p);
      return djb_hash (p, len);
    }
  else /* if (b->be_type == BE_MATRIX) */
    {
      return strhash_ci (b->v.mtx.hostname, strlen (b->v.mtx.hostname));
    }
}

static int
BACKEND_cmp (const BACKEND *a, const BACKEND *b)
{
  if (a->be_type == BE_REGULAR)
    {
      unsigned char *ap, *bp;
      int al = sockaddr_bytes (a->v.reg.addr.ai_addr, &ap);
      int bl = sockaddr_bytes (b->v.reg.addr.ai_addr, &bp);
      if (al != bl)
	return 1;
      return memcmp (ap, bp, al);
    }
  else /* if (a->be_type == BE_MATRIX) */
    return strcasecmp (a->v.mtx.hostname, b->v.mtx.hostname);
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

void
backend_table_free (BACKEND_TABLE bt)
{
  BACKEND_HASH_FREE (bt->hash);
  free (bt);
}

BACKEND *
backend_table_addr_lookup (BACKEND_TABLE bt, union dns_addr *addr)
{
  BACKEND key;
  key.be_type = BE_REGULAR;
  dns_addr_to_addrinfo (addr, &key.v.reg.addr);
  return BACKEND_RETRIEVE (bt->hash, &key);
}

BACKEND *
backend_table_hostname_lookup (BACKEND_TABLE bt, char const *hostname)
{
  BACKEND key;
  key.be_type = BE_MATRIX;
  key.v.mtx.hostname = (char*) hostname;
  return BACKEND_RETRIEVE (bt->hash, &key);
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
      SERVICE *svc = be->service;
      
      assert (be->refcount > 0);
      /* Mark backend as disabled so it won't get more requests. */
      be->disabled = 1;
      switch (be->be_type)
	{
	case BE_REGULAR:
	  {
	    BALANCER *balancer;
	    
	    /* Remove any sessions associated with it. */
	    service_session_remove_by_backend (svc, be);
	    /* Remove it from the balancer. */
	    balancer = be->balancer;
	    balancer_remove_backend (balancer, be);
	    if (DLIST_EMPTY (&balancer->backends))
	      {
		DLIST_REMOVE (&svc->backends, balancer, link);
		free (balancer);
	      }
	  }
	  break;

	case BE_MATRIX:
	  {
	    int mark = 1;
	    /* Cancel pending update job for that matrix. */
	    job_cancel (be->v.mtx.jid);
	    /* Schedule all regular backends for deletion. */
	    backend_table_foreach (be->v.mtx.betab, backend_mark, &mark);
	    backend_table_foreach (be->v.mtx.betab, backend_sweep,
				   be->v.mtx.betab);
	  }
	  break;

	default:
	  abort ();
	}

      /* If a load balancer stored this backend as current, reset it. */
      service_lb_reset (svc, be);
      
      /*
       * Remove backend from the hash table and decrement its refcount.
       */
      backend_table_delete (tab, be);
      be->refcount--;

      /* Add it to the list of removed backends. */
      DLIST_INSERT_TAIL (&svc->be_rem_head, be, link);
      
      be->mark = 0;
    }
  pthread_mutex_unlock (&be->mut);
}

static void
service_matrix_addr_update_backends (SERVICE *svc,
				     BACKEND *mtx,
				     struct dns_response *resp,
				     int locked)
{
  int i;
  int mark = 1;
  size_t n;
  struct timespec ts;
  BALANCER *balancer = balancer_list_get (&svc->backends, mtx->v.mtx.weight);

  if (!locked)
    {
      pthread_mutex_lock (&svc->mut);
      pthread_mutex_lock (&mtx->mut);
    }
  if (!mtx->disabled)
    {
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
	  BACKEND *be = backend_table_addr_lookup (mtx->v.mtx.betab,
						   &resp->addr[i]);
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
	      be->v.reg.parent = mtx;
	      
	      /* Add it to the list of service backends and to the hash
		 table. */
	      balancer_add_backend (balancer, be);
	      backend_table_insert (mtx->v.mtx.betab, be);
	    }
	}

      /* Remove all unreferenced backends. */
      backend_table_foreach (mtx->v.mtx.betab, backend_sweep, mtx->v.mtx.betab);
      balancer_recompute_pri_unlocked (balancer, NULL, NULL);

      if (!DLIST_EMPTY (&svc->be_rem_head))
	start_backend_removal (svc);
      
      /* Reschedule next update. */
      ts.tv_sec = resp->expires;
      ts.tv_nsec = 0;
      mtx->v.mtx.jid = job_enqueue (&ts, job_resolver, mtx);
    }
  if (!locked)
    {
      pthread_mutex_unlock (&mtx->mut);
      pthread_mutex_unlock (&svc->mut);
    }
}

static int
compute_priority (SERVICE *svc, struct dns_srv *srv, int total_weight)
{
  int result;

  switch (svc->balancer_algo)
    {
    case BALANCER_ALGO_RANDOM:
      result = srv->weight * 9 / total_weight;
      break;

    case BALANCER_ALGO_IWRR:
      result = srv->weight;
      break;

    default:
      abort ();
    }
  if (result <= 0)
    result = 1;
  return result;
}

static void
backend_set_prio (BACKEND *be, void *data)
{
  BACKEND *mtx = data;
  pthread_mutex_lock (&be->mut);
  be->priority = mtx->priority;
  pthread_mutex_unlock (&be->mut);
}

struct srv_stat
{
  int priority;
  int start;
  int count;
  unsigned long total_weight;
};

static int
analyze_srv_response (struct dns_response *resp, struct srv_stat **pstat)
{
  int i, j;
  int ngrp = 0;
  struct srv_stat *grp;
  int prio = -1;

  if (resp->count == 0)
    {
      *pstat = NULL;
      return 0;
    }
  
  /* Count SRV groups. */
  for (i = 0; i < resp->count; i++)
    if (prio != resp->srv[i].priority)
      {
	ngrp++;
	prio = resp->srv[i].priority;
      }

  /* Allocate statistics array. */
  if ((grp = calloc (ngrp, sizeof (grp[0]))) == NULL)
    return -1;

  /* Fill it in. */
  j = 0;
  prio = grp[j].priority = resp->srv[0].priority;
  for (i = 0; i < resp->count; i++)
    {
      if (prio != resp->srv[i].priority)
	{
	  j++;
	  prio = resp->srv[i].priority;
	  grp[j].priority = prio;
	  grp[j].start = i;
	}
      if (TOT_PRI_MAX - grp[j].total_weight > resp->srv[i].weight)
	{
	  grp[j].total_weight += resp->srv[i].weight;
	  grp[j].count++;
	}
      else
	{
	  logmsg (LOG_NOTICE,
		  "SRV record %d %d %d %s overflows total priority",
		  resp->srv[i].priority, resp->srv[i].weight,
		  resp->srv[i].port, resp->srv[i].host);
	  /* Skip rest of records with this priority. */
	  for (; i + 1 < resp->count; i++)
	    if (resp->srv[i].priority != prio)
	      break;
	}
    }

  *pstat = grp;
  return ngrp;
}

static void
service_matrix_srv_update_backends (SERVICE *svc, BACKEND *mtx,
				    struct dns_response *resp)
{
  int i;
  int nstat;
  struct srv_stat *stat;
  
  nstat = analyze_srv_response (resp, &stat);
  if (nstat < 0)
    return; //FIXME

  pthread_mutex_lock (&svc->mut);
  pthread_mutex_lock (&mtx->mut);
  if (!mtx->disabled)
    {
      int mark = 1;
      struct timespec ts;

      /* Mark all generated backends. */
      backend_table_foreach (mtx->v.mtx.betab, backend_mark, &mark);

      mark = 0;

      for (i = 0; i < nstat; i++)
	{
	  int j;

	  for (j = 0; j < stat[i].count; j++)
	    {
	      struct dns_srv *srv = &resp->srv[stat[i].start + j];
	      BACKEND *be = backend_table_hostname_lookup (mtx->v.mtx.betab,
							   srv->host);
	      if (be)
		{
		  int prio = compute_priority (svc, srv, stat[i].total_weight);
		  if (be->priority != prio)
		    {
		      /* Update priority of the matrix and all backends
			 produced by it. */
		      be->priority = prio;
		      backend_table_foreach (be->v.mtx.betab, backend_set_prio,
					     be);
		    }
		  be->mark = 0;
		}
	      else
		{
		  /*
		   * Backend doesn't exist.  Create new matrix backend using
		   * data from the SRV matrix and SRV RR.
		   */
		  be = calloc (1, sizeof (*be));
		  if (!be)
		    {
		      lognomem ();
		      break;
		    }
		  be->service = mtx->service;
		  be->locus = mtx->locus;
		  be->locus_str = mtx->locus_str;
		  be->be_type = BE_MATRIX;
		  be->priority = compute_priority (svc, srv,
						   stat->total_weight);
		  be->disabled = 0;
		  pthread_mutex_init (&be->mut, NULL);
		  be->refcount = 1;

		  be->v.mtx.hostname = strdup (srv->host);
		  if (!be->v.mtx.hostname)
		    {
		      lognomem ();
		      free (be);
		      break;
		    }
		  be->v.mtx.port = htons (srv->port);
		  be->v.mtx.family = mtx->v.mtx.family;
		  be->v.mtx.resolve_mode = bres_all;
		  be->v.mtx.retry_interval = mtx->v.mtx.retry_interval;
		  be->v.mtx.to = mtx->v.mtx.to;
		  be->v.mtx.conn_to = mtx->v.mtx.conn_to;
		  be->v.mtx.ws_to = mtx->v.mtx.ws_to;
		  be->v.mtx.ctx = mtx->v.mtx.ctx;
		  be->v.mtx.servername = mtx->v.mtx.servername;
		  be->v.mtx.betab = backend_table_new ();
		  if (!be->v.mtx.betab)
		    {
		      lognomem ();
		      free (be);
		      break;
		    }
		  be->v.mtx.weight = srv->priority;
		  be->v.mtx.parent = mtx;
		  
		  /*
		   * Trigger regular backend creation.
		   */
		  backend_matrix_addr_init (be, 1);

		  /* Add new matrix to the hash table. */
		  backend_table_insert (mtx->v.mtx.betab, be);

		  /*
		   * Notice, that subsidiary matrix backends are not added to
		   * the service backend list.  That would be senseless.
		   * This backend is here only to produce regular backends.
		   */
		}
	    }
	}
      
      /* Remove all unreferenced backends. */
      backend_table_foreach (mtx->v.mtx.betab, backend_sweep,
			     mtx->v.mtx.betab);

      /* Recompute service priorities. */
      service_recompute_pri_unlocked (svc, NULL, NULL);

      /* Reschedule next update. */
      ts.tv_sec = resp->expires;
      ts.tv_nsec = 0;
      mtx->v.mtx.jid = job_enqueue (&ts, job_resolver, mtx);
    }

  pthread_mutex_unlock (&mtx->mut);
  pthread_mutex_unlock (&svc->mut);
  
  free (stat);  
}

void
backend_matrix_disable (BACKEND *be, int disable_mode)
{
  if (disable_mode == BE_ENABLE)
    {
      if (be->disabled)
	{
	  be->disabled = 0;
	  backend_matrix_init (be);
	}
    }
  else
    {
      /* For matrix backends, BE_DISABLE and BE_KILL are the same. */
      /* Mark all generated backends. */
      int mark = 1;
      backend_table_foreach (be->v.mtx.betab, backend_mark, &mark);
      /* Unreference all backends. */
      backend_table_foreach (be->v.mtx.betab, backend_sweep, be->v.mtx.betab);
      /* Cancel pending job. */
      job_cancel (be->v.mtx.jid);
      /* Mark matrix as disabled. */
      be->disabled = 1;
      service_recompute_pri_unlocked (be->service, NULL, NULL);
    }
}

static void
backend_remover_cleanup (void *ptr)
{
  SERVICE *svc = ptr;
  pthread_mutex_unlock (&svc->mut);
}

static void
backend_release (BACKEND *be)
{
  switch (be->be_type)
    {
    case BE_REGULAR:
      free (be->v.reg.addr.ai_addr);
      break;

    case BE_MATRIX:
      free (be->v.mtx.hostname);
      backend_table_free (be->v.mtx.betab);
      break;

    default:
      abort ();
    }
  pthread_mutex_destroy (&be->mut);
  free (be);
}

static void *
thr_backend_remover (void *arg)
{
  SERVICE *svc = arg;
  pthread_mutex_lock (&svc->mut);
  pthread_cleanup_push (backend_remover_cleanup, svc);
  for (;;)
    {
      BACKEND *be, *tmp;

      DLIST_FOREACH_SAFE (be, tmp, &svc->be_rem_head, link)
	{
	  int refcount;
	  pthread_mutex_lock (&be->mut);
	  refcount = be->refcount;
	  pthread_mutex_unlock (&be->mut);
	  if (refcount == 0)
	    {
	      DLIST_REMOVE (&svc->be_rem_head, be, link);
	      backend_release (be);
	    }
	}

      if (DLIST_EMPTY (&svc->be_rem_head))
	break;

      pthread_cond_wait (&svc->be_rem_cond, &svc->mut);
    }
  pthread_cleanup_pop (1);
  return NULL;
}

static void
start_backend_removal (SERVICE *svc)
{
  pthread_t tid;
  pthread_create (&tid, &thread_attr_detached, thr_backend_remover, svc);
}

void
backend_ref (BACKEND *be)
{
  if (be && be->be_type == BE_REGULAR)
    {
      pthread_mutex_lock (&be->mut);
      be->refcount++;
      pthread_mutex_unlock (&be->mut);
    }
}

void
backend_unref (BACKEND *be)
{
  if (be && be->be_type == BE_REGULAR)
    {
      pthread_mutex_lock (&be->mut);
      assert (be->refcount > 0);
      be->refcount--;
      if (be->refcount == 0)
	pthread_cond_signal (&be->service->be_rem_cond);
      pthread_mutex_unlock (&be->mut);
    }
}
