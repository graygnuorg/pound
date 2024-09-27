/*
 * Dynamic backend support for pound.
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
#include <assert.h>
#include "resolver.h"

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
