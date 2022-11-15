/*
 * Pound - the reverse-proxy load-balancer
 * Copyright (C) 2002-2010 Apsis GmbH
 * Copyright (C) 2018-2022 Sergey Poznyakoff
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
 *
 * Contact information:
 * Apsis GmbH
 * P.O.Box
 * 8707 Uetikon am See
 * Switzerland
 * EMail: roseg@apsis.ch
 */

#include    "pound.h"

/* common variables */
char *user;			/* user to run as */
char *group;			/* group to run as */
char *root_jail;		/* directory to chroot to */
char *pid_name = F_PID;		/* file to record pid in */
char *ctrl_name;		/* control socket name */

int anonymise;			/* anonymise client address */
int daemonize = 1;		/* run as daemon */
int enable_supervisor = SUPERVISOR; /* enable supervisor process */
int log_facility = -1;		/* log facility to use */
int print_log;			/* print log messages to stdout/stderr */
int control_sock = -1;		/* control socket */

unsigned alive_to = DEFAULT_ALIVE_TO; /* check interval for resurrection */
unsigned grace = DEFAULT_GRACE_TO;    /* grace period before shutdown */

SERVICE *services;		/* global services (if any) */
LISTENER *listeners;		/* all available listeners */
int n_listeners;                /* Number of listeners */

regex_t HEADER,			/* Allowed header */
  CONN_UPGRD,			/* upgrade in connection header */
  CHUNK_HEAD,			/* chunk header line */
  RESP_SKIP,			/* responses for which we skip response */
  RESP_IGN,			/* responses for which we ignore content */
  LOCATION,			/* the host we are redirected to */
  AUTHORIZATION;		/* the Authorisation header */

static int shut_down = 0;

#ifndef  SOL_TCP
/* for systems without the definition */
int SOL_TCP;
#endif

/*
 * OpenSSL thread support stuff
 */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define l_init()
#else
static pthread_mutex_t *l_array;

static void
l_init (void)
{
  int i, n_locks;

  n_locks = CRYPTO_num_locks ();
  if ((l_array =
       (pthread_mutex_t *) calloc (n_locks,
				   sizeof (pthread_mutex_t))) == NULL)
    {
      logmsg (LOG_ERR, "lock init: out of memory - aborted...");
      exit (1);
    }
  for (i = 0; i < n_locks; i++)
    /* pthread_mutex_init() always returns 0 */
    pthread_mutex_init (&l_array[i], NULL);
  return;
}

static void
l_lock (const int mode, const int n, /* unused */ const char *file,
	/* unused */ int line)
{
  int ret_val;

  if (mode & CRYPTO_LOCK)
    {
      if (ret_val = pthread_mutex_lock (&l_array[n]))
	logmsg (LOG_ERR, "l_lock lock(): %s", strerror (ret_val));
    }
  else
    {
      if (ret_val = pthread_mutex_unlock (&l_array[n]))
	logmsg (LOG_ERR, "l_lock unlock(): %s", strerror (ret_val));
    }
  return;
}

static unsigned long
l_id (void)
{
  return (unsigned long) pthread_self ();
}
#endif

/*
 * work queue stuff
 */
static thr_arg *first = NULL, *last = NULL;
static pthread_cond_t arg_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t active_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t arg_mut = PTHREAD_MUTEX_INITIALIZER;
unsigned numthreads = DEFAULT_NUMTHREADS; /* Max. number of threads */
unsigned active_threads; /* Number of threads currently active, i.e processing
			    some requests. */

/*
 * add a request to the queue
 */
int
put_thr_arg (thr_arg * arg)
{
  thr_arg *res;

  if ((res = malloc (sizeof (thr_arg))) == NULL)
    {
      logmsg (LOG_WARNING, "thr_arg malloc");
      return -1;
    }
  memcpy (res, arg, sizeof (thr_arg));
  res->next = NULL;
  pthread_mutex_lock (&arg_mut);
  if (last == NULL)
    first = last = res;
  else
    {
      last->next = res;
      last = last->next;
    }
  pthread_cond_signal (&arg_cond);
  pthread_mutex_unlock (&arg_mut);
  return 0;
}

/*
 * get a request from the queue
 */
thr_arg *
get_thr_arg (void)
{
  thr_arg *res;

  pthread_mutex_lock (&arg_mut);

  /*
   * Wait until something becomes available in the queue.  Spurious wakeups
   * from pthread_cond_wait can occur, hence the need for a loop.
   */
  while (first == NULL)
    pthread_cond_wait (&arg_cond, &arg_mut);

  /* Dequeue the head element */
  res = first;
  if ((first = first->next) == NULL)
    last = NULL;
  else
    /*
     * If there's still more in the queue, signal other threads, so they
     * can have their share.
     * Notice, that pthread_cond_signal() may be called whether or not the
     * current thread owns the mutex associated with the condition.  However,
     * if predictable scheduling behavior is required, the mutex should be
     * locked.
     */
    pthread_cond_signal (&arg_cond);

  active_threads++;
  pthread_mutex_unlock (&arg_mut);
  return res;
}

/*
 * get the current queue length
 */
int
get_thr_qlen (void)
{
  int res;
  thr_arg *tap;

  pthread_mutex_lock (&arg_mut);
  for (res = 0, tap = first; tap != NULL; tap = tap->next, res++)
    ;
  pthread_mutex_unlock (&arg_mut);
  return res;
}

void
active_threads_decr (void)
{
  pthread_mutex_lock (&arg_mut);
  active_threads--;
  if (active_threads == 0)
    pthread_cond_broadcast (&active_cond);
  pthread_mutex_unlock (&arg_mut);
}

void
active_threads_wait (void)
{
  struct timespec ts;

  pthread_mutex_lock (&arg_mut);
  ts.tv_sec += grace;
  if (active_threads > 0)
    {
      logmsg (LOG_NOTICE, "waiting for %u active threads to terminate",
	      active_threads);
      clock_gettime (CLOCK_REALTIME, &ts);
      while (active_threads > 0 &&
	     pthread_cond_timedwait (&active_cond, &arg_mut, &ts) == 0)
	;
    }
  pthread_mutex_unlock (&arg_mut);
}

static void
listener_cleanup (void *ptr)
{
  LISTENER *lstn;
  for (lstn = listeners; lstn; lstn = lstn->next)
    close (lstn->sock);
}

void *
thr_dispatch (void *unused)
{
  int i;
  LISTENER *lstn;
  struct pollfd *polls;

  /* alloc the poll structures */
  if ((polls = calloc (n_listeners, sizeof (struct pollfd))) == NULL)
    {
      logmsg (LOG_ERR, "Out of memory for poll - aborted");
      exit (1);
    }
  for (lstn = listeners, i = 0; lstn; lstn = lstn->next, i++)
    polls[i].fd = lstn->sock;

  pthread_cleanup_push (listener_cleanup, NULL);
  for (;;)
    {
      for (lstn = listeners, i = 0; i < n_listeners; lstn = lstn->next, i++)
	{
	  polls[i].events = POLLIN | POLLPRI;
	  polls[i].revents = 0;
	}
      if (poll (polls, n_listeners, -1) < 0)
	{
	  logmsg (LOG_WARNING, "poll: %s", strerror (errno));
	}
      else
	{
	  for (lstn = listeners, i = 0; lstn; lstn = lstn->next, i++)
	    {
	      if (polls[i].revents & (POLLIN | POLLPRI))
		{
		  struct sockaddr_storage clnt_addr;
		  socklen_t clnt_length;
		  int clnt;

		  memset (&clnt_addr, 0, sizeof (clnt_addr));
		  clnt_length = sizeof (clnt_addr);
		  if ((clnt = accept (lstn->sock,
				      (struct sockaddr *) &clnt_addr,
				      &clnt_length)) < 0)
		    {
		      logmsg (LOG_WARNING, "HTTP accept: %s",
			      strerror (errno));
		    }
		  else
		    {
		      thr_arg arg;

		      if (lstn->disabled)
			{
			  /*
			    addr2str(tmp, MAXBUF - 1, &clnt_addr, 1);
			    logmsg(LOG_WARNING, "HTTP disabled listener from %s", tmp);
			  */
			  close (clnt);
			}

		      arg.sock = clnt;
		      arg.lstn = lstn;

		      if ((arg.from_host.ai_addr = (struct sockaddr *) malloc (clnt_length)) == NULL)
			{
			  logmsg (LOG_WARNING, "HTTP arg address: malloc");
			  close (clnt);
			  continue;
			}
		      memcpy (arg.from_host.ai_addr, &clnt_addr, clnt_length);
		      arg.from_host.ai_family = clnt_addr.ss_family;
		      arg.from_host.ai_addrlen = clnt_length;
		      if (put_thr_arg (&arg))
			close (clnt);
		    }
		}
	    }
	}
    }
  pthread_cleanup_pop (1);
}

static void
pidfile_create (void)
{
  FILE *fp;

  if (!pid_name)
    return;
  if ((fp = fopen (pid_name, "wt")) != NULL)
    {
      fprintf (fp, "%d\n", getpid ());
      fclose (fp);
    }
  else
    logmsg (LOG_NOTICE, "Create \"%s\": %s", pid_name, strerror (errno));
}

static void
pidfile_delete (void)
{
  if (pid_name)
    unlink (pid_name);
}

struct signal_handler
{
  int signo;
  void (*handler) (int);
};

static void
signull (int arg)
{
  /* nothing */
}

static struct signal_handler fatal_signals[] = {
  { SIGHUP, signull },
  { SIGINT, signull },
  { SIGTERM, signull },
  { SIGQUIT, signull },
  { SIGPIPE, SIG_IGN },
  { 0, NULL }
};

static void
server (void)
{
  int i;
  pthread_attr_t attr;
  pthread_t thr;
  struct sigaction act;
  sigset_t sigs;
  void *res;

  sigemptyset(&sigs);

  act.sa_flags = 0;
  sigemptyset (&act.sa_mask);

  for (i = 0; fatal_signals[i].signo; i++)
    {
      sigaddset (&sigs, fatal_signals[i].signo);
      act.sa_handler = fatal_signals[i].handler;
      sigaction (fatal_signals[i].signo, &act, NULL);
    }
  pthread_sigmask (SIG_BLOCK, &sigs, NULL);

  /* thread stuff */
  pthread_attr_init (&attr);
  pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_DETACHED);

#ifdef  NEED_STACK
  /* set new stack size - necessary for OpenBSD/FreeBSD and Linux NPTL */
  if (pthread_attr_setstacksize (&attr, 1 << 18))
    {
      logmsg (LOG_ERR, "can't set stack size - aborted");
      exit (1);
    }
#endif

  /* start timer */
  if (pthread_create (&thr, &attr, thr_timer, NULL))
    {
      logmsg (LOG_ERR, "create thr_resurect: %s - aborted",
	      strerror (errno));
      exit (1);
    }

  /* start the controlling thread (if needed) */
  if (control_sock >= 0 && pthread_create (&thr, &attr, thr_control, NULL))
    {
      logmsg (LOG_ERR, "create thr_control: %s - aborted", strerror (errno));
      exit (1);
    }

  /* FIXME: pause to make sure the service threads were started */
  sleep (1);

  /* create the worker threads */
  for (i = 0; i < numthreads; i++)
    if (pthread_create (&thr, &attr, thr_http, NULL))
      {
	logmsg (LOG_ERR, "create thr_http: %s - aborted", strerror (errno));
	exit (1);
      }

  pthread_create (&thr, NULL, thr_dispatch, NULL);

  /* Wait for a signal to arrive */
  sigwait (&sigs, &i);

  logmsg (LOG_NOTICE, "shutting down...");

  /* Stop main dispatcher thread */
  pthread_cancel (thr);
  pthread_join (thr, &res);

  switch (i)
    {
    case SIGHUP:
    case SIGINT:
      active_threads_wait ();
      break;

    default:
      /* Exit immediately */
      break;
    }

  if (ctrl_name != NULL)
    unlink (ctrl_name);

  exit (0);
}

#if SUPERVISOR
static void
supervisor (void)
{
  pid_t pid = 0;
  int i;
  struct sigaction act;
  sigset_t sigs;
  pid_t child_pid = 0;
  int status;

  enum supervisor_state
  {
    S_RUNNING,         /* Program is running */
    S_TERMINATING,     /* Program is terminating */
  } state = S_RUNNING;

  sigemptyset (&sigs);

  act.sa_flags = 0;
  sigemptyset (&act.sa_mask);

  for (i = 0; fatal_signals[i].signo; i++)
    {
      sigaddset (&sigs, fatal_signals[i].signo);
      act.sa_handler = fatal_signals[i].handler;
      sigaction (fatal_signals[i].signo, &act, NULL);
    }

  act.sa_handler = signull;
  sigaction (SIGCHLD, &act, NULL);
  sigaddset (&sigs, SIGCHLD);

  act.sa_handler = signull;
  sigaction (SIGALRM, &act, NULL);
  sigaddset (&sigs, SIGALRM);

  for (;;)
    {
      if (pid == 0)
	{
	  if (state != S_RUNNING)
	    break;
	  pid = fork ();
	  if (pid == -1)
	    {
	      logmsg (LOG_ERR, "fork: %s", strerror (errno));
	      break;
	    }
	  if (pid == 0)
	    {
	      server ();
	      exit (0);
	    }
	}

      sigwait (&sigs, &i);
      logmsg (LOG_NOTICE, "got signal %d", i);

      if (i == SIGCHLD)
	{
	  if (wait (&status) != pid)
	    {
	      logmsg (LOG_ERR, "wait: %s", strerror (errno));
	    }
	  else if (WIFEXITED (status))
	    {
	      int code = WEXITSTATUS (status);
	      if (code == 0)
		return;
	      else
		logmsg (LOG_NOTICE, "child exited with status %d", code);
	    }
	  else if (WIFSIGNALED (status))
	    {
	      char const *coremsg = "";
#ifdef WCOREDUMP
	      if (WCOREDUMP (status))
		coremsg = " (core dumped)";
#endif
	      logmsg (LOG_NOTICE, "child terminated on signal %d%s",
		      WTERMSIG (status), coremsg);
	    }
	  else if (WIFSTOPPED (status))
	    {
	      logmsg (LOG_NOTICE, "child stopped on signal %d",
		      WSTOPSIG (status));
	    }
	  else
	    {
	      logmsg (LOG_NOTICE, "child terminated with unrecognized status %d", status);
	    }
	  if (state == S_RUNNING)
	    {
	      /* restart the child */
	      pid = 0;
	      continue;
	    }
	  else
	    break;
	}
      else if (i == SIGALRM)
	{
	  kill (pid, SIGKILL);
	  break;
	}
      else if (state == S_RUNNING)
	{
	  /* Termination signal received.  Send it to child. */
	  if (pid)
	    kill (pid, i);
	  state = S_TERMINATING;
	  alarm (grace + 1);
	}
    }
}
#endif

int
main (const int argc, char **argv)
{
  int i;
  LISTENER *lstn;
  uid_t user_id;
  gid_t group_id;
  char tmp[MAXBUF];
#ifndef SOL_TCP
  struct protoent *pe;
#endif

  (void) umask (077);
  srandom (getpid ());

  /* SSL stuff */
  SSL_load_error_strings ();
  SSL_library_init ();
  OpenSSL_add_all_algorithms ();
  l_init ();
  CRYPTO_set_id_callback (l_id);
  CRYPTO_set_locking_callback (l_lock);

  /*
   * Disable SSL Compression for OpenSSL pre-1.0.  1.0 is handled with an
   * option in config.c
   */
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
#ifndef SSL_OP_NO_COMPRESSION
  {
    int i, n;
    STACK_OF (SSL_COMP) * ssl_comp_methods;

    ssl_comp_methods = SSL_COMP_get_compression_methods ();
    n = sk_SSL_COMP_num (ssl_comp_methods);

    for (i = n - 1; i >= 0; i--)
      {
	sk_SSL_COMP_delete (ssl_comp_methods, i);
      }
  }
#endif
#endif

  /* prepare regular expressions */
  if (regcomp
      (&HEADER, "^([a-z0-9!#$%&'*+.^_`|~-]+):[ \t]*(.*)[ \t]*$",
       REG_ICASE | REG_NEWLINE | REG_EXTENDED)
      || regcomp (&CONN_UPGRD, "(^|[ \t,])upgrade([ \t,]|$)",
		  REG_ICASE | REG_NEWLINE | REG_EXTENDED)
      || regcomp (&CHUNK_HEAD, "^([0-9a-f]+).*$",
		  REG_ICASE | REG_NEWLINE | REG_EXTENDED)
      || regcomp (&RESP_SKIP, "^HTTP/1.1 100.*$",
		  REG_ICASE | REG_NEWLINE | REG_EXTENDED)
      || regcomp (&RESP_IGN,
		  "^HTTP/1.[01] (10[1-9]|1[1-9][0-9]|204|30[456]).*$",
		  REG_ICASE | REG_NEWLINE | REG_EXTENDED)
      || regcomp (&LOCATION, "(http|https)://([^/]+)(.*)",
		  REG_ICASE | REG_NEWLINE | REG_EXTENDED)
      || regcomp (&AUTHORIZATION,
		  "Authorization:[ \t]*Basic[ \t]*\"?([^ \t]*)\"?[ \t]*",
		  REG_ICASE | REG_NEWLINE | REG_EXTENDED))
    {
      logmsg (LOG_ERR, "bad essential Regex - aborted");
      exit (1);
    }

#ifndef SOL_TCP
  /* for systems without the definition */
  if ((pe = getprotobyname ("tcp")) == NULL)
    {
      logmsg (LOG_ERR, "missing TCP protocol");
      exit (1);
    }
  SOL_TCP = pe->p_proto;
#endif

  /* read config */
  config_parse (argc, argv);

  if (log_facility != -1)
    openlog (progname, LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);

  logmsg (LOG_NOTICE, "starting...");

  if (ctrl_name != NULL)
    {
      struct sockaddr_un ctrl;

      memset (&ctrl, 0, sizeof (ctrl));
      ctrl.sun_family = AF_UNIX;
      strncpy (ctrl.sun_path, ctrl_name, sizeof (ctrl.sun_path) - 1);
      (void) unlink (ctrl.sun_path);
      if ((control_sock = socket (PF_UNIX, SOCK_STREAM, 0)) < 0)
	{
	  logmsg (LOG_ERR, "Control \"%s\" create: %s", ctrl.sun_path,
		  strerror (errno));
	  exit (1);
	}
      if (bind (control_sock, (struct sockaddr *) &ctrl,
		(socklen_t) sizeof (ctrl)) < 0)
	{
	  logmsg (LOG_ERR, "Control \"%s\" bind: %s", ctrl.sun_path,
		  strerror (errno));
	  exit (1);
	}
      listen (control_sock, 512);
    }

  /* open listeners */
  for (lstn = listeners, n_listeners = 0; lstn;
       lstn = lstn->next, n_listeners++)
    {
      /* prepare the socket */
      int opt;
      int domain;

      switch (lstn->addr.ai_family)
	{
	case AF_INET:
	  domain = PF_INET;
	  break;
	case AF_INET6:
	  domain = PF_INET6;
	  break;
	case AF_UNIX:
	  domain = PF_UNIX;
	  unlink (((struct sockaddr_un*)lstn->addr.ai_addr)->sun_path);
	  break;
	default:
	  abort ();
	}
      if ((lstn->sock = socket (domain, SOCK_STREAM, 0)) < 0)
	{
	  addr2str (tmp, MAXBUF - 1, &lstn->addr, 0);
	  logmsg (LOG_ERR, "HTTP socket %s create: %s - aborted", tmp,
		  strerror (errno));
	  exit (1);
	}
      opt = 1;
      setsockopt (lstn->sock, SOL_SOCKET, SO_REUSEADDR, (void *) &opt,
		  sizeof (opt));
      if (bind (lstn->sock, lstn->addr.ai_addr,
		(socklen_t) lstn->addr.ai_addrlen) < 0)
	{
	  addr2str (tmp, MAXBUF - 1, &lstn->addr, 0);
	  logmsg (LOG_ERR, "HTTP socket bind %s: %s - aborted", tmp,
		  strerror (errno));
	  exit (1);
	}
      listen (lstn->sock, 512);
    }

  /* set uid if necessary */
  if (user)
    {
      struct passwd *pw;

      if ((pw = getpwnam (user)) == NULL)
	{
	  logmsg (LOG_ERR, "no such user %s - aborted", user);
	  exit (1);
	}
      user_id = pw->pw_uid;
    }

  /* set gid if necessary */
  if (group)
    {
      struct group *gr;

      if ((gr = getgrnam (group)) == NULL)
	{
	  logmsg (LOG_ERR, "no such group %s - aborted", group);
	  exit (1);
	}
      group_id = gr->gr_gid;
    }

  /* Turn off verbose messages (if necessary) */
  print_log = 0;

  if (daemonize)
    {
      /* daemonize - make ourselves a subprocess. */
      switch (fork ())
	{
	case 0:
	  if (log_facility != -1)
	    {
	      close (0);
	      close (1);
	      close (2);
	      open ("/dev/null", O_RDONLY);
	      open ("/dev/null", O_WRONLY);
	    }
	  break;

	case -1:
	  logmsg (LOG_ERR, "fork: %s - aborted", strerror (errno));
	  exit (1);

	default:
	  _exit (0);
	}
      setsid ();
    }

  /* chroot if necessary */
  if (root_jail)
    {
      if (chroot (root_jail))
	{
	  logmsg (LOG_ERR, "chroot: %s - aborted", strerror (errno));
	  exit (1);
	}
      if (chdir ("/"))
	{
	  logmsg (LOG_ERR, "chroot/chdir: %s - aborted", strerror (errno));
	  exit (1);
	}
    }

  if (group)
    if (setgid (group_id) || setegid (group_id))
      {
	logmsg (LOG_ERR, "setgid: %s - aborted", strerror (errno));
	exit (1);
      }
  if (user)
    if (setuid (user_id) || seteuid (user_id))
      {
	logmsg (LOG_ERR, "setuid: %s - aborted", strerror (errno));
	exit (1);
      }

  pidfile_create ();

#if SUPERVISOR
  if (enable_supervisor && daemonize)
    supervisor ();
  else
#endif
    server ();

  pidfile_delete ();

  return 0;
}
