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

#include "config.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fnmatch.h>

#if HAVE_GETOPT_H
# include <getopt.h>
#endif

#ifndef UNIX_PATH_MAX
/* on Linux this is defined in linux/un.h rather than sys/un.h - go figure */
# define UNIX_PATH_MAX   108
#endif

#ifndef NI_MAXHOST
# define NI_MAXHOST      1025
#endif

#ifndef NI_MAXSERV
# define NI_MAXSERV      32
#endif

#define MAX_ADDR_BUFSIZE (NI_MAXHOST + NI_MAXSERV + 4)

#if HAVE_OPENSSL_SSL_H
# define OPENSSL_THREAD_DEFINES
# include <openssl/ssl.h>
# include <openssl/lhash.h>
# include <openssl/err.h>
# if OPENSSL_VERSION_NUMBER >= 0x00907000L
#  ifndef OPENSSL_THREADS
#   error "Pound requires OpenSSL with thread support"
#  endif
# else
#  ifndef THREADS
#   error  "Pound requires OpenSSL with thread support"
#  endif
# endif
#else
# error "Pound needs openssl/ssl.h"
#endif

#if HAVE_OPENSSL_ENGINE_H
# include <openssl/engine.h>
#endif

#if HAVE_LIBPCREPOSIX
# if HAVE_PCREPOSIX_H
#  include <pcreposix.h>
# elif HAVE_PCRE_PCREPOSIX_H
#  include <pcre/pcreposix.h>
# else
#  error "You have libpcreposix, but the header files are missing. Use --disable-pcreposix"
# endif
#else
# include <regex.h>
#endif

#ifdef  HAVE_LONG_LONG_INT
# define LONG    long long
# define L0      0LL
# define L_1     -1LL
# define STRTOL  strtoll
# define ATOL    atoll
#else
# define LONG    long
# define L0      0L
# define L_1     -1L
# define STRTOL  strtol
# define ATOL    atol
#endif

#ifndef NO_EXTERNALS
/*
 * Global variables needed by everybody
 */

extern char *progname;          /* program name */

extern char *user,		/* user to run as */
 *group,			/* group to run as */
 *root_jail,			/* directory to chroot to */
 *pid_name,			/* file to record pid in */
 *ctrl_name;			/* control socket name */

extern unsigned numthreads,	/* number of worker threads */
  grace;			/* grace period before shutdown */

extern int anonymise;		/* anonymise client address */
extern unsigned alive_to;	/* check interval for resurrection */
extern int daemonize;		/* run as daemon */
extern int enable_supervisor;   /* run supervisor process */
extern int log_facility;	/* log facility to use */
extern int print_log;		/* print log messages to stdout/stderr */
extern int control_sock;	/* control socket */

extern regex_t HEADER,		/* Allowed header */
  CONN_UPGRD,			/* upgrade in connection header */
  CHUNK_HEAD,			/* chunk header line */
  RESP_SKIP,			/* responses for which we skip response */
  RESP_IGN,			/* responses for which we ignore content */
  LOCATION,			/* the host we are redirected to */
  AUTHORIZATION;		/* the Authorisation header */

#ifndef  SOL_TCP
/* for systems without the definition */
extern int SOL_TCP;
#endif

#endif /* NO_EXTERNALS */

#ifndef DEFAULT_NUMTHREADS
# define DEFAULT_NUMTHREADS 128
#endif

#ifndef DEFAULT_GRACE_TO
# define DEFAULT_GRACE_TO 30
#endif

#ifndef DEFAULT_ALIVE_TO
# define DEFAULT_ALIVE_TO 30
#endif

#ifndef MAXBUF
# define MAXBUF      4096
#endif

#define MAXHEADERS  128

#ifndef SYSCONFDIR
# define SYSCONFDIR "/etc"
#endif
#ifndef LOCALSTATEDIR
# define LOCALSTATEDIR "/var"
#endif

#ifndef POUND_CONF
# define POUND_CONF SYSCONFDIR "/" "pound.cfg"
#endif

#ifndef POUND_PID
# define POUND_PID  LOCALSTATEDIR "/run/pound.pid"
#endif

/* matcher chain */
typedef struct _matcher
{
  regex_t pat;		/* pattern to match the request/header against */
  struct _matcher *next;
} MATCHER;

/* back-end types */
typedef enum
  {
    SESS_NONE,
    SESS_IP,
    SESS_COOKIE,
    SESS_URL,
    SESS_PARM,
    SESS_HEADER,
    SESS_BASIC
  }
  SESS_TYPE;

/* back-end definition */
typedef struct _backend
{
  int be_type;			/* 0 if real back-end, otherwise code (301, 302/default, 307) */
  struct addrinfo addr;		/* IPv4/6 address */
  int priority;			/* priority */
  unsigned to;			/* read/write time-out */
  unsigned conn_to;		/* connection time-out */
  unsigned ws_to;		/* websocket time-out */
  struct addrinfo ha_addr;	/* HA address/port */
  char *url;			/* for redirectors */
  int redir_req;		/* the redirect should include the request path */
  SSL_CTX *ctx;			/* CTX for SSL connections */
  pthread_mutex_t mut;		/* mutex for this back-end */
  int n_requests;		/* number of requests seen */
  double t_requests;		/* time to answer these requests */
  double t_average;		/* average time to answer requests */
  int alive;			/* false if the back-end is dead */
  int resurrect;		/* this back-end is to be resurrected */
  int disabled;			/* true if the back-end is disabled */
  struct _backend *next;
} BACKEND;

typedef struct _tn
{
  char *key;
  void *content;
  time_t last_acc;
} TABNODE;

#define n_children(N)   ((N)? (N)->children: 0)

/* maximal session key size */
#define KEY_SIZE    127

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
DEFINE_LHASH_OF (TABNODE);
#elif OPENSSL_VERSION_NUMBER >= 0x10000000L
DECLARE_LHASH_OF (TABNODE);
#endif

/* service definition */
typedef struct _service
{
  char name[KEY_SIZE + 1];	/* symbolic name */
  MATCHER *url,			/* request matcher */
   *req_head,			/* required headers */
   *deny_head;			/* forbidden headers */
  BACKEND *backends;
  BACKEND *emergency;
  int abs_pri;			/* abs total priority for all back-ends */
  int tot_pri;			/* total priority for current back-ends */
  pthread_mutex_t mut;		/* mutex for this service */
  SESS_TYPE sess_type;
  unsigned sess_ttl;		/* session time-to-live */
  regex_t sess_start;		/* pattern to identify the session data */
  regex_t sess_pat;		/* pattern to match the session data */
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    LHASH_OF (TABNODE) * sessions;	/* currently active sessions */
#else
  LHASH *sessions;		/* currently active sessions */
#endif
  int disabled;			/* true if the service is disabled */
  struct _service *next;
} SERVICE;

#ifndef NO_EXTERNALS
extern SERVICE *services;	/* global services (if any) */
#endif /* NO_EXTERNALS */

typedef struct _pound_ctx
{
  SSL_CTX *ctx;
  char *server_name;
  unsigned char **subjectAltNames;
  unsigned int subjectAltNameCount;
  struct _pound_ctx *next;
} POUND_CTX;

/* Listener definition */
typedef struct _listener
{
  struct addrinfo addr;		/* IPv4/6 address */
  int sock;			/* listening socket */
  POUND_CTX *ctx;		/* CTX for SSL connections */
  int clnt_check;		/* client verification mode */
  int noHTTPS11;		/* HTTP 1.1 mode for SSL */
  char *add_head;		/* extra SSL header */
  regex_t verb;			/* pattern to match the request verb against */
  unsigned to;			/* client time-out */
  int has_pat;			/* was a URL pattern defined? */
  regex_t url_pat;		/* pattern to match the request URL against */
  char *err413, *err414, *err500, *err501, *err503;
				/* error messages */
  LONG max_req; 		/* max. request size */
  MATCHER *head_off;		/* headers to remove */
  int rewr_loc;			/* rewrite location response */
  int rewr_dest;		/* rewrite destination header */
  int disabled;			/* true if the listener is disabled */
  int log_level;		/* log level for this listener */
  int allow_client_reneg;	/* Allow Client SSL Renegotiation */
  int disable_ssl_v2;		/* Disable SSL version 2 */
  SERVICE *services;
  struct _listener *next;

  /* Used during configuration parsing */
  int ssl_op_enable;
  int ssl_op_disable;
  int has_other;
} LISTENER;

#ifndef NO_EXTERNALS
extern LISTENER *listeners;	/* all available listeners */
#endif /* NO_EXTERNALS */

typedef struct _thr_arg
{
  int sock;
  LISTENER *lstn;
  struct addrinfo from_host;
  struct _thr_arg *next;
} thr_arg;			/* argument to processing threads: socket, origin */

/* Track SSL handshare/renegotiation so we can reject client-renegotiations. */
typedef enum
{ RENEG_INIT = 0, RENEG_REJECT, RENEG_ALLOW, RENEG_ABORT } RENEG_STATE;

/* Header types */
#define HEADER_ILLEGAL              -1
#define HEADER_OTHER                0
#define HEADER_TRANSFER_ENCODING    1
#define HEADER_CONTENT_LENGTH       2
#define HEADER_CONNECTION           3
#define HEADER_LOCATION             4
#define HEADER_CONTLOCATION         5
#define HEADER_HOST                 6
#define HEADER_REFERER              7
#define HEADER_USER_AGENT           8
#define HEADER_URI                  9
#define HEADER_DESTINATION          10
#define HEADER_EXPECT               11
#define HEADER_UPGRADE              13

/* control request stuff */
typedef enum
{
  CTRL_LST,
  CTRL_EN_LSTN, CTRL_DE_LSTN,
  CTRL_EN_SVC, CTRL_DE_SVC,
  CTRL_EN_BE, CTRL_DE_BE,
  CTRL_ADD_SESS, CTRL_DEL_SESS
} CTRL_CODE;

typedef struct
{
  CTRL_CODE cmd;
  int listener;
  int service;
  int backend;
  char key[KEY_SIZE + 1];
} CTRL_CMD;

/* add a request to the queue */
int put_thr_arg (thr_arg *);
/* get a request from the queue */
thr_arg *get_thr_arg (void);
/* get the current queue length */
int get_thr_qlen (void);
/* Decrement number of active threads. */
void active_threads_decr (void);

/* handle HTTP requests */
void *thr_http (void *);

/* Log an error to the syslog or to stderr */
void logmsg (const int, const char *, ...);

/* Parse a URL, possibly decoding hexadecimal-encoded characters */
int cpURL (char *, char *, int);

/* Translate inet/inet6 address into a string */
char *addr2str (char *, int, const struct addrinfo *, int);

/* Return a string representation for a back-end address */
#define str_be(BUF, LEN, BE)    addr2str((BUF), (LEN), &(BE)->addr, 0)

/* Find the right service for a request */
SERVICE *get_service (const LISTENER *, const char *, char **const);

/* Find the right back-end for a request */
BACKEND *get_backend (SERVICE * const, const struct addrinfo *,
		      const char *, char **const);

/* Search for a host name, return the addrinfo for it */
int get_host (char *const, struct addrinfo *, int);

/*
 * Find if a redirect needs rewriting
 * In general we have two possibilities that require it:
 * (1) if the redirect was done to the correct location with the wrong protocol
 * (2) if the redirect was done to the back-end rather than the listener
 */
int need_rewrite (const int, char *const, char *const, const char *,
		  const LISTENER *, const BACKEND *);
/*
 * (for cookies only) possibly create session based on response headers
 */
void upd_session (SERVICE * const, char **const, BACKEND * const);

/*
 * Parse a header
 */
int check_header (const char *, char *);

#define BE_DISABLE  -1
#define BE_KILL     1
#define BE_ENABLE   0

/*
 * mark a backend host as dead;
 * do nothing if no resurection code is active
 */
void kill_be (SERVICE * const, const BACKEND *, const int);

/*
 * Update the number of requests and time to answer for a given back-end
 */
void upd_be (SERVICE * const svc, BACKEND * const be, const double);

/*
 * Non-blocking version of connect(2). Does the same as connect(2) but
 * ensures it will time-out after a much shorter time period CONN_TO.
 */
int connect_nb (const int, const struct addrinfo *, const int);

/*
 * Parse arguments/config file
 */
void config_parse (int, char **);

/*
 * RSA ephemeral keys: how many and how often
 */
#define N_RSA_KEYS  11
#ifndef T_RSA_KEYS
# define T_RSA_KEYS  7200
#endif

/*
 * Renegotiation callback
 */
void SSLINFO_callback (const SSL * s, int where, int rc);

/*
 * expiration stuff
 */
#ifndef EXPIRE_TO
# define EXPIRE_TO   60
#endif

#ifndef HOST_TO
# define HOST_TO     300
#endif

/*
 * run timed functions:
 *  - RSAgen every T_RSA_KEYS seconds
 *  - resurrect every alive_to seconds
 *  - expire every EXPIRE_TO seconds
 */
void *thr_timer (void *);

/*
 * The controlling thread
 * listens to client requests and calls the appropriate functions
 */
void *thr_control (void *);

void POUND_SSL_CTX_init (SSL_CTX *ctx);
int set_ECDHCurve (char *name);

void *mem2nrealloc (void *p, size_t *pn, size_t s);
void xnomem (void);
void *xmalloc (size_t s);
void *xcalloc (size_t nmemb, size_t size);
#define xzalloc(s) xcalloc(1, s)
#define XZALLOC(v) (v = xzalloc (sizeof ((v)[0])))

void *xrealloc (void *p, size_t s);
void *x2nrealloc (void *p, size_t *pn, size_t s);
char *xstrdup (char const *s);
char *xstrndup (const char *s, size_t n);

struct stringbuf
{
  char *base;                     /* Buffer storage. */
  size_t size;                    /* Size of buf. */
  size_t len;                     /* Actually used length in buf. */
};

void stringbuf_init (struct stringbuf *sb);
void stringbuf_reset (struct stringbuf *sb);
char *stringbuf_finish (struct stringbuf *sb);
void stringbuf_free (struct stringbuf *sb);
void stringbuf_add_char (struct stringbuf *sb, int c);
void stringbuf_add_string (struct stringbuf *sb, char const *str);
void stringbuf_vprintf (struct stringbuf *sb, char const *fmt, va_list ap);
void stringbuf_printf (struct stringbuf *sb, char const *fmt, ...);
static inline char *stringbuf_value (struct stringbuf *sb)
{
  return sb->base;
}
