/*
 * Pound - the reverse-proxy load-balancer
 * Copyright (C) 2023 Sergey Poznyakoff
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

struct http_log_instr;

typedef void (*http_log_printer_fn) (struct stringbuf *sb,
				     struct http_log_instr *instr,
				     POUND_HTTP *phttp);

struct http_log_instr
{
  http_log_printer_fn prt;
  char *arg;
  SLIST_ENTRY (http_log_instr) link;
};

typedef SLIST_HEAD(,http_log_instr) HTTP_LOG_HEAD;

struct http_log_prog
{
  char *name;
  HTTP_LOG_HEAD head;
};

typedef struct http_log_prog *HTTP_LOG_PROG;

static void
add_instr (HTTP_LOG_PROG prog, http_log_printer_fn prt, const char *fmt, size_t fmtsize)
{
    struct http_log_instr *p;
    if (fmt == NULL)
      fmtsize = 0;
    p = xzalloc (sizeof(*p) + (fmtsize ? (fmtsize + 1) : 0));
    p->prt = prt;
    if (fmtsize)
      {
	p->arg = (char*) (p + 1);
	memcpy (p->arg, fmt, fmtsize);
	p->arg[fmtsize] = 0;
      }
    else
      p->arg = NULL;
    SLIST_PUSH (&prog->head, p, link);
}

static void
print_str (struct stringbuf *sb, const char *arg)
{
  size_t len;
  if (!arg)
    {
      arg = "-";
      len = 1;
    }
  else
    len = strlen (arg);
  stringbuf_add (sb, arg, len);
}

static void
i_print (struct stringbuf *sb, struct http_log_instr *instr,
	 POUND_HTTP *phttp)
{
  print_str (sb, instr->arg);
}

static char *
anon_addr2str (char *buf, size_t size, struct addrinfo const *from_host)
{
  if (from_host->ai_family == AF_UNIX)
    {
      strncpy (buf, "socket", size);
    }
  else
    {
      addr2str (buf, size, from_host, 1);
      if (anonymise)
	{
	  char *last;

	  if ((last = strrchr (buf, '.')) != NULL
	      || (last = strrchr (buf, ':')) != NULL)
	    strcpy (++last, "0");
	}
    }
  return buf;
}

static void
i_remote_ip (struct stringbuf *sb, struct http_log_instr *instr,
		    POUND_HTTP *phttp)
{
  char caddr[MAX_ADDR_BUFSIZE];
  print_str (sb, anon_addr2str (caddr, sizeof (caddr), &phttp->from_host));
}

static void
i_local_ip (struct stringbuf *sb, struct http_log_instr *instr,
		   POUND_HTTP *phttp)
{
  char caddr[MAX_ADDR_BUFSIZE];
  print_str (sb, addr2str (caddr, sizeof (caddr), &phttp->lstn->addr, 1));
}

static void
i_response_size (struct stringbuf *sb, struct http_log_instr *instr,
		 POUND_HTTP *phttp)
{
  stringbuf_printf (sb, "%"PRICLEN, phttp->res_bytes);
}

static void
i_response_size_clf (struct stringbuf *sb, struct http_log_instr *instr,
		     POUND_HTTP *phttp)
{
  if (phttp->res_bytes > 0)
    stringbuf_printf (sb, "%"PRICLEN, phttp->res_bytes);
  else
    stringbuf_add_char (sb, '-');
}

static void
i_protocol (struct stringbuf *sb, struct http_log_instr *instr,
	    POUND_HTTP *phttp)
{
  print_str (sb, phttp->ssl == NULL ? "http" : "https");
}

static void
i_method (struct stringbuf *sb, struct http_log_instr *instr,
	  POUND_HTTP *phttp)
{
  print_str (sb, method_name(phttp->request.method));
}

static void
i_query (struct stringbuf *sb, struct http_log_instr *instr,
	 POUND_HTTP *phttp)
{
  char const *query = NULL;
  http_request_get_query (&phttp->request, &query);
  print_str (sb, query);
}

static void
i_status (struct stringbuf *sb, struct http_log_instr *instr,
	  POUND_HTTP *phttp)
{
  if (instr->arg)
    stringbuf_add_string (sb, http_request_orig_line (&phttp->response));
  else
    stringbuf_printf (sb, "%3d", phttp->response_code);
}

enum
  {
    MILLI = 1000,
    MICRO = 1000000
  };

/*
 * If the format starts with begin: (default) the time is taken at the
 * beginning of the request processing. If it starts with end: it is the
 * time when the log entry gets written, close to the end of the request
 * processing. In addition to the formats supported by strftime(3), the
 * following format tokens are supported:
 *     sec		number of seconds since the Epoch
 *     msec		number of milliseconds since the Epoch
 *     usec		number of microseconds since the Epoch
 *     msec_frac	millisecond fraction
 *     usec_frac	microsecond fraction
 * These tokens can not be combined with each other or strftime(3) formatting
 * in the same format string. You can use multiple %{format}t tokens instead.
 */
static void
i_time (struct stringbuf *sb, struct http_log_instr *instr,
	POUND_HTTP *phttp)
{
  struct tm tm;
  char *fmt;
  struct timespec *ts = &phttp->start_req;

  if (instr->arg == 0)
    fmt = "[%d/%b/%Y:%H:%M:%S %z]";
  else
    {
      fmt = instr->arg;
      if (strncmp (fmt, "begin:", 6) == 0)
	fmt += 6;
      else if (strncmp (fmt, "end:", 4) == 0)
	{
	  fmt += 4;
	  ts = &phttp->end_req;
	}

      if (strcmp (fmt, "s") == 0)
	{
	  stringbuf_printf (sb, "%ld", (long) ts->tv_sec);
	  return;
	}
      else if (strcmp (fmt, "msec") == 0)
	{
	  stringbuf_printf (sb, "%.0f",
			    (double) ts->tv_sec * MILLI + ts->tv_nsec / MICRO);
	  return;
	}
      else if (strcmp (fmt, "usec") == 0)
	{
	  stringbuf_printf (sb, "%.0f",
			    (double) ts->tv_sec * MICRO + ts->tv_nsec / MILLI);
	  return;
	}
      else if (strcmp (fmt, "msec_frac") == 0)
	{
	  stringbuf_printf (sb, "%03ld", ts->tv_nsec / MICRO);
	  return;
	}
      else if (strcmp (fmt, "usec_frac") == 0)
	{
	  stringbuf_printf (sb, "%06ld", ts->tv_nsec / MILLI);
	  return;
	}
    }

  stringbuf_strftime (sb, fmt, localtime_r (&ts->tv_sec, &tm));
}

static void
i_process_time (struct stringbuf *sb, struct http_log_instr *instr,
		POUND_HTTP *phttp)
{
  struct timespec diff = timespec_sub (&phttp->end_req, &phttp->start_req);
  if (instr->arg)
    {
      if (strcmp (instr->arg, "ms") == 0)
	{
	  stringbuf_printf (sb, "%ld",
			    (unsigned long) diff.tv_sec * MILLI +
			    diff.tv_nsec / MICRO);
	  return;
	}
      else if (strcmp (instr->arg, "us") == 0)
	{
	  stringbuf_printf (sb, "%ld",
			    (unsigned long) diff.tv_sec * MICRO +
			    diff.tv_nsec / MILLI);
	  return;
	}
      else if (strcmp (instr->arg, "s") == 0)
	{
	  stringbuf_printf (sb, "%ld", diff.tv_sec);
	  return;
	}
      else if (strcmp (instr->arg, "f") == 0)
	{
	  stringbuf_printf (sb, "%ld.%03ld", diff.tv_sec, diff.tv_nsec / MICRO);
	  return;
	}
    }
  else
    stringbuf_printf (sb, "%ld", diff.tv_sec);
}

static void
i_process_time_ms (struct stringbuf *sb, struct http_log_instr *instr,
		   POUND_HTTP *phttp)
{
  struct timespec diff = timespec_sub (&phttp->end_req, &phttp->start_req);
  stringbuf_printf (sb, "%ld",
		    (unsigned long) diff.tv_sec * MILLI + diff.tv_nsec / MICRO);
}

static void
i_user_name (struct stringbuf *sb, struct http_log_instr *instr,
	     POUND_HTTP *phttp)
{
  print_str (sb, phttp->request.user);
}

static void
i_url (struct stringbuf *sb, struct http_log_instr *instr,
       POUND_HTTP *phttp)
{
  char const *val = NULL;
  http_request_get_path (&phttp->request, &val);
  print_str (sb, val);
}

static void
i_listener_name (struct stringbuf *sb, struct http_log_instr *instr,
		 POUND_HTTP *phttp)
{
  print_str (sb, phttp->lstn->name);
}

static void
i_tid (struct stringbuf *sb, struct http_log_instr *instr,
       POUND_HTTP *phttp)
{
  stringbuf_printf (sb, "%"PRItid, POUND_TID ());
}

static void
i_request (struct stringbuf *sb, struct http_log_instr *instr,
	   POUND_HTTP *phttp)
{
  print_str (sb, http_request_orig_line (&phttp->request));
}

static void
i_backend (struct stringbuf *sb, struct http_log_instr *instr,
	   POUND_HTTP *phttp)
{
  char caddr[MAX_ADDR_BUFSIZE];
  print_str (sb, str_be (caddr, sizeof (caddr), phttp->backend));
}

static char *
be_service_name (BACKEND *be)
{
  switch (be->be_type)
    {
    case BE_BACKEND:
      if (be->service->name)
       return be->service->name;
      break;
    case BE_REDIRECT:
      return "(redirect)";
    case BE_ACME:
      return "(acme)";
    case BE_CONTROL:
      return "(control)";
    case BE_ERROR:
      return "(error)";
    case BE_METRICS:
      return "(metrics)";
    }
  return "-";
}

static void
i_service (struct stringbuf *sb, struct http_log_instr *instr,
	   POUND_HTTP *phttp)
{
  print_str (sb, be_service_name (phttp->backend));
}

static void
i_header (struct stringbuf *sb, struct http_log_instr *instr,
	  POUND_HTTP *phttp)
{
  struct http_header *hdr;
  char const *val = NULL;

  if (instr->arg &&
      (hdr = http_header_list_locate_name (&phttp->request.headers, instr->arg,
					   strlen (instr->arg))) != NULL)
    val = http_header_get_value (hdr);
  if (val)
    stringbuf_add_string (sb, val);
}

static void
i_header_clf (struct stringbuf *sb, struct http_log_instr *instr,
	      POUND_HTTP *phttp)
{
  struct http_header *hdr;
  char const *val = NULL;

  if (instr->arg &&
      (hdr = http_header_list_locate_name (&phttp->request.headers,
					   instr->arg,
					   strlen (instr->arg))) != NULL)
    val = http_header_get_value (hdr);
  print_str (sb, val);
}


struct http_log_spec
{
  int ch;
  http_log_printer_fn prt;
  int allow_fmt;
};

static struct http_log_spec http_log_spec[] = {
    /* The percent sign */
    { '%', i_print },
    /* Remote IP-address */
    { 'a', i_remote_ip },
    /* Local IP-address */
    { 'A', i_local_ip },
    /* Size of response in bytes. */
    { 'B', i_response_size },
    /* Size of response in bytes in CLF format, i.e. a '-' rather
       than a 0 when no bytes are sent. */
    { 'b', i_response_size_clf },
    /* The time taken to serve the request, in microseconds. */
    { 'D', i_process_time_ms },
    /* Remote hostname - same as %a */
    { 'h', i_remote_ip },
    /* The request protocol. */
    { 'H', i_protocol },
    /* The contents of VARNAME: header line(s) in the request sent to the
       server. */
    { 'i', i_header, 1 },
    /* Same as %i, but in CLF format. */
    { 'I', i_header_clf, 1 },
    /* The request method. */
    { 'm', i_method },
    /* The canonical port of the server serving the request. */
    // { 'p', i_canon_port },
    /* Thread ID */
    { 'P', i_tid },
    /* The query string (prepended with a ? if a query string exists,
       otherwise an empty string). */
    { 'q', i_query },
    /* First line of request. */
    { 'r', i_request },
    /* Backend */
    { 'R', i_backend },
    /* Service name */
    { 'S', i_service },
    /* Status */
    { 's', i_status, 1 },
    /* %t          Time the request was received (standard english format)
       %{format}t  The time, in the form given by format, which should be in
		   strftime(3) format. (potentially localized) */
    { 't', i_time, 1 },
    /* %T          The time taken to serve the request, in seconds.
       %{UNIT}T    The time taken to serve the request, in a time unit given
		   by UNIT. Valid units are ms for milliseconds, us for
		   microseconds, s for seconds, and f for seconds with
		   fractional part. Using s gives the same result as %T
		   without any format; using us gives the same result as %D. */
    { 'T', i_process_time, 1 },
    /* Remote user. */
    { 'u', i_user_name },
    /* The URL path requested, not including any query string. */
    { 'U', i_url },
    /* Listener name */
    { 'v', i_listener_name },
    { 0 }
};

static struct http_log_spec *
find_spec (int c)
{
  struct http_log_spec *p;

  for (p = http_log_spec; p->ch; p++)
    if (p->ch == c)
      return p;
  return NULL;
}

static struct http_log_prog http_log_tab[MAX_HTTP_LOG_FORMATS];
static int http_log_next;

static int
find_log_prog (char const *name, int *alloc)
{
  int i;

  if (alloc)
    *alloc = 0;
  for (i = 0; i < http_log_next; i++)
    if (strcmp (http_log_tab[i].name, name) == 0)
      return i;
  if (!alloc)
    return -1;
  if (http_log_next == MAX_HTTP_LOG_FORMATS)
    return -1;
  *alloc = 1;
  i = http_log_next++;
  memset (&http_log_tab[i], 0, sizeof (http_log_tab[i]));
  http_log_tab[i].name = xstrdup (name);
  return i;
}

int
http_log_format_find (char const *name)
{
  return find_log_prog (name, NULL);
}

int
http_log_format_check (int n)
{
  if (n < 0 || n >= http_log_next)
    return -1;
  return 0;
}

int
http_log_format_compile (char const *name, char const *fmt,
			 void (*logfn) (void *, int, char const *, int),
			 void *logdata)
{
  char *p;
  size_t len;
  struct http_log_prog *prog;
  int i;
  int alloc;

  i = find_log_prog (name, &alloc);
  if (i == -1)
    {
      logfn (logdata, 1, "format table full", -1);
      return -1;
    }
  else if (!alloc)
    {
      logfn (logdata, 1, "format already defined", -1);
      return -1;
    }
  prog = http_log_tab + i;

  SLIST_INIT (&prog->head);
  while ((p = strchr (fmt, '%')))
    {
      char *arg = NULL;
      size_t arglen;
      struct http_log_spec *tptr;

      len = p - fmt;
      if (len)
	add_instr (prog, i_print, fmt, len);
      p++;
      if (*p == '>' && p[1] == 's')
	{
	  arg = "1";
	  arglen = 1;
	  p++;
	}
      else if (*p == '{')
	{
	  char *q = strchr (p + 1, '}');

	  if (!q)
	    {
	      logfn (logdata, 0,
		     "log format error: "
		     "missing terminating `}'",
		     p - fmt);
	      add_instr (prog, i_print, p - 1, 2);
	      fmt = p + 1;
	      continue;
	    }
	  arglen = q - p - 1;
	  arg = p + 1;
	  p = q + 1;
	}

      tptr = find_spec (*p);
      if (!tptr)
	{
	  logfn (logdata, 0,
		 "log format error: unknown format char",
		 p - fmt);
	  add_instr (prog, i_print, fmt, p - fmt + 1);
	}
      else
	{
	  if (arg && !tptr->allow_fmt)
	    {
	      logfn (logdata, 0,
		     "log format warning: format specifier does not "
		     "take arguments",
		     p - fmt);
	      arg = NULL;
	    }
	  if (tptr->ch == '%')
	    {
	      /* Special case */
	      arg = "%";
	      arglen = 1;
	    }
	  add_instr (prog, tptr->prt, arg, arglen);
	}
      fmt = p + 1;
    }
  len = strlen (fmt);
  if (len)
    add_instr (prog, i_print, fmt, len);
  return i;
}

void
http_log (POUND_HTTP *phttp)
{
  struct stringbuf sb;
  struct http_log_prog *prog;
  struct http_log_instr *ip;
  char *msg;

  if (http_log_format_check (phttp->lstn->log_level))
    return;
  prog = http_log_tab + phttp->lstn->log_level;
  if (SLIST_EMPTY (&prog->head))
    return;

  stringbuf_init_log (&sb);
  SLIST_FOREACH (ip, &prog->head, link)
    {
      ip->prt (&sb, ip, phttp);
    }
  if ((msg = stringbuf_finish (&sb)) == NULL)
    {
      logmsg (LOG_ERR, "error formatting log message");
    }
  else
    {
      logmsg (LOG_INFO, "%s", msg);
    }
  stringbuf_free (&sb);
}
