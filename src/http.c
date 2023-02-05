/*
 * Pound - the reverse-proxy load-balancer
 * Copyright (C) 2002-2010 Apsis GmbH
 * Copyright (C) 2018-2023 Sergey Poznyakoff
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

/*
 * Emit to BIO response line with the given CODE, descriptive TEXT and
 * HEADERS (may be NULL).  TYPE and LEN supply values for Content-Type
 * and Content-Length, correspondingly.  PROTO gives the minor version
 * of the HTTP protocol version: 0 or 1.  If it is 1, the Connection:
 * close header will be added to response.
 */
static void
bio_http_reply_start (BIO *bio, int proto, int code, char const *text,
		      char const *headers,
		      char const *type, CONTENT_LENGTH len)
{
  BIO_printf (bio, "HTTP/1.%d %d %s\r\n"
	      "Content-Type: %s\r\n",
	      proto,
	      code,
	      text,
	      type);
  if (proto == 1)
    {
      BIO_printf (bio,
		  "Content-Length: %"PRICLEN"\r\n"
		  "Connection: close\r\n", len);
    }
  BIO_printf (bio, "%s\r\n", headers ? headers : "");
}

/*
 * Emit to BIO response line with the given CODE and descriptive TEXT,
 * followed by HEADERS (may be NULL) and given CONTENT.  TYPE and
 * PROTO are same as for bio_http_reply_start.
 */
static void
bio_http_reply (BIO *bio, int proto, int code, char const *text,
		char const *headers,
		char const *type, char const *content)
{
  size_t len = strlen (content);
  bio_http_reply_start (bio, proto, code, text, headers, type, len);
  BIO_write (bio, content, len);
  BIO_flush (bio);
}

/*
 * HTTP error replies
 */
typedef struct
{
  int code;
  char const *reason;
  char const *text;
} HTTP_STATUS;

static HTTP_STATUS http_status[] = {
  [HTTP_STATUS_OK] = { 200, "OK", "Success" },
  [HTTP_STATUS_BAD_REQUEST] = {
    400,
    "Bad Request",
    "Your browser (or proxy) sent a request that"
    " this server could not understand."
  },
  [HTTP_STATUS_NOT_FOUND] = {
    404,
    "Not Found",
    "The requested URL was not found on this server."
  },
  [HTTP_STATUS_PAYLOAD_TOO_LARGE] = {
    413,
    "Payload Too Large",
    "The request content is larger than the proxy server is able to process."
  },
  [HTTP_STATUS_URI_TOO_LONG] = {
    414,
    "URI Too Long",
    "The length of the requested URL exceeds the capacity limit for"
    " this server."
  },
  [HTTP_STATUS_INTERNAL_SERVER_ERROR] = {
    500,
    "Internal Server Error",
    "The server encountered an internal error and was"
    " unable to complete your request."
  },
  [HTTP_STATUS_NOT_IMPLEMENTED] = {
    501,
    "Not Implemented",
    "The server does not support the action requested."
  },
  [HTTP_STATUS_SERVICE_UNAVAILABLE] = {
    503,
    "Service Unavailable",
    "The server is temporarily unable to service your"
    " request due to maintenance downtime or capacity"
    " problems. Please try again later."
  },
};

static char err_headers[] =
  "Expires: now\r\n"
  "Pragma: no-cache\r\n"
  "Cache-control: no-cache,no-store\r\n";

static char default_error_page[] = "\
<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\
<html><head>\
<title>%d %s</title>\
</head><body>\
<h1>%s</h1>\
<p>%s</p>\
</body></html>\
";

int
http_status_to_pound (int status)
{
  int i;

  for (i = 0; i < HTTP_STATUS_MAX; i++)
    if (http_status[i].code == status)
      return i;
  return -1;
}

int
pound_to_http_status (int err)
{
  if (!(err >= 0 && err < HTTP_STATUS_MAX))
    err = HTTP_STATUS_INTERNAL_SERVER_ERROR;
  return http_status[err].code;
}

/*
 * Write to BIO an error HTTP 1.PROTO response.  ERR is one of
 * HTTP_STATUS_* constants.  TXT supplies the error page content.
 * If it is NULL, the default text from the http_status table is
 * used.
 */
static void
bio_err_reply (BIO *bio, int proto, int err, char const *content)
{
  struct stringbuf sb;

  if (!(err >= 0 && err < HTTP_STATUS_MAX))
    {
      logmsg (LOG_NOTICE, "INTERNAL ERROR: unsupported error code in call to bio_err_reply");
      err = HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

  stringbuf_init_log (&sb);
  if (!content)
    {
      stringbuf_printf (&sb, default_error_page,
			http_status[err].code,
			http_status[err].reason,
			http_status[err].reason,
			http_status[err].text);
      if ((content = stringbuf_finish (&sb)) == NULL)
	content = http_status[err].text;
    }
  bio_http_reply (bio, proto, http_status[err].code, http_status[err].reason,
		  err_headers, "text/html", content);
  stringbuf_free (&sb);
}

/*
 * Send error response to the client BIO.  ERR is one of HTTP_STATUS_*
 * constants.  Status code and reason phrase will be taken from the
 * http_status array.  If custom error page is defined in the listener,
 * it will be used, otherwise the default error page for the ERR code
 * will be generated
 */
static void
http_err_reply (POUND_HTTP *phttp, int err)
{
  bio_err_reply (phttp->cl, phttp->request.version, err,
		 phttp->lstn->http_err[err]);
  phttp->conn_closed = 1;
}

static char *
expand_url (char const *url, char const *orig_url, struct submatch *sm, int append_uri)
{
  struct stringbuf sb;
  char *p;
  char const *expr = url; /* For error reporting */

  stringbuf_init_log (&sb);
  while (*url)
    {
      size_t len = strcspn (url, "$%");
      stringbuf_add (&sb, url, len);
      url += len;
      if (*url == 0)
	break;
      else if ((url[0] == '$' && (url[1] == '$' || url[1] == '%')) || url[1] == 0)
	{
	  stringbuf_add_char (&sb, url[0]);
	  url += 2;
	}
      else if (isdigit (url[1]))
	{
	  struct submatch *smu = &sm[url[0] == '$' ? SM_URL : SM_HDR];
	  long n;
	  errno = 0;
	  n = strtoul (url + 1, &p, 10);
	  if (errno)
	    {
	      stringbuf_add_char (&sb, url[0]);
	      url++;
	    }
	  else
	    {
	      if (n <= sm->matchn)
		{
		  stringbuf_add (&sb, smu->subject + smu->matchv[n].rm_so,
				 smu->matchv[n].rm_eo - smu->matchv[n].rm_so);
		}
	      else
		{
		  int n = p - url;
		  stringbuf_add (&sb, url, n);
		  logmsg (LOG_WARNING, "Redirect expression \"%s\" refers to non-existing group %*.*s", expr, n, n, url);
		}
	      append_uri = 1;
	      url = p;
	    }
	}
    }

  /* For compatibility with previous versions */
  if (!append_uri)
    stringbuf_add_string (&sb, orig_url);

  if ((p = stringbuf_finish (&sb)) == NULL)
    stringbuf_free (&sb);
  return p;
}

/*
 * Reply with a redirect
 */
static int
redirect_response (POUND_HTTP *phttp)
{
  struct be_redirect const *redirect = &phttp->backend->v.redirect;
  int code = redirect->status;
  char const *code_msg, *cont, *hdr;
  char *xurl, *url;
  struct stringbuf sb_url, sb_cont, sb_loc;
  int i;

  /*
   * Notice: the codes below must be in sync with the ones accepted
   * by the assign_redirect function in config.c
   */
  switch (code)
    {
    case 301:
      code_msg = "Moved Permanently";
      break;

    case 302:
      code_msg = "Found";
      break;

    case 303:
      code_msg = "See Other";
      break;

    case 307:
      code_msg = "Temporary Redirect";
      break;

    case 308:
      code_msg = "Permanent Redirect";
      break;

    default:
      logmsg (LOG_NOTICE, "INTERNAL ERROR: unsupported status code %d passed to redirect_response; please report", code);
      return HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

  xurl = expand_url (redirect->url, phttp->request.url, phttp->sm, redirect->append_uri);
  if (!xurl)
    {
      return HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

  /*
   * Make sure to return a safe version of the URL (otherwise CSRF
   * becomes a possibility)
   */
  stringbuf_init_log (&sb_url);
  for (i = 0; xurl[i]; i++)
    {
      if (isalnum (xurl[i]) || xurl[i] == '_' || xurl[i] == '.'
	  || xurl[i] == ':' || xurl[i] == '/' || xurl[i] == '?' || xurl[i] == '&'
	  || xurl[i] == ';' || xurl[i] == '-' || xurl[i] == '=')
	stringbuf_add_char (&sb_url, xurl[i]);
      else
	stringbuf_printf (&sb_url, "%%%02x", xurl[i]);
    }
  url = stringbuf_finish (&sb_url);
  free (xurl);

  if (!url)
    {
      stringbuf_free (&sb_url);
      return HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

  stringbuf_init_log (&sb_cont);
  stringbuf_printf (&sb_cont,
		    "<html><head><title>Redirect</title></head>"
		    "<body><h1>Redirect</h1>"
		    "<p>You should go to <a href=\"%s\">%s</a></p>"
		    "</body></html>",
		    url, url);

  if ((cont = stringbuf_finish (&sb_cont)) == NULL)
    {
      stringbuf_free (&sb_url);
      stringbuf_free (&sb_cont);
      return HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

  stringbuf_init_log (&sb_loc);
  stringbuf_printf (&sb_loc, "Location: %s\r\n", url);

  if ((hdr = stringbuf_finish (&sb_loc)) == NULL)
    {
      stringbuf_free (&sb_url);
      stringbuf_free (&sb_cont);
      stringbuf_free (&sb_loc);
      return HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

  bio_http_reply (phttp->cl, phttp->request.version, code, code_msg, hdr,
		  "text/html", cont);

  stringbuf_free (&sb_url);
  stringbuf_free (&sb_cont);
  stringbuf_free (&sb_loc);

  phttp->response_code = code;

  return HTTP_STATUS_OK;
}

/*
 * Read and write some binary data
 */
static int
copy_bin (BIO *cl, BIO *be, CONTENT_LENGTH cont, CONTENT_LENGTH *res_bytes, int no_write)
{
  char buf[MAXBUF];
  int res;

  while (cont > 0)
    {
      if ((res = BIO_read (cl, buf, cont > sizeof (buf) ? sizeof (buf) : cont)) < 0)
	return -1;
      else if (res == 0)
	return -2;
      if (!no_write)
	if (BIO_write (be, buf, res) != res)
	  return -3;
      cont -= res;
      if (res_bytes)
	*res_bytes += res;
    }
  if (!no_write)
    if (BIO_flush (be) != 1)
      return -4;
  return 0;
}

static int
acme_response (POUND_HTTP *phttp)
{
  int fd;
  struct stat st;
  BIO *bin;
  char *file_name;
  int rc = HTTP_STATUS_OK;

  file_name = expand_url (phttp->backend->v.acme.dir, phttp->request.url, phttp->sm, 1);

  if ((fd = open (file_name, O_RDONLY)) == -1)
    {
      if (errno == ENOENT)
	{
	  rc = HTTP_STATUS_NOT_FOUND;
	}
      else
	{
	  logmsg (LOG_ERR, "can't open %s: %s", file_name, strerror (errno));
	  rc = HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
    }
  else if (fstat (fd, &st))
    {
      logmsg (LOG_ERR, "can't stat %s: %s", file_name, strerror (errno));
      close (fd);
      rc = HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }
  else
    {
      bin = BIO_new_fd (fd, BIO_CLOSE);

      phttp->response_code = 200;
      bio_http_reply_start (phttp->cl, phttp->request.version, 200, "OK", NULL,
			    "text/html", (CONTENT_LENGTH) st.st_size);

      if (copy_bin (bin, phttp->cl, st.st_size, NULL, 0))
	{
	  if (errno)
	    logmsg (LOG_NOTICE, "(%"PRItid") error copying file %s: %s",
		    POUND_TID (), file_name, strerror (errno));
	}

      BIO_free (bin);
      BIO_flush (phttp->cl);
    }
  free (file_name);
  return rc;
}

static int
error_response (POUND_HTTP *phttp)
{
  int err = phttp->backend->v.error.status;
  char *file_name = phttp->backend->v.error.file;

  if (file_name)
    {
      int fd;
      struct stat st;

      if ((fd = open (file_name, O_RDONLY)) != -1)
	{
	  if (fstat (fd, &st) == 0)
	    {
	      BIO *bin;

	      bin = BIO_new_fd (fd, BIO_CLOSE);
	      bio_http_reply_start (phttp->cl, phttp->request.version,
				    http_status[err].code,
				    http_status[err].reason,
				    err_headers, "text/html",
				    (CONTENT_LENGTH) st.st_size);
	      if (copy_bin (bin, phttp->cl, st.st_size, NULL, 0))
		{
		  if (errno)
		    logmsg (LOG_NOTICE, "(%"PRItid") error copying file %s: %s",
			    POUND_TID (), file_name, strerror (errno));
		}

	      BIO_free (bin);
	      BIO_flush (phttp->cl);

	      phttp->response_code = http_status[err].code;
	      return 0;
	    }
	  else
	    {
	      logmsg (LOG_ERR, "(%"PRItid") failed to stat error file %s: %s",
		      POUND_TID (), file_name, strerror (errno));
	      close (fd);
	    }
	}
      else
	logmsg (LOG_ERR, "(%"PRItid") failed to open error file %s: %s",
		POUND_TID (), file_name, strerror (errno));
    }

  http_err_reply (phttp, err);

  phttp->response_code = http_status[err].code;
  return 0;
}

/*
 * Get a "line" from a BIO, strip the trailing newline, skip the input
 * stream if buffer too small
 * The result buffer is NULL terminated
 * Return 0 on success
 */
static int
get_line (BIO *in, char *const buf, int bufsize)
{
  char tmp;
  int i, seen_cr;

  memset (buf, 0, bufsize);
  for (i = 0, seen_cr = 0; i < bufsize - 1; i++)
    switch (BIO_read (in, &tmp, 1))
      {
      case -2:
	/*
	 * BIO_gets not implemented
	 */
	return -1;
      case 0:
      case -1:
	return 1;
      default:
	if (seen_cr)
	  {
	    if (tmp != '\n')
	      {
		/*
		 * we have CR not followed by NL
		 */
		do
		  {
		    if (BIO_read (in, &tmp, 1) <= 0)
		      return 1;
		  }
		while (tmp != '\n');
		return 1;
	      }
	    else
	      {
		buf[i - 1] = '\0';
		return 0;
	      }
	  }

	if (!iscntrl (tmp) || tmp == '\t')
	  {
	    buf[i] = tmp;
	    continue;
	  }

	if (tmp == '\r')
	  {
	    seen_cr = 1;
	    continue;
	  }

	if (tmp == '\n')
	  {
	    /*
	     * line ends in NL only (no CR)
	     */
	    buf[i] = 0;
	    return 0;
	  }

	/*
	 * all other control characters cause an error
	 */
	do
	  {
	    if (BIO_read (in, &tmp, 1) <= 0)
	      return 1;
	  }
	while (tmp != '\n');
	return 1;
      }

  /*
   * line too long
   */
  do
    {
      if (BIO_read (in, &tmp, 1) <= 0)
	return 1;
    }
  while (tmp != '\n');
  return 1;
}

/*
 * Strip trailing CRLF
 */
static int
strip_eol (char *lin)
{
  while (*lin)
    if (*lin == '\n' || (*lin == '\r' && *(lin + 1) == '\n'))
      {
	*lin = '\0';
	return 1;
      }
    else
      lin++;
  return 0;
}

CONTENT_LENGTH
get_content_length (char const *arg, int base)
{
  char *p;
  CONTENT_LENGTH n;

  errno = 0;
  n = STRTOCLEN (arg, &p, base);
  if (errno || n < 0 || (*p && !isspace (*p)))
    return NO_CONTENT_LENGTH;
  return n;
}

/*
 * Copy chunked
 */
static int
copy_chunks (BIO *cl, BIO *be, CONTENT_LENGTH *res_bytes, int no_write, CONTENT_LENGTH max_size)
{
  char buf[MAXBUF];
  CONTENT_LENGTH cont, tot_size;
  int res;

  for (tot_size = 0;;)
    {
      if ((res = get_line (cl, buf, sizeof (buf))) < 0)
	{
	  logmsg (LOG_NOTICE, "(%"PRItid" chunked read error: %s",
		  POUND_TID (),
		  strerror (errno));
	  return -1;
	}
      else if (res > 0)
	/*
	 * EOF
	 */
	return 0;

      if ((cont = get_content_length (buf, 16)) == NO_CONTENT_LENGTH)
	{
	  /*
	   * not chunk header
	   */
	  logmsg (LOG_NOTICE, "(%"PRItid") bad chunk header <%s>: %s",
		  POUND_TID (), buf, strerror (errno));
	  return -2;
	}
      if (!no_write)
	if (BIO_printf (be, "%s\r\n", buf) <= 0)
	  {
	    logmsg (LOG_NOTICE, "(%"PRItid") error write chunked: %s",
		    POUND_TID (), strerror (errno));
	    return -3;
	  }

      tot_size += cont;
      if (max_size > 0 && tot_size > max_size)
	{
	  logmsg (LOG_WARNING, "(%"PRItid") chunk content too large",
		  POUND_TID ());
	  return -4;
	}

      if (cont > 0)
	{
	  if (copy_bin (cl, be, cont, res_bytes, no_write))
	    {
	      if (errno)
		logmsg (LOG_NOTICE, "(%"PRItid") error copy chunk cont: %s",
			POUND_TID (), strerror (errno));
	      return -4;
	    }
	}
      else
	break;
      /*
       * final CRLF
       */
      if ((res = get_line (cl, buf, sizeof (buf))) < 0)
	{
	  logmsg (LOG_NOTICE, "(%"PRItid") error after chunk: %s",
		  POUND_TID (),
		  strerror (errno));
	  return -5;
	}
      else if (res > 0)
	{
	  logmsg (LOG_NOTICE, "(%"PRItid") unexpected EOF after chunk",
		  POUND_TID ());
	  return -5;
	}
      if (buf[0])
	logmsg (LOG_NOTICE, "(%"PRItid") unexpected after chunk \"%s\"",
		POUND_TID (), buf);
      if (!no_write)
	if (BIO_printf (be, "%s\r\n", buf) <= 0)
	  {
	    logmsg (LOG_NOTICE, "(%"PRItid") error after chunk write: %s",
		    POUND_TID (), strerror (errno));
	    return -6;
	  }
    }
  /*
   * possibly trailing headers
   */
  for (;;)
    {
      if ((res = get_line (cl, buf, sizeof (buf))) < 0)
	{
	  logmsg (LOG_NOTICE, "(%"PRItid") error post-chunk: %s",
		  POUND_TID (),
		  strerror (errno));
	  return -7;
	}
      else if (res > 0)
	break;
      if (!no_write)
	if (BIO_printf (be, "%s\r\n", buf) <= 0)
	  {
	    logmsg (LOG_NOTICE, "(%"PRItid") error post-chunk write: %s",
		    POUND_TID (), strerror (errno));
	    return -8;
	  }
      if (!buf[0])
	break;
    }
  if (!no_write)
    if (BIO_flush (be) != 1)
      {
	logmsg (LOG_NOTICE, "(%"PRItid") copy_chunks flush error: %s",
		POUND_TID (), strerror (errno));
	return -4;
      }
  return 0;
}

static int err_to = -1;

typedef struct
{
  int timeout;
  RENEG_STATE *reneg_state;
} BIO_ARG;

/*
 * Time-out for client read/gets
 * the SSL manual says not to do it, but it works well enough anyway...
 */
static long
bio_callback
#if OPENSSL_VERSION_MAJOR >= 3
(BIO *bio, int cmd, const char *argp, size_t len, int argi,
 long argl, int ret, size_t *processed)
#else
(BIO *bio, int cmd, const char *argp, int argi,
	      long argl, long ret)
#endif
{
  BIO_ARG *bio_arg;
  struct pollfd p;
  int to, p_res, p_err;

  if ((bio_arg = (BIO_ARG *) BIO_get_callback_arg (bio)) == NULL)
    return ret;

  if (cmd == BIO_CB_FREE)
    {
      free (bio_arg);
      return ret;
    }

  if (cmd != BIO_CB_READ && cmd != BIO_CB_WRITE)
    return ret;

  /*
   * a time-out already occured
   */
  if ((to = bio_arg->timeout * 1000) < 0)
    {
      errno = ETIMEDOUT;
      return -1;
    }

  /*
   * Renegotiations
   */
  /*
   * logmsg(LOG_NOTICE, "RENEG STATE %d",
   * bio_arg->reneg_state==NULL?-1:*bio_arg->reneg_state);
   */
  if (bio_arg->reneg_state != NULL && *bio_arg->reneg_state == RENEG_ABORT)
    {
      logmsg (LOG_NOTICE, "REJECTING renegotiated session");
      errno = ECONNABORTED;
      return -1;
    }

  if (to == 0)
    return ret;

  for (;;)
    {
      memset (&p, 0, sizeof (p));
      BIO_get_fd (bio, &p.fd);
      p.events = (cmd == BIO_CB_READ) ? (POLLIN | POLLPRI) : POLLOUT;
      p_res = poll (&p, 1, to);
      p_err = errno;
      switch (p_res)
	{
	case 1:
	  if (cmd == BIO_CB_READ)
	    {
	      if ((p.revents & POLLIN) || (p.revents & POLLPRI))
		/*
		 * there is readable data
		 */
		return ret;
	      else
		{
#ifdef  EBUG
		  logmsg (LOG_WARNING, "(%lx) CALLBACK read 0x%04x poll: %s",
			  pthread_self (), p.revents, strerror (p_err));
#endif
		  errno = EIO;
		}
	    }
	  else
	    {
	      if (p.revents & POLLOUT)
		/*
		 * data can be written
		 */
		return ret;
	      else
		{
#ifdef  EBUG
		  logmsg (LOG_WARNING, "(%lx) CALLBACK write 0x%04x poll: %s",
			  pthread_self (), p.revents, strerror (p_err));
#endif
		  errno = ECONNRESET;
		}
	    }
	  return -1;

	case 0:
	  /*
	   * timeout - mark the BIO as unusable for the future
	   */
	  bio_arg->timeout = err_to;
#ifdef  EBUG
	  logmsg (LOG_WARNING,
		  "(%lx) CALLBACK timeout poll after %d secs: %s",
		  pthread_self (), to / 1000, strerror (p_err));
#endif
	  errno = ETIMEDOUT;
	  return 0;

	default:
	  /*
	   * error
	   */
	  if (p_err != EINTR)
	    {
#ifdef  EBUG
	      logmsg (LOG_WARNING, "(%lx) CALLBACK bad %d poll: %s",
		      pthread_self (), p_res, strerror (p_err));
#endif
	      return -2;
#ifdef  EBUG
	    }
	  else
	    logmsg (LOG_WARNING, "(%lx) CALLBACK interrupted %d poll: %s",
		    pthread_self (), p_res, strerror (p_err));
#else
	    }
#endif
	}
    }
}

static void
set_callback (BIO *cl, int timeout, RENEG_STATE *state)
{
  BIO_ARG *arg = malloc (sizeof (*arg));
  if (!arg)
    {
      lognomem ();
      return;
    }

  arg->timeout = timeout;
  arg->reneg_state = state;

  BIO_set_callback_arg (cl, (char *) arg);
#if OPENSSL_VERSION_MAJOR >= 3
  BIO_set_callback_ex (cl, bio_callback);
#else
  BIO_set_callback (cl, bio_callback);
#endif
}

/*
 * Check if the file underlying a BIO is readable
 */
static int
is_readable (BIO *bio, int to_wait)
{
  struct pollfd p;

  if (BIO_pending (bio) > 0)
    return 1;
  memset (&p, 0, sizeof (p));
  BIO_get_fd (bio, &p.fd);
  p.events = POLLIN | POLLPRI;
  return (poll (&p, 1, to_wait * 1000) > 0);
}


static int
qualify_header (struct http_header *hdr)
{
  regmatch_t matches[4];
  static struct
  {
    char const *header;
    int len;
    int val;
  } hd_types[] = {
#define S(s) s, sizeof (s) - 1
    { S ("Transfer-encoding"), HEADER_TRANSFER_ENCODING },
    { S ("Content-length"),    HEADER_CONTENT_LENGTH },
    { S ("Connection"),        HEADER_CONNECTION },
    { S ("Location"),          HEADER_LOCATION },
    { S ("Content-location"),  HEADER_CONTLOCATION },
    { S ("Host"),              HEADER_HOST },
    { S ("Referer"),           HEADER_REFERER },
    { S ("User-agent"),        HEADER_USER_AGENT },
    { S ("Destination"),       HEADER_DESTINATION },
    { S ("Expect"),            HEADER_EXPECT },
    { S ("Upgrade"),           HEADER_UPGRADE },
    { S ("Authorization"),     HEADER_AUTHORIZATION },
    { S (""),                  HEADER_OTHER },
#undef S
  };
  int i;

  if (regexec (&HEADER, hdr->header, 4, matches, 0) == 0)
    {
      hdr->name_start = matches[1].rm_so;
      hdr->name_end = matches[1].rm_eo;
      hdr->val_start = matches[2].rm_so;
      hdr->val_end = matches[2].rm_eo;
      for (i = 0; hd_types[i].len > 0; i++)
	if ((matches[1].rm_eo - matches[1].rm_so) == hd_types[i].len
	    && strncasecmp (hdr->header + matches[1].rm_so, hd_types[i].header,
			    hd_types[i].len) == 0)
	  {
	    return hdr->code = hd_types[i].val;
	  }
      return hdr->code = HEADER_OTHER;
    }
  else
    return hdr->code = HEADER_ILLEGAL;
}

static struct http_header *
http_header_alloc (char *text)
{
  struct http_header *hdr;

  if ((hdr = calloc (1, sizeof (*hdr))) == NULL)
    {
      lognomem ();
      return NULL;
    }
  if ((hdr->header = strdup (text)) == NULL)
    {
      lognomem ();
      free (hdr);
      return NULL;
    }

  qualify_header (hdr);

  return hdr;
}

static void
http_header_free (struct http_header *hdr)
{
  free (hdr->header);
  free (hdr->value);
  free (hdr);
}

static int
http_header_change (struct http_header *hdr, char const *text, int alloc)
{
  char *ctext;

  if (alloc)
    {
      if ((ctext = strdup (text)) == NULL)
	{
	  lognomem ();
	  return -1;
	}
    }
  else
    ctext = (char*)text;
  free (hdr->header);
  hdr->header = ctext;
  qualify_header (hdr);
  return 0;
}

static int
http_header_copy_value (struct http_header *hdr, char *buf, size_t len)
{
  size_t n;

  if (buf == NULL || len == 0)
    {
      errno = EINVAL;
      return -1;
    }
  len--;
  n = hdr->val_end - hdr->val_start;

  if (len < n)
    len = n;

  memcpy (buf, hdr->header + hdr->val_start, n);
  buf[n] = 0;
  return 0;
}

static char *
http_header_get_value (struct http_header *hdr)
{
  if (!hdr->value)
    {
      size_t n = hdr->val_end - hdr->val_start + 1;
      if ((hdr->value = malloc (n)) == NULL)
	{
	  lognomem ();
	  return NULL;
	}
      http_header_copy_value (hdr, hdr->value, n);
    }
  return hdr->value;
}

static struct http_header *
http_header_list_locate (HTTP_HEADER_LIST *head, int code)
{
  struct http_header *hdr;
  DLIST_FOREACH (hdr, head, link)
    {
      if (hdr->code == code)
	return hdr;
    }
  return NULL;
}

static struct http_header *
http_header_list_locate_name (HTTP_HEADER_LIST *head, char const *name)
{
  struct http_header *hdr;
  size_t len = strcspn (name, ":");
  DLIST_FOREACH (hdr, head, link)
    {
      if (hdr->name_end - hdr->name_start == len &&
	  memcmp (hdr->header + hdr->name_start, name, len) == 0)
	return hdr;
    }
  return NULL;
}

/*
 * Append header TEXT to the list HEAD.  TEXT must be a correctly
 * formatted header line (NAME ":" VALUE).  Prior to appending, the
 * header list is scanned for a header with that name.  If found, the
 * REPLACE argument determines the further action: if it is 0, the list
 * is not modified, otherwise, the existing header is replaced with the
 * new value.
 */
int
http_header_list_append (HTTP_HEADER_LIST *head, char *text, int replace)
{
  struct http_header *hdr;

  if ((hdr = http_header_list_locate_name (head, text)) != NULL)
    {
      if (replace)
	return http_header_change (hdr, text, 1);
      else
	return 0;
    }
  else if ((hdr = http_header_alloc (text)) == NULL)
    return -1;
  else if (hdr->code == HEADER_ILLEGAL)
    {
      http_header_free (hdr);
      return 1;
    }
  else
    DLIST_INSERT_TAIL (head, hdr, link);
  return 0;
}

int
http_header_list_append_list (HTTP_HEADER_LIST *head, HTTP_HEADER_LIST *add,
			      int replace)
{
  struct http_header *hdr;
  DLIST_FOREACH (hdr, add, link)
    {
      if (http_header_list_append (head, hdr->header, replace))
	return -1;
    }
  return 0;
}

static void
http_header_list_free (HTTP_HEADER_LIST *head)
{
  while (!DLIST_EMPTY (head))
    {
      struct http_header *hdr = DLIST_FIRST (head);
      DLIST_REMOVE_HEAD (head, link);
      http_header_free (hdr);
    }
}

static void
http_header_list_remove (HTTP_HEADER_LIST *head, struct http_header *hdr)
{
  DLIST_REMOVE (head, hdr, link);
  http_header_free (hdr);
}

static void
http_header_list_filter (HTTP_HEADER_LIST *head, MATCHER *m)
{
  struct http_header *hdr, *tmp;

  DLIST_FOREACH_SAFE (hdr, tmp, head, link)
    {
      if (regexec (&m->pat, hdr->header, 0, NULL, 0))
	{
	  http_header_list_remove (head, hdr);
	}
    }
}

static char const *
http_request_line (struct http_request *req)
{
  return (req && req->request) ? req->request : "";
}

static char const *
http_request_user_name (struct http_request *req)
{
  return (req && req->user) ? req->user : "-";
}

static char const *
http_request_header_value (struct http_request *req, int code)
{
  struct http_header *hdr;
  if ((hdr = http_header_list_locate (&req->headers, code)) != NULL)
    return http_header_get_value (hdr);
  return NULL;
}

static char const *
http_request_host (struct http_request *req)
{
  return http_request_header_value (req, HEADER_HOST);
}

void
http_request_free (struct http_request *req)
{
  free (req->request);
  free (req->url);
  free (req->user);
  http_header_list_free (&req->headers);
  http_request_init (req);
}

static int
http_request_read (BIO *in, const LISTENER *lstn, struct http_request *req)
{
  char buf[MAXBUF];
  int res;

  http_request_init (req);

  /*
   * HTTP/1.1 allows leading CRLF
   */
  while ((res = get_line (in, buf, sizeof (buf))) == 0)
    if (buf[0])
      break;

  if (res < 0)
    {
      /*
       * this is expected to occur only on client reads
       */
      return -1;
    }

  if ((req->request = strdup (buf)) == NULL)
    {
      lognomem ();
      return -1;
    }

  for (;;)
    {
      struct http_header *hdr;

      if (get_line (in, buf, sizeof (buf)))
	{
	  http_request_free (req);
	  /*
	   * this is not necessarily an error, EOF/timeout are possible
	   */
	  return -1;
	}

      if (!buf[0])
	break;

      if ((hdr = http_header_alloc (buf)) == NULL)
	{
	  http_request_free (req);
	  return -1;
	}
      else if (hdr->code == HEADER_ILLEGAL)
	http_header_free (hdr);
      else
	DLIST_INSERT_TAIL (&req->headers, hdr, link);
    }
  return 0;
}

/*
 * Extrace username from the Basic Authorization header.
 * Input:
 *   hdrval   - value of the Authorization header;
 * Output:
 *   u_name   - return pointer address
 * Return value:
 *   0        - Success. Name returned in *u_name.
 *   1        - Not a Basic Authorization header.
 *  -1        - Other error.
 */
static int
get_user (char *hdrval, char **u_name)
{
  size_t len;
  BIO *bb, *b64;
  int inlen, u_len;
  char buf[MAXBUF], *q;

  if (strncasecmp (hdrval, "Basic", 5))
    return 1;

  hdrval += 5;
  while (*hdrval && isspace (*hdrval))
    hdrval++;

  len = strlen (hdrval);
  if (*hdrval == '"')
    {
      hdrval++;
      len--;

      while (len > 0 && isspace (hdrval[len-1]))
	len--;

      if (len == 0 || hdrval[len] != '"')
	return 1;
      len--;
    }

  if ((bb = BIO_new (BIO_s_mem ())) == NULL)
    {
      logmsg (LOG_WARNING, "(%"PRItid") Can't alloc BIO_s_mem", POUND_TID ());
      return -1;
    }

  if ((b64 = BIO_new (BIO_f_base64 ())) == NULL)
    {
      logmsg (LOG_WARNING, "(%"PRItid") Can't alloc BIO_f_base64",
	      POUND_TID ());
      BIO_free (bb);
      return -1;
    }

  b64 = BIO_push (b64, bb);
  BIO_write (bb, hdrval, len);
  BIO_write (bb, "\n", 1);
  inlen = BIO_read (b64, buf, sizeof (buf));
  BIO_free_all (b64);
  if (inlen <= 0)
    {
      logmsg (LOG_WARNING, "(%"PRItid") Can't read BIO_f_base64",
	      POUND_TID ());
      BIO_free_all (b64);
      return -1;
    }

  if ((q = memchr (buf, ':', inlen)) != NULL)
    {
      u_len = q - buf;
      if ((q = malloc (u_len + 1)) != NULL)
	{
	  memcpy (q, buf, u_len);
	  q[u_len] = 0;
	  *u_name = q;
	  return 0;
	}
    }
  return -1;
}

struct method_def
{
  char const *name;
  size_t length;
  int meth;
  int group;
};

static struct method_def methods[] = {
#define S(s) s, sizeof(s)-1
  { S("GET"),          METH_GET,           0 },
  { S("POST"),         METH_POST,          0 },
  { S("HEAD"),         METH_HEAD,          0 },
  { S("PUT"),          METH_PUT,           1 },
  { S("PATCH"),        METH_PATCH,         1 },
  { S("DELETE"),       METH_DELETE,        1 },
  { S("LOCK"),         METH_LOCK,          2 },
  { S("UNLOCK"),       METH_UNLOCK,        2 },
  { S("PROPFIND"),     METH_PROPFIND,      2 },
  { S("PROPPATCH"),    METH_PROPPATCH,     2 },
  { S("SEARCH"),       METH_SEARCH,        2 },
  { S("MKCOL"),        METH_MKCOL,         2 },
  { S("MOVE"),         METH_MOVE,          2 },
  { S("COPY"),         METH_COPY,          2 },
  { S("OPTIONS"),      METH_OPTIONS,       2 },
  { S("TRACE"),        METH_TRACE,         2 },
  { S("MKACTIVITY"),   METH_MKACTIVITY,    2 },
  { S("CHECKOUT"),     METH_CHECKOUT,      2 },
  { S("MERGE"),        METH_MERGE,         2 },
  { S("REPORT"),       METH_REPORT,        2 },
  { S("SUBSCRIBE"),    METH_SUBSCRIBE,     3 },
  { S("UNSUBSCRIBE"),  METH_UNSUBSCRIBE,   3 },
  { S("BPROPPATCH"),   METH_BPROPPATCH,    3 },
  { S("POLL"),         METH_POLL,          3 },
  { S("BMOVE"),        METH_BMOVE,         3 },
  { S("BCOPY"),        METH_BCOPY,         3 },
  { S("BDELETE"),      METH_BDELETE,       3 },
  { S("BPROPFIND"),    METH_BPROPFIND,     3 },
  { S("NOTIFY"),       METH_NOTIFY,        3 },
  { S("CONNECT"),      METH_CONNECT,       3 },
#undef S
  { NULL }
};

static struct method_def *
find_method (const char *str, int group)
{
  struct method_def *m;

  for (m = methods; m->name; m++)
    {
      if (strncasecmp (m->name, str, m->length) == 0)
	return m;
    }
  return NULL;
}

/*
 * Parse a URL, possibly decoding hexadecimal-encoded characters
 */
static int
decode_url (char **res, char const *src, int len)
{
  struct stringbuf sb;

  stringbuf_init_log (&sb);
  while (len)
    {
      char *p;
      size_t n;

      if ((p = memchr (src, '%', len)) != NULL)
	n = p - src;
      else
	n = len;

      if (n > 0)
	{
	  stringbuf_add (&sb, src, n);
	  src += n;
	  len -= n;
	}

      if (*src)
	{
	  static char xdig[] = "0123456789ABCDEFabcdef";
	  int a, b;

	  if (len < 3)
	    {
	      stringbuf_add (&sb, src, len);
	      break;
	    }

	  if ((p = strchr (xdig, src[1])) == NULL)
	    {
	      stringbuf_add (&sb, src, 2);
	      src += 2;
	      len -= 2;
	      continue;
	    }

	  if ((a = p - xdig) > 15)
	    a -= 6;

	  if ((p = strchr (xdig, src[2])) == NULL)
	    {
	      stringbuf_add (&sb, src, 3);
	      src += 3;
	      len -= 3;
	      continue;
	    }

	  if ((b = p - xdig) > 15)
	    b -= 6;

	  a = (a << 4) + b;
	  if (a == 0)
	    {
	      stringbuf_free (&sb);
	      return 1;
	    }
	  stringbuf_add_char (&sb, a);

	  src += 3;
	  len -= 3;
	}
    }

  if ((*res = stringbuf_finish (&sb)) == NULL)
    {
      stringbuf_free (&sb);
      return -1;
    }
  return 0;
}

static int
parse_http_request (struct http_request *req, int group)
{
  char *str;
  size_t len;
  struct method_def *md;
  char const *url;
  int http_ver;

  str = req->request;
  len = strcspn (str, " ");
  if (len == 0 || str[len-1] == 0)
    return -1;

  if ((md = find_method (str, len)) == NULL)
    return -1;

  if (md->group > group)
    return -1;

  str += len;
  str += strspn (str, " ");

  if (*str == 0)
    return -1;

  url = str;
  len = strcspn (url, " ");

  str += len;
  str += strspn (str, " ");
  if (!(strncmp (str, "HTTP/1.", 7) == 0 &&
	((http_ver = str[7]) == '0' || http_ver == '1') &&
	str[8] == 0))
    return -1;

  req->method = md->meth;
  if (decode_url (&req->url, url, len))
    return -1;

  req->version = http_ver - '0';

  return 0;
}

/*
 * HTTP Logging
 */

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

#define LOG_TIME_SIZE   32

/*
 * Apache log-file-style time format
 */
static char *
log_time_str (char *res, size_t size, struct timespec const *ts)
{
  struct tm tm;
  strftime (res, size, "%d/%b/%Y:%H:%M:%S %z", localtime_r (&ts->tv_sec, &tm));
  return res;
}

#define LOG_BYTES_SIZE  32

/*
 * Apache log-file-style number format
 */
static char *
log_bytes (char *res, size_t size, CONTENT_LENGTH cnt)
{
  if (cnt > 0)
    snprintf (res, size, "%"PRICLEN, cnt);
  else
    strcpy (res, "-");
  return res;
}

static char *
log_duration (char *buf, size_t size, struct timespec const *start)
{
  struct timespec end, diff;
  clock_gettime (CLOCK_REALTIME, &end);
  diff = timespec_sub (&end, start);
  snprintf (buf, size, "%ld.%03ld", diff.tv_sec, diff.tv_nsec / 1000000);
  return buf;
}

static void
http_log_0 (POUND_HTTP *phttp)
{
  /* nothing */
}

static void
http_log_1 (POUND_HTTP *phttp)
{
  char buf[MAX_ADDR_BUFSIZE];
  logmsg (LOG_INFO, "%s %s - %s",
	  anon_addr2str (buf, sizeof (buf), &phttp->from_host),
	  http_request_line (&phttp->request),
	  http_request_line (&phttp->response));
}

static char *
be_service_name (BACKEND *be)
{
  switch (be->be_type)
    {
    case BE_BACKEND:
      if (be->service->name[0])
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
    }
  return "-";
}

static void
http_log_2 (POUND_HTTP *phttp)
{
  char caddr[MAX_ADDR_BUFSIZE];
  char baddr[MAX_ADDR_BUFSIZE];
  char timebuf[LOG_TIME_SIZE];
  char const *v_host = http_request_host (&phttp->request);

  if (v_host)
    logmsg (LOG_INFO,
	    "%s %s - %s (%s/%s -> %s) %s sec",
	    anon_addr2str (caddr, sizeof (caddr), &phttp->from_host),
	    http_request_line (&phttp->request),
	    http_request_line (&phttp->response),
	    v_host, be_service_name (phttp->backend),
	    str_be (baddr, sizeof (baddr), phttp->backend),
	    log_duration (timebuf, sizeof (timebuf), &phttp->start_req));
  else
    logmsg (LOG_INFO,
	    "%s %s - %s (%s -> %s) %s sec",
	    anon_addr2str (caddr, sizeof (caddr), &phttp->from_host),
	    http_request_line (&phttp->request),
	    http_request_line (&phttp->response),
	    be_service_name (phttp->backend),
	    str_be (baddr, sizeof (baddr), phttp->backend),
	    log_duration (timebuf, sizeof (timebuf), &phttp->start_req));
}

static void
http_log_3 (POUND_HTTP *phttp)
{
  char caddr[MAX_ADDR_BUFSIZE];
  char timebuf[LOG_TIME_SIZE];
  char bytebuf[LOG_BYTES_SIZE];
  struct http_request *req = &phttp->request;
  char const *v_host = http_request_host (req);
  char *referer = NULL;
  char *u_agent = NULL;
  struct http_header *hdr;

  if ((hdr = http_header_list_locate (&req->headers, HEADER_REFERER)) != NULL)
    referer = http_header_get_value (hdr);
  if ((hdr = http_header_list_locate (&req->headers, HEADER_USER_AGENT)) != NULL)
    u_agent = http_header_get_value (hdr);

  logmsg (LOG_INFO,
	  "%s %s - %s [%s] \"%s\" %03d %s \"%s\" \"%s\"",
	  v_host ? v_host : "-",
	  anon_addr2str (caddr, sizeof (caddr), &phttp->from_host),
	  http_request_user_name (req),
	  log_time_str (timebuf, sizeof (timebuf), &phttp->start_req),
	  http_request_line (req),
	  phttp->response_code,
	  log_bytes (bytebuf, sizeof (bytebuf), phttp->res_bytes),
	  referer ? referer : "",
	  u_agent ? u_agent : "");
}

static void
http_log_4 (POUND_HTTP *phttp)
{
  struct http_request *req = &phttp->request;
  char caddr[MAX_ADDR_BUFSIZE];
  char timebuf[LOG_TIME_SIZE];
  char bytebuf[LOG_BYTES_SIZE];
  char *referer = NULL;
  char *u_agent = NULL;
  struct http_header *hdr;

  if ((hdr = http_header_list_locate (&req->headers, HEADER_REFERER)) != NULL)
    referer = http_header_get_value (hdr);
  if ((hdr = http_header_list_locate (&req->headers, HEADER_USER_AGENT)) != NULL)
    u_agent = http_header_get_value (hdr);

  logmsg (LOG_INFO,
	  "%s - %s [%s] \"%s\" %03d %s \"%s\" \"%s\"",
	  anon_addr2str (caddr, sizeof (caddr), &phttp->from_host),
	  http_request_user_name (req),
	  log_time_str (timebuf, sizeof (timebuf), &phttp->start_req),
	  http_request_line (req),
	  phttp->response_code,
	  log_bytes (bytebuf, sizeof (bytebuf), phttp->res_bytes),
	  referer ? referer : "",
	  u_agent ? u_agent : "");
}

static void
http_log_5 (POUND_HTTP *phttp)
{
  struct http_request *req = &phttp->request;
  char caddr[MAX_ADDR_BUFSIZE];
  char baddr[MAX_ADDR_BUFSIZE];
  char timebuf[LOG_TIME_SIZE];
  char dbuf[LOG_TIME_SIZE];
  char bytebuf[LOG_BYTES_SIZE];
  char const *v_host = http_request_host (req);
  char *referer = NULL;
  char *u_agent = NULL;
  struct http_header *hdr;

  if ((hdr = http_header_list_locate (&req->headers, HEADER_REFERER)) != NULL)
    referer = http_header_get_value (hdr);
  if ((hdr = http_header_list_locate (&req->headers, HEADER_USER_AGENT)) != NULL)
    u_agent = http_header_get_value (hdr);

  logmsg (LOG_INFO,
	  "%s %s - %s [%s] \"%s\" %03d %s \"%s\" \"%s\" (%s -> %s) %s sec",
	  v_host ? v_host : "-",
	  anon_addr2str (caddr, sizeof (caddr), &phttp->from_host),
	  http_request_user_name (req),
	  log_time_str (timebuf, sizeof (timebuf), &phttp->start_req),
	  http_request_line (req),
	  phttp->response_code,
	  log_bytes (bytebuf, sizeof (bytebuf), phttp->res_bytes),
	  referer ? referer : "",
	  u_agent ? u_agent : "",
	  be_service_name (phttp->backend),
	  str_be (baddr, sizeof (baddr), phttp->backend),
	  log_duration (dbuf, sizeof (dbuf), &phttp->start_req));
}

static void (*http_logger[]) (POUND_HTTP *phttp) = {
  http_log_0,
  http_log_1,
  http_log_2,
  http_log_3,
  http_log_4,
  http_log_5
};

static void
http_log (POUND_HTTP *phttp)
{
  http_logger[phttp->lstn->log_level] (phttp);
}

static int
http_request_send (BIO *be, struct http_request *req)
{
  struct http_header *hdr;

  if (BIO_printf (be, "%s\r\n", req->request) <= 0)
    return -1;
  DLIST_FOREACH (hdr, &req->headers, link)
    {
      if (BIO_printf (be, "%s\r\n", hdr->header) <= 0)
	return -1;
    }
  return 0;
}

static int
add_forwarded_headers (POUND_HTTP *phttp)
{
  char caddr[MAX_ADDR_BUFSIZE];
  struct stringbuf sb;
  char *str;
  int port;

  stringbuf_init_log (&sb);

  stringbuf_printf (&sb, "X-Forwarded-For: %s",
		    addr2str (caddr, sizeof (caddr), &phttp->from_host, 1));
  if ((str = stringbuf_finish (&sb)) == NULL
      || http_header_list_append (&phttp->request.headers, str, H_REPLACE))
    {
      stringbuf_free (&sb);
      return -1;
    }

  stringbuf_reset (&sb);
  stringbuf_printf (&sb, "X-Forwarded-Proto: %s",
		    phttp->ssl == NULL ? "http" : "https");
  if ((str = stringbuf_finish (&sb)) == NULL
      || http_header_list_append (&phttp->request.headers, str, H_REPLACE))
    {
      stringbuf_free (&sb);
      return -1;
    }

  switch (phttp->from_host.ai_family)
    {
    case AF_INET:
      port = ntohs (((struct sockaddr_in *)phttp->lstn->addr.ai_addr)->sin_port);
      break;

    case AF_INET6:
      port = ntohs (((struct sockaddr_in6 *)phttp->lstn->addr.ai_addr)->sin6_port);
      break;

    default:
      return 0;
    }

  stringbuf_reset (&sb);
  stringbuf_printf (&sb, "X-Forwarded-Port: %d", port);
  if ((str = stringbuf_finish (&sb)) == NULL
      || http_header_list_append (&phttp->request.headers, str, H_REPLACE))
    {
      stringbuf_free (&sb);
      return -1;
    }

  return 0;
}

static int
add_ssl_headers (POUND_HTTP *phttp)
{
  int res = 0;
  const SSL_CIPHER *cipher;
  struct stringbuf sb;
  char *str;
  char buf[MAXBUF];
  BIO *bio = NULL;

  stringbuf_init_log (&sb);
  if ((cipher = SSL_get_current_cipher (phttp->ssl)) != NULL)
    {
      SSL_CIPHER_description (cipher, buf, sizeof (buf));
      strip_eol (buf);
      stringbuf_printf (&sb, "X-SSL-cipher: %s/%s",
			SSL_get_version (phttp->ssl),
			buf);
      if ((str = stringbuf_finish (&sb)) == NULL
	  || http_header_list_append (&phttp->request.headers, str, H_REPLACE))
	{
	  res = -1;
	  goto end;
	}
      stringbuf_reset (&sb);
    }

  if (phttp->lstn->clnt_check > 0 && phttp->x509 != NULL
      && (bio = BIO_new (BIO_s_mem ())) != NULL)
    {
      X509_NAME_print_ex (bio, X509_get_subject_name (phttp->x509), 8,
			  XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
      get_line (bio, buf, sizeof (buf));
      stringbuf_printf (&sb, "X-SSL-Subject: %s", buf);
      if ((str = stringbuf_finish (&sb)) == NULL
	  || http_header_list_append (&phttp->request.headers, str, H_REPLACE))
	{
	  res = -1;
	  goto end;
	}
      stringbuf_reset (&sb);

      X509_NAME_print_ex (bio, X509_get_issuer_name (phttp->x509), 8,
			  XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
      get_line (bio, buf, sizeof (buf));
      stringbuf_printf (&sb, "X-SSL-Issuer: %s", buf);
      if ((str = stringbuf_finish (&sb)) == NULL
	  || http_header_list_append (&phttp->request.headers, str, H_REPLACE))
	{
	  res = -1;
	  goto end;
	}
      stringbuf_reset (&sb);

      ASN1_TIME_print (bio, X509_get_notBefore (phttp->x509));
      get_line (bio, buf, sizeof (buf));
      stringbuf_printf (&sb, "X-SSL-notBefore: %s", buf);
      if ((str = stringbuf_finish (&sb)) == NULL
	  || http_header_list_append (&phttp->request.headers, str, H_REPLACE))
	{
	  res = -1;
	  goto end;
	}
      stringbuf_reset (&sb);

      ASN1_TIME_print (bio, X509_get_notAfter (phttp->x509));
      get_line (bio, buf, sizeof (buf));
      stringbuf_printf (&sb, "X-SSL-notAfter: %s", buf);
      if ((str = stringbuf_finish (&sb)) == NULL
	  || http_header_list_append (&phttp->request.headers, str, H_REPLACE))
	{
	  res = -1;
	  goto end;
	}
      stringbuf_reset (&sb);

      stringbuf_printf (&sb, "X-SSL-serial: %ld",
			ASN1_INTEGER_get (X509_get_serialNumber (phttp->x509)));
      if ((str = stringbuf_finish (&sb)) == NULL
	  || http_header_list_append (&phttp->request.headers, str, H_REPLACE))
	{
	  res = -1;
	  goto end;
	}
      stringbuf_reset (&sb);

      PEM_write_bio_X509 (bio, phttp->x509);
      stringbuf_add_string (&sb, "X-SSL-certificate: ");
      while (get_line (bio, buf, sizeof (buf)) == 0)
	{
	  stringbuf_add_string (&sb, buf);
	}
      if ((str = stringbuf_finish (&sb)) == NULL
	  || http_header_list_append (&phttp->request.headers, str, H_REPLACE))
	{
	  res = -1;
	  goto end;
	}
    }

 end:
  if (bio)
    BIO_free_all (bio);
  stringbuf_free (&sb);

  return res;
}

/*
 * Cleanup code. This should really be in the pthread_cleanup_push, except
 * for bugs in some implementations
 */

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#  define clear_error(ssl)
#else /* OPENSSL_VERSION_NUMBER >= 0x10000000L */
#  define clear_error(ssl) \
	if(ssl != NULL) { ERR_clear_error(); ERR_remove_thread_state(NULL); }
#endif

static void
socket_setup (int sock)
{
  int n = 1;
  struct linger l;

  setsockopt (sock, SOL_SOCKET, SO_KEEPALIVE, (void *) &n, sizeof (n));
  l.l_onoff = 1;
  l.l_linger = 10;
  setsockopt (sock, SOL_SOCKET, SO_LINGER, (void *) &l, sizeof (l));
#ifdef  TCP_LINGER2
  n = 5;
  setsockopt (sock, SOL_TCP, TCP_LINGER2, (void *) &n, sizeof (n));
#endif
  n = 1;
  setsockopt (sock, SOL_TCP, TCP_NODELAY, (void *) &n, sizeof (n));
}

static int
force_http_10 (POUND_HTTP *phttp)
{
  /*
   * check the value if nohttps11:
   *  - if 0 ignore
   *  - if 1 and SSL force HTTP/1.0
   *  - if 2 and SSL and MSIE force HTTP/1.0
   */
  switch (phttp->lstn->noHTTPS11)
    {
    case 1:
      return (phttp->ssl != NULL);

    case 2:
      {
	char const *agent = http_request_header_value (&phttp->request, HEADER_USER_AGENT);
	return (phttp->ssl != NULL && agent != NULL && strstr (agent, "MSIE") != NULL);
      }

    default:
      break;
    }
  return 0;
}

static void
close_backend (POUND_HTTP *phttp)
{
  if (phttp->be)
    {
      BIO_reset (phttp->be);
      BIO_free_all (phttp->be);
      phttp->be = NULL;
    }
}

/*
 * get the response
 */
static int
backend_response (POUND_HTTP *phttp)
{
  int skip = 0;
  int be_11 = 0;  /* Whether backend connection is using HTTP/1.1. */
  CONTENT_LENGTH content_length;
  char caddr[MAX_ADDR_BUFSIZE], caddr2[MAX_ADDR_BUFSIZE];
  char duration_buf[LOG_TIME_SIZE];
  char buf[MAXBUF];
  struct http_header *hdr;
  char *val;
  int res;

  phttp->res_bytes = 0;
  do
    {
      int chunked; /* True if request contains Transfer-Enconding: chunked */

      if (http_request_read (phttp->be, phttp->lstn, &phttp->response))
	{
	  logmsg (LOG_NOTICE,
		  "(%"PRItid") e500 for %s response error read from %s/%s: %s (%s secs)",
		  POUND_TID (),
		  addr2str (caddr, sizeof (caddr), &phttp->from_host, 1),
		  str_be (caddr2, sizeof (caddr2), phttp->backend),
		  phttp->request.request, strerror (errno),
		  log_duration (duration_buf, sizeof (duration_buf), &phttp->start_req));
	  return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}

      be_11 = (phttp->response.request[7] == '1');
      phttp->response_code = strtol (phttp->response.request+9, NULL, 10);

      switch (phttp->response_code)
	{
	case 100:
	  /*
	   * responses with code 100 are never passed back to the client
	   */
	  skip = 1;
	  break;

	case 101:
	  phttp->ws_state |= WSS_RESP_101;
	  phttp->no_cont = 1;
	  break;

	case 204:
	case 304:
	case 305:
	case 306:
	  /* No content is expected */
	  phttp->no_cont = 1;
	  break;

	default:
	  if (phttp->response_code / 100 == 1)
	    phttp->no_cont = 1;
	}

      chunked = 0;
      content_length = NO_CONTENT_LENGTH;
      DLIST_FOREACH (hdr, &phttp->response.headers, link)
	{
	  switch (hdr->code)
	    {
	    case HEADER_CONNECTION:
	      if ((val = http_header_get_value (hdr)) == NULL)
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	      if (!strcasecmp ("close", val))
		phttp->conn_closed = 1;
	      /*
	       * Connection: upgrade
	       */
	      else if (!regexec (&CONN_UPGRD, val, 0, NULL, 0))
		phttp->ws_state |= WSS_RESP_HEADER_CONNECTION_UPGRADE;
	      break;

	    case HEADER_UPGRADE:
	      if ((val = http_header_get_value (hdr)) == NULL)
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	      if (!strcasecmp ("websocket", val))
		phttp->ws_state |= WSS_RESP_HEADER_UPGRADE_WEBSOCKET;
	      break;

	    case HEADER_TRANSFER_ENCODING:
	      if ((val = http_header_get_value (hdr)) == NULL)
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	      if (!strcasecmp ("chunked", val))
		{
		  chunked = 1;
		  phttp->no_cont = 0;
		}
	      break;

	    case HEADER_CONTENT_LENGTH:
	      if ((val = http_header_get_value (hdr)) == NULL)
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	      if ((content_length = get_content_length (val, 10)) == NO_CONTENT_LENGTH)
		{
		  logmsg (LOG_WARNING, "(%"PRItid") invalid content length: %s",
			  POUND_TID (), val);
		  http_header_list_remove (&phttp->response.headers, hdr);
		}
	      break;

	    case HEADER_LOCATION:
	      if ((val = http_header_get_value (hdr)) == NULL)
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	      else if (phttp->lstn->rewr_loc)
		{
		  char const *v_host = http_request_host (&phttp->request);
		  char const *path;
		  if (v_host && v_host[0] &&
		      need_rewrite (val, v_host, phttp->lstn, phttp->backend, &path))
		    {
		      struct stringbuf sb;
		      char *p;

		      stringbuf_init_log (&sb);
		      stringbuf_printf (&sb, "Location: %s://%s/%s",
					(phttp->ssl == NULL ? "http" : "https"),
					v_host,
					path);
		      if ((p = stringbuf_finish (&sb)) == NULL)
			{
			  stringbuf_free (&sb);
			  logmsg (LOG_WARNING,
				  "(%"PRItid") rewrite Location - out of memory: %s",
				  POUND_TID (), strerror (errno));
			  return HTTP_STATUS_INTERNAL_SERVER_ERROR;
			}
		      http_header_change (hdr, p, 0);
		    }
		}
	      break;

	    case HEADER_CONTLOCATION:
	      if ((val = http_header_get_value (hdr)) == NULL)
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	      else if (phttp->lstn->rewr_loc)
		{
		  char const *v_host = http_request_host (&phttp->request);
		  char const *path;
		  if (v_host && v_host[0] &&
		      need_rewrite (val, v_host, phttp->lstn, phttp->backend, &path))
		    {
		      struct stringbuf sb;
		      char *p;

		      stringbuf_init_log (&sb);
		      stringbuf_printf (&sb,
					"Content-location: %s://%s/%s",
					(phttp->ssl == NULL ? "http" : "https"),
					v_host,
					path);
		      if ((p = stringbuf_finish (&sb)) == NULL)
			{
			  stringbuf_free (&sb);
			  logmsg (LOG_WARNING,
				  "(%"PRItid") rewrite Content-location - out of memory: %s",
				  POUND_TID (), strerror (errno));
			  return HTTP_STATUS_INTERNAL_SERVER_ERROR;
			}
		      http_header_change (hdr, p, 0);
		    }
		  break;
		}
	    }
	}

      /*
       * possibly record session information (only for
       * cookies/header)
       */
      upd_session (phttp->svc, &phttp->response.headers, phttp->backend);

      /*
       * send the response
       */
      if (!skip)
	{
	  if (http_request_send (phttp->cl, &phttp->response))
	    {
	      if (errno)
		{
		  logmsg (LOG_NOTICE, "(%"PRItid") error write to %s: %s",
			  POUND_TID (),
			  addr2str (caddr, sizeof (caddr), &phttp->from_host, 1),
			  strerror (errno));
		}
	      return -1;
	    }
	  /* Final CRLF */
	  BIO_puts (phttp->cl, "\r\n");
	}

      if (BIO_flush (phttp->cl) != 1)
	{
	  if (errno)
	    {
	      logmsg (LOG_NOTICE, "(%"PRItid") error flush headers to %s: %s",
		      POUND_TID (),
		      addr2str (caddr, sizeof (caddr), &phttp->from_host, 1),
		      strerror (errno));
	    }
	  return -1;
	}

      if (!phttp->no_cont)
	{
	  /*
	   * ignore this if request was HEAD or similar
	   */
	  if (be_11 && chunked)
	    {
	      /*
	       * had Transfer-encoding: chunked so read/write all
	       * the chunks (HTTP/1.1 only)
	       */
	      if (copy_chunks (phttp->be, phttp->cl, &phttp->res_bytes, skip, 0))
		{
		  /*
		   * copy_chunks() has its own error messages
		   */
		  return -1;
		}
	    }
	  else if (content_length >= 0)
	    {
	      /*
	       * may have had Content-length, so do raw reads/writes
	       * for the length
	       */
	      if (copy_bin (phttp->be, phttp->cl, content_length, &phttp->res_bytes, skip))
		{
		  if (errno)
		    logmsg (LOG_NOTICE,
			    "(%"PRItid") error copy server cont: %s",
			    POUND_TID (), strerror (errno));
		  return -1;
		}
	    }
	  else if (!skip)
	    {
	      if (is_readable (phttp->be, phttp->backend->v.reg.to))
		{
		  char one;
		  BIO *be_unbuf;

		  /*
		   * old-style response - content until EOF
		   * also implies the client may not use HTTP/1.1
		   */
		  be_11 = 0;
		  phttp->conn_closed = 1;

		  /*
		   * first read whatever is already in the input buffer
		   */
		  while (BIO_pending (phttp->be))
		    {
		      if (BIO_read (phttp->be, &one, 1) != 1)
			{
			  logmsg (LOG_NOTICE,
				  "(%"PRItid") error read response pending: %s",
				  POUND_TID (), strerror (errno));
			  return -1;
			}
		      if (BIO_write (phttp->cl, &one, 1) != 1)
			{
			  if (errno)
			    logmsg (LOG_NOTICE,
				    "(%"PRItid") error write response pending: %s",
				    POUND_TID (), strerror (errno));
			  return -1;
			}
		      phttp->res_bytes++;
		    }
		  BIO_flush (phttp->cl);

		  /*
		   * find the socket BIO in the chain
		   */
		  if ((be_unbuf =
			   BIO_find_type (phttp->be,
					  backend_is_https (phttp->backend)
					    ? BIO_TYPE_SSL
					    : BIO_TYPE_SOCKET)) == NULL)
		    {
		      logmsg (LOG_WARNING,
			      "(%"PRItid") error get unbuffered: %s",
			      POUND_TID (), strerror (errno));
		      return -1;
		    }

		  /*
		   * copy till EOF
		   */
		  while ((res = BIO_read (be_unbuf, buf, sizeof (buf))) > 0)
		    {
		      if (BIO_write (phttp->cl, buf, res) != res)
			{
			  if (errno)
			    logmsg (LOG_NOTICE,
				    "(%"PRItid") error copy response body: %s",
				    POUND_TID (), strerror (errno));
			  return -1;
			}
		      else
			{
			  phttp->res_bytes += res;
			  BIO_flush (phttp->cl);
			}
		    }
		}
	    }
	  if (BIO_flush (phttp->cl) != 1)
	    {
	      if (errno)
		{
		  logmsg (LOG_NOTICE, "(%"PRItid") error final flush to %s: %s",
			  POUND_TID (),
			  addr2str (caddr, sizeof (caddr), &phttp->from_host, 1),
			  strerror (errno));
		}
	      return -1;
	    }
	}
      else if (phttp->ws_state == WSS_COMPLETE)
	{
	  /*
	   * special mode for Websockets - content until EOF
	   */
	  char one;
	  BIO *cl_unbuf;
	  BIO *be_unbuf;
	  struct pollfd p[2];

	  /* Force connection close on both sides when ws has finished */
	  be_11 = 0;
	  phttp->conn_closed = 1;

	  memset (p, 0, sizeof (p));
	  BIO_get_fd (phttp->cl, &p[0].fd);
	  p[0].events = POLLIN | POLLPRI;
	  BIO_get_fd (phttp->be, &p[1].fd);
	  p[1].events = POLLIN | POLLPRI;

	  while (BIO_pending (phttp->cl) || BIO_pending (phttp->be)
		 || poll (p, 2, phttp->backend->v.reg.ws_to * 1000) > 0)
	    {

	      /*
	       * first read whatever is already in the input buffer
	       */
	      while (BIO_pending (phttp->cl))
		{
		  if (BIO_read (phttp->cl, &one, 1) != 1)
		    {
		      logmsg (LOG_NOTICE,
			      "(%"PRItid") error read ws request pending: %s",
			      POUND_TID (), strerror (errno));
		      return -1;
		    }
		  if (BIO_write (phttp->be, &one, 1) != 1)
		    {
		      if (errno)
			logmsg (LOG_NOTICE,
				"(%"PRItid") error write ws request pending: %s",
				POUND_TID (), strerror (errno));
		      return -1;
		    }
		}
	      BIO_flush (phttp->be);

	      while (BIO_pending (phttp->be))
		{
		  if (BIO_read (phttp->be, &one, 1) != 1)
		    {
		      logmsg (LOG_NOTICE,
			      "(%"PRItid") error read ws response pending: %s",
			      POUND_TID (), strerror (errno));
		      return -1;
		    }
		  if (BIO_write (phttp->cl, &one, 1) != 1)
		    {
		      if (errno)
			logmsg (LOG_NOTICE,
				"(%"PRItid") error write ws response pending: %s",
				POUND_TID (), strerror (errno));
		      return -1;
		    }
		  phttp->res_bytes++;
		}
	      BIO_flush (phttp->cl);

	      /*
	       * find the socket BIO in the chain
	       */
	      if ((cl_unbuf =
		   BIO_find_type (phttp->cl,
				  SLIST_EMPTY (&phttp->lstn->ctx_head)
				  ? BIO_TYPE_SOCKET : BIO_TYPE_SSL)) == NULL)
		{
		  logmsg (LOG_WARNING, "(%"PRItid") error get unbuffered: %s",
			  POUND_TID (), strerror (errno));
		  return -1;
		}
	      if ((be_unbuf = BIO_find_type (phttp->be,
					     backend_is_https (phttp->backend)
					       ? BIO_TYPE_SSL
					       : BIO_TYPE_SOCKET)) == NULL)
		{
		  logmsg (LOG_WARNING, "(%"PRItid") error get unbuffered: %s",
			  POUND_TID (), strerror (errno));
		  return -1;
		}

	      /*
	       * copy till EOF
	       */
	      if (p[0].revents)
		{
		  res = BIO_read (cl_unbuf, buf, sizeof (buf));
		  if (res <= 0)
		    {
		      break;
		    }
		  if (BIO_write (phttp->be, buf, res) != res)
		    {
		      if (errno)
			logmsg (LOG_NOTICE,
				"(%"PRItid") error copy ws request body: %s",
				POUND_TID (), strerror (errno));
		      return -1;
		    }
		  else
		    {
		      BIO_flush (phttp->be);
		    }
		  p[0].revents = 0;
		}
	      if (p[1].revents)
		{
		  res = BIO_read (be_unbuf, buf, sizeof (buf));
		  if (res <= 0)
		    {
		      break;
		    }
		  if (BIO_write (phttp->cl, buf, res) != res)
		    {
		      if (errno)
			logmsg (LOG_NOTICE,
				"(%"PRItid") error copy ws response body: %s",
				POUND_TID (), strerror (errno));
		      return -1;
		    }
		  else
		    {
		      phttp->res_bytes += res;
		      BIO_flush (phttp->cl);
		    }
		  p[1].revents = 0;
		}
	    }
	}
      http_request_free (&phttp->response);
    }
  while (skip);

  if (!be_11)
    close_backend (phttp);

  return HTTP_STATUS_OK;
}

/*
 * Pass the request to the backend.  Return 0 on success and pound
 * http error number otherwise.
 */
static int
send_to_backend (POUND_HTTP *phttp, int chunked, CONTENT_LENGTH content_length)
{
  struct http_header *hdr;
  char const *val;
  char caddr[MAX_ADDR_BUFSIZE], caddr2[MAX_ADDR_BUFSIZE];
  char duration_buf[LOG_TIME_SIZE];

  /*
   * this is the earliest we can check for Destination - we
   * had no back-end before
   */
  if (phttp->lstn->rewr_dest &&
      (hdr = http_header_list_locate (&phttp->request.headers, HEADER_DESTINATION)) != NULL)
    {
      regmatch_t matches[4];

      if ((val = http_header_get_value (hdr)) == NULL)
	return HTTP_STATUS_INTERNAL_SERVER_ERROR;

      if (regexec (&LOCATION, val, 4, matches, 0))
	{
	  logmsg (LOG_NOTICE, "(%"PRItid") Can't parse Destination %s",
		  POUND_TID (), val);
	}
      else
	{
	  struct stringbuf sb;
	  char *p;

	  stringbuf_init_log (&sb);
	  str_be (caddr, sizeof (caddr), phttp->backend);
	  stringbuf_printf (&sb,
			    "Destination: %s://%s%s",
			    backend_is_https (phttp->backend) ? "https" : "http",
			    caddr,
			    val + matches[3].rm_so);
	  if ((p = stringbuf_finish (&sb)) == NULL)
	    {
	      stringbuf_free (&sb);
	      logmsg (LOG_WARNING,
		      "(%"PRItid") rewrite Destination - out of memory: %s",
		      POUND_TID (), strerror (errno));
	      return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	    }

	  http_header_change (hdr, p, 0);
	}
    }

  /*
   * Add "canned" headers.
   */
  if (phttp->lstn->header_options & HDROPT_FORWARDED_HEADERS)
    {
      if (add_forwarded_headers (phttp))
	lognomem ();
    }

  if (phttp->ssl != NULL && (phttp->lstn->header_options & HDROPT_SSL_HEADERS))
    {
      if (add_ssl_headers (phttp))
	lognomem ();
    }

  /*
   * Remove headers
   */
  if (!SLIST_EMPTY (&phttp->lstn->head_off))
    {
      MATCHER *m;

      SLIST_FOREACH (m, &phttp->lstn->head_off, next)
	http_header_list_filter (&phttp->request.headers, m);
    }

  /*
   * Add headers if required
   */
  if (http_header_list_append_list (&phttp->request.headers,
				    &phttp->lstn->add_header,
				    H_REPLACE))
    return HTTP_STATUS_INTERNAL_SERVER_ERROR;

  /*
   * Send the request and its headers
   */
  if (http_request_send (phttp->be, &phttp->request))
    {
      if (errno)
	{
	  logmsg (LOG_WARNING,
		  "(%"PRItid") e500 error write to %s/%s: %s (%s sec)",
		  POUND_TID (),
		  str_be (caddr, sizeof (caddr), phttp->backend),
		  phttp->request.request, strerror (errno),
		  log_duration (duration_buf, sizeof (duration_buf), &phttp->start_req));
	}
      return HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

  /*
   * final CRLF
   */
  BIO_puts (phttp->be, "\r\n");

  if (chunked)
    {
      /*
       * had Transfer-encoding: chunked so read/write all the chunks
       * (HTTP/1.1 only)
       */
      if (copy_chunks (phttp->cl, phttp->be, NULL,
		       phttp->backend->be_type != BE_BACKEND,
		       phttp->lstn->max_req))
	{
	  logmsg (LOG_NOTICE,
		  "(%"PRItid") e500 for %s copy_chunks to %s/%s (%s sec)",
		  POUND_TID (),
		  addr2str (caddr, sizeof (caddr), &phttp->from_host, 1),
		  str_be (caddr2, sizeof (caddr2), phttp->backend),
		  phttp->request.request,
		  log_duration (duration_buf, sizeof (duration_buf), &phttp->start_req));
	  return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
    }
  else if (content_length > 0)
    {
      /*
       * had Content-length, so do raw reads/writes for the length
       */
      if (copy_bin (phttp->cl, phttp->be, content_length, NULL, phttp->backend->be_type != BE_BACKEND))
	{
	  logmsg (LOG_NOTICE,
		  "(%"PRItid") e500 for %s error copy client cont to %s/%s: %s (%s sec)",
		  POUND_TID (),
		  addr2str (caddr, sizeof (caddr), &phttp->from_host, 1),
		  str_be (caddr2, sizeof (caddr2), phttp->backend),
		  phttp->request.request, strerror (errno),
		  log_duration (duration_buf, sizeof (duration_buf), &phttp->start_req));
	  return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
    }

  /*
   * flush to the back-end
   */
  if (BIO_flush (phttp->be) != 1)
    {
      logmsg (LOG_NOTICE,
	      "(%"PRItid") e500 for %s error flush to %s/%s: %s (%s sec)",
	      POUND_TID (),
	      addr2str (caddr, sizeof (caddr), &phttp->from_host, 1),
	      str_be (caddr2, sizeof (caddr2), phttp->backend),
	      phttp->request.request, strerror (errno),
	      log_duration (duration_buf, sizeof (duration_buf), &phttp->start_req));
      return HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }
  return 0;
}

static int
open_backend (POUND_HTTP *phttp, BACKEND *backend, int sock)
{
  char caddr[MAX_ADDR_BUFSIZE];

  /* Create new BIO */
  if ((phttp->be = BIO_new_socket (sock, 1)) == NULL)
    {
      logmsg (LOG_WARNING, "(%"PRItid") e503 BIO_new_socket server failed",
	      POUND_TID ());
      shutdown (sock, 2);
      close (sock);
      return HTTP_STATUS_SERVICE_UNAVAILABLE;
    }

  /* Configure it */
  BIO_set_close (phttp->be, BIO_CLOSE);
  if (backend->v.reg.to > 0)
    {
      set_callback (phttp->be, backend->v.reg.to, &phttp->reneg_state);
    }

  /*
   * Set up SSL, if requested.
   */
  if (backend_is_https (backend))
    {
      SSL *be_ssl;
      BIO *bb;

      if ((be_ssl = SSL_new (backend->v.reg.ctx)) == NULL)
	{
	  logmsg (LOG_WARNING, "(%"PRItid") be SSL_new: failed", POUND_TID ());
	  return HTTP_STATUS_SERVICE_UNAVAILABLE;
	}
      SSL_set_bio (be_ssl, phttp->be, phttp->be);
      if ((bb = BIO_new (BIO_f_ssl ())) == NULL)
	{
	  logmsg (LOG_WARNING, "(%"PRItid") BIO_new(Bio_f_ssl()) failed",
		  POUND_TID ());
	  return HTTP_STATUS_SERVICE_UNAVAILABLE;
	}

      BIO_set_ssl (bb, be_ssl, BIO_CLOSE);
      BIO_set_ssl_mode (bb, 1);
      phttp->be = bb;

      if (BIO_do_handshake (phttp->be) <= 0)
	{
	  logmsg (LOG_NOTICE, "BIO_do_handshake with %s failed: %s",
		  str_be (caddr, sizeof (caddr), backend),
		  ERR_error_string (ERR_get_error (), NULL));
	  return HTTP_STATUS_SERVICE_UNAVAILABLE;
	}

      if ((bb = BIO_new (BIO_f_buffer ())) == NULL)
	{
	  logmsg (LOG_WARNING, "(%"PRItid") e503 BIO_new(buffer) server failed",
		  POUND_TID ());
	  return HTTP_STATUS_SERVICE_UNAVAILABLE;
	}

      BIO_set_buffer_size (bb, MAXBUF);
      BIO_set_close (bb, BIO_CLOSE);
      phttp->be = BIO_push (bb, phttp->be);

    }
  return 0;
}

static int
select_backend (POUND_HTTP *phttp)
{
  BACKEND *backend;
  int sock;
  char const *v_host;
  char caddr[MAX_ADDR_BUFSIZE];

  if ((backend = get_backend (phttp->svc, &phttp->from_host,
			      phttp->request.url,
			      &phttp->request.headers)) != NULL)
    {
      if (phttp->be != NULL)
	{
	  if (backend == phttp->backend)
	    /* Same backend as before: nothing to do */
	    return 0;
	  else
	    close_backend (phttp);
	}

      do
	{
	  if (backend->be_type == BE_BACKEND)
	    {
	      /*
	       * Try to open connection to this backend.
	       */
	      int sock_proto;

	      switch (backend->v.reg.addr.ai_family)
		{
		case AF_INET:
		  sock_proto = PF_INET;
		  break;

		case AF_INET6:
		  sock_proto = PF_INET6;
		  break;

		case AF_UNIX:
		  sock_proto = PF_UNIX;
		  break;

		default:
		  logmsg (LOG_WARNING, "(%"PRItid") e503 backend: unknown family %d",
			  POUND_TID (), backend->v.reg.addr.ai_family);
		  return HTTP_STATUS_SERVICE_UNAVAILABLE;
		}

	      if ((sock = socket (sock_proto, SOCK_STREAM, 0)) < 0)
		{
		  logmsg (LOG_WARNING, "(%"PRItid") e503 backend %s socket create: %s",
			  POUND_TID (),
			  str_be (caddr, sizeof (caddr), backend),
			  strerror (errno));
		  return HTTP_STATUS_SERVICE_UNAVAILABLE;
		}

	      if (connect_nb (sock, &backend->v.reg.addr, backend->v.reg.conn_to) == 0)
		{
		  int res;

		  /*
		   * Connected successfully.  Open the backend connection.
		   */
		  if (sock_proto == PF_INET || sock_proto == PF_INET6)
		    socket_setup (sock);
		  if ((res = open_backend (phttp, backend, sock)) != 0)
		    {
		      close_backend (phttp);
		      return res;
		    }
		  /* New backend selected. */
		  phttp->backend = backend;
		  return 0;
		}

	      logmsg (LOG_WARNING, "(%"PRItid") backend %s connect: %s",
		      POUND_TID (),
		      str_be (caddr, sizeof (caddr), backend),
		      strerror (errno));
	      shutdown (sock, 2);
	      close (sock);
	      /*
	       * The following will close all sessions associated with
	       * this backend, and mark the backend itself as dead, so
	       * that it won't be returned again by the call to get_backed
	       * below.
	       */
	      kill_be (phttp->svc, backend, BE_KILL);
	      /* Try next backend now. */
	    }
	  else
	    {
	      /* New backend selected. */
	      phttp->backend = backend;
	      return 0;
	    }
	}
      while ((backend = get_backend (phttp->svc, &phttp->from_host,
				     phttp->request.url, &phttp->request.headers)) != NULL);
    }

  /*
   * No backend found or is available.
   */
  v_host = http_request_host (&phttp->request);
  logmsg (LOG_NOTICE, "(%"PRItid") e503 no back-end \"%s\" from %s %s",
	  POUND_TID (), phttp->request.request,
	  addr2str (caddr, sizeof (caddr), &phttp->from_host, 1),
	  (v_host && v_host[0]) ? v_host : "-");

  return HTTP_STATUS_SERVICE_UNAVAILABLE;
}

static void
backend_update_stats (BACKEND *be, struct timespec const *start)
{
  struct timespec diff, end;
  double t;

  clock_gettime (CLOCK_REALTIME, &end);
  pthread_mutex_lock (&be->mut);
  diff = timespec_sub (&end, start);
  t = (double) diff.tv_sec * 1e9 + diff.tv_nsec;
  be->avgtime = (be->numreq * be->avgtime + t) / (be->numreq + 1);
  be->avgsqtime = (be->numreq * be->avgsqtime + t*t) / (be->numreq + 1);
  be->numreq++;
  pthread_mutex_unlock (&be->mut);
}

/*
 * handle an HTTP request
 */
void
do_http (POUND_HTTP *phttp)
{
  int cl_11;  /* Whether client connection is using HTTP/1.1 */
  int res;  /* General-purpose result variable */
  int chunked; /* True if request contains Transfer-Enconding: chunked
		* FIXME: this belongs to struct http_request, perhaps.
		*/
  BIO *bb;
  char caddr[MAX_ADDR_BUFSIZE];
  CONTENT_LENGTH content_length;
  struct http_header *hdr, *hdrtemp;
  char *val;
  struct timespec be_start;

  if (phttp->lstn->allow_client_reneg)
    phttp->reneg_state = RENEG_ALLOW;
  else
    phttp->reneg_state = RENEG_INIT;

  socket_setup (phttp->sock);

  if ((phttp->cl = BIO_new_socket (phttp->sock, 1)) == NULL)
    {
      logmsg (LOG_ERR, "(%"PRItid") BIO_new_socket failed", POUND_TID ());
      shutdown (phttp->sock, 2);
      close (phttp->sock);
      return;
    }
  set_callback (phttp->cl, phttp->lstn->to, &phttp->reneg_state);

  if (!SLIST_EMPTY (&phttp->lstn->ctx_head))
    {
      if ((phttp->ssl = SSL_new (SLIST_FIRST (&phttp->lstn->ctx_head)->ctx)) == NULL)
	{
	  logmsg (LOG_ERR, "(%"PRItid") SSL_new: failed", POUND_TID ());
	  return;
	}
      SSL_set_app_data (phttp->ssl, &phttp->reneg_state);
      SSL_set_bio (phttp->ssl, phttp->cl, phttp->cl);
      if ((bb = BIO_new (BIO_f_ssl ())) == NULL)
	{
	  logmsg (LOG_ERR, "(%"PRItid") BIO_new(Bio_f_ssl()) failed",
		  POUND_TID ());
	  return;
	}
      BIO_set_ssl (bb, phttp->ssl, BIO_CLOSE);
      BIO_set_ssl_mode (bb, 0);
      phttp->cl = bb;
      if (BIO_do_handshake (phttp->cl) <= 0)
	{
	  return;
	}
      else
	{
	  if ((phttp->x509 = SSL_get_peer_certificate (phttp->ssl)) != NULL
	      && phttp->lstn->clnt_check < 3
	      && SSL_get_verify_result (phttp->ssl) != X509_V_OK)
	    {
	      logmsg (LOG_NOTICE, "Bad certificate from %s",
		      addr2str (caddr, sizeof (caddr), &phttp->from_host, 1));
	      return;
	    }
	}
    }
  else
    {
      phttp->x509 = NULL;
    }
  phttp->backend = NULL;

  if ((bb = BIO_new (BIO_f_buffer ())) == NULL)
    {
      logmsg (LOG_ERR, "(%"PRItid") BIO_new(buffer) failed", POUND_TID ());
      return;
    }
  BIO_set_close (phttp->cl, BIO_CLOSE);
  BIO_set_buffer_size (phttp->cl, MAXBUF);
  phttp->cl = BIO_push (bb, phttp->cl);

  cl_11 = 0;
  for (;;)
    {
      http_request_free (&phttp->request);
      http_request_free (&phttp->response);

      phttp->ws_state = WSS_INIT;
      phttp->conn_closed = 0;
      if (http_request_read (phttp->cl, phttp->lstn, &phttp->request))
	{
	  if (!cl_11)
	    {
	      if (errno)
		{
		  logmsg (LOG_NOTICE, "(%"PRItid") error read from %s: %s",
			  POUND_TID (),
			  addr2str (caddr, sizeof (caddr), &phttp->from_host, 1),
			  strerror (errno));
		}
	    }
	  return;
	}

      clock_gettime (CLOCK_REALTIME, &phttp->start_req);

      /*
       * check for correct request
       */
      if (parse_http_request (&phttp->request, phttp->lstn->verb))
	{
	  logmsg (LOG_WARNING, "(%"PRItid") e501 bad request \"%s\" from %s",
		  POUND_TID (), phttp->request.request,
		  addr2str (caddr, sizeof (caddr), &phttp->from_host, 1));
	  http_err_reply (phttp, HTTP_STATUS_NOT_IMPLEMENTED);
	  return;
	}
      cl_11 = phttp->request.version;

      phttp->no_cont = phttp->request.method == METH_HEAD;
      if (phttp->request.method == METH_GET)
	phttp->ws_state |= WSS_REQ_GET;

      if (phttp->lstn->has_pat &&
	  regexec (&phttp->lstn->url_pat, phttp->request.url, 0, NULL, 0))
	{
	  logmsg (LOG_NOTICE, "(%"PRItid") e501 bad URL \"%s\" from %s",
		  POUND_TID (), phttp->request.url,
		  addr2str (caddr, sizeof (caddr), &phttp->from_host, 1));
	  http_err_reply (phttp, HTTP_STATUS_NOT_IMPLEMENTED);
	  return;
	}

      /*
       * check headers
       */
      chunked = 0;
      content_length = NO_CONTENT_LENGTH;
      DLIST_FOREACH_SAFE (hdr, hdrtemp, &phttp->request.headers, link)
	{
	  switch (hdr->code)
	    {
	    case HEADER_CONNECTION:
	      if ((val = http_header_get_value (hdr)) == NULL)
		goto err;
	      if (!strcasecmp ("close", val))
		phttp->conn_closed = 1;
	      /*
	       * Connection: upgrade
	       */
	      else if (!regexec (&CONN_UPGRD, val, 0, NULL, 0))
		phttp->ws_state |= WSS_REQ_HEADER_CONNECTION_UPGRADE;
	      break;

	    case HEADER_UPGRADE:
	      if ((val = http_header_get_value (hdr)) == NULL)
		goto err;
	      if (!strcasecmp ("websocket", val))
		phttp->ws_state |= WSS_REQ_HEADER_UPGRADE_WEBSOCKET;
	      break;

	    case HEADER_TRANSFER_ENCODING:
	      if ((val = http_header_get_value (hdr)) == NULL)
		goto err;
	      if (!strcasecmp ("chunked", val))
		chunked = 1;
	      else
		{
		  logmsg (LOG_NOTICE,
			  "(%"PRItid") e400 multiple Transfer-encoding \"%s\" from %s",
			  POUND_TID (), phttp->request.url,
			  addr2str (caddr, sizeof (caddr), &phttp->from_host, 1));
		  http_err_reply (phttp, HTTP_STATUS_BAD_REQUEST);
		  return;
		}
	      break;

	    case HEADER_CONTENT_LENGTH:
	      if ((val = http_header_get_value (hdr)) == NULL)
		goto err;
	      if (content_length != NO_CONTENT_LENGTH || strchr (val, ','))
		{
		  logmsg (LOG_NOTICE,
			  "(%"PRItid") e400 multiple Content-length \"%s\" from %s",
			  POUND_TID (), phttp->request.url,
			  addr2str (caddr, sizeof (caddr), &phttp->from_host, 1));
		  http_err_reply (phttp, HTTP_STATUS_BAD_REQUEST);
		  return;
		}
	      else if ((content_length = get_content_length (val, 10)) == NO_CONTENT_LENGTH)
		{
		  logmsg (LOG_NOTICE,
			  "(%"PRItid") e400 Content-length bad value \"%s\" from %s",
			  POUND_TID (), phttp->request.url,
			  addr2str (caddr, sizeof (caddr), &phttp->from_host, 1));
		  http_err_reply (phttp, HTTP_STATUS_BAD_REQUEST);
		  return;
		}

	      if (content_length == NO_CONTENT_LENGTH)
		{
		  http_header_list_remove (&phttp->request.headers, hdr);
		}
	      break;

	    case HEADER_EXPECT:
	      /*
	       * We do NOT support the "Expect: 100-continue" headers;
	       * Supporting them may involve severe performance penalties
	       * (non-responding back-end, etc).
	       * As a stop-gap measure we just skip these headers.
	       */
	      if ((val = http_header_get_value (hdr)) == NULL)
		goto err;
	      if (!strcasecmp ("100-continue", val))
		{
		  http_header_list_remove (&phttp->request.headers, hdr);
		}
	      break;

	    case HEADER_ILLEGAL:
	      /*
	       * FIXME: This should not happen.  See the handling of
	       * HEADER_ILLEGAL in http_header_list_append.
	       */
	      if (phttp->lstn->log_level > 0)
		{
		  logmsg (LOG_NOTICE, "(%"PRItid") bad header from %s (%s)",
			  POUND_TID (),
			  addr2str (caddr, sizeof (caddr), &phttp->from_host, 1),
			  hdr->header);
		}
	      http_header_list_remove (&phttp->request.headers, hdr);
	      break;

	    case HEADER_AUTHORIZATION:
	      if ((val = http_header_get_value (hdr)) == NULL)
		goto err;
	      get_user (val, &phttp->request.user);
	      break;
	    }
	}

      /*
       * check for possible request smuggling attempt
       */
      if (chunked != 0 && content_length != NO_CONTENT_LENGTH)
	{
	  logmsg (LOG_NOTICE,
		  "(%"PRItid") e501 Transfer-encoding and Content-length \"%s\" from %s",
		  POUND_TID (), phttp->request.url,
		  addr2str (caddr, sizeof (caddr), &phttp->from_host, 1));
	  http_err_reply (phttp, HTTP_STATUS_BAD_REQUEST);
	  return;
	}

      /*
       * possibly limited request size
       */
      if (phttp->lstn->max_req > 0 && content_length > 0
	  && content_length > phttp->lstn->max_req)
	{
	  logmsg (LOG_NOTICE, "(%"PRItid") e413 request too large (%"PRICLEN") from %s",
		  POUND_TID (), content_length,
		  addr2str (caddr, sizeof (caddr), &phttp->from_host, 1));
	  http_err_reply (phttp, HTTP_STATUS_PAYLOAD_TOO_LARGE);
	  return;
	}

      if (phttp->be != NULL)
	{
	  if (is_readable (phttp->be, 0))
	    {
	      /*
	       * The only way it's readable is if it's at EOF, so close
	       * it!
	       */
	      close_backend (phttp);
	    }
	}

      /*
       * check that the requested URL still fits the old back-end (if
       * any)
       */
      if ((phttp->svc = get_service (phttp->lstn, phttp->from_host.ai_addr,
				     phttp->request.url,
				     &phttp->request.headers, phttp->sm)) == NULL)
	{
	  char const *v_host = http_request_host (&phttp->request);
	  logmsg (LOG_NOTICE, "(%"PRItid") e503 no service \"%s\" from %s %s",
		  POUND_TID (), phttp->request.request,
		  addr2str (caddr, sizeof (caddr), &phttp->from_host, 1),
		  (v_host && v_host[0]) ? v_host : "-");
	  http_err_reply (phttp, HTTP_STATUS_SERVICE_UNAVAILABLE);
	  return;
	}

      if ((res = select_backend (phttp)) != 0)
	{
	  http_err_reply (phttp, res);
	  return;
	}

      /*
       * if we have anything but a BACK_END we close the channel
       */
      if (phttp->be != NULL && phttp->backend->be_type != BE_BACKEND)
	close_backend (phttp);

      if (force_http_10 (phttp))
	phttp->conn_closed = 1;

      phttp->res_bytes = 0;
      http_request_free (&phttp->response);

      clock_gettime (CLOCK_REALTIME, &be_start);
      switch (phttp->backend->be_type)
	{
	case BE_REDIRECT:
	  res = redirect_response (phttp);
	  break;

	case BE_ACME:
	  res = acme_response (phttp);
	  break;

	case BE_CONTROL:
	  res = control_response (phttp);
	  break;

	case BE_ERROR:
	  res = error_response (phttp);
	  break;

	case BE_BACKEND:
	  /* Send the request. */
	  res = send_to_backend (phttp, cl_11 && chunked, content_length);
	  if (res == 0)
	    /* Process the response. */
	    res = backend_response (phttp);
	  break;
	}

      if (enable_backend_stats)
	backend_update_stats (phttp->backend, &be_start);

      if (res == -1)
	break;
      else
	{
	  if (res != HTTP_STATUS_OK)
	    http_err_reply (phttp, res);
	  if (phttp->response_code == 0)
	    phttp->response_code = http_status[res].code;
	  http_log (phttp);
	}

      /*
       * Stop processing if:
       *  - client is not HTTP/1.1
       *      or
       *  - we had a "Connection: closed" header
       */
      if (!cl_11 || phttp->conn_closed)
	break;
    }

  return;

 err:
  http_err_reply (phttp, HTTP_STATUS_INTERNAL_SERVER_ERROR);
  return;
}

void *
thr_http (void *dummy)
{
  POUND_HTTP *phttp;

  while ((phttp = pound_http_dequeue ()) != NULL)
    {
      do_http (phttp);
      clear_error (phttp->ssl);
      pound_http_destroy (phttp);
      active_threads_decr ();
    }
  logmsg (LOG_NOTICE, "thread %"PRItid" terminating on idle timeout",
	  POUND_TID ());
  return NULL;
}
