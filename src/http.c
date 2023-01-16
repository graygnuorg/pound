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
 * HTTP error replies
 */
typedef struct
{
  int code;
  char const *text;
} HTTP_STATUS;

static HTTP_STATUS http_status[] = {
  [HTTP_STATUS_OK] = { 200, "OK" },
  [HTTP_STATUS_BAD_REQUEST] = { 400, "Bad Request" },
  [HTTP_STATUS_NOT_FOUND] = { 404, "Not Found" },
  [HTTP_STATUS_PAYLOAD_TOO_LARGE] = { 413, "Payload Too Large" },
  [HTTP_STATUS_URI_TOO_LONG] = { 414, "URI Too Long" },
  [HTTP_STATUS_INTERNAL_SERVER_ERROR] = { 500, "Internal Server Error" },
  [HTTP_STATUS_NOT_IMPLEMENTED] = { 501, "Not Implemented" },
  [HTTP_STATUS_SERVICE_UNAVAILABLE] = { 503, "Service Unavailable" },
};

static char *err_response =
	"HTTP/1.0 %d %s\r\n"
	"Content-Type: text/html\r\n"
	"Content-Length: %d\r\n"
	"Expires: now\r\n"
	"Pragma: no-cache\r\n"
	"Cache-control: no-cache,no-store\r\n"
	"\r\n"
	"%s";

/*
 * Reply with an error
 */
static void
err_reply (BIO *c, int err, char const *txt)
{
  if (!(err >= 0 && err < HTTP_STATUS_MAX))
    {
      err = HTTP_STATUS_INTERNAL_SERVER_ERROR;
      txt = "Bad error code returned";
    }
  if (!txt)
    txt = http_status[err].text;
  BIO_printf (c, err_response, http_status[err].code, http_status[err].text,
	      strlen (txt), txt);
  BIO_flush (c);
  return;
}

static void
listener_err_reply (BIO *c, int err, LISTENER const *lstn)
{
  err_reply (c, err, lstn->http_err[err]);
}

static char *
expand_url (char const *url, char const *orig_url, struct submatch *sm, int redir_req)
{
  struct stringbuf sb;
  char *p;

  stringbuf_init_log (&sb);
  while (*url)
    {
      size_t len = strcspn (url, "$");
      stringbuf_add (&sb, url, len);
      url += len;
      if (*url == 0)
	break;
      else if (url[1] == '$' || url[1] == 0)
	{
	  stringbuf_add_char (&sb, url[0]);
	  url += 2;
	}
      else if (isdigit (url[1]))
	{
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
	      if (n < sm->matchn)
		{
		  stringbuf_add (&sb, orig_url + sm->matchv[n].rm_so,
				 sm->matchv[n].rm_eo - sm->matchv[n].rm_so);
		}
	      else
		{
		  stringbuf_add (&sb, url, p - url);
		}
	      redir_req = 1;
	      url = p;
	    }
	}
    }

  /* For compatibility with previous versions */
  if (!redir_req)
    stringbuf_add_string (&sb, orig_url);

  if ((p = stringbuf_finish (&sb)) == NULL)
    stringbuf_free (&sb);
  return p;
}

/*
 * Reply with a redirect
 */
static int
redirect_reply (BIO *c, const char *url, BACKEND *be, struct submatch *sm)
{
  int code = be->redir_code;
  char const *code_msg, *cont;
  char *xurl;
  struct stringbuf cont_buf, url_buf;
  int i;

  switch (code)
    {
    case 301:
      code_msg = "Moved Permanently";
      break;

    case 307:
      code_msg = "Temporary Redirect";
      break;

    default:
      code_msg = "Found";
      break;
    }

  xurl = expand_url (be->url, url, sm, be->redir_req);
  if (!xurl)
    {
      return HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

  /*
   * Make sure to return a safe version of the URL (otherwise CSRF
   * becomes a possibility)
   */
  stringbuf_init_log (&url_buf);
  for (i = 0; xurl[i]; i++)
    {
      if (isalnum (xurl[i]) || xurl[i] == '_' || xurl[i] == '.'
	  || xurl[i] == ':' || xurl[i] == '/' || xurl[i] == '?' || xurl[i] == '&'
	  || xurl[i] == ';' || xurl[i] == '-' || xurl[i] == '=')
	stringbuf_add_char (&url_buf, xurl[i]);
      else
	stringbuf_printf (&url_buf, "%%%02x", xurl[i]);
    }
  url = stringbuf_finish (&url_buf);
  free (xurl);

  if (!url)
    {
      stringbuf_free (&url_buf);
      return HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

  stringbuf_init_log (&cont_buf);
  stringbuf_printf (&cont_buf,
		    "<html><head><title>Redirect</title></head>"
		    "<body><h1>Redirect</h1>"
		    "<p>You should go to <a href=\"%s\">%s</a></p>"
		    "</body></html>",
		    url, url);

  if ((cont = stringbuf_finish (&cont_buf)) == NULL)
    {
      stringbuf_free (&cont_buf);
      stringbuf_free (&url_buf);
      return HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

  BIO_printf (c,
	      "HTTP/1.0 %d %s\r\n"
	      "Location: %s\r\n"
	      "Content-Type: text/html\r\n"
	      "Content-Length: %"PRILONG"\r\n\r\n"
	      "%s",
	      code, code_msg, url, (LONG)strlen (cont), cont);

  BIO_flush (c);

  stringbuf_free (&cont_buf);
  stringbuf_free (&url_buf);

  return HTTP_STATUS_OK;
}

/*
 * Read and write some binary data
 */
static int
copy_bin (BIO *cl, BIO *be, LONG cont, LONG *res_bytes, int no_write)
{
  char buf[MAXBUF];
  int res;

  while (cont > L0)
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
acme_reply (BIO *c, const char *url, BACKEND *be, struct submatch *sm)
{
  int fd;
  struct stat st;
  BIO *bin;
  char *file_name;
  int rc = HTTP_STATUS_OK;

  file_name = expand_url (be->url, url, sm, 1);

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

      BIO_printf (c,
		  "HTTP/1.0 %d %s\r\n"
		  "Content-Type: text/plain\r\n"
		  "Content-Length: %"PRILONG"\r\n\r\n",
		  200, "OK", (LONG) st.st_size);

      if (copy_bin (bin, c, st.st_size, NULL, 0))
	{
	  if (errno)
	    logmsg (LOG_NOTICE, "(%"PRItid") error copying file %s: %s",
		    POUND_TID (), file_name, strerror (errno));
	}

      BIO_free (bin);
      BIO_flush (c);
    }
  free (file_name);
  return rc;
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

/*
 * Copy chunked
 */
static int
copy_chunks (BIO *cl, BIO *be, LONG * res_bytes, int no_write, LONG max_size)
{
  char buf[MAXBUF];
  LONG cont, tot_size;
  regmatch_t matches[2];
  int res;

  for (tot_size = 0L;;)
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
      if (!regexec (&CHUNK_HEAD, buf, 2, matches, 0))
	cont = STRTOL (buf, NULL, 16);
      else
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
      if (max_size > L0 && tot_size > max_size)
	{
	  logmsg (LOG_WARNING, "(%"PRItid") chunk content too large",
		  POUND_TID ());
	  return -4;
	}

      if (cont > L0)
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

  if (cmd != BIO_CB_READ && cmd != BIO_CB_WRITE)
    return ret;

  /*
   * a time-out already occured
   */
  if ((bio_arg = (BIO_ARG *) BIO_get_callback_arg (bio)) == NULL)
    return ret;
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
set_callback (BIO *cl, BIO_ARG *arg)
{
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

int
http_header_list_append (HTTP_HEADER_LIST *head, char *text)
{
  struct http_header *hdr;

  if ((hdr = http_header_alloc (text)) == NULL)
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
http_header_list_append_list (HTTP_HEADER_LIST *head, HTTP_HEADER_LIST *add)
{
  struct http_header *hdr;
  DLIST_FOREACH (hdr, add, link)
    {
      if (http_header_list_append (head, hdr->header))
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
      /*
       * logmsg(LOG_NOTICE, "headers: bad starting read");
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
	   * logmsg(LOG_WARNING, "(%lx) e500 can't read header",
	   * pthread_self()); err_reply(cl, h500, lstn->err500);
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
  { S("RPC_IN_DATA"),  METH_RPC_IN_DATA,   4 },
  { S("RPC_OUT_DATA"), METH_RPC_OUT_DATA,  4 },
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

static int
parse_http_request (const char *req, int group,
		    int *ret_meth, char *ret_url, /* FIXME: size_t url_size, */
		    int *ret_http_ver)
{
  size_t len;
  struct method_def *md;
  char const *url;
  int http_ver;
  int n;

  len = strcspn (req, " ");
  if (len == 0 || req[len-1] == 0)
    return -1;

  if ((md = find_method (req, len)) == NULL)
    return -1;

  if (md->group > group)
    return -1;

  req += len;
  req += strspn (req, " ");

  if (*req == 0)
    return -1;

  url = req;
  len = strcspn (url, " ");

  req += len;
  req += strspn (req, " ");
  if (!(strncmp (req, "HTTP/1.", 7) == 0 &&
	((http_ver = req[7]) == '0' || http_ver == '1') &&
	req[8] == 0))
    return -1;

  *ret_meth = md->meth;
  n = cpURL (ret_url, (char*) url, len);
  if (n != strlen (ret_url))
    /*
     * the URL probably contained a %00 aka NULL - which we don't
     * allow
     */
    return -1;

  *ret_http_ver = http_ver;

  return 0;
}

/*
 * HTTP Logging
 *
 * Function signatures are overly complex.  They will get simplified when
 * do_http gets revised.
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
log_bytes (char *res, size_t size, LONG cnt)
{
  if (cnt > L0)
    snprintf (res, size, "%"PRILONG, cnt);
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
http_log_0 (struct addrinfo const *from_host, struct timespec *ts,
	    LISTENER *lstn, BACKEND *be,
	    struct http_request *req, struct http_request *resp,
	    int code, LONG bytes)
{
  /* nothing */
}

static void
http_log_1 (struct addrinfo const *from_host, struct timespec *ts,
	    LISTENER *lstn, BACKEND *be,
	    struct http_request *req, struct http_request *resp,
	    int code, LONG bytes)
{
  char buf[MAX_ADDR_BUFSIZE];
  logmsg (LOG_INFO, "%s %s - %s",
	  anon_addr2str (buf, sizeof (buf), from_host),
	  http_request_line (req),
	  http_request_line (resp));
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
    }
  return "-";
}

static void
http_log_2 (struct addrinfo const *from_host, struct timespec *ts,
	    LISTENER *lstn, BACKEND *be,
	    struct http_request *req, struct http_request *resp,
	    int code, LONG bytes)
{
  char caddr[MAX_ADDR_BUFSIZE];
  char baddr[MAX_ADDR_BUFSIZE];
  char timebuf[LOG_TIME_SIZE];
  char const *v_host = http_request_host (req);

  if (v_host)
    logmsg (LOG_INFO,
	    "%s %s - %s (%s/%s -> %s) %s sec",
	    anon_addr2str (caddr, sizeof (caddr), from_host),
	    http_request_line (req),
	    http_request_line (resp),
	    v_host, be_service_name (be),
	    str_be (baddr, sizeof (baddr), be),
	    log_duration (timebuf, sizeof (timebuf), ts));
  else
    logmsg (LOG_INFO,
	    "%s %s - %s (%s -> %s) %s sec",
	    anon_addr2str (caddr, sizeof (caddr), from_host),
	    http_request_line (req),
	    http_request_line (resp),
	    be_service_name (be),
	    str_be (baddr, sizeof (baddr), be),
	    log_duration (timebuf, sizeof (timebuf), ts));
}

static void
http_log_3 (struct addrinfo const *from_host, struct timespec *ts,
	    LISTENER *lstn, BACKEND *be,
	    struct http_request *req, struct http_request *resp,
	    int code, LONG bytes)
{
  char caddr[MAX_ADDR_BUFSIZE];
  char timebuf[LOG_TIME_SIZE];
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
	  "%s %s - %s [%s] \"%s\" %03d %s \"%s\" \"%s\"",
	  v_host ? v_host : "-",
	  anon_addr2str (caddr, sizeof (caddr), from_host),
	  http_request_user_name (req),
	  log_time_str (timebuf, sizeof (timebuf), ts),
	  http_request_line (req),
	  code,
	  log_bytes (bytebuf, sizeof (bytebuf), bytes),
	  referer ? referer : "",
	  u_agent ? u_agent : "");
}

static void
http_log_4 (struct addrinfo const *from_host, struct timespec *ts,
	    LISTENER *lstn, BACKEND *be,
	    struct http_request *req, struct http_request *resp,
	    int code, LONG bytes)
{
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
	  anon_addr2str (caddr, sizeof (caddr), from_host),
	  http_request_user_name (req),
	  log_time_str (timebuf, sizeof (timebuf), ts),
	  http_request_line (req),
	  code,
	  log_bytes (bytebuf, sizeof (bytebuf), bytes),
	  referer ? referer : "",
	  u_agent ? u_agent : "");
}

static void
http_log_5 (struct addrinfo const *from_host, struct timespec *ts,
	    LISTENER *lstn, BACKEND *be,
	    struct http_request *req, struct http_request *resp,
	    int code, LONG bytes)
{
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
	  anon_addr2str (caddr, sizeof (caddr), from_host),
	  http_request_user_name (req),
	  log_time_str (timebuf, sizeof (timebuf), ts),
	  http_request_line (req),
	  code,
	  log_bytes (bytebuf, sizeof (bytebuf), bytes),
	  referer ? referer : "",
	  u_agent ? u_agent : "",
	  be_service_name (be), str_be (baddr, sizeof (baddr), be),
	  log_duration (dbuf, sizeof (dbuf), ts));
}

static void (*http_logger[]) (struct addrinfo const *, struct timespec *,
			      LISTENER *, BACKEND *,
			      struct http_request *, struct http_request *,
			      int, LONG) = {
  http_log_0,
  http_log_1,
  http_log_2,
  http_log_3,
  http_log_4,
  http_log_5
};

static void
http_log (struct addrinfo const *from_host, struct timespec *ts,
	  LISTENER *lstn, BACKEND *be,
	  struct http_request *req, struct http_request *resp,
	  int code, LONG bytes)
{
  http_logger[lstn->log_level] (from_host, ts, lstn, be,
				req, resp, code, bytes);
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

int
add_ssl_headers (HTTP_HEADER_LIST *headers, SSL *ssl, LISTENER *lstn, X509 *x509)
{
  int res = 0;
  const SSL_CIPHER *cipher;
  struct stringbuf sb;
  char *str;
  char buf[MAXBUF];
  BIO *bio = NULL;

  stringbuf_init_log (&sb);
  if ((cipher = SSL_get_current_cipher (ssl)) != NULL)
    {
      SSL_CIPHER_description (cipher, buf, sizeof (buf));
      strip_eol (buf);
      stringbuf_printf (&sb, "X-SSL-cipher: %s/%s",
			SSL_get_version (ssl),
			buf);
      if ((str = stringbuf_finish (&sb)) == NULL
	  || http_header_list_append (headers, str))
	{
	  res = -1;
	  goto end;
	}
      stringbuf_reset (&sb);
    }

  if (lstn->clnt_check > 0 && x509 != NULL
      && (bio = BIO_new (BIO_s_mem ())) != NULL)
    {
      X509_NAME_print_ex (bio, X509_get_subject_name (x509), 8,
			  XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
      get_line (bio, buf, sizeof (buf));
      stringbuf_printf (&sb, "X-SSL-Subject: %s", buf);
      if ((str = stringbuf_finish (&sb)) == NULL
	  || http_header_list_append (headers, str))
	{
	  res = -1;
	  goto end;
	}
      stringbuf_reset (&sb);

      X509_NAME_print_ex (bio, X509_get_issuer_name (x509), 8,
			  XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
      get_line (bio, buf, sizeof (buf));
      stringbuf_printf (&sb, "X-SSL-Issuer: %s", buf);
      if ((str = stringbuf_finish (&sb)) == NULL
	  || http_header_list_append (headers, str))
	{
	  res = -1;
	  goto end;
	}
      stringbuf_reset (&sb);

      ASN1_TIME_print (bio, X509_get_notBefore (x509));
      get_line (bio, buf, sizeof (buf));
      stringbuf_printf (&sb, "X-SSL-notBefore: %s", buf);
      if ((str = stringbuf_finish (&sb)) == NULL
	  || http_header_list_append (headers, str))
	{
	  res = -1;
	  goto end;
	}
      stringbuf_reset (&sb);

      ASN1_TIME_print (bio, X509_get_notAfter (x509));
      get_line (bio, buf, sizeof (buf));
      stringbuf_printf (&sb, "X-SSL-notAfter: %s", buf);
      if ((str = stringbuf_finish (&sb)) == NULL
	  || http_header_list_append (headers, str))
	{
	  res = -1;
	  goto end;
	}
      stringbuf_reset (&sb);

      stringbuf_printf (&sb, "X-SSL-serial: %ld",
			ASN1_INTEGER_get (X509_get_serialNumber (x509)));
      if ((str = stringbuf_finish (&sb)) == NULL
	  || http_header_list_append (headers, str))
	{
	  res = -1;
	  goto end;
	}
      stringbuf_reset (&sb);

      PEM_write_bio_X509 (bio, x509);
      stringbuf_add_string (&sb, "X-SSL-certificate: ");
      while (get_line (bio, buf, sizeof (buf)) == 0)
	{
	  stringbuf_add_string (&sb, buf);
	}
      if ((str = stringbuf_finish (&sb)) == NULL
	  || http_header_list_append (headers, str))
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
#  define clear_error()
#else /* OPENSSL_VERSION_NUMBER >= 0x10000000L */
#  define clear_error() \
	if(ssl != NULL) { ERR_clear_error(); ERR_remove_thread_state(NULL); }
#endif

#define clean_all()                                                     \
  do                                                                    \
    {                                                                   \
      if (ssl != NULL)                                                  \
	BIO_ssl_shutdown (cl);                                          \
      if (be != NULL)                                                   \
	{                                                               \
	  BIO_flush (be);                                               \
	  BIO_reset(be);                                                \
	  BIO_free_all(be);                                             \
	  be = NULL;                                                    \
	}                                                               \
      if (cl != NULL)                                                   \
	{                                                               \
	  BIO_flush (cl);                                               \
	  BIO_reset (cl);                                               \
	  BIO_free_all (cl);                                            \
	  cl = NULL;                                                    \
	}                                                               \
      if (x509 != NULL)                                                 \
	{                                                               \
	  X509_free (x509);                                             \
	  x509 = NULL;                                                  \
	}                                                               \
      clear_error ();                                                   \
      submatch_free (&sm);						\
    }                                                                   \
  while (0)

/*
 * handle an HTTP request
 */
void
do_http (THR_ARG *arg)
{
  int cl_11, be_11, res, chunked, n, sock, no_cont, skip, conn_closed,
    force_10, sock_proto, is_rpc, is_ws;
  int method;
  LISTENER *lstn;
  SERVICE *svc;
  BACKEND *backend, *cur_backend;
  struct addrinfo from_host;
  struct sockaddr_storage from_host_addr;
  BIO *cl, *be, *bb;
  X509 *x509;
  struct http_request request, response;
  char loc_path[MAXBUF],
    buf1[MAXBUF],
    url[MAXBUF],
    caddr[MAX_ADDR_BUFSIZE], *mh;
  char duration_buf[LOG_TIME_SIZE];
  SSL *ssl, *be_ssl;
  LONG cont, res_bytes = 0;
  struct linger l;
  struct timespec start_req;
  RENEG_STATE reneg_state;
  BIO_ARG ba1, ba2;
  enum
  {
    WSS_REQ_GET = 0x01,
    WSS_REQ_HEADER_CONNECTION_UPGRADE = 0x02,
    WSS_REQ_HEADER_UPGRADE_WEBSOCKET = 0x04,

    WSS_RESP_101 = 0x08,
    WSS_RESP_HEADER_CONNECTION_UPGRADE = 0x10,
    WSS_RESP_HEADER_UPGRADE_WEBSOCKET = 0x20,
    WSS_COMPLETE = WSS_REQ_GET
      | WSS_REQ_HEADER_CONNECTION_UPGRADE
      | WSS_REQ_HEADER_UPGRADE_WEBSOCKET | WSS_RESP_101 |
      WSS_RESP_HEADER_CONNECTION_UPGRADE | WSS_RESP_HEADER_UPGRADE_WEBSOCKET
  };
  struct submatch sm = SUBMATCH_INITIALIZER;
  struct http_header *hdr, *hdrtemp;
  char *val;

  reneg_state = RENEG_INIT;
  ba1.reneg_state = &reneg_state;
  ba2.reneg_state = &reneg_state;
  ba1.timeout = 0;
  ba2.timeout = 0;
  from_host = arg->from_host;
  memcpy (&from_host_addr, from_host.ai_addr, from_host.ai_addrlen);
  from_host.ai_addr = (struct sockaddr *) &from_host_addr;
  lstn = arg->lstn;
  sock = arg->sock;
  free (arg->from_host.ai_addr);
  free (arg);

  if (lstn->allow_client_reneg)
    reneg_state = RENEG_ALLOW;

  n = 1;
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

  cl = NULL;
  be = NULL;
  ssl = NULL;
  x509 = NULL;

  if ((cl = BIO_new_socket (sock, 1)) == NULL)
    {
      logmsg (LOG_WARNING, "(%"PRItid") BIO_new_socket failed", POUND_TID ());
      shutdown (sock, 2);
      close (sock);
      return;
    }
  ba1.timeout = lstn->to;
  set_callback (cl, &ba1);

  if (!SLIST_EMPTY (&lstn->ctx_head))
    {
      if ((ssl = SSL_new (SLIST_FIRST (&lstn->ctx_head)->ctx)) == NULL)
	{
	  logmsg (LOG_WARNING, "(%"PRItid") SSL_new: failed", POUND_TID ());
	  BIO_reset (cl);
	  BIO_free_all (cl);
	  return;
	}
      SSL_set_app_data (ssl, &reneg_state);
      SSL_set_bio (ssl, cl, cl);
      if ((bb = BIO_new (BIO_f_ssl ())) == NULL)
	{
	  logmsg (LOG_WARNING, "(%"PRItid") BIO_new(Bio_f_ssl()) failed",
		  POUND_TID ());
	  BIO_reset (cl);
	  BIO_free_all (cl);
	  return;
	}
      BIO_set_ssl (bb, ssl, BIO_CLOSE);
      BIO_set_ssl_mode (bb, 0);
      cl = bb;
      if (BIO_do_handshake (cl) <= 0)
	{
	  /*
	   * no need to log every client without a certificate...
	   * addr2str(caddr, sizeof (caddr), &from_host, 1);
	   * logmsg(LOG_NOTICE, "BIO_do_handshake with %s failed: %s",
	   * caddr, ERR_error_string(ERR_get_error(), NULL)); x509 =
	   * NULL;
	   */
	  BIO_reset (cl);
	  BIO_free_all (cl);
	  return;
	}
      else
	{
	  if ((x509 = SSL_get_peer_certificate (ssl)) != NULL
	      && lstn->clnt_check < 3
	      && SSL_get_verify_result (ssl) != X509_V_OK)
	    {
	      logmsg (LOG_NOTICE, "Bad certificate from %s",
		      addr2str (caddr, sizeof (caddr), &from_host, 1));
	      X509_free (x509);
	      BIO_reset (cl);
	      BIO_free_all (cl);
	      return;
	    }
	}
    }
  else
    {
      x509 = NULL;
    }
  cur_backend = NULL;

  if ((bb = BIO_new (BIO_f_buffer ())) == NULL)
    {
      logmsg (LOG_WARNING, "(%"PRItid") BIO_new(buffer) failed", POUND_TID ());
      if (x509 != NULL)
	X509_free (x509);
      BIO_reset (cl);
      BIO_free_all (cl);
      return;
    }
  BIO_set_close (cl, BIO_CLOSE);
  BIO_set_buffer_size (cl, MAXBUF);
  cl = BIO_push (bb, cl);

  for (cl_11 = be_11 = 0;;)
    {
      http_request_init (&request);
      http_request_init (&response);

      res_bytes = L0;
      is_rpc = -1;
      is_ws = 0;
      conn_closed = 0;
      if (http_request_read (cl, lstn, &request))
	{
	  if (!cl_11)
	    {
	      if (errno)
		{
		  logmsg (LOG_NOTICE, "(%"PRItid") error read from %s: %s",
			  POUND_TID (),
			  addr2str (caddr, sizeof (caddr), &from_host, 1),
			  strerror (errno));
		  /*
		   * err_reply(cl, h500, lstn->err500);
		   */
		}
	    }
	  clean_all ();
	  return;
	}

      clock_gettime (CLOCK_REALTIME, &start_req);

      /*
       * check for correct request
       */
      if (parse_http_request (request.request, lstn->verb, &method, url, &cl_11))
	{
	  logmsg (LOG_WARNING, "(%"PRItid") e501 bad request \"%s\" from %s",
		  POUND_TID (), request.request,
		  addr2str (caddr, sizeof (caddr), &from_host, 1));
	  listener_err_reply (cl, HTTP_STATUS_NOT_IMPLEMENTED, lstn);
	  http_request_free (&request);
	  clean_all ();
	  return;
	}

      no_cont = method == METH_HEAD;
      switch (method)
	{
	case METH_RPC_IN_DATA:
	  is_rpc = 1;
	  break;

	case METH_RPC_OUT_DATA:
	  is_rpc = 0;
	  break;

	case METH_GET:
	  is_ws |= WSS_REQ_GET;
	}

      if (lstn->has_pat && regexec (&lstn->url_pat, url, 0, NULL, 0))
	{
	  logmsg (LOG_NOTICE, "(%"PRItid") e501 bad URL \"%s\" from %s",
		  POUND_TID (), url,
		  addr2str (caddr, sizeof (caddr), &from_host, 1));
	  listener_err_reply (cl, HTTP_STATUS_NOT_IMPLEMENTED, lstn);
	  http_request_free (&request);
	  clean_all ();
	  return;
	}

      /*
       * check headers
       */
      chunked = 0;
      cont = L_1;
      DLIST_FOREACH_SAFE (hdr, hdrtemp, &request.headers, link)
	{
	  switch (hdr->code)
	    {
	    case HEADER_CONNECTION:
	      if ((val = http_header_get_value (hdr)) == NULL)
		goto err;
	      if (!strcasecmp ("close", val))
		conn_closed = 1;
	      /*
	       * Connection: upgrade
	       */
	      else if (!regexec (&CONN_UPGRD, val, 0, NULL, 0))
		is_ws |= WSS_REQ_HEADER_CONNECTION_UPGRADE;
	      break;

	    case HEADER_UPGRADE:
	      if ((val = http_header_get_value (hdr)) == NULL)
		goto err;
	      if (!strcasecmp ("websocket", val))
		is_ws |= WSS_REQ_HEADER_UPGRADE_WEBSOCKET;
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
			  POUND_TID (), url,
			  addr2str (caddr, sizeof (caddr), &from_host, 1));
		  err_reply (cl, HTTP_STATUS_BAD_REQUEST,
			     "Bad request: multiple Transfer-encoding values");
		  http_request_free (&request);
		  clean_all ();
		  return;
		}
	      break;

	    case HEADER_CONTENT_LENGTH:
	      if ((val = http_header_get_value (hdr)) == NULL)
		goto err;
	      if (cont != L_1 || strchr (val, ','))
		{
		  logmsg (LOG_NOTICE,
			  "(%"PRItid") e400 multiple Content-length \"%s\" from %s",
			  POUND_TID (), url,
			  addr2str (caddr, sizeof (caddr), &from_host, 1));
		  err_reply (cl, HTTP_STATUS_BAD_REQUEST,
			     "Bad request: multiple Content-length values");
		  http_request_free (&request);
		  clean_all ();
		  return;
		}
	      for (mh = val; *mh; mh++)
		if (!isdigit (*mh))
		  {
		    logmsg (LOG_NOTICE,
			    "(%"PRItid") e400 Content-length bad value \"%s\" from %s",
			    POUND_TID (), url,
			    addr2str (caddr, sizeof (caddr), &from_host, 1));
		    err_reply (cl, HTTP_STATUS_BAD_REQUEST,
			       "Bad request: Content-length bad value");
		    http_request_free (&request);
		    clean_all ();
		    return;
		  }
	      if ((cont = ATOL (val)) < 0L)
		{
		  http_header_list_remove (&request.headers, hdr);
		  hdr = NULL;
		}
	      if (is_rpc == 1 && (cont < 0x20000L || cont > 0x80000000L))
		is_rpc = -1;
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
		  http_header_list_remove (&request.headers, hdr);
		  hdr = NULL;
		}
	      break;

	    case HEADER_ILLEGAL:
	      //FIXME: should not happen
	      if (lstn->log_level > 0)
		{
		  logmsg (LOG_NOTICE, "(%"PRItid") bad header from %s (%s)",
			  POUND_TID (),
			  addr2str (caddr, sizeof (caddr), &from_host, 1),
			  hdr->header);
		}
	      http_header_list_remove (&request.headers, hdr);
	      hdr = NULL;
	      break;

	    case HEADER_AUTHORIZATION:
	      if ((val = http_header_get_value (hdr)) == NULL)
		goto err;
	      get_user (val, &request.user);
	      break;
	    }
	}

      if (!SLIST_EMPTY (&lstn->head_off))
	{
	  MATCHER *m;

	  SLIST_FOREACH (m, &lstn->head_off, next)
	    http_header_list_filter (&request.headers, m);
	}

      /*
       * check for possible request smuggling attempt
       */
      if (chunked != 0 && cont != L_1)
	{
	  logmsg (LOG_NOTICE,
		  "(%"PRItid") e501 Transfer-encoding and Content-length \"%s\" from %s",
		  POUND_TID (), url,
		  addr2str (caddr, sizeof (caddr), &from_host, 1));
	  err_reply (cl, HTTP_STATUS_BAD_REQUEST,
		     "Bad request: Transfer-encoding and Content-length headers present");
	  http_request_free (&request);
	  clean_all ();
	  return;
	}

      /*
       * possibly limited request size
       */
      if (lstn->max_req > L0 && cont > L0 && cont > lstn->max_req
	  && is_rpc != 1)
	{
	  logmsg (LOG_NOTICE, "(%"PRItid") e413 request too large (%"PRILONG") from %s",
		  POUND_TID (), cont,
		  addr2str (caddr, sizeof (caddr), &from_host, 1));
	  listener_err_reply (cl, HTTP_STATUS_PAYLOAD_TOO_LARGE, lstn);
	  http_request_free (&request);
	  clean_all ();
	  return;
	}

      if (be != NULL)
	{
	  if (is_readable (be, 0))
	    {
	      /*
	       * The only way it's readable is if it's at EOF, so close
	       * it!
	       */
	      BIO_reset (be);
	      BIO_free_all (be);
	      be = NULL;
	    }
	}

      /*
       * check that the requested URL still fits the old back-end (if
       * any)
       */
      if ((svc = get_service (lstn, from_host.ai_addr, url, &request.headers, &sm)) == NULL)
	{
	  char const *v_host = http_request_host (&request);
	  logmsg (LOG_NOTICE, "(%"PRItid") e503 no service \"%s\" from %s %s",
		  POUND_TID (), request.request,
		  addr2str (caddr, sizeof (caddr), &from_host, 1),
		  (v_host && v_host[0]) ? v_host : "-");
	  listener_err_reply (cl, HTTP_STATUS_SERVICE_UNAVAILABLE, lstn);
	  http_request_free (&request);
	  clean_all ();
	  return;
	}
      if ((backend = get_backend (svc, &from_host, url, &request.headers)) == NULL)
	{
	  char const *v_host = http_request_host (&request);
	  logmsg (LOG_NOTICE, "(%"PRItid") e503 no back-end \"%s\" from %s %s",
		  POUND_TID (), request.request,
		  addr2str (caddr, sizeof (caddr), &from_host, 1),
		  (v_host && v_host[0]) ? v_host : "-");
	  listener_err_reply (cl, HTTP_STATUS_SERVICE_UNAVAILABLE, lstn);
	  http_request_free (&request);
	  clean_all ();
	  return;
	}

      if (be != NULL && backend != cur_backend)
	{
	  BIO_reset (be);
	  BIO_free_all (be);
	  be = NULL;
	}
      while (be == NULL && backend->be_type == BE_BACKEND)
	{
	  switch (backend->addr.ai_family)
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
		      POUND_TID (), backend->addr.ai_family);
	      listener_err_reply (cl, HTTP_STATUS_SERVICE_UNAVAILABLE, lstn);
	      http_request_free (&request);
	      clean_all ();
	      return;
	    }

	  if ((sock = socket (sock_proto, SOCK_STREAM, 0)) < 0)
	    {
	      str_be (buf1, sizeof (buf1), backend);
	      logmsg (LOG_WARNING, "(%"PRItid") e503 backend %s socket create: %s",
		      POUND_TID (), buf1, strerror (errno));
	      listener_err_reply (cl, HTTP_STATUS_SERVICE_UNAVAILABLE, lstn);
	      http_request_free (&request);
	      clean_all ();
	      return;
	    }
	  if (connect_nb (sock, &backend->addr, backend->conn_to) < 0)
	    {
	      str_be (buf1, sizeof (buf1), backend);
	      logmsg (LOG_WARNING, "(%"PRItid") backend %s connect: %s",
		      POUND_TID (), buf1, strerror (errno));
	      shutdown (sock, 2);
	      close (sock);
	      kill_be (svc, backend, BE_KILL);
	      if ((backend = get_backend (svc, &from_host, url, &request.headers)) == NULL)
		{
		  logmsg (LOG_NOTICE, "(%"PRItid") e503 no back-end \"%s\" from %s",
			  POUND_TID (), request.request,
			  addr2str (caddr, sizeof (caddr), &from_host, 1));
		  listener_err_reply (cl, HTTP_STATUS_SERVICE_UNAVAILABLE, lstn);
		  http_request_free (&request);
		  clean_all ();
		  return;
		}
	      continue;
	    }

	  if (sock_proto == PF_INET || sock_proto == PF_INET6)
	    {
	      n = 1;
	      setsockopt (sock, SOL_SOCKET, SO_KEEPALIVE, (void *) &n,
			  sizeof (n));
	      l.l_onoff = 1;
	      l.l_linger = 10;
	      setsockopt (sock, SOL_SOCKET, SO_LINGER, (void *) &l,
			  sizeof (l));
#ifdef  TCP_LINGER2
	      n = 5;
	      setsockopt (sock, SOL_TCP, TCP_LINGER2, (void *) &n,
			  sizeof (n));
#endif
	      n = 1;
	      setsockopt (sock, SOL_TCP, TCP_NODELAY, (void *) &n,
			  sizeof (n));
	    }
	  if ((be = BIO_new_socket (sock, 1)) == NULL)
	    {
	      logmsg (LOG_WARNING, "(%"PRItid") e503 BIO_new_socket server failed",
		      POUND_TID ());
	      shutdown (sock, 2);
	      close (sock);
	      listener_err_reply (cl, HTTP_STATUS_SERVICE_UNAVAILABLE, lstn);
	      http_request_free (&request);
	      clean_all ();
	      return;
	    }
	  BIO_set_close (be, BIO_CLOSE);
	  if (backend->to > 0)
	    {
	      ba2.timeout = backend->to;
	      set_callback (be, &ba2);
	    }
	  if (backend->ctx != NULL)
	    {
	      if ((be_ssl = SSL_new (backend->ctx)) == NULL)
		{
		  logmsg (LOG_WARNING, "(%"PRItid") be SSL_new: failed",
			  POUND_TID ());
		  listener_err_reply (cl, HTTP_STATUS_SERVICE_UNAVAILABLE, lstn);
		  http_request_free (&request);
		  clean_all ();
		  return;
		}
	      SSL_set_bio (be_ssl, be, be);
	      if ((bb = BIO_new (BIO_f_ssl ())) == NULL)
		{
		  logmsg (LOG_WARNING, "(%"PRItid") BIO_new(Bio_f_ssl()) failed",
			  POUND_TID ());
		  listener_err_reply (cl, HTTP_STATUS_SERVICE_UNAVAILABLE, lstn);
		  http_request_free (&request);
		  clean_all ();
		  return;
		}
	      BIO_set_ssl (bb, be_ssl, BIO_CLOSE);
	      BIO_set_ssl_mode (bb, 1);
	      be = bb;
	      if (BIO_do_handshake (be) <= 0)
		{
		  str_be (buf1, sizeof (buf1), backend);
		  logmsg (LOG_NOTICE, "BIO_do_handshake with %s failed: %s",
			  buf1, ERR_error_string (ERR_get_error (), NULL));
		  listener_err_reply (cl, HTTP_STATUS_SERVICE_UNAVAILABLE, lstn);
		  http_request_free (&request);
		  clean_all ();
		  return;
		}
	    }
	  if ((bb = BIO_new (BIO_f_buffer ())) == NULL)
	    {
	      logmsg (LOG_WARNING, "(%"PRItid") e503 BIO_new(buffer) server failed",
		      POUND_TID ());
	      listener_err_reply (cl, HTTP_STATUS_SERVICE_UNAVAILABLE, lstn);
	      http_request_free (&request);
	      clean_all ();
	      return;
	    }
	  BIO_set_buffer_size (bb, MAXBUF);
	  BIO_set_close (bb, BIO_CLOSE);
	  be = BIO_push (bb, be);
	}
      cur_backend = backend;

      /*
       * if we have anything but a BACK_END we close the channel
       */
      if (be != NULL && cur_backend->be_type != BE_BACKEND)
	{
	  BIO_reset (be);
	  BIO_free_all (be);
	  be = NULL;
	}

      /*
       * send the request
       */
      if (cur_backend->be_type == BE_BACKEND)
	{
	  /*
	   * this is the earliest we can check for Destination - we
	   * had no back-end before
	   */
	  if (lstn->rewr_dest &&
	      (hdr = http_header_list_locate (&request.headers, HEADER_DESTINATION)) != NULL)
	    {
	      regmatch_t matches[4];

	      if ((val = http_header_get_value (hdr)) == NULL)
		goto err;

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
		  str_be (caddr, sizeof (caddr), cur_backend);
		  stringbuf_printf (&sb,
				    "Destination: %s://%s%s",
				    cur_backend->ctx ? "https" : "http",
				    caddr,
				    val + matches[3].rm_so);
		  if ((p = stringbuf_finish (&sb)) == NULL)
		    {
		      logmsg (LOG_WARNING,
			      "(%"PRItid") rewrite Destination - out of memory: %s",
			      POUND_TID (), strerror (errno));
		      http_request_free (&request);
		      clean_all ();
		      return;
		    }

		  http_header_change (hdr, p, 0);
		}
	    }

	  /*
	   * add headers if required
	   */
	  if (http_header_list_append_list (&request.headers, &lstn->add_header))
	    goto err;

	  if (cur_backend->be_type == BE_BACKEND)
	    {
	      if (ssl != NULL)
		{
		  if (add_ssl_headers (&request.headers, ssl, lstn, x509))
		    lognomem ();
		}
	    }

	  if (http_request_send (be, &request))
	    {
	      if (errno)
		{
		  str_be (buf1, sizeof (buf1), cur_backend);
		  logmsg (LOG_WARNING,
			  "(%"PRItid") e500 error write to %s/%s: %s (%s sec)",
			  POUND_TID (), buf1, request.request, strerror (errno),
			  log_duration (duration_buf, sizeof (duration_buf), &start_req));
		}
	      listener_err_reply (cl, HTTP_STATUS_INTERNAL_SERVER_ERROR, lstn);
	      http_request_free (&request);
	      clean_all ();
	      return;
	    }
	}

      /*
       * put additional client IP header
       */
      if (cur_backend->be_type == BE_BACKEND)
	{
	  addr2str (caddr, sizeof (caddr), &from_host, 1);
	  BIO_printf (be, "X-Forwarded-For: %s\r\n", caddr);

	  /*
	   * final CRLF
	   */
	  BIO_puts (be, "\r\n");
	}

      if (cl_11 && chunked)
	{
	  /*
	   * had Transfer-encoding: chunked so read/write all the chunks
	   * (HTTP/1.1 only)
	   */
	  if (copy_chunks (cl, be, NULL, cur_backend->be_type != BE_BACKEND,
			   lstn->max_req))
	    {
	      str_be (buf1, sizeof (buf1), cur_backend);
	      logmsg (LOG_NOTICE,
		      "(%"PRItid") e500 for %s copy_chunks to %s/%s (%s sec)",
		      POUND_TID (),
		      addr2str (caddr, sizeof (caddr), &from_host, 1),
		      buf1, request.request,
		      log_duration (duration_buf, sizeof (duration_buf), &start_req));
	      listener_err_reply (cl, HTTP_STATUS_INTERNAL_SERVER_ERROR, lstn);
	      clean_all ();
	      return;
	    }
	}
      else if (cont > L0 && is_rpc != 1)
	{
	  /*
	   * had Content-length, so do raw reads/writes for the length
	   */
	  if (copy_bin (cl, be, cont, NULL, cur_backend->be_type != BE_BACKEND))
	    {
	      str_be (buf1, sizeof (buf1), cur_backend);
	      logmsg (LOG_NOTICE,
		      "(%"PRItid") e500 for %s error copy client cont to %s/%s: %s (%s sec)",
		      POUND_TID (),
		      addr2str (caddr, sizeof (caddr), &from_host, 1),
		      buf1, request.request, strerror (errno),
		      log_duration (duration_buf, sizeof (duration_buf), &start_req));
	      listener_err_reply (cl, HTTP_STATUS_INTERNAL_SERVER_ERROR, lstn);
	      clean_all ();
	      return;
	    }
	}
      else if (cont > 0L && is_readable (cl, lstn->to))
	{
	  char one;
	  BIO *cl_unbuf;
	  /*
	   * special mode for RPC_IN_DATA - content until EOF
	   * force HTTP/1.0 - client closes connection when done.
	   */
	  cl_11 = be_11 = 0;

	  /*
	   * first read whatever is already in the input buffer
	   */
	  while (BIO_pending (cl))
	    {
	      if (BIO_read (cl, &one, 1) != 1)
		{
		  logmsg (LOG_NOTICE, "(%"PRItid") error read request pending: %s",
			  POUND_TID (), strerror (errno));
		  clean_all ();
		  pthread_exit (NULL);
		}
	      if (++res_bytes > cont)
		{
		  logmsg (LOG_NOTICE,
			  "(%"PRItid") error read request pending: max. RPC length exceeded",
			  POUND_TID ());
		  clean_all ();
		  pthread_exit (NULL);
		}
	      if (BIO_write (be, &one, 1) != 1)
		{
		  if (errno)
		    logmsg (LOG_NOTICE,
			    "(%"PRItid") error write request pending: %s",
			    POUND_TID (), strerror (errno));
		  clean_all ();
		  pthread_exit (NULL);
		}
	    }
	  BIO_flush (be);

	  /*
	   * find the socket BIO in the chain
	   */
	  if ((cl_unbuf = BIO_find_type (cl,
					 SLIST_EMPTY (&lstn->ctx_head)
					   ? BIO_TYPE_SOCKET : BIO_TYPE_SSL)) == NULL)
	    {
	      logmsg (LOG_WARNING, "(%"PRItid") error get unbuffered: %s",
		      POUND_TID (), strerror (errno));
	      clean_all ();
	      pthread_exit (NULL);
	    }

	  /*
	   * copy till EOF
	   */
	  while ((res = BIO_read (cl_unbuf, buf1, sizeof (buf1))) > 0)
	    {
	      if ((res_bytes += res) > cont)
		{
		  logmsg (LOG_NOTICE,
			  "(%"PRItid") error copy request body: max. RPC length exceeded",
			  POUND_TID ());
		  clean_all ();
		  pthread_exit (NULL);
		}
	      if (BIO_write (be, buf1, res) != res)
		{
		  if (errno)
		    logmsg (LOG_NOTICE, "(%"PRItid") error copy request body: %s",
			    POUND_TID (), strerror (errno));
		  clean_all ();
		  pthread_exit (NULL);
		}
	      else
		{
		  BIO_flush (be);
		}
	    }
	}

      /*
       * flush to the back-end
       */
      if (cur_backend->be_type == BE_BACKEND && BIO_flush (be) != 1)
	{
	  str_be (buf1, sizeof (buf1), cur_backend);
	  logmsg (LOG_NOTICE,
		  "(%"PRItid") e500 for %s error flush to %s/%s: %s (%s sec)",
		  POUND_TID (),
		  addr2str (caddr, sizeof (caddr), &from_host, 1),
		  buf1, request.request, strerror (errno),
		  log_duration (duration_buf, sizeof (duration_buf), &start_req));
	  listener_err_reply (cl, HTTP_STATUS_INTERNAL_SERVER_ERROR, lstn);
	  clean_all ();
	  return;
	}

      /*
       * check on no_https_11:
       *  - if 0 ignore
       *  - if 1 and SSL force HTTP/1.0
       *  - if 2 and SSL and MSIE force HTTP/1.0
       */
      switch (lstn->noHTTPS11)
	{
	case 1:
	  force_10 = (ssl != NULL);
	  break;

	case 2:
	  {
	    char const *agent = http_request_header_value (&request, HEADER_USER_AGENT);
	    force_10 = (ssl != NULL && agent != NULL && strstr (agent, "MSIE") != NULL);
	  }
	  break;

	default:
	  force_10 = 0;
	  break;
	}

      if (cur_backend->be_type != BE_BACKEND)
	{
	  int code;

	  switch (cur_backend->be_type)
	    {
	    case BE_REDIRECT:
	      code = redirect_reply (cl, url, cur_backend, &sm);
	      break;

	    case BE_ACME:
	      code = acme_reply (cl, url, cur_backend, &sm);
	      break;

	    case BE_CONTROL:
	      code = control_reply (cl, method, url, cur_backend);
	    }

	  if (code != HTTP_STATUS_OK)
	    listener_err_reply (cl, code, lstn);

	  http_log (&from_host, &start_req,
		    lstn, cur_backend,
		    &request, NULL,
		    code, 0); //FIXME: number of bytes

	  if (!cl_11 || conn_closed || force_10)
	    break;
	  continue;
	}
      else if (is_rpc == 1)
	{
	  http_log (&from_host, &start_req,
		    lstn, cur_backend,
		    &request, NULL,
		    0, res_bytes); //FIXME: response code
	  /*
	   * no response expected - bail out
	   */
	  break;
	}

      /*
       * get the response
       */
      for (skip = 1; skip;)
	{
	  if (http_request_read (be, lstn, &response))
	    {
	      str_be (buf1, sizeof (buf1), cur_backend);
	      logmsg (LOG_NOTICE,
		      "(%"PRItid") e500 for %s response error read from %s/%s: %s (%s secs)",
		      POUND_TID (),
		      addr2str (caddr, sizeof (caddr), &from_host, 1),
		      buf1, request.request, strerror (errno),
		      log_duration (duration_buf, sizeof (duration_buf), &start_req));
	      listener_err_reply (cl, HTTP_STATUS_INTERNAL_SERVER_ERROR, lstn);
	      clean_all ();
	      return;
	    }

	  be_11 = (response.request[7] == '1');
	  /*
	   * responses with code 100 are never passed back to the client
	   */
	  skip = !regexec (&RESP_SKIP, response.request, 0, NULL, 0);
	  /*
	   * some response codes (1xx, 204, 304) have no content
	   */
	  if (!no_cont && !regexec (&RESP_IGN, response.request, 0, NULL, 0))
	    no_cont = 1;
	  if (!strncasecmp ("101", response.request + 9, 3))
	    is_ws |= WSS_RESP_101;

	  chunked = 0;
	  cont = L_1;
	  DLIST_FOREACH (hdr, &response.headers, link)
	    {
	      switch (hdr->code)
		{
		case HEADER_CONNECTION:
		  if ((val = http_header_get_value (hdr)) == NULL)
		    goto err;
		  if (!strcasecmp ("close", val))
		    conn_closed = 1;
		  /*
		   * Connection: upgrade
		   */
		  else if (!regexec (&CONN_UPGRD, val, 0, NULL, 0))
		    is_ws |= WSS_RESP_HEADER_CONNECTION_UPGRADE;
		  break;

		case HEADER_UPGRADE:
		  if ((val = http_header_get_value (hdr)) == NULL)
		    goto err;
		  if (!strcasecmp ("websocket", val))
		    is_ws |= WSS_RESP_HEADER_UPGRADE_WEBSOCKET;
		  break;

		case HEADER_TRANSFER_ENCODING:
		  if ((val = http_header_get_value (hdr)) == NULL)
		    goto err;
		  if (!strcasecmp ("chunked", val))
		    {
		      chunked = 1;
		      no_cont = 0;
		    }
		  break;

		case HEADER_CONTENT_LENGTH:
		  if ((val = http_header_get_value (hdr)) == NULL)
		    goto err;
		  cont = ATOL (val);
		  /*
		   * treat RPC_OUT_DATA like reply without
		   * content-length
		   */
		  if (is_rpc == 0)
		    {
		      if (cont >= 0x20000L && cont <= 0x80000000L)
			cont = -1L;
		      else
			is_rpc = -1;
		    }
		  break;

		case HEADER_LOCATION:
		  if ((val = http_header_get_value (hdr)) == NULL)
		    goto err;
		  else
		    {
		      char const *v_host = http_request_host (&request);
		      if (v_host && v_host[0] &&
			  need_rewrite (lstn->rewr_loc, val, loc_path, v_host,
					lstn, cur_backend))
			{
			  struct stringbuf sb;
			  char *p;

			  stringbuf_init_log (&sb);
			  stringbuf_printf (&sb, "Location: %s://%s/%s",
					    (ssl == NULL ? "http" : "https"),
					    v_host,
					    loc_path);
			  if ((p = stringbuf_finish (&sb)) == NULL)
			    {
			      logmsg (LOG_WARNING,
				      "(%"PRItid") rewrite Location - out of memory: %s",
				      POUND_TID (), strerror (errno));
			      http_request_free (&response);
			      clean_all ();
			      return;
			    }
			  http_header_change (hdr, p, 0);
			}
		    }
		  break;

		case HEADER_CONTLOCATION:
		  if ((val = http_header_get_value (hdr)) == NULL)
		    goto err;
		  else
		    {
		      char const *v_host = http_request_host (&request);
		      if (v_host && v_host[0] &&
			  need_rewrite (lstn->rewr_loc, val, loc_path,
					v_host, lstn, cur_backend))
			{
			  struct stringbuf sb;
			  char *p;

			  stringbuf_init_log (&sb);
			  stringbuf_printf (&sb,
					    "Content-location: %s://%s/%s",
					    (ssl == NULL ? "http" : "https"), v_host,
					    loc_path);
			  if ((p = stringbuf_finish (&sb)) == NULL)
			    {
			      logmsg (LOG_WARNING,
				      "(%"PRItid") rewrite Content-location - out of memory: %s",
				      POUND_TID (), strerror (errno));
			      http_request_free (&response);
			      clean_all ();
			      return;
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
	  upd_session (svc, &response.headers, cur_backend);

	  /*
	   * send the response
	   */
	  if (!skip)
	    {
	      if (http_request_send (cl, &response))
		{
		  if (errno)
		    {
		      logmsg (LOG_NOTICE, "(%"PRItid") error write to %s: %s",
			      POUND_TID (),
			      addr2str (caddr, sizeof (caddr), &from_host, 1),
			      strerror (errno));
		    }
		  http_request_free (&response);
		  clean_all ();
		  return;
		}
	      /* Final CRLF */
	      BIO_puts (cl, "\r\n");
	    }

	  if (BIO_flush (cl) != 1)
	    {
	      if (errno)
		{
		  logmsg (LOG_NOTICE, "(%"PRItid") error flush headers to %s: %s",
			  POUND_TID (),
			  addr2str (caddr, sizeof (caddr), &from_host, 1),
			  strerror (errno));
		}
	      clean_all ();
	      return;
	    }

	  if (!no_cont)
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
		  if (copy_chunks (be, cl, &res_bytes, skip, L0))
		    {
		      /*
		       * copy_chunks() has its own error messages
		       */
		      clean_all ();
		      return;
		    }
		}
	      else if (cont >= L0)
		{
		  /*
		   * may have had Content-length, so do raw reads/writes
		   * for the length
		   */
		  if (copy_bin (be, cl, cont, &res_bytes, skip))
		    {
		      if (errno)
			logmsg (LOG_NOTICE,
				"(%"PRItid") error copy server cont: %s",
				POUND_TID (), strerror (errno));
		      clean_all ();
		      return;
		    }
		}
	      else if (!skip)
		{
		  if (is_readable (be, cur_backend->to))
		    {
		      char one;
		      BIO *be_unbuf;
		      /*
		       * old-style response - content until EOF
		       * also implies the client may not use HTTP/1.1
		       */
		      cl_11 = be_11 = 0;

		      /*
		       * first read whatever is already in the input buffer
		       */
		      while (BIO_pending (be))
			{
			  if (BIO_read (be, &one, 1) != 1)
			    {
			      logmsg (LOG_NOTICE,
				      "(%"PRItid") error read response pending: %s",
				      POUND_TID (), strerror (errno));
			      clean_all ();
			      return;
			    }
			  if (BIO_write (cl, &one, 1) != 1)
			    {
			      if (errno)
				logmsg (LOG_NOTICE,
					"(%"PRItid") error write response pending: %s",
					POUND_TID (), strerror (errno));
			      clean_all ();
			      return;
			    }
			  res_bytes++;
			}
		      BIO_flush (cl);

		      /*
		       * find the socket BIO in the chain
		       */
		      if ((be_unbuf =
			   BIO_find_type (be, cur_backend->ctx ? BIO_TYPE_SSL : BIO_TYPE_SOCKET)) == NULL)
			{
			  logmsg (LOG_WARNING,
				  "(%"PRItid") error get unbuffered: %s",
				  POUND_TID (), strerror (errno));
			  clean_all ();
			  return;
			}

		      /*
		       * copy till EOF
		       */
		      while ((res = BIO_read (be_unbuf, buf1, sizeof (buf1))) > 0)
			{
			  if (BIO_write (cl, buf1, res) != res)
			    {
			      if (errno)
				logmsg (LOG_NOTICE,
					"(%"PRItid") error copy response body: %s",
					POUND_TID (), strerror (errno));
			      clean_all ();
			      return;
			    }
			  else
			    {
			      res_bytes += res;
			      BIO_flush (cl);
			    }
			}
		    }
		}
	      if (BIO_flush (cl) != 1)
		{
		  /*
		   * client closes RPC_OUT_DATA connection - no error
		   */
		  if (is_rpc == 0 && res_bytes > 0L)
		    break;
		  if (errno)
		    {
		      logmsg (LOG_NOTICE, "(%"PRItid") error final flush to %s: %s",
			      POUND_TID (),
			      addr2str (caddr, sizeof (caddr), &from_host, 1),
			      strerror (errno));
		    }
		  clean_all ();
		  return;
		}
	    }
	  else if (is_ws == WSS_COMPLETE)
	    {
	      /*
	       * special mode for Websockets - content until EOF
	       */
	      char one;
	      BIO *cl_unbuf;
	      BIO *be_unbuf;
	      struct pollfd p[2];

	      cl_11 = be_11 = 0;

	      memset (p, 0, sizeof (p));
	      BIO_get_fd (cl, &p[0].fd);
	      p[0].events = POLLIN | POLLPRI;
	      BIO_get_fd (be, &p[1].fd);
	      p[1].events = POLLIN | POLLPRI;

	      while (BIO_pending (cl) || BIO_pending (be)
		     || poll (p, 2, cur_backend->ws_to * 1000) > 0)
		{

		  /*
		   * first read whatever is already in the input buffer
		   */
		  while (BIO_pending (cl))
		    {
		      if (BIO_read (cl, &one, 1) != 1)
			{
			  logmsg (LOG_NOTICE,
				  "(%"PRItid") error read ws request pending: %s",
				  POUND_TID (), strerror (errno));
			  clean_all ();
			  return;
			}
		      if (BIO_write (be, &one, 1) != 1)
			{
			  if (errno)
			    logmsg (LOG_NOTICE,
				    "(%"PRItid") error write ws request pending: %s",
				    POUND_TID (), strerror (errno));
			  clean_all ();
			  return;
			}
		    }
		  BIO_flush (be);

		  while (BIO_pending (be))
		    {
		      if (BIO_read (be, &one, 1) != 1)
			{
			  logmsg (LOG_NOTICE,
				  "(%"PRItid") error read ws response pending: %s",
				  POUND_TID (), strerror (errno));
			  clean_all ();
			  return;
			}
		      if (BIO_write (cl, &one, 1) != 1)
			{
			  if (errno)
			    logmsg (LOG_NOTICE,
				    "(%"PRItid") error write ws response pending: %s",
				    POUND_TID (), strerror (errno));
			  clean_all ();
			  return;
			}
		      res_bytes++;
		    }
		  BIO_flush (cl);

		  /*
		   * find the socket BIO in the chain
		   */
		  if ((cl_unbuf =
		       BIO_find_type (cl,
				      SLIST_EMPTY (&lstn->ctx_head)
				       ? BIO_TYPE_SOCKET : BIO_TYPE_SSL)) == NULL)
		    {
		      logmsg (LOG_WARNING, "(%"PRItid") error get unbuffered: %s",
			      POUND_TID (), strerror (errno));
		      clean_all ();
		      return;
		    }
		  if ((be_unbuf = BIO_find_type (be, cur_backend->ctx ? BIO_TYPE_SSL : BIO_TYPE_SOCKET)) == NULL)
		    {
		      logmsg (LOG_WARNING, "(%"PRItid") error get unbuffered: %s",
			      POUND_TID (), strerror (errno));
		      clean_all ();
		      return;
		    }

		  /*
		   * copy till EOF
		   */
		  if (p[0].revents)
		    {
		      res = BIO_read (cl_unbuf, buf1, sizeof (buf1));
		      if (res <= 0)
			{
			  break;
			}
		      if (BIO_write (be, buf1, res) != res)
			{
			  if (errno)
			    logmsg (LOG_NOTICE,
				    "(%"PRItid") error copy ws request body: %s",
				    POUND_TID (), strerror (errno));
			  clean_all ();
			  return;
			}
		      else
			{
			  BIO_flush (be);
			}
		      p[0].revents = 0;
		    }
		  if (p[1].revents)
		    {
		      res = BIO_read (be_unbuf, buf1, sizeof (buf1));
		      if (res <= 0)
			{
			  break;
			}
		      if (BIO_write (cl, buf1, res) != res)
			{
			  if (errno)
			    logmsg (LOG_NOTICE,
				    "(%"PRItid") error copy ws response body: %s",
				    POUND_TID (), strerror (errno));
			  clean_all ();
			  return;
			}
		      else
			{
			  res_bytes += res;
			  BIO_flush (cl);
			}
		      p[1].revents = 0;
		    }
		}
	    }
	}

      http_log (&from_host, &start_req,
		lstn, cur_backend,
		&request, &response,
		strtol (response.request+9, NULL, 10), res_bytes);

      if (!be_11)
	{
	  BIO_reset (be);
	  BIO_free_all (be);
	  be = NULL;
	}

      http_request_free (&request);
      http_request_free (&response);

      /*
       * Stop processing if:
       *  - client is not HTTP/1.1
       *      or
       *  - we had a "Connection: closed" header
       *      or
       *  - this is an SSL connection and we had a NoHTTPS11 directive
       */
      if (!cl_11 || conn_closed || force_10)
	break;
    }

  /*
   * This may help with some versions of IE with a broken channel shutdown
   */
  if (ssl != NULL)
    SSL_set_shutdown (ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);

  clean_all ();
  return;

 err:
  //FIXME
  listener_err_reply (cl, HTTP_STATUS_INTERNAL_SERVER_ERROR, lstn);
  http_request_free (&request);
  http_request_free (&response);
  clean_all ();
  return;
}

void *
thr_http (void *dummy)
{
  THR_ARG *arg;

  while ((arg = get_thr_arg ()) != NULL)
    {
      do_http (arg);
      active_threads_decr ();
    }
  logmsg (LOG_NOTICE, "thread %"PRItid" terminating on idle timeout",
	  POUND_TID ());
  return NULL;
}
