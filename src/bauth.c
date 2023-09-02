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

/*
 * The code below uses MD5 and SHA1 algorithms, which are marked as deprecated
 * since OpenSSL version 3.0.  These algorithms are used intentionally, for
 * compatibility with other software (namely, htpasswd program from Apache).
 */
#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "pound.h"
#if HAVE_CRYPT_H
# include <crypt.h>
#endif
#ifndef OPENSSL_NO_MD5
# include <openssl/md5.h>
#endif

static pthread_mutex_t crypt_mutex = PTHREAD_MUTEX_INITIALIZER;

static int
auth_plain (const char *pass, const char *hash)
{
  return strcmp (pass, hash);
}

static int
auth_crypt (const char *pass, const char *hash)
{
  int res = 1;
  char *cp;

  pthread_mutex_lock (&crypt_mutex);
  cp = crypt (pass, hash);
  if (cp)
    res = strcmp (cp, hash);
  pthread_mutex_unlock (&crypt_mutex);
  return res;
}

#ifndef OPENSSL_NO_MD5

static void
to64 (char *s, unsigned long v, int n)
{
  static unsigned char itoa64[] =         /* 0 ... 63 => ASCII - 64 */
	    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  while (--n >= 0)
    {
      *s++ = itoa64[v&0x3f];
      v >>= 6;
    }
}

#define APR_MD5_DIGESTSIZE 16
#define APR1_ID_STR "$apr1$"
#define APR1_ID_LEN (sizeof (APR1_ID_STR)-1)

char *
apr_md5_encode(const char *pw, const char *salt, char *result, size_t nbytes)
{
  /*
   * Minimum size is 8 bytes for salt, plus 1 for the trailing NUL,
   * plus 4 for the '$' separators, plus the password hash itself.
   */

   char passwd[120];
   char *p;
   unsigned char final[APR_MD5_DIGESTSIZE];
   ssize_t slen, plen, i;
   MD5_CTX ctx, ctx1;

   if (!strncmp (salt, APR1_ID_STR, APR1_ID_LEN))
     salt += APR1_ID_LEN;

   if ((p = memchr (salt, '$', 8)) != NULL)
     slen = p - salt;
   else
     slen = 8;

   plen = strlen (pw);

   MD5_Init (&ctx);
   MD5_Update (&ctx, pw, plen);
   MD5_Update (&ctx, APR1_ID_STR, APR1_ID_LEN);
   MD5_Update (&ctx, salt, slen);

   MD5_Init (&ctx1);
   MD5_Update (&ctx1, pw, plen);
   MD5_Update (&ctx1, salt, slen);
   MD5_Update (&ctx1, pw, plen);
   MD5_Final (final, &ctx1);

   for (i = plen; i > 0; i -= APR_MD5_DIGESTSIZE)
     MD5_Update (&ctx, final,
		 (i > APR_MD5_DIGESTSIZE) ? APR_MD5_DIGESTSIZE : i);

   memset (final, 0, sizeof (final));

   for (i = plen; i != 0; i >>= 1)
     MD5_Update (&ctx, (i & 1) ? (char*)final : pw, 1);

   strcpy (passwd, APR1_ID_STR);
   strncat (passwd, salt, slen);
   strcat (passwd, "$");

   MD5_Final (final, &ctx);

   for (i = 0; i < 1000; i++)
     {
       MD5_Init (&ctx1);
       if (i & 1)
	 MD5_Update (&ctx1, pw, plen);
       else
	 MD5_Update (&ctx1, final, APR_MD5_DIGESTSIZE);

       if (i % 3)
	 MD5_Update (&ctx1, salt, slen);

       if (i % 7)
	 MD5_Update (&ctx1, pw, plen);

       if (i & 1)
	 MD5_Update (&ctx1, final, APR_MD5_DIGESTSIZE);
       else
	 MD5_Update (&ctx1, pw, plen);
       MD5_Final (final, &ctx1);
     }

   p = passwd + strlen (passwd);

   to64 (p, (final[0]<<16) | (final[6]<<8) | final[12], 4);
   p += 4;

   to64 (p, (final[1]<<16) | (final[7]<<8) | final[13], 4);
   p += 4;

   to64 (p, (final[2]<<16) | (final[8]<<8) | final[14], 4);
   p += 4;

   to64 (p, (final[3]<<16) | (final[9]<<8) | final[15], 4);
   p += 4;

   to64 (p, (final[4]<<16) | (final[10]<<8) | final[5], 4);
   p += 4;

   to64 (p, final[11], 2);
   p += 2;

   *p = '\0';

   memset (final, 0, sizeof (final));

   i = strlen (passwd);
   if (i >= nbytes)
     i = nbytes - 1;
   memcpy (result, passwd, i);
   result[i] = 0;

   return result;
}

static int
auth_apr (const char *pass, const char *hash)
{
  char buf[120];
  char *cp = apr_md5_encode (pass, hash, buf, sizeof (buf));
  return cp ? strcmp (cp, hash) : 1;
}
#endif /* OPENSSL_NO_MD5 */

static int
auth_sha1 (const char *pass, const char *hash)
{
  int len;
  BIO *bb, *b64;
  char hashbuf[SHA_DIGEST_LENGTH], resbuf[SHA_DIGEST_LENGTH];

  if ((bb = BIO_new (BIO_s_mem ())) == NULL)
    {
      logmsg (LOG_WARNING, "(%"PRItid") Can't alloc BIO_s_mem", POUND_TID ());
      return 1;
    }

  if ((b64 = BIO_new (BIO_f_base64 ())) == NULL)
    {
      logmsg (LOG_WARNING, "(%"PRItid") Can't alloc BIO_f_base64",
	      POUND_TID ());
      BIO_free (bb);
      return 1;
    }

  b64 = BIO_push (b64, bb);
  hash += 5; /* Skip past {SHA} */
  BIO_write (bb, hash, strlen (hash));
  BIO_write (bb, "\n", 1);
  len = BIO_read (b64, hashbuf, sizeof (hashbuf));
  if (len <= 0)
    {
      logmsg (LOG_WARNING, "(%"PRItid") Can't read BIO_f_base64",
	      POUND_TID ());
      BIO_free_all (b64);
      return 1;
    }

  if (!BIO_eof (b64))
    {
      logmsg (LOG_WARNING, "(%"PRItid") excess data in SHA1 hash",
	      POUND_TID ());
      BIO_free_all (b64);
      return 1;
    }

  BIO_free_all (b64);

  SHA_CTX ctx;
  SHA1_Init (&ctx);
  SHA1_Update (&ctx, pass, strlen (pass));
  SHA1_Final ((unsigned char*) resbuf, &ctx);

  return memcmp (resbuf, hashbuf, SHA_DIGEST_LENGTH);
}

struct auth_matcher
{
  char *auth_pfx;
  size_t auth_len;
  int (*auth_match) (const char *, const char *);
};

static struct auth_matcher auth_match_tab[] = {
#define S(s) #s, sizeof(#s)-1
#ifndef OPENSSL_NO_MD5
  { S($apr1$), auth_apr },
#endif
  { S({SHA}), auth_sha1 },
  { "", 0, auth_crypt },
  { "", 0, auth_plain },
  { NULL }
};

static int
auth_match (const char *pass, const char *hash)
{
  struct auth_matcher *p;
  size_t plen = strlen (hash);

  for (p = auth_match_tab; p->auth_match; p++)
    {
      if (p->auth_len < plen &&
	  memcmp (p->auth_pfx, hash, p->auth_len) == 0)
	{
	  if (p->auth_match (pass, hash) == 0)
	    return 0;
	  if (p->auth_len > 0)
	    break;
	}
    }
  return 1;
}

static int
basic_auth_internal (char const *file, char const *user, char const *pass)
{
  FILE *fp;
  char buf[MAXBUF];
  int rc;

  fp = fopen (file, "r");
  if (!fp)
    {
      logmsg (LOG_WARNING, "(%"PRItid") can't open %s: %s", POUND_TID (),
	      file, strerror (errno));
      return 1;
    }

  rc = 1;
  while (fgets (buf, sizeof (buf), fp))
    {
      char *p, *q;
      for (p = buf; *p && (*p == ' ' || *p == '\t'); p++);
      if (*p == '#')
	continue;
      q = p + strlen (p);
      if (q == p)
	continue;
      if (q[-1] == '\n')
	*--q = 0;
      if (!*p)
	continue;
      if ((q = strchr (p, ':')) == NULL)
	continue;
      *q++ = 0;
      if (strcmp (p, user))
	continue;
      rc = auth_match (pass, q);
      break;
    }
  fclose (fp);

  return rc;
}

int
basic_auth (char const *file, struct http_request *req)
{
  char *user;
  char *pass;
  int rc;

  if ((rc = http_request_get_basic_auth (req, &user, &pass)) == 0)
    {
      rc = basic_auth_internal (file, user, pass);
      memset (pass, 0, strlen (pass));
      free (pass);
      free (user);
    }
  return rc;
}
