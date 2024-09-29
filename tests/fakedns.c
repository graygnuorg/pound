/*
 * NAME
 *   libfakedns - use fake DNS port and/or IP address.
 *
 * SYNOPSIS
 *   LD_PRELOAD=/path/to/libfakedns.so
 *
 * DESCRIPTION
 *   To test the dynamic backend functionality, pound testsuite needs
 *   to start a mock DNS on a non-standard port.  Unfortunately, libadns
 *   which pound uses as a resolver library, makes no provisions for using
 *   port other than 53 for DNS queries.  This preload library is designed
 *   to overcome this difficulty.
 *
 *   It provides replacements for connect, recvfrom, and sendto system calls.
 *   The connect and sendto function check if the address to communicate with
 *   is 192.0.2.24:53.  If so, they replace the address with the IP and
 *   port defined by environment variables FAKEDNS_IP and FAKEDNS_PORT,
 *   correspondingly.  Then control is passed to the original system call.
 *   The recvfrom wrapper does the reverse: the originam system call is
 *   invoked.  On success, if the returned sockaddr indicates that the
 *   response came from the address $FAKEDNS_IP:$FAKEDNS_PORT, it is replaced
 *   with 192.0.2.24:53.
 *
 *   The testsuite configures the test DNS to listen on
 *   $FAKEDNS_IP:$FAKEDNS_PORT and the adns library to use 192.0.2.24:53
 *   as a nameserver.  Pound is started with LD_PRELOAD set to the location
 *   of libfakedns.so.  As a result, adns communicates with the correct
 *   DNS server without knowing its actual address.
 *
 *   FAKEDNS_IP defaults to 127.0.0.1 and FAKEDNS_PORT defaults to 15353.
 *
 * LICENSE
 *   This library is part of pound testsuite.
 *   Copyright (C) 2024 Sergey Poznyakoff
 *
 *   Pound is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   Pound is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with pound.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/syscall.h>
#include <assert.h>
#include <limits.h>

/* 192.0.2.24 */
#define DNS_ADDR 0x180200C0
/* 53 */
#define DNS_PORT 0x3500

#define DEFAULT_FAKEDNS_PORT 15353

static struct sockaddr_in si_dns;

static void
si_dns_init (void)
{
  if (si_dns.sin_port == 0)
    {
      char *p;
      int n;

      si_dns.sin_family = AF_INET;

      if ((p = getenv ("FAKEDNS_IP")) != NULL)
	assert (inet_pton (AF_INET, p, &si_dns.sin_addr) == 1);
      else
	si_dns.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

      if ((p = getenv ("FAKEDNS_PORT")) != NULL)
	{
	  n = atoi (p);
	  assert (n != 0 && n < USHRT_MAX);
	}
      else
	n = DEFAULT_FAKEDNS_PORT;
      si_dns.sin_port = htons (n);
    }
}

const struct sockaddr *
sa_check (const struct sockaddr *addr)
{
  if (addr->sa_family == AF_INET)
    {
      struct sockaddr_in *si = (struct sockaddr_in *) addr;
      if (si->sin_port == DNS_PORT && si->sin_addr.s_addr == DNS_ADDR)
	{
	  si_dns_init ();
	  addr = (struct sockaddr *) &si_dns;
	}
    }
  return addr;
}

int
connect (int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  return syscall (SYS_connect, sockfd, sa_check (addr), addrlen);
}

ssize_t
sendto (int sockfd, const void *buf, size_t len, int flags,
	const struct sockaddr *addr, socklen_t addrlen)
{
  return syscall (SYS_sendto, sockfd, buf, len, flags, sa_check (addr),
		  addrlen);
}

ssize_t
recvfrom (int sockfd, void *restrict buf, size_t len, int flags,
	  struct sockaddr *restrict src_addr, socklen_t *restrict addrlen)
{
  ssize_t rc = syscall (SYS_recvfrom, sockfd, buf, len, flags,
			src_addr, addrlen);
  if (rc != -1)
    {
      if (src_addr->sa_family == AF_INET)
	{
	  struct sockaddr_in *si = (struct sockaddr_in *)src_addr;
	  si_dns_init ();
	  if (si->sin_port == si_dns.sin_port && si->sin_addr.s_addr == si_dns.sin_addr.s_addr)
	    {
	      si->sin_addr.s_addr = DNS_ADDR;
	      si->sin_port = DNS_PORT;
	    }
	}
    }
  return rc;
}
