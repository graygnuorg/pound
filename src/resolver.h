/*
 * Resolver definitions for pound.
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
struct resolver_config
{
  char *config_file;
  int debug;
  unsigned max_cname_chain;
};

#define RESOLVER_CONFIG_INITIALIZER { NULL, 0, 0 }

enum dns_status
  {
    dns_success,
    dns_failure,
    dns_temp_failure,
    dns_not_found
  };

union dns_addr
{
  struct sockaddr sa;
  struct sockaddr_in s_in;
  struct sockaddr_in6 s_in6;
};

struct dns_srv
{
  uint16_t priority;
  uint16_t weight;
  uint16_t port;
  char *host;
};

enum dns_resp_type
  {
    dns_resp_none,
    dns_resp_addr,
    dns_resp_srv
  };

struct dns_response
{
  enum dns_resp_type type;
  time_t expires;
  size_t count;
  union
  {
    union dns_addr *addr;
    struct dns_srv *srv;
  };
};

int dns_lookup (char const *name, int family, struct dns_response **presp);
void dns_response_free (struct dns_response *resp);
void resolver_set_config (struct resolver_config *);
int sockaddr_bytes (struct sockaddr *sa, unsigned char **ret_ptr);
