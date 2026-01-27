/*
 * Pound - the reverse-proxy load-balancer
 * Copyright (C) 2026 Sergey Poznyakoff
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

#include <openssl/bio.h>

enum
  {
    BIO_CTLR_CAPTURE_SET_CAP = 1000,
    BIO_CTLR_CAPTURE_GET_CAP,
    BIO_CTLR_CAPTURE_GET_LEN,
    BIO_CTLR_CAPTURE_GET_PTR,
    BIO_CTLR_CAPTURE_GET_TRNC,
    BIO_CTLR_CAPTURE_GET_MEM
  };

const BIO_METHOD *BIO_f_capture (void);
BIO *bio_new_capture (size_t cap);

#define BIO_capture_is_truncated(b) \
  BIO_ctrl (b, BIO_CTLR_CAPTURE_GET_TRNC, 0, NULL)
#define BIO_capture_get_mem_data(b,pp) \
  BIO_ctrl (b, BIO_CTLR_CAPTURE_GET_PTR, 0, pp)

static inline void BIO_capture_expand(BIO *b, size_t s) {
  BIO_ctrl (b, BIO_CTLR_CAPTURE_SET_CAP, s, NULL);
}
static inline BIO *BIO_capture_unwrap(BIO *b) {
  BIO *mem;
  BIO_ctrl (b, BIO_CTLR_CAPTURE_GET_MEM, 0, &mem);
  BIO_free (b);
  return mem;
}
