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
    BIO_CTLR_CAPTURE_GET_TRNC
  };
  
const BIO_METHOD *BIO_f_capture (void);
BIO *bio_new_capture (size_t cap);
