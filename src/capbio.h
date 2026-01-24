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
