#include "ossl.h"
BIO *ossl_obj2bio(mrb_state *mrb, mrb_value obj)
{
  BIO *bio;

  bio = BIO_new_mem_buf(RSTRING_PTR(obj), RSTRING_LEN(obj));
  if (!bio)
    mrb_raise(mrb, eOSSLError, NULL);

  return bio;
}
