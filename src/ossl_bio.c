//LICENSE: https://github.com/ruby/openssl/blob/master/LICENSE.txt

#include "ossl.h"
BIO *ossl_obj2bio(mrb_state *mrb, mrb_value obj)
{
  BIO *bio;

  bio = BIO_new_mem_buf(RSTRING_PTR(obj), RSTRING_LEN(obj));
  if (!bio)
    mrb_raise(mrb, eOSSLError, NULL);

  return bio;
}

VALUE
ossl_membio2str0(mrb_state *mrb, BIO *bio)
{
  VALUE ret;
  BUF_MEM *buf;

  BIO_get_mem_ptr(bio, &buf);
  ret = mrb_str_new(mrb, buf->data, buf->length);

  return ret;
}
VALUE
ossl_protect_membio2str(mrb_state *mrb, BIO *bio)
{
  return ossl_membio2str0(mrb, bio);
}

VALUE
ossl_membio2str(mrb_state *mrb, BIO *bio)
{
  VALUE ret;
  int status = 0;

  ret = ossl_protect_membio2str(mrb, bio);
  BIO_free(bio);

  return ret;
}
