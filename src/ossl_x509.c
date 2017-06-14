
//LICENSE: https://github.com/ruby/openssl/blob/master/LICENSE.txt
#include "ossl.h"

void mrb_init_ossl_x509(mrb_state *mrb)
{
  mX509 = mrb_define_module_under(mrb, mOSSL, "X509");
  Init_ossl_x509attr(mrb);
  Init_ossl_x509name(mrb);
  Init_ossl_x509cert(mrb);
  Init_ossl_x509ext(mrb);
  Init_ossl_x509crl(mrb);
  Init_ossl_x509req(mrb);
}
