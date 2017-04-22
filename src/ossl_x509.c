#include "ossl.h"

void mrb_init_ossl_x509(mrb_state *mrb)
{
  mX509 = mrb_define_module_under(mrb, mOSSL, "X509");
}
