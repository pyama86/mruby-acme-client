#include "ossl.h"

struct RClass *eOSSLError;
struct RClass *mOSSL;

mrb_value ossl_to_der(mrb_state *mrb, mrb_value obj)
{
  mrb_value tmp;

  tmp = mrb_funcall(mrb, obj, "to_der", 0);
  return tmp;
}

mrb_value ossl_to_der_if_possible(mrb_state *mrb, mrb_value obj)
{
  if (mrb_respond_to(mrb, obj, mrb_intern_lit(mrb, "to_der")))
    return ossl_to_der(mrb, obj);
  return obj;
}
void mrb_init_ossl(mrb_state *mrb)
{
  mOSSL = mrb_define_module(mrb, "OpenSSL");
  eOSSLError = mrb_define_class_under(mrb, mOSSL, "OpenSSLError", mrb->eStandardError_class);
}
