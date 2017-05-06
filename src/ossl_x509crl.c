#include "ossl.h"
#define GetX509CRL(mrb, obj, crl)                                                                  \
  do {                                                                                             \
    mrb_value value_crl = mrb_iv_get(mrb, obj, mrb_intern_lit(mrb, "x509crl"));                    \
    crl = DATA_PTR(value_crl);                                                                     \
  } while (0)

#define SafeGetX509CRL(mrb, obj, crl)                                                              \
  do {                                                                                             \
    OSSL_Check_Kind((mrb), (obj), cX509CRL);                                                       \
    GetX509CRL((mrb), (obj), (crl));                                                               \
  } while (0)
struct RClass *cX509CRL;
struct RClass *eX509CRLError;

static void ossl_x509crl_free(mrb_state *mrb, void *ptr)
{
  X509_CRL_free(ptr);
}

static const mrb_data_type ossl_x509crl_type = {"OpenSSL/X509/CRL", ossl_x509crl_free};
X509_CRL *GetX509CRLPtr(mrb_state *mrb, VALUE obj)
{
  X509_CRL *crl;

  SafeGetX509CRL(mrb, obj, crl);

  return crl;
}

void Init_ossl_x509crl(mrb_state *mrb)
{
  eX509CRLError = mrb_define_class_under(mrb, mX509, "CRLError", eOSSLError);
  cX509CRL = mrb_define_class_under(mrb, mX509, "CRL", mrb->object_class);
};
