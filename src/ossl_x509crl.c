
//LICENSE: https://github.com/ruby/openssl/blob/master/LICENSE.txt
#include "ossl.h"
extern struct RClass *mX509;
#define GetX509CRL(obj, crl)                                                                  \
  do {                                                                                             \
    crl = DATA_PTR(obj);                                                                     \
  } while (0)

#define SafeGetX509CRL(obj, crl)                                                              \
  do {                                                                                             \
    OSSL_Check_Kind((mrb), (obj), cX509CRL);                                                       \
    GetX509CRL((obj), (crl));                                                               \
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

  SafeGetX509CRL(obj, crl);

  return crl;
}

void Init_ossl_x509crl(mrb_state *mrb)
{
  eX509CRLError = mrb_define_class_under(mrb, mX509, "CRLError", eOSSLError);
  cX509CRL = mrb_define_class_under(mrb, mX509, "CRL", mrb->object_class);
};
