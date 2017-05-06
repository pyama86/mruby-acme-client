#include "ossl.h"
struct RClass *cX509Cert;
struct RClass *eX509CertError;
#define GetX509(mrb, obj, x509)                                                                    \
  do {                                                                                             \
    mrb_value value_x509 = mrb_iv_get(mrb, obj, mrb_intern_lit(mrb, "x509"));                      \
    x509 = DATA_PTR(value_x509);                                                                   \
  } while (0)
#define SetX509(mrb, obj, x509)                                                                    \
  do {                                                                                             \
    if (!(x509)) {                                                                                 \
      mrb_raise((mrb), E_RUNTIME_ERROR, " wasn't initialized!");                                   \
    }                                                                                              \
    mrb_iv_set(                                                                                    \
        (mrb), (obj), mrb_intern_lit(mrb, "x509"),                                                 \
        mrb_obj_value(Data_Wrap_Struct(mrb, mrb->object_class, &ossl_x509_type, (void *)x509)));   \
  } while (0)
#define SafeGetX509(mrb, obj, x509)                                                                \
  do {                                                                                             \
    OSSL_Check_Kind((mrb), (obj), cX509Cert);                                                      \
    GetX509((mrb), (obj), (x509));                                                                 \
  } while (0)

static void ossl_x509_free(mrb_state *mrb, void *ptr)
{
  X509_free(ptr);
}

static const mrb_data_type ossl_x509_type = {"OpenSSL/X509", ossl_x509_free};

X509 *GetX509CertPtr(mrb_state *mrb, VALUE obj)
{
  X509 *x509;

  SafeGetX509(mrb, obj, x509);

  return x509;
}

static VALUE ossl_x509_initialize(mrb_state *mrb, VALUE self)
{
  BIO *in;
  X509 *x509, *x;
  VALUE arg;
  VALUE obj;

  x = X509_new();
  if (!x)
    mrb_raise(mrb, eX509CertError, NULL);

  if (mrb_get_args(mrb, "o", &arg) > 0) {

    arg = ossl_to_der_if_possible(mrb, arg);
    in = ossl_obj2bio(mrb, arg);
    x509 = PEM_read_bio_X509(in, &x, NULL, NULL);
    if (!x509) {
      OSSL_BIO_reset(in);
      x509 = d2i_X509_bio(in, &x);
    }
    BIO_free(in);
    if (!x509)
      mrb_raise(mrb, eX509CertError, NULL);
  }
  SetX509(mrb, self, x);

  return self;
}

static VALUE ossl_x509_to_pem(mrb_state *mrb, VALUE self)
{
  X509 *x509;
  BIO *out;
  VALUE str;

  GetX509(mrb, self, x509);
  out = BIO_new(BIO_s_mem());
  if (!out)
    mrb_raise(mrb, eX509CertError, NULL);

  if (!PEM_write_bio_X509(out, x509)) {
    BIO_free(out);
    mrb_raise(mrb, eX509CertError, NULL);
  }
  str = ossl_membio2str(mrb, out);

  return str;
}

void Init_ossl_x509cert(mrb_state *mrb)
{
  eX509CertError = mrb_define_class_under(mrb, mX509, "CertificateError", eOSSLError);
  cX509Cert = mrb_define_class_under(mrb, mX509, "Certificate", mrb->object_class);
  mrb_define_method(mrb, cX509Cert, "initialize", ossl_x509_initialize, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, cX509Cert, "to_pem", ossl_x509_to_pem, 0);
}
