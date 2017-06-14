
//LICENSE: https://github.com/ruby/openssl/blob/master/LICENSE.txt
#include "ossl.h"

struct RClass *eX509ReqError;
struct RClass *cX509Req;
#define SetX509Req(obj, req)                                                                  \
  do {                                                                                             \
    if (!(req)) {                                                                                  \
      mrb_raise((mrb), E_RUNTIME_ERROR, "Req wasn't initialized!");                                \
    }                                                                                              \
    DATA_PTR(obj) = req; \
    DATA_TYPE(obj) = &ossl_x509_request_type; \
  } while (0)
#define GetX509Req(obj, req)                                                                  \
  do {                                                                                             \
    req = DATA_PTR(obj);                          \
  } while (0)

#define SafeGetX509Req(obj, req)                                                              \
  do {                                                                                             \
    OSSL_Check_Kind((mrb), (obj), cX509Req);                                                       \
    GetX509Req((obj), (req));                                                               \
  } while (0)

static void ossl_x509req_free(mrb_state *mrb, void *ptr)
{
  X509_REQ_free(ptr);
}

static const mrb_data_type ossl_x509_request_type = {"OpenSSL/X509/REQ", ossl_x509req_free};

static mrb_value ossl_x509req_initialize(mrb_state *mrb, mrb_value self)
{
  BIO *in;
  X509_REQ *req, *x;
  VALUE arg;

  if (!(x = X509_REQ_new())) {
    mrb_raise(mrb, eX509ReqError, NULL);
  }
  SetX509Req(self, x);

  if (mrb_get_args(mrb, "|o", &arg) == 0)
    return self;

  arg = ossl_to_der_if_possible(mrb, arg);
  in = ossl_obj2bio(mrb, arg);

  req = PEM_read_bio_X509_REQ(in, &x, NULL, NULL);

  SetX509Req(self, x);

  if (!req) {
    OSSL_BIO_reset(in);
    req = d2i_X509_REQ_bio(in, &x);
    SetX509Req(self, x);
  }
  BIO_free(in);
  if (!req)
    mrb_raise(mrb, eX509ReqError, NULL);

  return self;
}

static mrb_value ossl_x509req_set_public_key(mrb_state *mrb, mrb_value self)
{
  X509_REQ *req;
  EVP_PKEY *pkey;
  mrb_value key;
  GetX509Req(self, req);
  mrb_get_args(mrb, "o", &key);
  pkey = GetPKeyPtr(mrb, key); /* NO NEED TO DUP */
  if (!X509_REQ_set_pubkey(req, pkey)) {
    mrb_raise(mrb, eX509ReqError, NULL);
  }

  return key;
}

X509_NAME *GetX509NamePtr(mrb_state *mrb, mrb_value obj)
{
  X509_NAME *name;

  SafeGetX509Name(obj, name);

  return name;
}
static mrb_value ossl_x509req_set_subject(mrb_state *mrb, mrb_value self)
{
  X509_REQ *req;
  mrb_value subject;

  mrb_get_args(mrb, "o", &subject);
  GetX509Req(self, req);
  /* DUPs name */
  if (!X509_REQ_set_subject_name(req, GetX509NamePtr(mrb, subject))) {
    mrb_raise(mrb, eX509ReqError, NULL);
  }

  return subject;
}
static mrb_value ossl_x509req_set_version(mrb_state *mrb, mrb_value self)
{
  X509_REQ *req;
  long ver;

  mrb_value version;

  mrb_get_args(mrb, "i", &version);

  if ((ver = mrb_fixnum(version)) < 0) {
    mrb_raise(mrb, eX509ReqError, "version must be >= 0!");
  }
  GetX509Req(self, req);
  if (!X509_REQ_set_version(req, ver)) {
    mrb_raise(mrb, eX509ReqError, NULL);
  }

  return version;
}

X509_ATTRIBUTE *GetX509AttrPtr(mrb_state *mrb, VALUE obj)
{
  X509_ATTRIBUTE *attr;

  GetX509Attr(obj, attr);

  return attr;
}

static VALUE ossl_x509req_add_attribute(mrb_state *mrb, VALUE self)
{
  X509_REQ *req;
  VALUE attr;
  mrb_get_args(mrb, "o", &attr);

  GetX509Req(self, req);

  if (!X509_REQ_add1_attr(req, GetX509AttrPtr(mrb, attr))) {
    mrb_raisef(mrb, eX509ReqError, "missing add attribute:%S", ossl_fetch_error(mrb));
  }

  return attr;
}

X509_REQ *GetX509ReqPtr(mrb_state *mrb, VALUE obj)
{
  X509_REQ *req;

  SafeGetX509Req(obj, req);

  return req;
}

static VALUE ossl_x509req_sign(mrb_state *mrb, VALUE self)
{
  mrb_value key, digest;
  X509_REQ *req;
  EVP_PKEY *pkey;
  const EVP_MD *md;
  mrb_get_args(mrb, "oo", &key, &digest);

  GetX509Req(self, req);
  pkey = GetPrivPKeyPtr(mrb, key); /* NO NEED TO DUP */
  md = GetDigestPtr(mrb, digest);
  if (!X509_REQ_sign(req, pkey, md)) {
    mrb_raise(mrb, eX509ReqError, NULL);
  }

  return self;
}

static VALUE ossl_x509req_to_der(mrb_state *mrb, VALUE self)
{
  X509_REQ *req;
  VALUE str;
  long len;
  unsigned char *p;

  GetX509Req(self, req);
  if ((len = i2d_X509_REQ(req, NULL)) <= 0)
    mrb_raise(mrb, eX509ReqError, NULL);
  str = mrb_str_new(mrb, 0, len);
  p = (unsigned char *)RSTRING_PTR(str);
  if (i2d_X509_REQ(req, &p) <= 0)
    mrb_raise(mrb, eX509ReqError, NULL);
  ossl_str_adjust(mrb, str, p);

  return str;
}

void Init_ossl_x509req(mrb_state *mrb)
{
  eX509ReqError = mrb_define_class_under(mrb, mX509, "RequestError", eOSSLError);

  cX509Req = mrb_define_class_under(mrb, mX509, "Request", mrb->object_class);
  MRB_SET_INSTANCE_TT(cX509Req, MRB_TT_DATA);
  mrb_define_method(mrb, cX509Req, "initialize", ossl_x509req_initialize, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, cX509Req, "public_key=", ossl_x509req_set_public_key, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, cX509Req, "subject=", ossl_x509req_set_subject, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, cX509Req, "version=", ossl_x509req_set_version, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, cX509Req, "add_attribute", ossl_x509req_add_attribute, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, cX509Req, "sign", ossl_x509req_sign, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, cX509Req, "to_der", ossl_x509req_to_der, MRB_ARGS_NONE());
}
