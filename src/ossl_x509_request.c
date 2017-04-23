#include "ossl.h"

struct RClass *eX509ReqError;
struct RClass *cX509Req;
#define SetX509Req(mrb, obj, req)                                                                  \
  do {                                                                                             \
    if (!(req)) {                                                                                  \
      mrb_raise((mrb), E_RUNTIME_ERROR, "Req wasn't initialized!");                                \
    }                                                                                              \
    mrb_iv_set((mrb), (obj), mrb_intern_lit(mrb, "x509req"),                                       \
               mrb_obj_value(Data_Wrap_Struct(mrb, mrb->object_class, &ossl_x509_request_type,     \
                                              (void *)req)));                                      \
  } while (0)
#define GetX509Req(mrb, obj, req)                                                                  \
  do {                                                                                             \
    mrb_value value_req;                                                                           \
    value_req = mrb_iv_get((mrb), (obj), mrb_intern_lit(mrb, "x509req"));                          \
    req = DATA_PTR(value_req);                                                                     \
  } while (0)

static void ossl_x509req_free(mrb_state *mrb, void *ptr)
{
  X509_REQ_free(ptr);
}

static const mrb_data_type ossl_x509_request_type = {"OpenSSL/X509/REQ", ossl_x509req_free};

static mrb_value ossl_x509_request_init(mrb_state *mrb, mrb_value self)
{
  X509_REQ *req;
  if (!(req = X509_REQ_new())) {
    mrb_raise(mrb, eX509ReqError, NULL);
  }
  SetX509Req(mrb, self, req);

  return self;
}

static mrb_value ossl_x509req_set_public_key(mrb_state *mrb, mrb_value self)
{
  X509_REQ *req;
  EVP_PKEY *pkey;
  mrb_value key;
  GetX509Req(mrb, self, req);
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

  SafeGetX509Name(mrb, obj, name);

  return name;
}
static mrb_value ossl_x509req_set_subject(mrb_state *mrb, mrb_value self)
{
  X509_REQ *req;
  mrb_value subject;

  mrb_get_args(mrb, "o", &subject);
  GetX509Req(mrb, self, req);
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
  GetX509Req(mrb, self, req);
  if (!X509_REQ_set_version(req, ver)) {
    mrb_raise(mrb, eX509ReqError, NULL);
  }

  return version;
}
static VALUE ossl_x509req_add_attribute(mrb_state *mrb, VALUE self)
{
  X509_REQ *req;
  VALUE attr;
  mrb_get_args(mrb, "o", &attr);

  GetX509Req(mrb, self, req);
  if (!X509_REQ_add1_attr(req, DupX509AttrPtr(mrb, attr))) {
    mrb_raise(mrb, eX509ReqError, NULL);
  }

  return attr;
}

void mrb_init_ossl_x509_request(mrb_state *mrb)
{
  eX509ReqError = mrb_define_class_under(mrb, mX509, "RequestError", eOSSLError);

  cX509Req = mrb_define_class_under(mrb, mX509, "Request", mrb->object_class);
  mrb_define_method(mrb, cX509Req, "initialize", ossl_x509_request_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, cX509Req, "public_key=", ossl_x509req_set_public_key, MRB_ARGS_NONE());
  mrb_define_method(mrb, cX509Req, "subject=", ossl_x509req_set_subject, MRB_ARGS_NONE());
  mrb_define_method(mrb, cX509Req, "version=", ossl_x509req_set_version, MRB_ARGS_NONE());
  mrb_define_method(mrb, cX509Req, "add_attribute", ossl_x509req_add_attribute, MRB_ARGS_REQ(1));
}
