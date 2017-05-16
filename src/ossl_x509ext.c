#include "ossl.h"
struct RClass *cX509Ext;
struct RClass *cX509ExtFactory;
struct RClass *eX509ExtError;

#define MakeX509ExtFactory(obj, ctx)                                                               \
  do {                                                                                             \
    if (!((ctx) = OPENSSL_malloc(sizeof(X509V3_CTX))))                                             \
      mrb_raise(mrb, E_RUNTIME_ERROR, "CTX wasn't allocated!");                                    \
    X509V3_set_ctx((ctx), NULL, NULL, NULL, NULL, 0);                                              \
    DATA_PTR(obj) = ctx;                                                                           \
    DATA_TYPE(obj) = &ossl_x509extfactory_type;                                                    \
  } while (0)
#define GetX509ExtFactory(obj, ctx)                                                                \
  do {                                                                                             \
    ctx = DATA_PTR(obj);                                                                           \
  } while (0)

#define SetX509Ext(obj, ext)                                                                       \
  do {                                                                                             \
    if (!(ext)) {                                                                                  \
      mrb_raise(mrb, E_RUNTIME_ERROR, "EXT wasn't initialized!");                                  \
    }                                                                                              \
    DATA_PTR(obj) = ext;                                                                           \
    DATA_TYPE(obj) = &ossl_x509ext_type;                                                           \
  } while (0)

#define GetX509Ext(obj, ctx)                                                                       \
  do {                                                                                             \
    ctx = DATA_PTR(obj);                                                                           \
  } while (0)

static void ossl_x509extfactory_free(mrb_state *mrb, void *ctx)
{
  OPENSSL_free(ctx);
}
static const mrb_data_type ossl_x509extfactory_type = {"OpenSSL/X509/EXTENSION/Factory",
                                                       ossl_x509extfactory_free};

static void ossl_x509ext_free(mrb_state *mrb, void *ptr)
{
  X509_EXTENSION_free(ptr);
}
static const mrb_data_type ossl_x509ext_type = {"OpenSSL/X509/EXTENSION", ossl_x509ext_free};

static VALUE ossl_x509extfactory_set_issuer_cert(mrb_state *mrb, VALUE self, VALUE cert)
{
  X509V3_CTX *ctx;

  GetX509ExtFactory(self, ctx);
  mrb_iv_set(mrb, self, "@issuer_certificate", cert);
  ctx->issuer_cert = GetX509CertPtr(mrb, cert); /* NO DUP NEEDED */

  return cert;
}

static VALUE ossl_x509extfactory_set_subject_cert(mrb_state *mrb, VALUE self, VALUE cert)
{
  X509V3_CTX *ctx;
  GetX509ExtFactory(self, ctx);

  mrb_iv_set(mrb, self, "@subject_certificate", cert);
  ctx->subject_cert = GetX509CertPtr(mrb, cert); /* NO DUP NEEDED */

  return cert;
}

static VALUE ossl_x509extfactory_set_subject_req(mrb_state *mrb, VALUE self, VALUE req)
{
  X509V3_CTX *ctx;
  GetX509ExtFactory(self, ctx);
  mrb_iv_set(mrb, self, "@subject_request", req);
  ctx->subject_req = GetX509ReqPtr(mrb, req); /* NO DUP NEEDED */

  return req;
}

static VALUE ossl_x509extfactory_set_crl(mrb_state *mrb, VALUE self, VALUE crl)
{
  X509V3_CTX *ctx;

  GetX509ExtFactory(self, ctx);
  mrb_iv_set(mrb, self, "@crl", crl);
  ctx->crl = GetX509CRLPtr(mrb, crl); /* NO DUP NEEDED */

  return crl;
}

static VALUE ossl_x509extfactory_initialize(mrb_state *mrb, VALUE self)
{
  VALUE issuer_cert, subject_cert, subject_req, crl;
  X509V3_CTX *ctx;
  MakeX509ExtFactory(self, ctx);
  int argc;
  mrb_iv_set(mrb, self, "@config", mrb_nil_value());

  argc = mrb_get_args(mrb, "|oooo", &issuer_cert, &subject_cert, &subject_req, &crl);

  if (argc == 1 && !NIL_P(issuer_cert))
    ossl_x509extfactory_set_issuer_cert(mrb, self, issuer_cert);
  if (argc == 2 && !NIL_P(subject_cert))
    ossl_x509extfactory_set_subject_cert(mrb, self, subject_cert);
  if (argc == 3 && !NIL_P(subject_req))
    ossl_x509extfactory_set_subject_req(mrb, self, subject_req);
  if (argc == 4 && !NIL_P(crl))
    ossl_x509extfactory_set_crl(mrb, self, crl);

  return self;
}

static VALUE ossl_x509ext_to_der(mrb_state *mrb, VALUE self)
{
  X509_EXTENSION *ext;
  unsigned char *p;
  long len;
  VALUE str;

  GetX509Ext(self, ext);
  if ((len = i2d_X509_EXTENSION(ext, NULL)) <= 0)
    mrb_raise(mrb, eX509ExtError, NULL);
  str = mrb_str_new(mrb, 0, len);
  p = (unsigned char *)RSTRING_PTR(str);
  if (i2d_X509_EXTENSION(ext, &p) < 0)
    mrb_raise(mrb, eX509ExtError, NULL);
  ossl_str_adjust(mrb, str, p);

  return str;
}

static VALUE ossl_x509extfactory_create_ext(mrb_state *mrb, VALUE self)
{
  X509V3_CTX *ctx;
  X509_EXTENSION *ext;
  VALUE oid, value, critical, valstr, obj;
  VALUE rconf;
  CONF *conf;
  int nid;

  mrb_get_args(mrb, "SS|o", &oid, &value, &critical);
  if (NIL_P(critical))
    critical = mrb_false_value();

  nid = OBJ_ln2nid(RSTRING_PTR(oid));
  if (!nid)
    nid = OBJ_sn2nid(RSTRING_PTR(oid));
  if (!nid)
    mrb_raisef(mrb, eX509ExtError, "unknown OID `%s'", RSTRING_PTR(oid));
  valstr = mrb_str_new_cstr(mrb, RTEST(critical) ? "critical," : "");
  mrb_str_append(mrb, valstr, value);
  GetX509ExtFactory(self, ctx);

  obj = mrb_class_new_instance(mrb, 0, NULL, cX509Ext);
  rconf = mrb_iv_get(mrb, self, "@config");
  conf = NIL_P(rconf) ? NULL : GetConfigPtr(mrb, rconf);
  X509V3_set_nconf(ctx, conf);
  ext = X509V3_EXT_nconf_nid(conf, ctx, nid, RSTRING_PTR(valstr));
  X509V3_set_ctx_nodb(ctx);

  if (!ext) {
    mrb_raise(mrb, eX509ExtError, NULL);
  }
  NCONF_free(conf);
  SetX509Ext(obj, ext);
  return obj;
}

static VALUE ossl_x509ext_init(mrb_state *mrb, VALUE self)
{
  X509_EXTENSION *ext;

  if (!(ext = X509_EXTENSION_new())) {
    mrb_raise(mrb, eX509ExtError, NULL);
  }
  SetX509Ext(self, ext);
  return self;
}

void Init_ossl_x509ext(mrb_state *mrb)
{
  eX509ExtError = mrb_define_class_under(mrb, mX509, "ExtensionError", eOSSLError);
  cX509ExtFactory = mrb_define_class_under(mrb, mX509, "ExtensionFactory", mrb->object_class);
  MRB_SET_INSTANCE_TT(cX509ExtFactory, MRB_TT_DATA);
  mrb_define_method(mrb, cX509ExtFactory, "initialize", ossl_x509extfactory_initialize,
                    MRB_ARGS_OPT(4));
  mrb_define_method(mrb, cX509ExtFactory, "create_ext", ossl_x509extfactory_create_ext,
                    MRB_ARGS_ARG(2, 1));

  cX509Ext = mrb_define_class_under(mrb, mX509, "Extension", mrb->object_class);
  MRB_SET_INSTANCE_TT(cX509Ext, MRB_TT_DATA);
  mrb_define_method(mrb, cX509Ext, "initialize", ossl_x509ext_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, cX509Ext, "to_der", ossl_x509ext_to_der, MRB_ARGS_NONE());
}
