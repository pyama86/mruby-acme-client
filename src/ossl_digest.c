
//LICENSE: https://github.com/ruby/openssl/blob/master/LICENSE.txt
#include "ossl.h"

#define GetDigest(obj, ctx)                                                                        \
  do {                                                                                             \
    ctx = DATA_PTR(obj);                                                                           \
  } while (0)
#define SafeGetDigest(obj, ctx)                                                                    \
  do {                                                                                             \
    OSSL_Check_Kind((mrb), (obj), cDigest);                                                        \
    GetDigest((mrb), (obj), (ctx));                                                                \
  } while (0)

#define SetDigest(obj, digest)                                                                     \
  do {                                                                                             \
    if (!(digest)) {                                                                               \
      mrb_raise(mrb, E_RUNTIME_ERROR, "Digest  wasn't initialized!");                              \
    }                                                                                              \
    DATA_PTR(obj) = digest;                                                            \
    DATA_TYPE(obj) = &ossl_digest_type;                                                            \
  } while (0)
const EVP_MD *GetDigestPtr(mrb_state *mrb, VALUE obj)
{
  const EVP_MD *md;
  ASN1_OBJECT *oid = NULL;

  if (mrb_type(obj) == MRB_TT_STRING) {
    const char *name = mrb_str_to_cstr(mrb, obj);

    md = EVP_get_digestbyname(name);
    if (!md) {
      oid = OBJ_txt2obj(name, 0);
      md = EVP_get_digestbyobj(oid);
      ASN1_OBJECT_free(oid);
    }
    if (!md)
      mrb_raisef(mrb, E_RUNTIME_ERROR, "Unsupported digest algorithm (%s).", name);
  } else {
    EVP_MD_CTX *ctx;

    GetDigest(obj, ctx);

    md = EVP_MD_CTX_md(ctx);
  }

  return md;
}

static void ossl_digest_free(mrb_state *mrb, void *ctx)
{
  EVP_MD_CTX_destroy(ctx);
}
static const mrb_data_type ossl_digest_type = {"OpenSSL/Digest", ossl_digest_free};

EVP_MD_CTX *ctx_new(mrb_state *mrb)
{
  const EVP_MD *md;
  EVP_MD_CTX *ctx;
  md = EVP_get_digestbyname("SHA256");
  ctx = EVP_MD_CTX_create();

  if (!EVP_DigestInit_ex(ctx, md, NULL))
    mrb_raise(mrb, eDigestError, "Digest initialization failed");
  return ctx;
}

mrb_value mrb_ossl_digest_sha256_digest(mrb_state *mrb, mrb_value self)
{
  const EVP_MD *md;
  EVP_MD_CTX *ctx;
  char *src;
  unsigned char buffer[SHA256_DIGEST_LENGTH];
  mrb_get_args(mrb, "z", &src);

  ctx = DATA_PTR(self);

  if (!ctx) {
    ctx = ctx_new(mrb);
  }
  if (!EVP_DigestUpdate(ctx, src, strlen(src)))
    mrb_raise(mrb, eDigestError, "EVP_DigestUpdate");

  if (!EVP_DigestFinal_ex(ctx, buffer, NULL))
    mrb_raise(mrb, eDigestError, "EVP_DigestFinal_ex");

  return mrb_str_new(mrb, (char *)buffer, EVP_MD_CTX_size(ctx));
}

mrb_value mrb_ossl_digest_sha256_init(mrb_state *mrb, mrb_value self)
{
  EVP_MD_CTX *ctx;
  char *src;
  unsigned char buffer[SHA256_DIGEST_LENGTH];

  ctx = ctx_new(mrb);
  SetDigest(self, ctx);
}

void Init_ossl_digest(mrb_state *mrb)
{
  struct RClass *ossl_digest_sha256;

  mDigest = mrb_define_module_under(mrb, mOSSL, "Digest");
  eDigestError = mrb_define_class_under(mrb, mDigest, "DigestError", eOSSLError);

  ossl_digest_sha256 = mrb_define_class_under(mrb, mDigest, "SHA256", mrb->object_class);
  MRB_SET_INSTANCE_TT(ossl_digest_sha256, MRB_TT_DATA);

  mrb_define_method(mrb, ossl_digest_sha256, "initialize", mrb_ossl_digest_sha256_init,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, ossl_digest_sha256, "digest", mrb_ossl_digest_sha256_digest,
                    MRB_ARGS_REQ(1));
}
