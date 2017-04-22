#include "ossl.h"

struct RClass *cDigest;
struct RClass *eDigestError;
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
static void ossl_digest_free(mrb_state *mrb, void *ctx)
{
  EVP_MD_CTX_destroy(ctx);
}

static const mrb_data_type ossl_digest_type = {"OpenSSL/Digest", ossl_digest_free};

mrb_value mrb_ossl_digest_sha256_digest(mrb_state *mrb, mrb_value self)
{
  const EVP_MD *md;
  EVP_MD_CTX *ctx;
  char *src;
  unsigned char buffer[SHA256_DIGEST_LENGTH];
  mrb_get_args(mrb, "z", &src);

  mrb_value value_ctx = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "ctx"));
  ctx = DATA_PTR(value_ctx);

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
  mrb_iv_set(
      mrb, self, mrb_intern_lit(mrb, "ctx"),
      mrb_obj_value(Data_Wrap_Struct(mrb, mrb->object_class, &ossl_digest_type, (void *)ctx)));
}

void mrb_init_ossl_digest(mrb_state *mrb)
{
  struct RClass *ossl_digest_sha256;

  cDigest= mrb_define_module_under(mrb, mOSSL, "Digest");
  eDigestError = mrb_define_class_under(mrb, cDigest, "DigestError", eOSSLError);

  ossl_digest_sha256 = mrb_define_class_under(mrb, cDigest, "SHA256", mrb->object_class);
  mrb_define_method(mrb, ossl_digest_sha256, "initialize", mrb_ossl_digest_sha256_init,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, ossl_digest_sha256, "digest", mrb_ossl_digest_sha256_digest,
                    MRB_ARGS_REQ(1));
}
