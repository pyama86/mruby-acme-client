#include "openssl.h"

static void ossl_evp_pkey_free(mrb_state *mrb, void *ptr)
{
  EVP_PKEY_free(ptr);
}

static const mrb_data_type ossl_evp_pkey_type = {"OpenSSL/EVP_PKEY", ossl_evp_pkey_free};
static mrb_value mrb_openssl_pkey_rsa_initialize(mrb_state *mrb, mrb_value self)
{
  int size = 0;
  unsigned long exp = 65537;
  EVP_PKEY *pkey;
  RSA *rsa;
  mrb_get_args(mrb, "i", &size);
  rsa = RSA_generate_key(size, exp, NULL, NULL);
  if (!rsa)
    mrb_raise(mrb, E_RUNTIME_ERROR, NULL);

  pkey = EVP_PKEY_new();
  if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
    RSA_free(rsa);
    mrb_raise(mrb, E_RUNTIME_ERROR, NULL);
  }

  mrb_iv_set(
      mrb, self, mrb_intern_lit(mrb, "pkey"),
      mrb_obj_value(Data_Wrap_Struct(mrb, mrb->object_class, &ossl_evp_pkey_type, (void *)pkey)));

  return self;
}

static mrb_value mrb_openssl_pkey_rsa_public_key(mrb_state *mrb, mrb_value self)
{
  EVP_PKEY *pkey;
  RSA *rsa;
  mrb_value obj;

  mrb_value value_pkey = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "pkey"));
  pkey = DATA_PTR(value_pkey);

  rsa = RSAPublicKey_dup(pkey->pkey.rsa);
  obj = mrb_obj_dup(mrb, self);

  pkey = EVP_PKEY_new();
  if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
    RSA_free(rsa);
    mrb_raise(mrb, E_RUNTIME_ERROR, NULL);
  }

  mrb_iv_set(
      mrb, obj, mrb_intern_lit(mrb, "pkey"),
      mrb_obj_value(Data_Wrap_Struct(mrb, mrb->object_class, &ossl_evp_pkey_type, (void *)pkey)));
  return obj;
}

OSSL_PKEY_BN(rsa, n)
OSSL_PKEY_BN(rsa, e)

void mrb_init_openssl_pkey(mrb_state *mrb)
{
  struct RClass *openssl;
  struct RClass *openssl_pkey;
  struct RClass *openssl_pkey_rsa;

  openssl = mrb_define_module(mrb, "OpenSSL");
  openssl_pkey = mrb_define_module_under(mrb, openssl, "PKey");
  openssl_pkey_rsa = mrb_define_class_under(mrb, openssl_pkey, "RSA", mrb->object_class);

  mrb_define_method(mrb, openssl_pkey_rsa, "initialize", mrb_openssl_pkey_rsa_initialize,
                    MRB_ARGS_ARG(1, 1));
  mrb_define_method(mrb, openssl_pkey_rsa, "public_key", mrb_openssl_pkey_rsa_public_key,
                    MRB_ARGS_NONE());
  DEF_OSSL_PKEY_BN(mrb, openssl_pkey_rsa, rsa, n);
  DEF_OSSL_PKEY_BN(mrb, openssl_pkey_rsa, rsa, e);
}
