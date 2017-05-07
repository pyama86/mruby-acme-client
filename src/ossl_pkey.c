#include "ossl.h"

struct RClass *ePKeyError;
struct RClass *cPKey;
struct RClass *mPKey;

static void ossl_evp_pkey_free(mrb_state *mrb, void *ptr)
{
  EVP_PKEY_free(ptr);
}

const mrb_data_type ossl_evp_pkey_type = {"OpenSSL/EVP_PKEY", ossl_evp_pkey_free};

mrb_value ossl_pkey_new(mrb_state *mrb, EVP_PKEY *pkey)
{
  if (!pkey) {
    mrb_raise(mrb, ePKeyError, "Cannot make new key from NULL.");
  }
  switch (EVP_PKEY_type(pkey->type)) {
  case EVP_PKEY_RSA:
    return ossl_rsa_new(mrb, pkey);
  default:
    mrb_raise(mrb, ePKeyError, "unsupported key type");
  }

  UNREACHABLE;
}

EVP_PKEY *GetPKeyPtr(mrb_state *mrb, mrb_value obj)
{
  EVP_PKEY *pkey;

  SafeGetPKey(obj, pkey);

  return pkey;
}

static mrb_value mrb_ossl_pkey_sign(mrb_state *mrb, mrb_value self)
{
  EVP_PKEY *pkey;
  EVP_MD_CTX ctx, *ictx;
  unsigned int buf_len;
  mrb_value str, digest_instance, data;
  int result;

  if (!mrb_bool(mrb_funcall(mrb, self, "private?", 0, NULL))) {
    mrb_raise(mrb, ePKeyError, "Private key is needed.");
  }

  mrb_get_args(mrb, "oS", &digest_instance, &data);

  GetPKey(self, pkey);

  mrb_value value_ctx = mrb_iv_get(mrb, digest_instance, mrb_intern_lit(mrb, "ctx"));
  ictx = DATA_PTR(value_ctx);

  EVP_SignInit(&ctx, ictx->digest);
  EVP_SignUpdate(&ctx, RSTRING_PTR(data), RSTRING_LEN(data));
  str = mrb_str_new(mrb, 0, EVP_PKEY_size(pkey) + 16);
  result = EVP_SignFinal(&ctx, (unsigned char *)RSTRING_PTR(str), &buf_len, pkey);
  EVP_MD_CTX_cleanup(&ctx);
  if (!result)
    mrb_raise(mrb, ePKeyError, NULL);
  assert((long)buf_len <= RSTRING_LEN(str));

  mrb_str_resize(mrb, str, mrb_fixnum(mrb_fixnum_value(buf_len)));
  return str;
}

mrb_value ossl_pkey_init(mrb_state *mrb, mrb_value klass)
{
  return ossl_pkey_alloc(mrb, klass);
}

mrb_value ossl_pkey_alloc(mrb_state *mrb, mrb_value klass)
{
  EVP_PKEY *pkey;

  if (!(pkey = EVP_PKEY_new())) {
    mrb_raise(mrb, ePKeyError, NULL);
  }
  SetPKey(klass, pkey);

  return klass;
}

EVP_PKEY *GetPrivPKeyPtr(mrb_state *mrb, VALUE obj)
{
  EVP_PKEY *pkey;
  if (!mrb_bool(mrb_funcall(mrb, obj, "private?", 0, NULL))) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "Private key is needed.");
  }
  SafeGetPKey(obj, pkey);

  return pkey;
}
void Init_ossl_pkey(mrb_state *mrb)
{
  mPKey = mrb_define_module_under(mrb, mOSSL, "PKey");
  ePKeyError = mrb_define_class_under(mrb, mPKey, "PKeyError", eOSSLError);
  cPKey = mrb_define_class_under(mrb, mPKey, "PKey", mrb->object_class);
  mrb_define_method(mrb, cPKey, "initialize", ossl_pkey_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, cPKey, "sign", mrb_ossl_pkey_sign, MRB_ARGS_REQ(2));
  Init_ossl_rsa(mrb);
}
