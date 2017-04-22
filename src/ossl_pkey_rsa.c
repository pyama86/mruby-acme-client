#include "ossl.h"

struct RClass *cRSA;
struct RClass *eRSAError;
#define RSA_HAS_PRIVATE(rsa) ((rsa)->p && (rsa)->q)
#define OSSL_PKEY_IS_PRIVATE(mrb, obj) (mrb_bool(mrb_iv_get((mrb), (obj), "private")))
#define RSA_PRIVATE(mrb, obj, rsa) (RSA_HAS_PRIVATE(rsa) || OSSL_PKEY_IS_PRIVATE(mrb, obj))
static RSA *rsa_generate(int size, unsigned long exp)
{
#if defined(HAVE_RSA_GENERATE_KEY_EX) && HAVE_BN_GENCB
  int i;
  BN_GENCB cb;
  struct ossl_generate_cb_arg cb_arg;
  struct rsa_blocking_gen_arg gen_arg;
  RSA *rsa = RSA_new();
  BIGNUM *e = BN_new();

  if (!rsa || !e) {
    if (e)
      BN_free(e);
    if (rsa)
      RSA_free(rsa);
    return 0;
  }
  for (i = 0; i < (int)sizeof(exp) * 8; ++i) {
    if (exp & (1UL << i)) {
      if (BN_set_bit(e, i) == 0) {
        BN_free(e);
        RSA_free(rsa);
        return 0;
      }
    }
  }

  memset(&cb_arg, 0, sizeof(struct ossl_generate_cb_arg));
  if (rb_block_given_p())
    cb_arg.yield = 1;
  BN_GENCB_set(&cb, ossl_generate_cb_2, &cb_arg);
  gen_arg.rsa = rsa;
  gen_arg.e = e;
  gen_arg.size = size;
  gen_arg.cb = &cb;
  /* we cannot release GVL when callback proc is supplied */
  rsa_blocking_gen(&gen_arg);
  if (!gen_arg.result) {
    BN_free(e);
    RSA_free(rsa);
    if (cb_arg.state)
      rb_jump_tag(cb_arg.state);
    return 0;
  }

  BN_free(e);
  return rsa;
#else
  return RSA_generate_key(size, exp, NULL, NULL);
#endif
}

static void ossl_evp_pkey_free(mrb_state *mrb, void *ptr)
{
  EVP_PKEY_free(ptr);
}

static const mrb_data_type ossl_evp_pkey_type = {"OpenSSL/EVP_PKEY", ossl_evp_pkey_free};

static mrb_value mrb_ossl_pkey_rsa_init(mrb_state *mrb, mrb_value self)
{
  ossl_pkey_alloc(mrb, self);
  EVP_PKEY *pkey;
  RSA *rsa;
  BIO *in;
  int argc;
  char *passwd = NULL;
  mrb_value arg, pass;

  GetPKey(mrb, self, pkey);
  argc = mrb_get_args(mrb, "i|i", &arg, &pass);
  if (mrb_fixnum(arg) == 0) {
    rsa = RSA_new();
  } else if (mrb_fixnum(arg)) {
    rsa = rsa_generate(mrb_fixnum(arg), argc == 1 ? RSA_F4 : (unsigned) mrb_fixnum(pass));
//    rsa = rsa_generate(mrb_fixnum(arg), RSA_F4);
    if (!rsa)
      mrb_raise(mrb, eRSAError, NULL);
  } else {
    mrb_raise(mrb, eRSAError, "unsupported interface");
  }

  if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
    RSA_free(rsa);
    mrb_raise(mrb, eRSAError, NULL);
  }
  return self;
}

static mrb_value rsa_instance(mrb_state *mrb, struct RClass *klass, RSA *rsa)
{
  EVP_PKEY *pkey;
  mrb_value obj;

  if (!rsa) {
    return mrb_nil_value();
  }

  obj = NewPKey(mrb, klass);
  if (!(pkey = EVP_PKEY_new())) {
    return mrb_nil_value();
  }
  if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
    EVP_PKEY_free(pkey);
    return mrb_nil_value();
  }
  SetPKey(mrb, obj, pkey);

  return obj;
}

mrb_value ossl_rsa_new(mrb_state *mrb, EVP_PKEY *pkey)
{
  mrb_value obj;

  if (!pkey) {
    obj = rsa_instance(mrb, cRSA, RSA_new());
  } else {
    obj = NewPKey(mrb, mrb_class_get(mrb, "OpenSSL::PKey::RSA"));
    if (EVP_PKEY_type(pkey->type) != EVP_PKEY_RSA) {
      mrb_raise(mrb, E_TYPE_ERROR, "Not a RSA key!");
    }
    SetPKey(mrb, obj, pkey);
  }
  if (mrb_nil_p(obj)) {
    mrb_raise(mrb, eRSAError, NULL);
  }

  return obj;
}

static mrb_value mrb_ossl_pkey_rsa_public_key(mrb_state *mrb, mrb_value self)
{
  EVP_PKEY *pkey;
  RSA *rsa;
  mrb_value obj;

  GetPKeyRSA(mrb, self, pkey);

  rsa = RSAPublicKey_dup(pkey->pkey.rsa);
  obj = rsa_instance(mrb, mrb_class(mrb, self), rsa);

  if (mrb_nil_p(obj)) {
    RSA_free(rsa);
    mrb_raise(mrb, eRSAError, NULL);
  }

  return obj;
}

static mrb_value mrb_ossl_rsa_is_private(mrb_state *mrb, mrb_value self)
{
  EVP_PKEY *pkey;
  GetPKey(mrb, self, pkey);
  return (RSA_PRIVATE(mrb, self, pkey->pkey.rsa)) ? mrb_bool_value(true) : mrb_bool_value(false);
}

OSSL_PKEY_BN(rsa, n)
OSSL_PKEY_BN(rsa, e)

void mrb_init_ossl_pkey_rsa(mrb_state *mrb)
{

  cRSA = mrb_define_class_under(mrb, mPKey, "RSA", cPKey);
  eRSAError = mrb_define_class_under(mrb, mPKey, "RSAError", ePKeyError);

  mrb_define_method(mrb, cRSA, "initialize", mrb_ossl_pkey_rsa_init, MRB_ARGS_ARG(1, 1));
  mrb_define_method(mrb, cRSA, "public_key", mrb_ossl_pkey_rsa_public_key, MRB_ARGS_NONE());
  mrb_define_method(mrb, cRSA, "private?", mrb_ossl_rsa_is_private, MRB_ARGS_NONE());

  DEF_OSSL_PKEY_BN(mrb, cRSA, rsa, n);
  DEF_OSSL_PKEY_BN(mrb, cRSA, rsa, e);
}
