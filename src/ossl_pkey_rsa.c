
//LICENSE: https://github.com/ruby/openssl/blob/master/LICENSE.txt
#include "ossl.h"

struct RClass *cRSA;
struct RClass *eRSAError;

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined LIBRESSL_VERSION_NUMBER)
static inline int
RSA_HAS_PRIVATE(RSA *rsa)
{
    const BIGNUM *p, *q;

    RSA_get0_factors(rsa, &p, &q);
    return p && q; /* d? why? */
}

#define GetRSA(obj, rsa) do { \
    EVP_PKEY *_pkey; \
    GetPKeyRSA((obj), _pkey); \
    (rsa) = EVP_PKEY_get0_RSA(_pkey); \
} while (0)

#else
#define RSA_HAS_PRIVATE(rsa) ((rsa)->p && (rsa)->q)
#endif

#define OSSL_PKEY_IS_PRIVATE(mrb, obj) (mrb_bool(mrb_iv_get((mrb), (obj), "private")))
#define RSA_PRIVATE(obj, rsa) (RSA_HAS_PRIVATE(rsa) || OSSL_PKEY_IS_PRIVATE(mrb, obj))

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

  GetPKey(self, pkey);
  argc = mrb_get_args(mrb, "o|o", &arg, &pass);
  if (mrb_fixnum_p(arg) && mrb_fixnum(arg) == 0) {
    rsa = RSA_new();
  } else if (mrb_fixnum_p(arg)) {
    rsa = rsa_generate(mrb_fixnum(arg), argc == 1 ? RSA_F4 : (unsigned)mrb_fixnum(pass));
    if (!rsa)
      mrb_raise(mrb, eRSAError, NULL);
  } else {
    arg = ossl_to_der_if_possible(mrb, arg);
    in = ossl_obj2bio(mrb, arg);
    rsa = PEM_read_bio_RSAPrivateKey(in, NULL, ossl_pem_passwd_cb, passwd);
    if (!rsa) {
      OSSL_BIO_reset(in);
      rsa = PEM_read_bio_RSA_PUBKEY(in, NULL, NULL, NULL);
    }
    if (!rsa) {
      OSSL_BIO_reset(in);
      rsa = d2i_RSAPrivateKey_bio(in, NULL);
    }
    if (!rsa) {
      OSSL_BIO_reset(in);
      rsa = d2i_RSA_PUBKEY_bio(in, NULL);
    }
    if (!rsa) {
      OSSL_BIO_reset(in);
      rsa = PEM_read_bio_RSAPublicKey(in, NULL, NULL, NULL);
    }
    if (!rsa) {
      OSSL_BIO_reset(in);
      rsa = d2i_RSAPublicKey_bio(in, NULL);
    }
    BIO_free(in);
    if (!rsa) {
      mrb_raise(mrb, eRSAError, "Neither PUB key nor PRIV key");
    }
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

  obj = NewPKey(klass);
  if (!(pkey = EVP_PKEY_new())) {
    return mrb_nil_value();
  }
  if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
    EVP_PKEY_free(pkey);
    return mrb_nil_value();
  }
  SetPKey(obj, pkey);

  return obj;
}

mrb_value ossl_rsa_new(mrb_state *mrb, EVP_PKEY *pkey)
{
  mrb_value obj;
  int type;

  if (!pkey) {
    obj = rsa_instance(mrb, cRSA, RSA_new());
  } else {
    obj = NewPKey(mrb_class_get(mrb, "OpenSSL::PKey::RSA"));
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined LIBRESSL_VERSION_NUMBER)
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
#else
    if (EVP_PKEY_type(pkey->type) != EVP_PKEY_RSA) {
#endif
      mrb_raise(mrb, E_TYPE_ERROR, "Not a RSA key!");
    }

    SetPKey(obj, pkey);
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

  GetPKeyRSA(self, pkey);

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined LIBRESSL_VERSION_NUMBER)
  rsa = RSAPublicKey_dup(EVP_PKEY_get0_RSA(pkey));
#else
  rsa = RSAPublicKey_dup(pkey->pkey.rsa);
#endif

  obj = rsa_instance(mrb, mrb_class(mrb, self), rsa);

  if (mrb_nil_p(obj)) {
    RSA_free(rsa);
    mrb_raise(mrb, eRSAError, NULL);
  }

  return obj;
}

mrb_value mrb_ossl_rsa_is_private(mrb_state *mrb, mrb_value self)
{
  EVP_PKEY *pkey;
  GetPKey(self, pkey);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined LIBRESSL_VERSION_NUMBER)
  RSA *rsa;
  GetRSA(self, rsa);
  return RSA_PRIVATE(self, rsa)  ? mrb_bool_value(true) : mrb_bool_value(false);
#else
  return (RSA_PRIVATE(self, pkey->pkey.rsa)) ? mrb_bool_value(true) : mrb_bool_value(false);
#endif
}

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined LIBRESSL_VERSION_NUMBER)
OSSL_PKEY_BN_DEF3(rsa, RSA, key, n, e, d)
#else
OSSL_PKEY_BN(rsa, n)
OSSL_PKEY_BN(rsa, e)
#endif

static VALUE ossl_rsa_export(mrb_state *mrb, VALUE self)
{
  EVP_PKEY *pkey;
  BIO *out;
  const EVP_CIPHER *ciph = NULL;
  char *passwd = NULL;
  VALUE cipher, pass, str;

  GetPKeyRSA(self, pkey);

  int argc = mrb_get_args(mrb, "|oo", &cipher, &pass);

  if (argc > 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "unsupport interface");
  }
  if (!(out = BIO_new(BIO_s_mem()))) {
    mrb_raise(mrb, eRSAError, NULL);
  }
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined LIBRESSL_VERSION_NUMBER)

  RSA *rsa;
  etRSA(self, rsa);
  if (RSA_HAS_PRIVATE(rsa)) {
    if (!PEM_write_bio_RSAPrivateKey(out, rsa, ciph, NULL, 0, ossl_pem_passwd_cb,
                                     passwd)) {
#else
  if (RSA_HAS_PRIVATE(pkey->pkey.rsa)) {
    if (!PEM_write_bio_RSAPrivateKey(out, pkey->pkey.rsa, ciph, NULL, 0, ossl_pem_passwd_cb,
                                     passwd)) {
#endif
      BIO_free(out);
      mrb_raise(mrb, eRSAError, NULL);
    }
  } else {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined LIBRESSL_VERSION_NUMBER)
    if (!PEM_write_bio_RSA_PUBKEY(out, rsa)) {
#else
    if (!PEM_write_bio_RSA_PUBKEY(out, pkey->pkey.rsa)) {
#endif
      BIO_free(out);
      mrb_raise(mrb, eRSAError, NULL);
    }
  }
  str = ossl_membio2str(mrb, out);

  return str;
}

void Init_ossl_rsa(mrb_state *mrb)
{

  cRSA = mrb_define_class_under(mrb, mPKey, "RSA", cPKey);
  MRB_SET_INSTANCE_TT(cRSA, MRB_TT_DATA);

  eRSAError = mrb_define_class_under(mrb, mPKey, "RSAError", ePKeyError);

  mrb_define_method(mrb, cRSA, "initialize", mrb_ossl_pkey_rsa_init, MRB_ARGS_ARG(1, 1));
  mrb_define_method(mrb, cRSA, "public_key", mrb_ossl_pkey_rsa_public_key, MRB_ARGS_NONE());
  mrb_define_method(mrb, cRSA, "private?", mrb_ossl_rsa_is_private, MRB_ARGS_NONE());
  mrb_define_method(mrb, cRSA, "export", ossl_rsa_export, -1);
  mrb_define_alias(mrb, cRSA, "to_pem", "export");

  DEF_OSSL_PKEY_BN(cRSA, rsa, n);
  DEF_OSSL_PKEY_BN(cRSA, rsa, e);
}
