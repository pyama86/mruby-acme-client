#ifndef OSSL_PKEY
#define OSSL_PKEY
void Init_ossl_rsa(mrb_state *mrb);

#define GetPKeyRSA(obj, pkey)                                                                 \
  do {                                                                                             \
    GetPKey((obj), (pkey));                                                                 \
    if (EVP_PKEY_type((pkey)->type) != EVP_PKEY_RSA) { /* PARANOIA? */                             \
      mrb_raise(mrb, E_RUNTIME_ERROR, "THIS IS NOT A RSA!");                                            \
    }                                                                                              \
  } while (0)

mrb_value ossl_rsa_new(mrb_state *mrb, EVP_PKEY *pkey);

#define OSSL_PKEY_BN(keytype, name)                                                                \
  /*                                                                                               \
   *  call-seq:                                                                                    \
   *     key.##name -> aBN                                                                         \
   */                                                                                              \
  static mrb_value ossl_##keytype##_get_##name(mrb_state *mrb, mrb_value self)                     \
  {                                                                                                \
    EVP_PKEY *pkey;                                                                                \
    mrb_value value_pkey;                                                                          \
    BIGNUM *bn;                                                                                    \
                                                                                                   \
    pkey = DATA_PTR(self);                                                                   \
    bn = pkey->pkey.keytype->name;                                                                 \
    if (bn == NULL)                                                                                \
      return mrb_nil_value();                                                                      \
    return ossl_bn_new(mrb, bn);                                                                   \
  }

#define DEF_OSSL_PKEY_BN(class, keytype, name)                                                \
  do {                                                                                             \
    mrb_define_method(mrb, (class), #name, ossl_##keytype##_get_##name, MRB_ARGS_NONE());        \
  } while (0)
#endif /* _OSSL_PKEY */
