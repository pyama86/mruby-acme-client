
// LICENSE: https://github.com/ruby/openssl/blob/master/LICENSE.txt
#ifndef OSSL_PKEY
#define OSSL_PKEY
void Init_ossl_rsa(mrb_state *mrb);

#define OSSL_PKEY_BN_DEF_GETTER0(_keytype, _type, _name, _get)                                     \
  /*                                                                                               \
   *  call-seq:                                                                                    \
   *     key.##name -> aBN                                                                         \
   */                                                                                              \
  static mrb_value ossl_##_keytype##_get_##_name(mrb_state *mrb, mrb_value self)                    \
  {                                                                                                \
    _type *obj;                                                                                    \
    BIGNUM *bn;                                                                                    \
                                                                                                   \
    Get##_type(self, obj);                                                                         \
    _get;                                                                                          \
    if (bn == NULL)                                                                                \
      return mrb_nil_value();                                                                      \
    return ossl_bn_new(mrb, bn);                                                                   \
  }

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined LIBRESSL_VERSION_NUMBER)
#define GetPKeyRSA(obj, pkey)                                                                      \
  do {                                                                                             \
    GetPKey((obj), (pkey));                                                                        \
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {                                                  \
      mrb_raise(mrb, E_RUNTIME_ERROR, "THIS IS NOT A RSA!");                                       \
    }                                                                                              \
  } while (0)
#else
#define GetPKeyRSA(obj, pkey)                                                                      \
  do {                                                                                             \
    GetPKey((obj), (pkey));                                                                        \
    if (EVP_PKEY_type((pkey)->type) != EVP_PKEY_RSA) { /* PARANOIA? */                             \
      mrb_raise(mrb, E_RUNTIME_ERROR, "THIS IS NOT A RSA!");                                       \
    }                                                                                              \
  } while (0)


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


#endif

mrb_value ossl_rsa_new(mrb_state *mrb, EVP_PKEY *pkey);

#define OSSL_PKEY_BN_DEF_GETTER3(_keytype, _type, _group, a1, a2, a3)                              \
  OSSL_PKEY_BN_DEF_GETTER0(_keytype, _type, a1, _type##_get0_##_group(obj, &bn, NULL, NULL))       \
  OSSL_PKEY_BN_DEF_GETTER0(_keytype, _type, a2, _type##_get0_##_group(obj, NULL, &bn, NULL))       \
  OSSL_PKEY_BN_DEF_GETTER0(_keytype, _type, a3, _type##_get0_##_group(obj, NULL, NULL, &bn))

#define OSSL_PKEY_BN_DEF3(_keytype, _type, _group, a1, a2, a3)                                     \
  OSSL_PKEY_BN_DEF_GETTER3(_keytype, _type, _group, a1, a2, a3)

#define DEF_OSSL_PKEY_BN(class, keytype, name)                                                     \
  do {                                                                                             \
    mrb_define_method(mrb, (class), #name, ossl_##keytype##_get_##name, MRB_ARGS_NONE());          \
  } while (0)
#endif /* _OSSL_PKEY */
