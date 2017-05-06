#if !defined(_OSSL_PKEY_H_)
#define _OSSL_PKEY_H_
extern struct RClass *cPKey;
extern struct RClass *mPKey;
extern struct RClass *ePKeyError;
void Init_ossl_pkey(mrb_state *mrb);
mrb_value ossl_pkey_new(mrb_state *mrb, EVP_PKEY *pkey);
mrb_value ossl_pkey_alloc(mrb_state *mrb, mrb_value klass);
EVP_PKEY *GetPKeyPtr(mrb_state *mrb, mrb_value obj);
EVP_PKEY *GetPrivPKeyPtr(mrb_state *mrb, VALUE obj);

#define NewPKey(klass)                                                                         \
  mrb_obj_value(Data_Wrap_Struct(mrb, klass, &ossl_evp_pkey_type, 0))

#define OSSL_PKEY_SET_PUBLIC(obj)                                                             \
  mrb_iv_set(mrb, (obj), mrb_intern_lit(mrb, "private"), mrb_false_value())

#define SetPKey(obj, pkey)                                                                    \
  do {                                                                                             \
    if (!(pkey)) {                                                                                 \
      mrb_raise((mrb), E_RUNTIME_ERROR, "PKEY wasn't initialized!");                               \
    }                                                                                              \
    mrb_iv_set((mrb), (obj), mrb_intern_lit(mrb, "pkey"),                                          \
               mrb_obj_value(                                                                      \
                   Data_Wrap_Struct(mrb, mrb->object_class, &ossl_evp_pkey_type, (void *)pkey)));  \
    OSSL_PKEY_SET_PUBLIC(obj);                                                                \
  } while (0)

#define GetPKey(obj, pkey)                                                                    \
  do {                                                                                             \
    mrb_value value_pkey = mrb_iv_get(mrb, obj, mrb_intern_lit(mrb, "pkey"));                      \
    pkey = DATA_PTR(value_pkey);                                                                   \
  } while (0)

#define SafeGetPKey(obj, pkey)                                                                \
  do {                                                                                             \
    OSSL_Check_Kind(mrb, (obj), cPKey);                                                          \
    GetPKey((obj), (pkey));                                                                \
  } while (0)
#endif /* _OSSL_PKEY_H_ */
