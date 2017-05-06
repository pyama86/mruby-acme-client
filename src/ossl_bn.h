#if !defined(_OSSL_BN_H_)
#define _OSSL_BN_H_
#define NewBN(mrb, klass) mrb_obj_value(Data_Wrap_Struct(mrb, klass, &ossl_bn_type, 0))

#define SetBN(mrb, obj, bn)                                                                        \
  do {                                                                                             \
    if (!(bn)) {                                                                                   \
      mrb_raise((mrb), E_RUNTIME_ERROR, "BN wasn't initialized!");                                 \
    }                                                                                              \
    mrb_iv_set(                                                                                    \
        (mrb), (obj), mrb_intern_lit(mrb, "bn"),                                                   \
        mrb_obj_value(Data_Wrap_Struct(mrb, mrb->object_class, &ossl_bn_type, (void *)bn)));       \
  } while (0)

#define GetBN(mrb, obj, bn)                                                                        \
  do {                                                                                             \
    mrb_value value_bn;                                                                            \
    value_bn = mrb_iv_get((mrb), (obj), mrb_intern_lit(mrb, "bn"));                                \
    bn = DATA_PTR(value_bn);                                                                       \
  } while (0)


void Init_ossl_bn(mrb_state *mrb);
mrb_value ossl_bn_new(mrb_state *mrb, const BIGNUM *);
BIGNUM *GetBNPtr(mrb_state *mrb, VALUE);

#endif /* _OSS_BN_H_ */
