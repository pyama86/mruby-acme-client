#if !defined(_OSSL_BN_H_)
#define _OSSL_BN_H_
#define NewBN(klass) mrb_obj_value(Data_Wrap_Struct(mrb, klass, &ossl_bn_type, 0))

#define SetBN(obj, bn)                                                                             \
  do {                                                                                             \
    if (!(bn)) {                                                                                   \
      mrb_raise((mrb), E_RUNTIME_ERROR, "BN wasn't initialized!");                                 \
    }                                                                                              \
    DATA_PTR(obj) = bn;                                                                            \
    DATA_TYPE(obj) = &ossl_bn_type;                                                                \
  } while (0)

#define GetBN(obj, bn)                                                                             \
  do {                                                                                             \
    bn = DATA_PTR(obj);                                                                             \
  } while (0)

void Init_ossl_bn(mrb_state *mrb);
mrb_value ossl_bn_new(mrb_state *mrb, const BIGNUM *);
BIGNUM *GetBNPtr(mrb_state *mrb, VALUE);

#endif /* _OSS_BN_H_ */
