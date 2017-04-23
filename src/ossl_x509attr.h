#define SetX509Attr(mrb, obj, attr) do { \
    if (!(attr)) { \
      mrb_raise((mrb), E_RUNTIME_ERROR, "ATTR wasn't initialized!");                               \
    } \
    mrb_iv_set((mrb), (obj), mrb_intern_lit(mrb, "x509attr"),                                          \
               mrb_obj_value(                                                                      \
                   Data_Wrap_Struct(mrb, mrb->object_class, &ossl_x509attr_type, (void *)attr)));  \
} while (0)
#define GetX509Attr(mrb, obj, attr) do { \
    mrb_value value_attr = mrb_iv_get(mrb, obj, mrb_intern_lit(mrb, "x509attr"));                      \
    attr = DATA_PTR(value_attr);                                                                   \
    if (!(attr)) { \
      mrb_raise((mrb), E_RUNTIME_ERROR, "ATTR wasn't initialized!");                               \
    } \
} while (0)
#define SafeGetX509Attr(mrb, obj, attr) do { \
    OSSL_Check_Kind((mrb), (obj), cX509Attr); \
    GetX509Attr((mrb), (obj), (attr)); \
} while (0)
X509_ATTRIBUTE *DupX509AttrPtr(mrb_state *mrb, VALUE obj);
