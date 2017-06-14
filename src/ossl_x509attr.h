
//LICENSE: https://github.com/ruby/openssl/blob/master/LICENSE.txt
#define SetX509Attr(obj, attr) do { \
    if (!(attr)) { \
      mrb_raise((mrb), E_RUNTIME_ERROR, "ATTR wasn't initialized!");                               \
    } \
    DATA_PTR(obj) = attr; \
    DATA_TYPE(obj) = &ossl_x509attr_type; \
} while (0)
#define GetX509Attr(obj, attr) do { \
    attr = DATA_PTR(obj);                                                                   \
    if (!(attr)) { \
      mrb_raise((mrb), E_RUNTIME_ERROR, "ATTR wasn't initialized!");                               \
    } \
} while (0)
#define SafeGetX509Attr(obj, attr) do { \
    OSSL_Check_Kind((mrb), (obj), cX509Attr); \
    GetX509Attr((mrb), (obj), (attr)); \
} while (0)
void Init_ossl_x509attr(mrb_state *mrb);
X509_ATTRIBUTE *DupX509AttrPtr(mrb_state *mrb, VALUE obj);
