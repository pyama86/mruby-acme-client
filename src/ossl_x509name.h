
extern struct RClass *cX509Name;
extern struct RClass *eX509NameError;
#define GetX509Name(obj, name)                                                                \
  do {                                                                                             \
    name = DATA_PTR(obj);                                                                   \
  } while (0)

#define SetX509Name(obj, name)                                                                \
  do {                                                                                             \
    if (!(name)) {                                                                                 \
      mrb_raise((mrb), E_RUNTIME_ERROR, "Name wasn't initialized!");                               \
    }                                                                                              \
    DATA_PTR(obj) = name; \
    DATA_TYPE(obj) = &ossl_x509name_type; \
  } while (0)
#define SafeGetX509Name(obj, name)                                                            \
  do {                                                                                             \
    OSSL_Check_Kind((mrb), (obj), cX509Name);                                                      \
    GetX509Name((obj), (name));                                                             \
  } while (0)
#define OBJECT_TYPE_TEMPLATE(mrb, klass)                                                           \
  mrb_const_get(mrb, klass, mrb_intern_lit(mrb, "OBJECT_TYPE_TEMPLATE"))
#define DEFAULT_OBJECT_TYPE(mrb, klass)                                                            \
  mrb_const_get(mrb, klass, mrb_intern_lit(mrb, "DEFAULT_OBJECT_TYPE"))

#define mrb_aref(mrb, obj, key) mrb_funcall((mrb), (obj), "[]", 1, (key))
void Init_ossl_x509name(mrb_state *mrb);
