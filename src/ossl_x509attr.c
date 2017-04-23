#include "ossl.h"
struct RClass *cX509Attr;
struct RClass *eX509AttrError;

static void ossl_x509attr_free(mrb_state *mrb, void *ptr)
{
  X509_ATTRIBUTE_free(ptr);
}

static const mrb_data_type ossl_x509attr_type = {"OpenSSL/X509/ATTRIBUTE", ossl_x509attr_free};

X509_ATTRIBUTE *DupX509AttrPtr(mrb_state *mrb, VALUE obj)
{
  X509_ATTRIBUTE *attr, *new;

  SafeGetX509Attr(mrb, obj, attr);
  if (!(new = X509_ATTRIBUTE_dup(attr))) {
    mrb_raise(mrb, eX509AttrError, NULL);
  }

  return new;
}

static VALUE ossl_x509attr_initialize(mrb_state *mrb, VALUE self)
{
  VALUE oid, value;
  X509_ATTRIBUTE *attr, *x;
  const unsigned char *p;

  GetX509Attr(mrb, self, attr);
  if (mrb_get_args(mrb, "S|o", &oid, &value) == 1) {
    oid = ossl_to_der_if_possible(mrb, oid);
    p = (unsigned char *)RSTRING_PTR(oid);
    x = d2i_X509_ATTRIBUTE(&attr, &p, RSTRING_LEN(oid));
    SetX509Attr(mrb, self, attr);
    if (!x) {
      mrb_raise(mrb, eX509AttrError, NULL);
    }
    return self;
  }
  mrb_funcall(mrb, self, mrb_intern_lit(mrb, "oid="), 1, oid);
  mrb_funcall(mrb, self, mrb_intern_lit(mrb, "value="), 1, value);

  return self;
}
#if defined(HAVE_ST_X509_ATTRIBUTE_SINGLE) || defined(HAVE_ST_SINGLE)
#  define OSSL_X509ATTR_IS_SINGLE(attr)  ((attr)->single)
#  define OSSL_X509ATTR_SET_SINGLE(attr) ((attr)->single = 1)
#else
#  define OSSL_X509ATTR_IS_SINGLE(attr)  (!(attr)->value.set)
#  define OSSL_X509ATTR_SET_SINGLE(attr) ((attr)->value.set = 0)
#endif
static VALUE ossl_x509attr_set_value(mrb_state *mrb, VALUE self)
{
  VALUE value;
  X509_ATTRIBUTE *attr;
  ASN1_TYPE *a1type;

  mrb_get_args(mrb, "o", &value);
  if (!(a1type = ossl_asn1_get_asn1type(mrb, value)))
    mrb_raise(mrb, eASN1Error, "could not get ASN1_TYPE");
  if (ASN1_TYPE_get(a1type) == V_ASN1_SEQUENCE) {
    ASN1_TYPE_free(a1type);
    mrb_raise(mrb, eASN1Error, "couldn't set SEQUENCE for attribute value.");
  }
  GetX509Attr(mrb, self, attr);
  if (attr->value.set) {
    if (OSSL_X509ATTR_IS_SINGLE(attr))
      ASN1_TYPE_free(attr->value.single);
    else
      sk_ASN1_TYPE_free(attr->value.set);
  }
  OSSL_X509ATTR_SET_SINGLE(attr);
  attr->value.single = a1type;

  return value;
}
static VALUE
ossl_x509attr_set_oid(mrb_state *mrb, VALUE self)
{
    X509_ATTRIBUTE *attr;
    ASN1_OBJECT *obj;
    char *s;
    VALUE oid;

    mrb_get_args(mrb, "S", &oid);
    s = mrb_str_to_cstr(mrb, oid);
    obj = OBJ_txt2obj(s, 0);
    if(!obj) obj = OBJ_txt2obj(s, 1);
    if(!obj) mrb_raise(mrb, eX509AttrError, NULL);
    GetX509Attr(mrb, self, attr);
    X509_ATTRIBUTE_set1_object(attr, obj);

    return oid;
}

void mrb_init_ossl_x509_attr(mrb_state *mrb)
{
  eX509AttrError = mrb_define_class_under(mrb, mX509, "AttributeError", eOSSLError);

  cX509Attr = mrb_define_class_under(mrb, mX509, "Attribute", mrb->object_class);
  mrb_define_method(mrb, cX509Attr, "initialize", ossl_x509attr_initialize, MRB_ARGS_ARG(1, 1));
  mrb_define_method(mrb, cX509Attr, "oid=", ossl_x509attr_set_oid, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, cX509Attr, "value=", ossl_x509attr_set_value, MRB_ARGS_REQ(1));
}
