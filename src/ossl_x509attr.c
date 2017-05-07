#include "ossl.h"
struct RClass *cX509Attr;
struct RClass *eX509AttrError;

static void ossl_x509attr_free(mrb_state *mrb, void *ptr)
{
  X509_ATTRIBUTE_free(ptr);
}

static const mrb_data_type ossl_x509attr_type = {"OpenSSL/X509/ATTRIBUTE", ossl_x509attr_free};

static VALUE ossl_x509attr_initialize(mrb_state *mrb, VALUE self)
{
  VALUE oid, value;
  X509_ATTRIBUTE *attr, *x;
  const unsigned char *p;

  if (!(attr = X509_ATTRIBUTE_new()))
    mrb_raise(mrb, eX509AttrError, NULL);

  SetX509Attr(self, attr);
  if (mrb_get_args(mrb, "S|o", &oid, &value) == 1) {
    oid = ossl_to_der_if_possible(mrb, oid);
    p = (unsigned char *)RSTRING_PTR(oid);
    x = d2i_X509_ATTRIBUTE(&attr, &p, RSTRING_LEN(oid));
    SetX509Attr(self, attr);
    if (!x) {
      mrb_raise(mrb, eX509AttrError, NULL);
    }
    return self;
  }
  mrb_funcall(mrb, self, "oid=", 1, oid);
  mrb_funcall(mrb, self, "value=", 1, value);

  return self;
}
#if defined(HAVE_ST_X509_ATTRIBUTE_SINGLE) || defined(HAVE_ST_SINGLE)
#define OSSL_X509ATTR_IS_SINGLE(attr) ((attr)->single)
#define OSSL_X509ATTR_SET_SINGLE(attr) ((attr)->single = 1)
#else
#define OSSL_X509ATTR_IS_SINGLE(attr) (!(attr)->value.set)
#define OSSL_X509ATTR_SET_SINGLE(attr) ((attr)->value.set = 0)
#endif
static VALUE ossl_x509attr_set_value(mrb_state *mrb, VALUE self)
{
  X509_ATTRIBUTE *attr;
  VALUE asn1_value;
  VALUE value;
  int i, asn1_tag;

  mrb_get_args(mrb, "o", &value);
  OSSL_Check_Kind(mrb, value, cASN1Data);
  asn1_tag = mrb_fixnum(mrb_attr_get(mrb, value, mrb_intern_lit(mrb, "@tag")));
  asn1_value = mrb_attr_get(mrb, value, mrb_intern_lit(mrb, "@value"));

  if (asn1_tag != V_ASN1_SET)
    mrb_raise(mrb, eASN1Error, "argument must be ASN1::Set");
  if (!mrb_type(asn1_value) == MRB_TT_ARRAY)
    mrb_raise(mrb, eASN1Error, "ASN1::Set has non-array value");

  GetX509Attr(self, attr);
  if (X509_ATTRIBUTE_count(attr)) { /* populated, reset first */
    ASN1_OBJECT *obj = X509_ATTRIBUTE_get0_object(attr);
    X509_ATTRIBUTE *new_attr = X509_ATTRIBUTE_create_by_OBJ(NULL, obj, 0, NULL, -1);
    if (!new_attr)
      mrb_raise(mrb, eX509AttrError, NULL);
    SetX509Attr(self, new_attr);
    X509_ATTRIBUTE_free(attr);
    attr = new_attr;
  }

  for (i = 0; i < RARRAY_LEN(asn1_value); i++) {
    ASN1_TYPE *a1type = ossl_asn1_get_asn1type(mrb, mrb_ary_entry(asn1_value, i));
    if (!X509_ATTRIBUTE_set1_data(attr, ASN1_TYPE_get(a1type), a1type->value.ptr, -1)) {
      ASN1_TYPE_free(a1type);
      mrb_raise(mrb, eX509AttrError, NULL);
    }
    ASN1_TYPE_free(a1type);
  }

  return value;
}

static VALUE ossl_x509attr_set_oid(mrb_state *mrb, VALUE self)
{
  X509_ATTRIBUTE *attr;
  ASN1_OBJECT *obj;
  char *s;
  VALUE oid;
  GetX509Attr(self, attr);

  mrb_get_args(mrb, "S", &oid);
  s = mrb_str_to_cstr(mrb, oid);
  obj = OBJ_txt2obj(s, 0);
  if (!obj)
    obj = OBJ_txt2obj(s, 1);
  if (!obj)
    mrb_raise(mrb, eX509AttrError, NULL);

  if (!X509_ATTRIBUTE_set1_object(attr, obj)) {
    ASN1_OBJECT_free(obj);
    mrb_raise(mrb, eX509AttrError, "X509_ATTRIBUTE_set1_object");
  }
  ASN1_OBJECT_free(obj);
  return oid;
}

static VALUE ossl_x509attr_get_oid(mrb_state *mrb, VALUE self)
{
  X509_ATTRIBUTE *attr;
  ASN1_OBJECT *oid;
  BIO *out;
  VALUE ret;
  int nid;

  GetX509Attr(self, attr);
  oid = X509_ATTRIBUTE_get0_object(attr);
  if ((nid = OBJ_obj2nid(oid)) != NID_undef)
    ret = mrb_str_new_cstr(mrb, OBJ_nid2sn(nid));
}

void Init_ossl_x509attr(mrb_state *mrb)
{
  eX509AttrError = mrb_define_class_under(mrb, mX509, "AttributeError", eOSSLError);

  cX509Attr = mrb_define_class_under(mrb, mX509, "Attribute", mrb->object_class);
  mrb_define_method(mrb, cX509Attr, "initialize", ossl_x509attr_initialize, MRB_ARGS_ARG(1, 1));
  mrb_define_method(mrb, cX509Attr, "oid=", ossl_x509attr_set_oid, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, cX509Attr, "oid", ossl_x509attr_get_oid, MRB_ARGS_NONE());
  mrb_define_method(mrb, cX509Attr, "value=", ossl_x509attr_set_value, MRB_ARGS_REQ(1));
}
