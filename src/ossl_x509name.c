
//LICENSE: https://github.com/ruby/openssl/blob/master/LICENSE.txt
#include "ossl.h"

extern struct RClass *mX509;
struct RClass *cX509Name;
struct RClass *eX509NameError;

static void ossl_x509name_free(mrb_state *mrb, void *ptr)
{
  X509_NAME_free(ptr);
}

static const mrb_data_type ossl_x509name_type = {"OpenSSL/X509/NAME", ossl_x509name_free};

static mrb_value ossl_x509name_add_entry(mrb_state *mrb, mrb_value self)
{
  X509_NAME *name;
  const char *oid_name;
  mrb_value oid, value, type;

  mrb_get_args(mrb, "SS|o", &oid, &value, &type);

  oid_name = mrb_str_to_cstr(mrb, oid);
  if (mrb_nil_p(type))
    type = mrb_aref(mrb, OBJECT_TYPE_TEMPLATE(mrb, self), oid);
  GetX509Name(self, name);
  if (!X509_NAME_add_entry_by_txt(name, oid_name, mrb_fixnum(type),
                                  (const unsigned char *)RSTRING_PTR(value), RSTRING_LEN(value), -1,
                                  0)) {
    mrb_raise(mrb, eX509NameError, NULL);
  }
  return self;
}

static mrb_value ossl_x509name_init_i(mrb_state *mrb, mrb_value args, mrb_value cur)
{
  mrb_value self = mrb_ary_entry(args, 0);
  mrb_value template = mrb_ary_entry(args, 1);
  mrb_value entry[3];

  entry[0] = mrb_ary_entry(cur, 0);
  entry[1] = mrb_ary_entry(cur, 1);
  entry[2] = mrb_ary_entry(cur, 2);
  if (mrb_nil_p(entry[2]))
    entry[2] = mrb_aref(mrb, template, entry[0]);
  if (mrb_nil_p(entry[2]))
    entry[2] = DEFAULT_OBJECT_TYPE(mrb, self);

  mrb_funcall(mrb, self, "add_entry", 3, entry[0], entry[1], entry[2]);
  return mrb_false_value();
}

static mrb_value ossl_x509name_initialize(mrb_state *mrb, mrb_value self)
{
  X509_NAME *name;
  mrb_value arg, template;
  int argc;

  if (!(name = X509_NAME_new())) {
    mrb_raise(mrb, eX509NameError, NULL);
  }
  SetX509Name(self, name);

  argc = mrb_get_args(mrb, "|oo", &arg, &template);
  if (argc == 0) {
    return self;
  } else {
    mrb_value tmp = mrb_check_array_type(mrb, arg);
    if (!mrb_nil_p(tmp)) {
      mrb_value args;
      if (mrb_nil_p(template))
        template = OBJECT_TYPE_TEMPLATE(mrb, self);
      args = mrb_ary_new(mrb);
      mrb_ary_push(mrb, args, self);
      mrb_ary_push(mrb, args, template);

      int len = RARRAY_LEN(tmp);
      for (int i = 0; i < len; ++i) {
        ossl_x509name_init_i(mrb, args, mrb_ary_entry(tmp, i));
      }
    } else {
      const unsigned char *p;
      mrb_value str = ossl_to_der_if_possible(mrb, arg);
      X509_NAME *x;
      p = (unsigned char *)RSTRING_PTR(str);
      x = d2i_X509_NAME(&name, &p, RSTRING_LEN(str));
      DATA_PTR(self) = name;
      if (!x) {
        mrb_raise(mrb, eX509NameError, NULL);
      }
    }
  }

  return self;
}

void Init_ossl_x509name(mrb_state *mrb)
{
  eX509NameError = mrb_define_class_under(mrb, mX509, "NameError", eOSSLError);
  cX509Name = mrb_define_class_under(mrb, mX509, "Name", mrb->object_class);
  MRB_SET_INSTANCE_TT(cX509Name, MRB_TT_DATA);
  mrb_define_method(mrb, cX509Name, "initialize", ossl_x509name_initialize, MRB_ARGS_OPT(2));
  mrb_define_method(mrb, cX509Name, "add_entry", ossl_x509name_add_entry, MRB_ARGS_ARG(2, 1));
}
