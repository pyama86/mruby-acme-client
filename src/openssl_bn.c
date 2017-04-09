#include "openssl.h"

static void ossl_bn_free(mrb_state *mrb, void *ptr)
{
  BN_clear_free(ptr);
}

static const mrb_data_type ossl_bn_type = {"OpenSSL/BN", ossl_bn_free};

mrb_value ossl_bn_new(mrb_state *mrb, const BIGNUM *bn)
{
  struct RClass *openssl, *openssl_bn;
  mrb_value openssl_bn_instance;
  BIGNUM *newbn;

  newbn = bn ? BN_dup(bn) : BN_new();

  if (!newbn) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "BN new Error!");
  }

  openssl = mrb_module_get(mrb, "OpenSSL");
  openssl_bn = mrb_class_get_under(mrb, openssl, "BN");
  openssl_bn_instance = mrb_obj_new(mrb, openssl_bn, 0, NULL);

  mrb_iv_set(mrb, openssl_bn_instance, mrb_intern_lit(mrb, "bn"),
             mrb_obj_value(Data_Wrap_Struct(mrb, mrb->object_class, &ossl_bn_type, (void *)newbn)));
  return openssl_bn_instance;
}

static mrb_value mrb_openssl_bn_to_s(mrb_state *mrb, mrb_value self)
{
  int base = 10, len;
  BIGNUM *bn;
  mrb_value str, value_bn;

  mrb_get_args(mrb, "i", &base);

  value_bn = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "bn"));
  bn = DATA_PTR(value_bn);

  switch (base) {
  case 2:
    len = BN_num_bytes(bn);
    str = mrb_str_new(mrb, 0, len);
    if (BN_bn2bin(bn, (unsigned char *)RSTRING_PTR(str)) != len)
      mrb_raise(mrb, E_RUNTIME_ERROR, "BN bn2bin Error!");
    break;
  default:
    mrb_raisef(mrb, E_RUNTIME_ERROR, "invalid radix %d", base);
  }

  return str;
}

void mrb_init_openssl_bn(mrb_state *mrb)
{
  struct RClass *openssl, *openssl_bn;

  openssl = mrb_define_module(mrb, "OpenSSL");
  openssl_bn = mrb_define_class_under(mrb, openssl, "BN", mrb->object_class);
  mrb_define_method(mrb, openssl_bn, "to_s", mrb_openssl_bn_to_s, MRB_ARGS_REQ(1));
}
