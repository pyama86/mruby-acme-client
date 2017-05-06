#include "ossl.h"

struct RClass *cBN;
struct RClass *eBNError;
static void ossl_bn_free(mrb_state *mrb, void *ptr)
{
  BN_clear_free(ptr);
}
static const mrb_data_type ossl_bn_type = {"OpenSSL/BN", ossl_bn_free};

BIGNUM *GetBNPtr(mrb_state *mrb, VALUE obj)
{
  BIGNUM *bn = NULL;
  VALUE newobj;

  if (mrb_obj_is_kind_of(mrb, obj, cBN)) {
    GetBN(obj, bn);
  } else
    switch (mrb_type(obj)) {
    case MRB_TT_FIXNUM:
      newobj = NewBN(cBN); /* GC bug */
      if (!BN_dec2bn(&bn, RSTRING_PTR(obj))) {
        mrb_raise(mrb, eBNError, NULL);
      }
      SetBN(newobj, bn); /* Handle potencial mem leaks */
      break;
    default:
      mrb_raise(mrb, E_TYPE_ERROR, "Cannot convert into OpenSSL::BN");
    }
  return bn;
}


mrb_value ossl_bn_new(mrb_state *mrb, const BIGNUM *bn)
{
  BIGNUM *newbn;
  VALUE obj;

  obj = NewBN(cBN);
  newbn = bn ? BN_dup(bn) : BN_new();
  if (!newbn) {
    mrb_raise(mrb, eBNError, NULL);
  }
  SetBN(obj, newbn);

  return obj;
}

static mrb_value mrb_ossl_bn_to_s(mrb_state *mrb, mrb_value self)
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
static VALUE ossl_bn_initialize(mrb_state *mrb, VALUE self)
{
  BIGNUM *bn;
  VALUE str, bs;
  int base = 10;

  if (!(bn = BN_new())) {
    mrb_raise(mrb, eBNError, NULL);
  }
  SetBN(self, bn);

  if (mrb_get_args(mrb, "S|i", &str, &bs) == 2) {
    base = NUM2INT(bs);
  }

  if (mrb_type(str) == MRB_TT_FIXNUM) {
    long i;
    unsigned char bin[sizeof(long)];
    long n = FIX2LONG(str);
    unsigned long un = labs(n);

    for (i = sizeof(long) - 1; 0 <= i; i--) {
      bin[i] = un & 0xff;
      un >>= 8;
    }

    if (!BN_bin2bn(bin, sizeof(bin), bn)) {
      mrb_raise(mrb, eBNError, NULL);
    }
    if (n < 0)
      BN_set_negative(bn, 1);
    return self;
  } else {
    mrb_raise(mrb, eBNError, "undefined method");
  }
  if (mrb_obj_is_kind_of(mrb, str, cBN)) {
    BIGNUM *other;

    GetBN(self, bn);
    GetBN(str, other); /* Safe - we checked kind_of? above */
    if (!BN_copy(bn, other)) {
      mrb_raise(mrb, eBNError, NULL);
    }
    return self;
  }

  GetBN(self, bn);
  switch (base) {
  case 0:
    if (!BN_mpi2bn((unsigned char *)RSTRING_PTR(str), RSTRING_LEN(str), bn)) {
      mrb_raise(mrb, eBNError, NULL);
    }
    break;
  case 2:
    if (!BN_bin2bn((unsigned char *)RSTRING_PTR(str), RSTRING_LEN(str), bn)) {
      mrb_raise(mrb, eBNError, NULL);
    }
    break;
  case 10:
    if (!BN_dec2bn(&bn, RSTRING_PTR(str))) {
      mrb_raise(mrb, eBNError, NULL);
    }
    break;
  case 16:
    if (!BN_hex2bn(&bn, RSTRING_PTR(str))) {
      mrb_raise(mrb, eBNError, NULL);
    }
    break;
  default:
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "invalid radix %d", base);
  }
  return self;
}

void Init_ossl_bn(mrb_state *mrb)
{
  eBNError = mrb_define_class_under(mrb, mOSSL, "BNError", eOSSLError);

  cBN = mrb_define_class_under(mrb, mOSSL, "BN", mrb->object_class);
  mrb_define_method(mrb, cBN, "initialize", ossl_bn_initialize, MRB_ARGS_ARG(1, 1));

  mrb_define_method(mrb, cBN, "to_s", mrb_ossl_bn_to_s, MRB_ARGS_REQ(1));
}
