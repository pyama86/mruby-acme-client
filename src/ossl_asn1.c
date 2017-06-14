#include "ossl.h"
// LICENCE: https://github.com/ruby/openssl/blob/master/LICENSE.txt

struct RClass *mASN1;
struct RClass *eASN1Error;
struct RClass *cASN1Data;
struct RClass *cASN1Primitive;
struct RClass *cASN1Constructive;

struct RClass *cASN1EndOfContent;
struct RClass *cASN1Boolean;                       /* BOOLEAN           */
struct RClass *cASN1Integer, *cASN1Enumerated;     /* INTEGER           */
struct RClass *cASN1BitString;                     /* BIT STRING        */
struct RClass *cASN1OctetString, *cASN1UTF8String; /* STRINGs           */
struct RClass *cASN1NumericString, *cASN1PrintableString;
struct RClass *cASN1T61String, *cASN1VideotexString;
struct RClass *cASN1IA5String, *cASN1GraphicString;
struct RClass *cASN1ISO64String, *cASN1GeneralString;
struct RClass *cASN1UniversalString, *cASN1BMPString;
struct RClass *cASN1Null;                           /* NULL              */
struct RClass *cASN1ObjectId;                       /* OBJECT IDENTIFIER */
struct RClass *cASN1UTCTime, *cASN1GeneralizedTime; /* TIME              */
struct RClass *cASN1Sequence, *cASN1Set;            /* CONSTRUCTIVE      */

static ID sIMPLICIT, sEXPLICIT;
static ID sUNIVERSAL, sAPPLICATION, sCONTEXT_SPECIFIC, sPRIVATE;
static ID sivVALUE, sivTAG, sivTAG_CLASS, sivTAGGING, sivINFINITE_LENGTH, sivUNUSED_BITS;
#define ossl_asn1_get_value(o) mrb_attr_get(mrb, (o), sivVALUE)
#define ossl_asn1_get_tag(o) mrb_attr_get(mrb, (o), sivTAG)
#define ossl_asn1_get_tagging(o) mrb_attr_get(mrb, (o), sivTAGGING)
#define ossl_asn1_get_tag_class(o) mrb_attr_get(mrb, (o), sivTAG_CLASS)
#define ossl_asn1_get_infinite_length(o) mrb_attr_get(mrb, (o), sivINFINITE_LENGTH)

#define ossl_asn1_set_value(o, v) mrb_iv_set(mrb, (o), sivVALUE, (v))
#define ossl_asn1_set_tag(o, v) mrb_iv_set(mrb, (o), sivTAG, (v))
#define ossl_asn1_set_tagging(o, v) mrb_iv_set(mrb, (o), sivTAGGING, (v))
#define ossl_asn1_set_tag_class(o, v) mrb_iv_set(mrb, (o), sivTAG_CLASS, (v))
#define ossl_asn1_set_infinite_length(o, v) mrb_iv_set(mrb, (o), sivINFINITE_LENGTH, (v))

#if OPENSSL_VERSION_NUMBER < 0x00908000L
#define ossl_asn1_object_size(cons, len, tag)                                                      \
  (cons) == 2 ? (len) + ASN1_object_size((cons), 0, (tag)) : ASN1_object_size((cons), (len), (tag))
#define ossl_asn1_put_object(pp, cons, len, tag, xc)                                               \
  (cons) == 2 ? ASN1_put_object((pp), (cons), 0, (tag), (xc))                                      \
              : ASN1_put_object((pp), (cons), (len), (tag), (xc))
#else
#define ossl_asn1_object_size(cons, len, tag) ASN1_object_size((cons), (len), (tag))
#define ossl_asn1_put_object(pp, cons, len, tag, xc)                                               \
  ASN1_put_object((pp), (cons), (len), (tag), (xc))
#endif

typedef struct {
  const char *name;
  struct RClass *klass;
} ossl_asn1_info_t;
static const ossl_asn1_info_t ossl_asn1_info[] = {
    {
        "EOC", &cASN1EndOfContent,
    }, /*  0 */
    {
        "BOOLEAN", &cASN1Boolean,
    }, /*  1 */
    {
        "INTEGER", &cASN1Integer,
    }, /*  2 */
    {
        "BIT_STRING", &cASN1BitString,
    }, /*  3 */
    {
        "OCTET_STRING", &cASN1OctetString,
    }, /*  4 */
    {
        "NULL", &cASN1Null,
    }, /*  5 */
    {
        "OBJECT", &cASN1ObjectId,
    }, /*  6 */
    {
        "OBJECT_DESCRIPTOR", NULL,
    }, /*  7 */
    {
        "EXTERNAL", NULL,
    }, /*  8 */
    {
        "REAL", NULL,
    }, /*  9 */
    {
        "ENUMERATED", &cASN1Enumerated,
    }, /* 10 */
    {
        "EMBEDDED_PDV", NULL,
    }, /* 11 */
    {
        "UTF8STRING", &cASN1UTF8String,
    }, /* 12 */
    {
        "RELATIVE_OID", NULL,
    }, /* 13 */
    {
        "[UNIVERSAL 14]", NULL,
    }, /* 14 */
    {
        "[UNIVERSAL 15]", NULL,
    }, /* 15 */
    {
        "SEQUENCE", &cASN1Sequence,
    }, /* 16 */
    {
        "SET", &cASN1Set,
    }, /* 17 */
    {
        "NUMERICSTRING", &cASN1NumericString,
    }, /* 18 */
    {
        "PRINTABLESTRING", &cASN1PrintableString,
    }, /* 19 */
    {
        "T61STRING", &cASN1T61String,
    }, /* 20 */
    {
        "VIDEOTEXSTRING", &cASN1VideotexString,
    }, /* 21 */
    {
        "IA5STRING", &cASN1IA5String,
    }, /* 22 */
    {
        "UTCTIME", &cASN1UTCTime,
    }, /* 23 */
    {
        "GENERALIZEDTIME", &cASN1GeneralizedTime,
    }, /* 24 */
    {
        "GRAPHICSTRING", &cASN1GraphicString,
    }, /* 25 */
    {
        "ISO64STRING", &cASN1ISO64String,
    }, /* 26 */
    {
        "GENERALSTRING", &cASN1GeneralString,
    }, /* 27 */
    {
        "UNIVERSALSTRING", &cASN1UniversalString,
    }, /* 28 */
    {
        "CHARACTER_STRING", NULL,
    }, /* 29 */
    {
        "BMPSTRING", &cASN1BMPString,
    }, /* 30 */
};

mrb_value get_class_tag_map(mrb_state *mrb)
{
  mrb_value class_tag_map;
  class_tag_map = mrb_hash_new(mrb);

  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1EndOfContent), INT2NUM(V_ASN1_EOC));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1Boolean), INT2NUM(V_ASN1_BOOLEAN));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1Integer), INT2NUM(V_ASN1_INTEGER));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1BitString), INT2NUM(V_ASN1_BIT_STRING));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1OctetString), INT2NUM(V_ASN1_OCTET_STRING));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1Null), INT2NUM(V_ASN1_NULL));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1ObjectId), INT2NUM(V_ASN1_OBJECT));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1Enumerated), INT2NUM(V_ASN1_ENUMERATED));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1UTF8String), INT2NUM(V_ASN1_UTF8STRING));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1Sequence), INT2NUM(V_ASN1_SEQUENCE));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1Set), INT2NUM(V_ASN1_SET));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1NumericString),
               INT2NUM(V_ASN1_NUMERICSTRING));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1PrintableString),
               INT2NUM(V_ASN1_PRINTABLESTRING));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1T61String), INT2NUM(V_ASN1_T61STRING));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1VideotexString),
               INT2NUM(V_ASN1_VIDEOTEXSTRING));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1IA5String), INT2NUM(V_ASN1_IA5STRING));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1UTCTime), INT2NUM(V_ASN1_UTCTIME));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1GeneralizedTime),
               INT2NUM(V_ASN1_GENERALIZEDTIME));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1GraphicString),
               INT2NUM(V_ASN1_GRAPHICSTRING));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1ISO64String), INT2NUM(V_ASN1_ISO64STRING));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1GeneralString),
               INT2NUM(V_ASN1_GENERALSTRING));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1UniversalString),
               INT2NUM(V_ASN1_UNIVERSALSTRING));
  mrb_hash_set(mrb, class_tag_map, CLASS_NAME(mrb, cASN1BMPString), INT2NUM(V_ASN1_BMPSTRING));
  return class_tag_map;
}

static VALUE ossl_asn1data_initialize(mrb_state *mrb, VALUE self)
{
  VALUE value, tag, tag_class;
  if (!SYMBOL_P(tag_class))

    mrb_raise(mrb, eASN1Error, "invalid tag class");
  if ((mrb_intern_str(mrb, tag_class) == sUNIVERSAL) && NUM2INT(tag) > 31)
    mrb_raise(mrb, eASN1Error, "tag number for Universal too large");
  ossl_asn1_set_tag(self, tag);
  ossl_asn1_set_value(self, value);
  ossl_asn1_set_tag_class(self, tag_class);
  ossl_asn1_set_infinite_length(self, mrb_false_value());

  return self;
}

static int ossl_asn1_default_tag(mrb_state *mrb, VALUE obj)
{
  VALUE tag;
  struct RClass *tmp_class;
  mrb_value class_tag_map;

  class_tag_map = get_class_tag_map(mrb);
  tmp_class = mrb_class(mrb, obj);
  while (tmp_class) {
    tag = mrb_hash_get(mrb, class_tag_map, CLASS_NAME(mrb, tmp_class));
    if (!mrb_nil_p(tag)) {
      return NUM2INT(tag);
    }
    tmp_class = tmp_class->super;
  }
  mrb_raisef(mrb, eASN1Error, "universal tag for %s  not found", mrb_obj_class(mrb, obj));

  return -1; /* dummy */
}

static ASN1_BOOLEAN *obj_to_asn1bool(mrb_state *mrb, VALUE obj)
{
  if (mrb_nil_p(obj))
    mrb_raise(mrb, E_TYPE_ERROR, "Can't convert nil into Boolean");

#if OPENSSL_VERSION_NUMBER < 0x00907000L
  return RTEST(obj) ? 0xff : 0x100;
#else
  return RTEST(obj) ? 0xff : 0x0;
#endif
}
#if DO_IT_VIA_RUBY
ASN1_INTEGER *num_to_asn1integer(mrb_state *mrb, VALUE obj, ASN1_INTEGER *ai)
{
  BIGNUM *bn = NULL;

  if (RTEST(mrb_obj_is_kind_of(mrb, obj, cBN))) {
    bn = GetBNPtr(mrb, obj);
  } else {
    obj = rb_String(obj);
    if (!BN_dec2bn(&bn, StringValuePtr(obj))) {
      mrb_raise(mrb, eOSSLError, NULL);
    }
  }
  if (!(ai = BN_to_ASN1_INTEGER(bn, ai))) {
    BN_free(bn);
    mrb_raise(mrb, eOSSLError, NULL);
  }
  BN_free(bn);
  return ai;
}
#else
ASN1_INTEGER *num_to_asn1integer(mrb_state *mrb, VALUE obj, ASN1_INTEGER *ai)
{
  BIGNUM *bn;

  if (mrb_nil_p(obj))
    mrb_raise(mrb, E_TYPE_ERROR, "Can't convert nil into Integer");

  bn = GetBNPtr(mrb, obj);

  if (!(ai = BN_to_ASN1_INTEGER(bn, ai)))
    mrb_raise(mrb, eOSSLError, NULL);

  return ai;
}
#endif

static ASN1_INTEGER *obj_to_asn1int(mrb_state *mrb, VALUE obj)
{
  return num_to_asn1integer(mrb, obj, NULL);
}

static ASN1_BIT_STRING *obj_to_asn1bstr(mrb_state *mrb, VALUE obj, long unused_bits)
{
  ASN1_BIT_STRING *bstr;

  if (unused_bits < 0)
    unused_bits = 0;
  if (!(bstr = ASN1_BIT_STRING_new()))
    mrb_raise(mrb, eASN1Error, NULL);
  ASN1_BIT_STRING_set(bstr, (unsigned char *)RSTRING_PTR(obj), RSTRING_LEN(obj));
  bstr->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07); /* clear */
  bstr->flags |= ASN1_STRING_FLAG_BITS_LEFT | (unused_bits & 0x07);

  return bstr;
}

static ASN1_NULL *obj_to_asn1null(mrb_state *mrb, VALUE obj)
{
  ASN1_NULL *null;

  if (!mrb_nil_p(obj))
    mrb_raise(mrb, eASN1Error, "nil expected");
  if (!(null = ASN1_NULL_new()))
    mrb_raise(mrb, eASN1Error, NULL);

  return null;
}

static ASN1_STRING *obj_to_asn1str(mrb_state *mrb, VALUE obj)
{
  ASN1_STRING *str;

  if (!(str = ASN1_STRING_new()))
    mrb_raise(mrb, eASN1Error, NULL);
  ASN1_STRING_set(str, RSTRING_PTR(obj), RSTRING_LEN(obj));

  return str;
}

time_t time_to_time_t(VALUE time)
{
  return (time_t)mrb_fixnum(time);
}

static ASN1_UTCTIME *obj_to_asn1utime(mrb_state *mrb, VALUE time)
{
  time_t sec;
  ASN1_UTCTIME *t;

  sec = time_to_time_t(time);
  if (!(t = ASN1_UTCTIME_set(NULL, sec)))
    mrb_raise(mrb, eASN1Error, NULL);

  return t;
}
static ASN1_OBJECT *obj_to_asn1obj(mrb_state *mrb, VALUE obj)
{
  ASN1_OBJECT *a1obj;

  a1obj = OBJ_txt2obj(RSTRING_PTR(obj), 0);
  if (!a1obj)
    a1obj = OBJ_txt2obj(RSTRING_PTR(obj), 1);
  if (!a1obj)
    mrb_raise(mrb, eASN1Error, "invalid OBJECT ID");

  return a1obj;
}

static ASN1_GENERALIZEDTIME *obj_to_asn1gtime(mrb_state *mrb, VALUE time)
{
  time_t sec;
  ASN1_GENERALIZEDTIME *t;

  sec = time_to_time_t(time);
  if (!(t = ASN1_GENERALIZEDTIME_set(NULL, sec)))
    mrb_raise(mrb, eASN1Error, NULL);

  return t;
}

static ASN1_STRING *obj_to_asn1derstr(mrb_state *mrb, VALUE obj)
{
  ASN1_STRING *a1str;
  VALUE str;

  str = ossl_to_der(mrb, obj);
  if (!(a1str = ASN1_STRING_new()))
    mrb_raise(mrb, eASN1Error, NULL);

  ASN1_STRING_set(a1str, RSTRING_PTR(str), RSTRING_LEN(str));

  return a1str;
}

ASN1_TYPE *ossl_asn1_get_asn1type(mrb_state *mrb, VALUE obj)
{
  ASN1_TYPE *ret;
  VALUE value, rflag;
  void *ptr;
  void (*free_func)();
  int tag, flag;

  tag = ossl_asn1_default_tag(mrb, obj);
  value = ossl_asn1_get_value(obj);
  switch (tag) {
  case V_ASN1_BOOLEAN:
    // ptr = (void *)(VALUE)obj_to_asn1bool(mrb, value);
    ptr = obj_to_asn1bool(mrb, value);
    free_func = NULL;
    break;
  case V_ASN1_INTEGER: /* FALLTHROUGH */
  case V_ASN1_ENUMERATED:
    ptr = obj_to_asn1int(mrb, value);
    free_func = ASN1_INTEGER_free;
    break;
  case V_ASN1_BIT_STRING:
    rflag = mrb_attr_get(mrb, obj, sivUNUSED_BITS);
    flag = mrb_nil_p(rflag) ? -1 : NUM2INT(rflag);
    ptr = obj_to_asn1bstr(mrb, value, flag);
    free_func = ASN1_BIT_STRING_free;
    break;
  case V_ASN1_NULL:
    ptr = obj_to_asn1null(mrb, value);
    free_func = ASN1_NULL_free;
    break;
  case V_ASN1_OCTET_STRING:    /* FALLTHROUGH */
  case V_ASN1_UTF8STRING:      /* FALLTHROUGH */
  case V_ASN1_NUMERICSTRING:   /* FALLTHROUGH */
  case V_ASN1_PRINTABLESTRING: /* FALLTHROUGH */
  case V_ASN1_T61STRING:       /* FALLTHROUGH */
  case V_ASN1_VIDEOTEXSTRING:  /* FALLTHROUGH */
  case V_ASN1_IA5STRING:       /* FALLTHROUGH */
  case V_ASN1_GRAPHICSTRING:   /* FALLTHROUGH */
  case V_ASN1_ISO64STRING:     /* FALLTHROUGH */
  case V_ASN1_GENERALSTRING:   /* FALLTHROUGH */
  case V_ASN1_UNIVERSALSTRING: /* FALLTHROUGH */
  case V_ASN1_BMPSTRING:
    ptr = obj_to_asn1str(mrb, value);
    free_func = ASN1_STRING_free;
    break;
  case V_ASN1_OBJECT:
    ptr = obj_to_asn1obj(mrb, value);
    free_func = ASN1_OBJECT_free;
    break;
  case V_ASN1_UTCTIME:
    ptr = obj_to_asn1utime(mrb, value);
    free_func = ASN1_TIME_free;
    break;
  case V_ASN1_GENERALIZEDTIME:
    ptr = obj_to_asn1gtime(mrb, value);
    free_func = ASN1_TIME_free;
    break;
  case V_ASN1_SET: /* FALLTHROUGH */
  case V_ASN1_SEQUENCE:
    ptr = obj_to_asn1derstr(mrb, obj);
    free_func = ASN1_STRING_free;
    break;
  default:
    mrb_raise(mrb, eASN1Error, "unsupported ASN.1 type");
  }
  if (!(ret = OPENSSL_malloc(sizeof(ASN1_TYPE)))) {
    if (free_func)
      free_func(ptr);
    mrb_raise(mrb, eASN1Error, "ASN1_TYPE alloc failure");
  }
  memset(ret, 0, sizeof(ASN1_TYPE));
  ASN1_TYPE_set(ret, tag, ptr);

  return ret;
}

static int ossl_asn1_tag_class(mrb_state *mrb, VALUE obj)
{
  VALUE s;
  int ret = -1;

  s = ossl_asn1_get_tag_class(obj);
  if (NIL_P(s))
    ret = V_ASN1_UNIVERSAL;
  else if (mrb_string_p(s)) {
    if (mrb_intern_str(mrb, s) == sUNIVERSAL)
      ret = V_ASN1_UNIVERSAL;
    else if (mrb_intern_str(mrb, s) == sAPPLICATION)
      ret = V_ASN1_APPLICATION;
    else if (mrb_intern_str(mrb, s) == sCONTEXT_SPECIFIC)
      ret = V_ASN1_CONTEXT_SPECIFIC;
    else if (mrb_intern_str(mrb, s) == sPRIVATE)
      ret = V_ASN1_PRIVATE;
  }
  if (ret < 0) {
    mrb_raise(mrb, eASN1Error, "invalid tag class");
  }

  return ret;
}

static int ossl_asn1_is_explicit(mrb_state *mrb, VALUE obj)
{
  VALUE s;
  int ret = -1;

  s = ossl_asn1_get_tagging(obj);
  if (NIL_P(s))
    return 0;
  else if (SYMBOL_P(s)) {
    if (mrb_intern_str(mrb, s) == sIMPLICIT)
      ret = 0;
    else if (mrb_intern_str(mrb, s) == sEXPLICIT)
      ret = 1;
  }
  if (ret < 0) {
    mrb_raise(mrb, eASN1Error, "invalid tag default");
  }

  return ret;
}

static VALUE join_der_i(mrb_state *mrb, mrb_value str, mrb_value current)
{
  mrb_value i;
  i = ossl_to_der_if_possible(mrb, current);
  mrb_str_append(mrb, str, i);
  return mrb_nil_value();
}

static VALUE join_der(mrb_state *mrb, VALUE enumerable)
{
  VALUE str = mrb_str_new(mrb, 0, 0);
  int len = RARRAY_LEN(enumerable);
  for (int i = 0; i < len; ++i) {
    join_der_i(mrb, str, mrb_ary_entry(enumerable, i));
  }

  return str;
}

static VALUE ossl_asn1cons_to_der(mrb_state *mrb, VALUE self)
{
  int tag, tn, tc, explicit, constructed = 1;
  int found_prim = 0, seq_len;
  long length;
  unsigned char *p;
  VALUE value, str, inf_length;

  tn = mrb_fixnum(ossl_asn1_get_tag(self));
  tc = ossl_asn1_tag_class(mrb, self);
  inf_length = ossl_asn1_get_infinite_length(self);
  if (mrb_bool(inf_length)) {
    VALUE ary, example;
    constructed = 2;
    if (mrb_class(mrb, self) == cASN1Sequence || mrb_class(mrb, self) == cASN1Set) {
      tag = ossl_asn1_default_tag(mrb, self);
    } else { /* must be a constructive encoding of a primitive value */
      ary = ossl_asn1_get_value(self);
      if (!mrb_obj_is_kind_of(mrb, ary, mrb->array_class))
        mrb_raise(mrb, eASN1Error, "Constructive value must be an Array");
      while (!found_prim) {
        example = mrb_ary_entry(ary, 0);
        if (mrb_obj_is_kind_of(mrb, example, cASN1Primitive)) {
          found_prim = 1;
        } else {
          if (!mrb_obj_is_kind_of(mrb, example, cASN1Constructive)) {
            mrb_raise(mrb, eASN1Error, "invalid constructed encoding");
            return mrb_nil_value(); /* dummy */
          }
          ary = ossl_asn1_get_value(example);
        }
      }
      tag = ossl_asn1_default_tag(mrb, example);
    }
  } else {
    if (mrb_class(mrb, self) == cASN1Constructive)
      mrb_raise(mrb, eASN1Error, "Constructive shall only be used with infinite length");
    tag = ossl_asn1_default_tag(mrb, self);
  }
  explicit = ossl_asn1_is_explicit(mrb, self);
  value = join_der(mrb, ossl_asn1_get_value(self));

  seq_len = ossl_asn1_object_size(constructed, RSTRING_LEN(value), tag);
  length = ossl_asn1_object_size(constructed, seq_len, tn);
  str = mrb_str_new(mrb, 0, length);
  p = (unsigned char *)RSTRING_PTR(str);
  if (tc == V_ASN1_UNIVERSAL)
    ossl_asn1_put_object(&p, constructed, RSTRING_LEN(value), tn, tc);
  else {
    if (explicit) {
      ossl_asn1_put_object(&p, constructed, seq_len, tn, tc);
      ossl_asn1_put_object(&p, constructed, RSTRING_LEN(value), tag, V_ASN1_UNIVERSAL);
    } else {
      ossl_asn1_put_object(&p, constructed, RSTRING_LEN(value), tn, tc);
    }
  }
  memcpy(p, RSTRING_PTR(value), RSTRING_LEN(value));
  p += RSTRING_LEN(value);
  if (explicit && mrb_bool(inf_length)) {
    ASN1_put_eoc(&p);
  }
  ossl_str_adjust(mrb, str, p);
  return str;
}

static VALUE ossl_asn1_initialize(mrb_state *mrb, VALUE self)
{
  VALUE value, tag, tagging, tag_class;
  int argc;
  argc = mrb_get_args(mrb, "o|ooo", &value, &tag, &tagging, &tag_class);
  if (argc > 1) {
    if (NIL_P(tag))
      mrb_raise(mrb, eASN1Error, "must specify tag number");
    if (!NIL_P(tagging) && !SYMBOL_P(tagging))
      mrb_raise(mrb, eASN1Error, "invalid tagging method");
    if (NIL_P(tag_class)) {
      if (NIL_P(tagging))
        tag_class = mrb_sym2str(mrb, sUNIVERSAL);
      else
        tag_class = mrb_sym2str(mrb, sCONTEXT_SPECIFIC);
    }
    if (!SYMBOL_P(tag_class))
      mrb_raise(mrb, eASN1Error, "invalid tag class");
    if (!NIL_P(tagging) && mrb_intern_str(mrb, tagging) == sIMPLICIT && NUM2INT(tag) > 31)
      mrb_raise(mrb, eASN1Error, "tag number for Universal too large");
  } else {
    tag = mrb_fixnum_value(ossl_asn1_default_tag(mrb, self));
    tagging = mrb_nil_value();
    tag_class = mrb_sym2str(mrb, sUNIVERSAL);
  }
  ossl_asn1_set_tag(self, tag);
  ossl_asn1_set_value(self, value);
  ossl_asn1_set_tagging(self, tagging);
  ossl_asn1_set_tag_class(self, tag_class);
  ossl_asn1_set_infinite_length(self, mrb_false_value());

  return self;
}

static int ossl_i2d_ASN1_TYPE(ASN1_TYPE *a, unsigned char **pp)
{
#if OPENSSL_VERSION_NUMBER < 0x00907000L
  if (!a)
    return 0;
  if (a->type == V_ASN1_BOOLEAN)
    return i2d_ASN1_BOOLEAN(a->value.boolean, pp);
#endif
  return i2d_ASN1_TYPE(a, pp);
}
static void ossl_ASN1_TYPE_free(ASN1_TYPE *a)
{
#if OPENSSL_VERSION_NUMBER < 0x00907000L
  if (!a)
    return;
  if (a->type == V_ASN1_BOOLEAN) {
    OPENSSL_free(a);
    return;
  }
#endif
  ASN1_TYPE_free(a);
}
static VALUE ossl_asn1prim_to_der(mrb_state *mrb, VALUE self)
{
  ASN1_TYPE *asn1;
  int tn, tc, explicit;
  long len, reallen;
  unsigned char *buf, *p;
  VALUE str;

  tn = mrb_fixnum(ossl_asn1_get_tag(self));
  tc = ossl_asn1_tag_class(mrb, self);
  explicit = ossl_asn1_is_explicit(mrb, self);
  asn1 = ossl_asn1_get_asn1type(mrb, self);

  len = ossl_asn1_object_size(1, ossl_i2d_ASN1_TYPE(asn1, NULL), tn);
  if (!(buf = OPENSSL_malloc(len))) {
    ossl_ASN1_TYPE_free(asn1);
    mrb_raise(mrb, eASN1Error, "cannot alloc buffer");
  }
  p = buf;
  if (tc == V_ASN1_UNIVERSAL) {
    ossl_i2d_ASN1_TYPE(asn1, &p);
  } else if (explicit) {
    ossl_asn1_put_object(&p, 1, ossl_i2d_ASN1_TYPE(asn1, NULL), tn, tc);
    ossl_i2d_ASN1_TYPE(asn1, &p);
  } else {
    ossl_i2d_ASN1_TYPE(asn1, &p);
    *buf = tc | tn | (*buf & V_ASN1_CONSTRUCTED);
  }
  ossl_ASN1_TYPE_free(asn1);
  reallen = p - buf;
  assert(reallen <= len);
  str = ossl_buf2str(mrb, (char *)buf, (int)(reallen)); /* buf will be free in ossl_buf2str */

  return str;
}

#define OSSL_ASN1_IMPL_FACTORY_METHOD(klass)                                                       \
  static VALUE ossl_asn1_##klass(mrb_state *mrb, VALUE self)                                       \
  {                                                                                                \
    return mrb_instance_new(mrb, mrb_obj_value(cASN1##klass));                                     \
  }

OSSL_ASN1_IMPL_FACTORY_METHOD(Boolean)
OSSL_ASN1_IMPL_FACTORY_METHOD(Integer)
OSSL_ASN1_IMPL_FACTORY_METHOD(Enumerated)
OSSL_ASN1_IMPL_FACTORY_METHOD(BitString)
OSSL_ASN1_IMPL_FACTORY_METHOD(OctetString)
OSSL_ASN1_IMPL_FACTORY_METHOD(UTF8String)
OSSL_ASN1_IMPL_FACTORY_METHOD(NumericString)
OSSL_ASN1_IMPL_FACTORY_METHOD(PrintableString)
OSSL_ASN1_IMPL_FACTORY_METHOD(T61String)
OSSL_ASN1_IMPL_FACTORY_METHOD(VideotexString)
OSSL_ASN1_IMPL_FACTORY_METHOD(IA5String)
OSSL_ASN1_IMPL_FACTORY_METHOD(GraphicString)
OSSL_ASN1_IMPL_FACTORY_METHOD(ISO64String)
OSSL_ASN1_IMPL_FACTORY_METHOD(GeneralString)
OSSL_ASN1_IMPL_FACTORY_METHOD(UniversalString)
OSSL_ASN1_IMPL_FACTORY_METHOD(BMPString)
OSSL_ASN1_IMPL_FACTORY_METHOD(Null)
OSSL_ASN1_IMPL_FACTORY_METHOD(ObjectId)
OSSL_ASN1_IMPL_FACTORY_METHOD(UTCTime)
OSSL_ASN1_IMPL_FACTORY_METHOD(GeneralizedTime)
OSSL_ASN1_IMPL_FACTORY_METHOD(Sequence)
OSSL_ASN1_IMPL_FACTORY_METHOD(Set)
OSSL_ASN1_IMPL_FACTORY_METHOD(EndOfContent)

enum { ossl_asn1_info_size = (sizeof(ossl_asn1_info) / sizeof(ossl_asn1_info[0])) };
#define OSSL_ASN1_DEFINE_CLASS(mrb, name, super)                                                   \
  do {                                                                                             \
    cASN1##name = mrb_define_class_under(mrb, mASN1, #name, cASN1##super);                         \
    mrb_define_module_function(mrb, mASN1, #name, ossl_asn1_##name, MRB_ARGS_ARG(1, 3));           \
  } while (0)

void mrb_init_ossl_asn1(mrb_state *mrb)
{
  int i;
  mrb_value ary;
  mASN1 = mrb_define_module_under(mrb, mOSSL, "ASN1");
  eASN1Error = mrb_define_class_under(mrb, mASN1, "ASN1Error", eOSSLError);

  cASN1Data = mrb_define_class_under(mrb, mASN1, "ASN1Data", mrb->object_class);
  mrb_define_method(mrb, cASN1Data, "initialize", ossl_asn1data_initialize, MRB_ARGS_REQ(3));
  cASN1Primitive = mrb_define_class_under(mrb, mASN1, "Primitive", cASN1Data);
  mrb_define_method(mrb, cASN1Primitive, "initialize", ossl_asn1_initialize, MRB_ARGS_ARG(1, 3));
  mrb_define_method(mrb, cASN1Primitive, "to_der", ossl_asn1prim_to_der, 0);
  cASN1Constructive = mrb_define_class_under(mrb, mASN1, "Constructive", cASN1Data);
  mrb_define_method(mrb, cASN1Constructive, "initialize", ossl_asn1_initialize, MRB_ARGS_ARG(1, 3));
  mrb_define_method(mrb, cASN1Constructive, "to_der", ossl_asn1cons_to_der, MRB_ARGS_NONE());

  OSSL_ASN1_DEFINE_CLASS(mrb, Boolean, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, Integer, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, Enumerated, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, BitString, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, OctetString, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, UTF8String, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, NumericString, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, PrintableString, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, T61String, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, VideotexString, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, IA5String, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, GraphicString, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, ISO64String, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, GeneralString, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, UniversalString, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, BMPString, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, Null, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, ObjectId, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, UTCTime, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, GeneralizedTime, Primitive);
  OSSL_ASN1_DEFINE_CLASS(mrb, Sequence, Constructive);
  OSSL_ASN1_DEFINE_CLASS(mrb, Set, Constructive);
  OSSL_ASN1_DEFINE_CLASS(mrb, EndOfContent, Data);

  ary = mrb_ary_new(mrb);

  /*
   * Array storing tag names at the tag's index.
   */
  mrb_define_const(mrb, mASN1, "UNIVERSAL_TAG_NAME", ary);
  for (i = 0; i < ossl_asn1_info_size; i++) {
    if (ossl_asn1_info[i].name[0] == '[')
      continue;
    mrb_define_const(mrb, mASN1, ossl_asn1_info[i].name, mrb_fixnum_value(i));
    mrb_ary_set(mrb, ary, i,
                mrb_str_new(mrb, ossl_asn1_info[i].name, strlen(ossl_asn1_info[i].name)));
  }

  sUNIVERSAL = mrb_intern_lit(mrb, "UNIVERSAL");
  sCONTEXT_SPECIFIC = mrb_intern_lit(mrb, "CONTEXT_SPECIFIC");
  sAPPLICATION = mrb_intern_lit(mrb, "APPLICATION");
  sPRIVATE = mrb_intern_lit(mrb, "PRIVATE");
  sEXPLICIT = mrb_intern_lit(mrb, "EXPLICIT");
  sIMPLICIT = mrb_intern_lit(mrb, "IMPLICIT");

  sivVALUE = mrb_intern_lit(mrb, "@value");
  sivTAG = mrb_intern_lit(mrb, "@tag");
  sivTAGGING = mrb_intern_lit(mrb, "@tagging");
  sivTAG_CLASS = mrb_intern_lit(mrb, "@tag_class");
  sivINFINITE_LENGTH = mrb_intern_lit(mrb, "@infinite_length");
  sivUNUSED_BITS = mrb_intern_lit(mrb, "@unused_bits");
}
