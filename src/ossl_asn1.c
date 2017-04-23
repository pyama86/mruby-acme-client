#include "ossl.h"

struct RClass *mASN1;
struct RClass *eASN1Error;
struct RClass *cASN1Data;
struct RClass *cASN1Primitive;
struct RClass *cASN1Constructive;
static VALUE class_tag_map;

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

static ID sivVALUE, sivUNUSED_BITS;
#define ossl_asn1_get_value(mrb, o) mrb_attr_get((mrb), (o), sivVALUE)

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

static int ossl_asn1_default_tag(mrb_state *mrb, VALUE obj)
{
  VALUE tag;
  struct RClass *tmp_class;

  tmp_class = mrb_class(mrb, obj);
  while (tmp_class) {
    tag = mrb_hash_get(mrb, class_tag_map, mrb_obj_value(tmp_class));
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
      ossl_raise(eOSSLError, NULL);
    }
  }
  if (!(ai = BN_to_ASN1_INTEGER(bn, ai))) {
    BN_free(bn);
    ossl_raise(eOSSLError, NULL);
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
  value = ossl_asn1_get_value(mrb, obj);
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

enum { ossl_asn1_info_size = (sizeof(ossl_asn1_info) / sizeof(ossl_asn1_info[0])) };
#define OSSL_ASN1_DEFINE_CLASS(mrb, name, super)                                                   \
  do {                                                                                             \
    cASN1##name = mrb_define_class_under(mrb, mASN1, #name, cASN1##super);                         \
  } while (0)

void mrb_init_ossl_asn1(mrb_state *mrb)
{
  int i;
  mrb_value ary;
  mASN1 = mrb_define_module_under(mrb, mOSSL, "ASN1");
  eASN1Error = mrb_define_class_under(mrb, mASN1, "ASN1Error", eOSSLError);

  cASN1Data = mrb_define_class_under(mrb, mASN1, "ASN1Data", mrb->object_class);
  cASN1Primitive = mrb_define_class_under(mrb, mASN1, "Primitive", cASN1Data);

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

  class_tag_map = mrb_hash_new(mrb);
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1EndOfContent), INT2NUM(V_ASN1_EOC));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1Boolean), INT2NUM(V_ASN1_BOOLEAN));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1Integer), INT2NUM(V_ASN1_INTEGER));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1BitString), INT2NUM(V_ASN1_BIT_STRING));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1OctetString), INT2NUM(V_ASN1_OCTET_STRING));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1Null), INT2NUM(V_ASN1_NULL));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1ObjectId), INT2NUM(V_ASN1_OBJECT));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1Enumerated), INT2NUM(V_ASN1_ENUMERATED));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1UTF8String), INT2NUM(V_ASN1_UTF8STRING));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1Sequence), INT2NUM(V_ASN1_SEQUENCE));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1Set), INT2NUM(V_ASN1_SET));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1NumericString),
               INT2NUM(V_ASN1_NUMERICSTRING));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1PrintableString),
               INT2NUM(V_ASN1_PRINTABLESTRING));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1T61String), INT2NUM(V_ASN1_T61STRING));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1VideotexString),
               INT2NUM(V_ASN1_VIDEOTEXSTRING));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1IA5String), INT2NUM(V_ASN1_IA5STRING));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1UTCTime), INT2NUM(V_ASN1_UTCTIME));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1GeneralizedTime),
               INT2NUM(V_ASN1_GENERALIZEDTIME));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1GraphicString),
               INT2NUM(V_ASN1_GRAPHICSTRING));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1ISO64String), INT2NUM(V_ASN1_ISO64STRING));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1GeneralString),
               INT2NUM(V_ASN1_GENERALSTRING));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1UniversalString),
               INT2NUM(V_ASN1_UNIVERSALSTRING));
  mrb_hash_set(mrb, class_tag_map, mrb_obj_value(cASN1BMPString), INT2NUM(V_ASN1_BMPSTRING));
  sivVALUE = mrb_intern_lit(mrb, "@value");
  sivUNUSED_BITS = mrb_intern_lit(mrb, "@unused_bits");
}
