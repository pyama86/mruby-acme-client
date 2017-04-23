#include "ossl.h"

struct RClass *mASN1;
struct RClass *eASN1Error;
struct RClass *cASN1Data;
struct RClass *cASN1Primitive;

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
  OSSL_ASN1_DEFINE_CLASS(mrb, UTF8String, Primitive);
  ary = mrb_ary_new(mrb);

  /*
   * Array storing tag names at the tag's index.
   */
  mrb_define_const(mrb, mASN1, "UNIVERSAL_TAG_NAME", ary);
  for (i = 0; i < ossl_asn1_info_size; i++) {
    if (ossl_asn1_info[i].name[0] == '[')
      continue;
    mrb_define_const(mrb, mASN1, ossl_asn1_info[i].name, mrb_fixnum_value(i));
    mrb_ary_set(mrb, ary, i, mrb_str_new(mrb, ossl_asn1_info[i].name, strlen(ossl_asn1_info[i].name)));
  }
}
