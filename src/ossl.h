

#if !defined(_OSSL_H_)
#define _OSSL_H_
#include <mruby.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <stdbool.h>
#include <string.h>

extern struct RClass *mOSSL;
extern struct RClass *eOSSLError;
extern struct RClass *mOSSL;

mrb_value ossl_to_der_if_possible(mrb_state *mrb, mrb_value obj);
mrb_value ossl_to_der(mrb_state *mrb, mrb_value obj);

#include <mruby/compile.h>
#include <mruby/data.h>
#include <mruby/hash.h>
#include <mruby/array.h>
#include <mruby/object.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#include <openssl/asn1_mac.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>

#define VALUE mrb_value
#define ID mrb_sym
#define INT2NUM mrb_fixnum_value
#define FIX2LONG mrb_fixnum
#define NUM2INT mrb_fixnum

#include "ossl_bio.h"
#include "ossl_bn.h"
#include "ossl_digest.h"
#include "ossl_pkey.h"
#include "ossl_pkey_rsa.h"
#include "ossl_x509.h"
#include "ossl_x509attr.h"
#include "ossl_x509name.h"
#include "ossl_asn1.h"

#define RTEST(v) (!mrb_nil_p(v) && !mrb_bool(v))

#ifndef UNREACHABLE
#define UNREACHABLE /* unreachable */
#endif

#ifdef HAVE_ASSERT_H
#include <assert.h>
#else
#define assert(condition)
#endif

#define OSSL_Check_Kind(mrb, obj, klass)                                                           \
  do {                                                                                             \
    if (!mrb_obj_is_kind_of((mrb), (obj), (klass))) {                                              \
      mrb_raise((mrb), E_TYPE_ERROR, NULL);                                                             \
    }                                                                                              \
  } while (0)

#endif /* _OSSL_H_ */
