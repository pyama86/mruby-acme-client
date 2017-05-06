

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
mrb_value ossl_buf2str(mrb_state *mrb, char *buf, int len);
mrb_value ossl_fetch_error();

int ossl_pem_passwd_cb(char *buf, int max_len, int flag, void *pwd);
#include <mruby/compile.h>
#include <mruby/data.h>
#include <mruby/hash.h>
#include <mruby/array.h>
#include <mruby/object.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <openssl/opensslv.h>

#ifdef HAVE_ASSERT_H
#  include <assert.h>
#else
#  define assert(condition)
#endif

#if defined(_WIN32)
#  include <openssl/e_os2.h>
#  define OSSL_NO_CONF_API 1
#  if !defined(OPENSSL_SYS_WIN32)
#    define OPENSSL_SYS_WIN32 1
#  endif
#  include <winsock2.h>
#endif
#include <errno.h>
#include <openssl/err.h>
#include <openssl/asn1_mac.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/conf_api.h>
#if !defined(_WIN32)
#  include <openssl/crypto.h>
#endif
#undef X509_NAME
#undef PKCS7_SIGNER_INFO
#if defined(HAVE_OPENSSL_ENGINE_H) && defined(HAVE_EVP_CIPHER_CTX_ENGINE)
#  define OSSL_ENGINE_ENABLED
#  include <openssl/engine.h>
#endif
#if defined(HAVE_OPENSSL_OCSP_H)
#  define OSSL_OCSP_ENABLED
#  include <openssl/ocsp.h>
#endif

#define VALUE mrb_value
#define ID mrb_sym
#define SYM2ID(mrb, o) mrb_sym2str(mrb, mrb_symbol(o))
#define ID2SYM(o) mrb_symbol(o)
#define INT2NUM mrb_fixnum_value
#define FIX2LONG mrb_fixnum
#define NUM2INT mrb_fixnum
#define NIL_P(name) mrb_nil_p(name)
#define SYMBOL_P(name) mrb_symbol_p(name)
#include "ossl_bio.h"
#include "ossl_bn.h"
#include "ossl_digest.h"
#include "ossl_pkey.h"
#include "ossl_pkey_rsa.h"
#include "ossl_x509.h"
#include "ossl_x509attr.h"
#include "ossl_x509name.h"
#include "ossl_asn1.h"
#include "ossl_config.h"

#define CLASS_NAME(mrb, obj) mrb_str_to_str(mrb, mrb_funcall(mrb, mrb_obj_value(obj), "name", 0))
#define RTEST(v) (!mrb_nil_p(v) && mrb_bool(v))

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

#define ossl_str_adjust(mrb, str, p) \
do{\
    long len = RSTRING_LEN(str);\
    long newlen = (long)((p) - (unsigned char*)RSTRING_PTR(str));\
    assert(newlen <= len);\
    mrb_str_resize((mrb), (str), newlen);\
}while(0)

#define OSSL_BIO_reset(bio)	(void)BIO_reset((bio)); \
				ERR_clear_error();
#endif /* _OSSL_H_ */
