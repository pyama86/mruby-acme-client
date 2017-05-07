#include "ossl.h"

struct RClass *eOSSLError;
struct RClass *mOSSL;

mrb_value ossl_to_der(mrb_state *mrb, mrb_value obj)
{
  mrb_value tmp;

  tmp = mrb_funcall(mrb, obj, "to_der", 0);
  return mrb_str_to_str(mrb, tmp);
}

mrb_value ossl_to_der_if_possible(mrb_state *mrb, mrb_value obj)
{
  if (mrb_respond_to(mrb, obj, mrb_intern_lit(mrb, "to_der")))
    return ossl_to_der(mrb, obj);
  return obj;
}

static mrb_value ossl_str_new(mrb_state *mrb, int size)
{
  return mrb_str_new(mrb, 0, size);
}

mrb_value ossl_fetch_error(mrb_state *mrb)
{
  const char *msg;
  const char *warn;
  long e;

#ifdef HAVE_ERR_PEEK_LAST_ERROR
  e = ERR_peek_last_error();
#else
  e = ERR_peek_error();
#endif
  if (e) {
    msg = ERR_reason_error_string(e);
  }


  while ((e = ERR_get_error()) != 0) {
    warn = ERR_error_string(e, NULL);
    if (warn)
      mrb_warn(mrb, "error on stack:lib: %S", mrb_str_new_cstr(mrb, warn));
  }

  ERR_clear_error();
  if (msg)
    return mrb_str_new_cstr(mrb, msg);
  else
    mrb_nil_value();
}

mrb_value ossl_buf2str(mrb_state *mrb, char *buf, int len)
{
  mrb_value str;

  str = ossl_str_new(mrb, len);
  if (!NIL_P(str))
    memcpy(RSTRING_PTR(str), buf, len);
  return str;
}


int ossl_pem_passwd_cb(char *buf, int max_len, int flag, void *mrb)
{
  return 0;
}

void mrb_init_ossl(mrb_state *mrb)
{
  mOSSL = mrb_define_module(mrb, "OpenSSL");
  eOSSLError = mrb_define_class_under(mrb, mOSSL, "OpenSSLError", mrb->eStandardError_class);
  Init_ossl_digest(mrb);
  Init_ossl_bn(mrb);
  Init_ossl_pkey(mrb);
  Init_ossl_config(mrb);
}
