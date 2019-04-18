// LICENSE: https://github.com/ruby/openssl/blob/master/LICENSE.txt
#include "ossl.h"
struct RClass *cConfig;
struct RClass *eConfigError;

CONF *GetConfigPtr(mrb_state *mrb, VALUE obj)
{
  CONF *conf;
  VALUE str;
  BIO *bio;
  long eline = -1;

  OSSL_Check_Kind(mrb, obj, cConfig);
  str = mrb_funcall(mrb, obj, "to_s", 0);
  bio = ossl_obj2bio(mrb, str);
  conf = NCONF_new(NULL);
  if (!conf) {
    BIO_free(bio);
    mrb_raise(mrb, eConfigError, NULL);
  }
  if (!NCONF_load_bio(conf, bio, &eline)) {
    BIO_free(bio);
    NCONF_free(conf);
    if (eline <= 0)
      mrb_raise(mrb, eConfigError, "wrong config format");
    else
      mrb_raisef(mrb, eConfigError, "error in line %d", eline);
    mrb_raise(mrb, eConfigError, NULL);
  }
  BIO_free(bio);

  return conf;
}

void Init_ossl_config(mrb_state *mrb)
{
  char *default_config_file;
  eConfigError = mrb_define_class_under(mrb, mOSSL, "ConfigError", eOSSLError);
  cConfig = mrb_define_class_under(mrb, mOSSL, "Config", mrb->object_class);

  default_config_file = CONF_get1_default_config_file();
  mrb_define_const(mrb, cConfig, "DEFAULT_CONFIG_FILE", mrb_str_new_cstr(mrb, default_config_file));
  OPENSSL_free(default_config_file);
  /* methods are defined by openssl/config.rb */
}
