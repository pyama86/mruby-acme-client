
//LICENSE: https://github.com/ruby/openssl/blob/master/LICENSE.txt
#if !defined(_OSSL_BIO_H_)
#define _OSSL_BIO_H_

BIO *ossl_obj2bio(mrb_state *mrb, mrb_value self);

VALUE ossl_membio2str(mrb_state *mrb, BIO *bio);
#endif
