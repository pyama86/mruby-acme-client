
//LICENSE: https://github.com/ruby/openssl/blob/master/LICENSE.txt
X509 *GetX509CertPtr(mrb_state *mrb, mrb_value VALUE);
void Init_ossl_x509ext(mrb_state *mrb);
void Init_ossl_x509cert(mrb_state *mrb);
void Init_ossl_x509crl(mrb_state *mrb);
void Init_ossl_x509req(mrb_state *mrb);

X509_REQ *GetX509ReqPtr(mrb_state *mrb, VALUE obj);
X509_CRL *GetX509CRLPtr(mrb_state *mrb, VALUE obj);
