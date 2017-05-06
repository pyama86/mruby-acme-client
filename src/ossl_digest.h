#if !defined(_OSSL_DIGEST_H_)
#define _OSSL_DIGEST_H_
struct RClass *mDigest;
struct RClass *eDigestError;

void Init_ossl_digest(mrb_state *mrb);
const EVP_MD *GetDigestPtr(mrb_state *mrb, mrb_value);
#endif /* _OSSL_DIGEST_H_ */
