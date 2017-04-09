#include "openssl.h"
mrb_value mrb_openssl_digest_sha256_digest(mrb_state* mrb, mrb_value self) {
  const EVP_MD *md;
  EVP_MD_CTX *ctx;
  char* src;
  unsigned char buffer[SHA256_DIGEST_LENGTH];
  mrb_get_args(mrb, "z", &src);

	md = EVP_get_digestbyname("SHA256");
  ctx = EVP_MD_CTX_create();

  if (!EVP_DigestInit_ex(ctx, md, NULL))
    mrb_raise(mrb, E_RUNTIME_ERROR, "Digest initialization failed");

  if (!EVP_DigestUpdate(ctx, src, strlen(src)))
    mrb_raise(mrb, E_RUNTIME_ERROR, "EVP_DigestUpdate");

  if (!EVP_DigestFinal_ex(ctx, buffer, NULL))
	  mrb_raise(mrb, E_RUNTIME_ERROR, "EVP_DigestFinal_ex");

  return mrb_str_new(mrb, (char*)buffer, EVP_MD_CTX_size(ctx));
}
void mrb_init_openssl_digest(mrb_state* mrb) {
  struct RClass* openssl;
  struct RClass* openssl_digest;
  struct RClass* openssl_digest_sha256;

  openssl = mrb_define_module(mrb, "OpenSSL");
  openssl_digest = mrb_define_module_under(mrb, openssl, "Digest");
  openssl_digest_sha256 =
      mrb_define_class_under(mrb, openssl_digest, "SHA256", mrb->object_class);
  mrb_define_method(mrb, openssl_digest_sha256, "digest",
                    mrb_openssl_digest_sha256_digest, MRB_ARGS_REQ(1));
}
