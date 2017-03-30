#include <mruby.h>
#include <mruby/string.h>
#include <mruby/compile.h>
#include <openssl/sha.h>
mrb_value mrb_openssl_digest_sha256_digest(mrb_state *mrb, mrb_value self)
{
  mrb_value v;
  SHA256_CTX c;
  char *src;
  unsigned char buffer[SHA256_DIGEST_LENGTH];

  mrb_get_args(mrb, "S", &v);

  src = mrb_str_to_cstr(mrb, v);
  SHA256_Init(&c);
  SHA256_Update(&c, src, sizeof(src));
  SHA256_Final(buffer, &c);
  return mrb_str_new(mrb, (char *)buffer, SHA256_DIGEST_LENGTH);
}
void
mrb_init_openssl_digest(mrb_state* mrb) {
  struct RClass* openssl;
  struct RClass* openssl_digest;
  struct RClass* openssl_digest_sha256;

  openssl = mrb_define_module(mrb, "OpenSSL");
  openssl_digest = mrb_define_module_under(mrb, openssl, "Digest");
  openssl_digest_sha256 = mrb_define_class_under(mrb, openssl_digest, "SHA256", mrb->object_class);
  mrb_define_method(mrb, openssl_digest_sha256, "digest", mrb_openssl_digest_sha256_digest, MRB_ARGS_REQ(1));
}
