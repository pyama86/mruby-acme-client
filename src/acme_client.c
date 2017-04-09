#include "openssl.h"
void mrb_init_openssl_digest(mrb_state *mrb);
void mrb_init_openssl_pkey(mrb_state *mrb);
void mrb_init_openssl_bn(mrb_state *mrb);
#define DONE mrb_gc_arena_restore(mrb, 0)

void mrb_mruby_acme_client_gem_init(mrb_state *mrb)
{
  mrb_init_openssl_digest(mrb);
  DONE;
  mrb_init_openssl_pkey(mrb);
  DONE;
  mrb_init_openssl_bn(mrb);
  DONE;
}
void mrb_mruby_acme_client_gem_final(mrb_state *mrb)
{
}
