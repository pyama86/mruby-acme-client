#include "ossl.h"
void mrb_init_ossl(mrb_state *mrb);
void mrb_init_ossl_x509(mrb_state *mrb);
void mrb_init_ossl_asn1(mrb_state *mrb);
#define DONE mrb_gc_arena_restore(mrb, 0)

void mrb_mruby_acme_client_gem_init(mrb_state *mrb)
{
  mrb_init_ossl(mrb);
  DONE;
  mrb_init_ossl_x509(mrb);
  DONE;
  mrb_init_ossl_asn1(mrb);
  DONE;
}
void mrb_mruby_acme_client_gem_final(mrb_state *mrb)
{
}
