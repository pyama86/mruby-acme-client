MRuby::Build.new do |conf|
  toolchain :gcc
  conf.gembox 'default'
  conf.gem File.expand_path(File.dirname(__FILE__))
  conf.enable_test
  conf.cc.include_paths = [
    "/home/pyama/src/github.com/pyama86/mruby-acme-client/mruby/include",
    "/opt/openssl/include",
    "/usr/lib/include"
  ]
  conf.linker.library_paths = "/opt/openssl/lib"
  conf.cc.flags << "-g3 -O0"
end
