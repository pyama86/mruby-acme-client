require 'open3'
require 'fileutils'
MRuby::Gem::Specification.new('mruby-acme-client') do |spec|
  spec.license = 'MIT'
  spec.authors = 'pyama86'
  spec.add_dependency 'mruby-polarssl', github: 'pyama86/mruby-polarssl', branch: 'disable-base64'
  spec.add_dependency 'mruby-io'
  spec.add_dependency 'mruby-json'
  spec.add_dependency 'mruby-process'
  spec.add_dependency 'mruby-onig-regexp'
  spec.add_dependency 'mruby-forwardable'
  spec.add_dependency 'mruby-tempfile'
  spec.add_dependency 'mruby-pack'
  spec.add_dependency 'mruby-digest'
  spec.add_dependency 'mruby-httprequest'
  spec.add_dependency 'mruby-base64'
  build_dependency if ENV["BUILD_SSL_DEPENDENCY"]
  spec.cc.include_paths << "#{build.root}/src"
  spec.linker.libraries << 'crypto' unless RUBY_PLATFORM =~ /darwin/
end

