MRUBY_CONFIG=File.expand_path(ENV["MRUBY_CONFIG"] || "build_config.rb")

require 'fileutils'

if ENV["MRUBY_VERSION"] && !ENV["MRUBY_VERSION"].empty?
  MRUBY_VERSION = ENV["MRUBY_VERSION"]
else
  MRUBY_VERSION = File.read(File.expand_path "../mruby_version.lock", __FILE__).chomp
end

file :mruby do
  cmd = "git clone --depth=1 https://github.com/mruby/mruby.git"
  case MRUBY_VERSION
  when /\A[a-fA-F0-9]+\z/
    cmd << " && cd mruby"
    cmd << " && git fetch --depth=5000 && git checkout #{MRUBY_VERSION}"
  when /\A\d\.\d\.\d\z/
    cmd << " && cd mruby"
    cmd << " && git fetch --tags && git checkout $(git rev-parse #{MRUBY_VERSION})"
  when "master"
    # skip
  else
    fail "Invalid MRUBY_VERSION spec: #{MRUBY_VERSION}"
  end
  sh cmd
end

desc "compile binary"
task :compile => :mruby do
  sh "cd mruby && rake all MRUBY_CONFIG=\"#{MRUBY_CONFIG}\""
end

desc "test"
task :test => :mruby do
  sh "cd mruby && rake all test MRUBY_CONFIG=\"#{MRUBY_CONFIG}\""
end

desc "cleanup"
task :clean do
  sh "cd mruby && rake deep_clean"
end

task :default => :compile
