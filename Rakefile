MRUBY_CONFIG=File.expand_path(ENV["MRUBY_CONFIG"] || "build_config.rb")
MRUBY_VERSION=ENV["MRUBY_VERSION"] || "3703aed7ab7c056ef7a58fd8d25b84b59f715dad"

file :mruby do
  sh "git clone --depth=1 git://github.com/mruby/mruby.git"
  Dir.chdir("./mruby") do
    sh "git checkout #{MRUBY_VERSION}"
  end
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
