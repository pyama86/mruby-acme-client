# mruby-acme-client   [![Build Status](https://travis-ci.org/pyama86/mruby-acme-client.svg?branch=master)](https://travis-ci.org/pyama86/mruby-acme-client)
LetsEncrypt class
## install by mrbgems
- add conf.gem line to `build_config.rb`

```ruby
MRuby::Build.new do |conf|

    # ... (snip) ...

    conf.gem :github => 'pyama86/mruby-acme-client'
end
```
## example
```ruby
p LetsEncrypt.hi
#=> "hi!!"
t = LetsEncrypt.new "hello"
p t.hello
#=> "hello"
p t.bye
#=> "hello bye"
```

## License
under the MIT License:
- see LICENSE file
