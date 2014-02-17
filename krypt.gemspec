lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'krypt/version'

Gem::Specification.new do |s|

  s.name = 'krypt'
  s.version = Krypt::VERSION 

  s.author = 'Hiroshi Nakamura, Martin Bosslet'
  s.email = 'Martin.Bosslet@gmail.com'
  s.homepage = 'https://github.com/krypt/krypt'
  s.summary = 'Platform- and library-independent cryptography for Ruby'
  s.description = 'krypt provides a unified framework for Ruby cryptography by offering a platform- and library-independent provider mechanism.' 

  s.required_ruby_version     = '>= 1.9.3'

  s.files = Dir.glob('{lib,spec,test}/**/*')
  s.files += ['LICENSE']
  s.test_files = Dir.glob('test/**/test_*.rb')
  s.extra_rdoc_files = [ "README.md" ]
  s.require_path = "lib"
  s.license = 'MIT'

  s.add_dependency 'ffi'
  s.add_dependency 'krypt-core', '0.0.1'

end
