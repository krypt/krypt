require 'fileutils'

Gem::Specification.new do |s|
  s.name = 'krypt'
  s.version = '0.0.1'
  s.author = 'Hiroshi Nakamura, Martin Bosslet'
  s.email = 'Martin.Bosslet@gmail.com'
  s.homepage = 'https://github.com/krypt/krypt'
  s.summary = 'Platform- and library-independent cryptography for Ruby'
  s.files = Dir.glob('{lib,spec,test}/**/*')
  s.files += ['LICENSE']
  s.test_files = Dir.glob('test/**/test_*.rb')
  s.extra_rdoc_files = [ "README.md" ]
  s.require_path = "lib"
  s.license = 'MIT'
end
