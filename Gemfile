source 'https://rubygems.org'

gem 'krypt-provider-openssl', :platforms => :ruby,  :git => "git://github.com/krypt/krypt-provider-openssl.git"
gem 'krypt-core-c',           :platforms => :ruby,  :git => "git://github.com/krypt/krypt-core-c.git"

gem 'krypt-provider-jce', :platforms => :jruby,  :git => "git://github.com/krypt/krypt-provider-jce.git"
gem 'krypt-core-java',    :platforms => :jruby,  :git => "git://github.com/krypt/krypt-core-java.git"

group :development do
  gem 'rake'
  gem 'rspec'
  gem 'jruby-openssl', :platforms => :jruby
  gem 'fuzzbert',      :git => "git://github.com/krypt/FuzzBert.git"
end

group :test do
  gem 'simplecov', :require => false
end

gemspec
