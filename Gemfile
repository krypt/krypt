source 'https://rubygems.org'

gem 'binyo',                  :platforms => :ruby,  :github => 'krypt/binyo', :branch => 'master'
gem 'krypt-provider-openssl', :platforms => :ruby,  :github => 'krypt/krypt-provider-openssl', :branch => 'master'
gem 'krypt-core-c',           :platforms => :ruby,  :github => 'krypt/krypt-core-c', :branch => 'master'

gem 'krypt-provider-jdk',     :platforms => :jruby, :github => 'krypt/krypt-provider-jdk', :branch => 'master'
gem 'krypt-core-java',        :platforms => :jruby, :github => 'krypt/krypt-core-java', :branch => 'master'

group :development do
  gem 'rake'
  gem 'rspec'
  gem 'jruby-openssl', :platforms => :jruby
end

group :test do
  gem 'simplecov', :require => false
  gem 'fuzzbert',  :github => 'krypt/FuzzBert', :branch => 'master'
end

gemspec
