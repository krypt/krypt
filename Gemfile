source 'https://rubygems.org'

# bundler doesn't like krypt-core being specified at two different locations
if RUBY_PLATFORM =~ /java/
  gem 'krypt-core',             :platforms => :jruby, :github => 'krypt/krypt-core-java', :branch => 'master'
  gem 'krypt-provider-jdk',     :platforms => :jruby, :github => 'krypt/krypt-provider-jdk', :branch => 'master'
else
  gem 'krypt-core',             :platforms => :ruby,  :github => 'krypt/krypt-core-c', :branch => 'master'
  gem 'krypt-provider-openssl', :platforms => :ruby,  :github => 'krypt/krypt-provider-openssl', :branch => 'master'
  gem 'binyo',                  :platforms => :ruby,  :github => 'krypt/binyo', :branch => 'master'
end

gem 'ffi'

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
