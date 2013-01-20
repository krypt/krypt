require 'krypt'
require 'benchmark'
require 'openssl'

# cf. http://blog.nathanielbibler.com/post/63031273/openssl-hmac-vs-ruby-hmac-benchmarks

iter  = 10_000
key     = "secretkey"
data    = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."

Benchmark.bmbm do |results|
  results.report('krypt-hmac') do
    md = Krypt::Digest.new("SHA1")
    iter.times do
      Krypt::HMAC.digest(md, key, data)
    end
  end
  results.report('openssl-hmac') do
    md = OpenSSL::Digest.new("SHA1")
    iter.times do
      OpenSSL::HMAC.digest(md, key, data)
    end
  end
end
