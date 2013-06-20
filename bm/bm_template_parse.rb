require 'krypt'
require_relative 'resources'
require 'stringio'
require 'openssl'
require 'benchmark'

Benchmark.bm do |bm|

  cert = Resources.certificate
  [1000, 10_000, 100_000].each do |n|
    bm.report("Krypt::X509.parse_der String(n=#{n})     ") { n.times { Krypt::X509::Certificate.parse_der(cert) } }
    bm.report("OpenSSL::X509::Certificate String(n=#{n})") { n.times { OpenSSL::X509::Certificate.new(Resources.certificate) } }
    puts
  end

end

