require 'krypt'
require_relative 'resources'
require 'stringio'
require 'openssl'
require 'benchmark'

def ossl_content
  [
    OpenSSL::ASN1::Boolean.new(true),
    OpenSSL::ASN1::Integer.new(65536),
    OpenSSL::ASN1::Integer.new(1234567890123456789012345678901234567890),
    OpenSSL::ASN1::BitString.new("abcdefghijklmnopqrstuvwxyz"),
    OpenSSL::ASN1::OctetString.new("abcdefghijklmnopqrstuvwxyz"),
    OpenSSL::ASN1::Null.new(nil),
    OpenSSL::ASN1::ObjectId.new("1.30.87654321.987654321.23" + ".23" * 50),
    OpenSSL::ASN1::Enumerated.new(65536),
    OpenSSL::ASN1::Enumerated.new(1234567890123456789012345678901234567890),
    OpenSSL::ASN1::UTF8String.new("abcdefghijklmnopqrstuvwxyz"),
    OpenSSL::ASN1::UTCTime.new(Time.now),
    OpenSSL::ASN1::UTCTime.new(Time.now.to_i),
    OpenSSL::ASN1::GeneralizedTime.new(Time.now),
    OpenSSL::ASN1::GeneralizedTime.new(Time.now.to_i),
    OpenSSL::ASN1::NumericString.new("abcdefghijklmnopqrstuvwxyz"),
    OpenSSL::ASN1::PrintableString.new("abcdefghijklmnopqrstuvwxyz"),
    OpenSSL::ASN1::T61String.new("abcdefghijklmnopqrstuvwxyz"),
    OpenSSL::ASN1::VideotexString.new("abcdefghijklmnopqrstuvwxyz"),
    OpenSSL::ASN1::IA5String.new("abcdefghijklmnopqrstuvwxyz"),
    OpenSSL::ASN1::GraphicString.new("abcdefghijklmnopqrstuvwxyz"),
    OpenSSL::ASN1::ISO64String.new("abcdefghijklmnopqrstuvwxyz"),
    OpenSSL::ASN1::GeneralString.new("abcdefghijklmnopqrstuvwxyz"),
    OpenSSL::ASN1::UniversalString.new("abcdefghijklmnopqrstuvwxyz"),
    OpenSSL::ASN1::BMPString.new("abcdefghijklmnopqrstuvwxyz")
  ]
end

def krypt_content
  [
    Krypt::ASN1::Boolean.new(true),
    Krypt::ASN1::Integer.new(65536),
    Krypt::ASN1::Integer.new(1234567890123456789012345678901234567890),
    Krypt::ASN1::BitString.new("abcdefghijklmnopqrstuvwxyz"),
    Krypt::ASN1::OctetString.new("abcdefghijklmnopqrstuvwxyz"),
    Krypt::ASN1::Null.new,
    Krypt::ASN1::ObjectId.new("1.30.87654321.987654321.23" + ".23" * 50),
    Krypt::ASN1::Integer.new(65536),
    Krypt::ASN1::Integer.new(1234567890123456789012345678901234567890),
    Krypt::ASN1::UTF8String.new("abcdefghijklmnopqrstuvwxyz"),
    Krypt::ASN1::UTCTime.new(Time.now),
    Krypt::ASN1::UTCTime.new(Time.now.to_i),
    Krypt::ASN1::GeneralizedTime.new(Time.now),
    Krypt::ASN1::GeneralizedTime.new(Time.now.to_i),
    Krypt::ASN1::NumericString.new("abcdefghijklmnopqrstuvwxyz"),
    Krypt::ASN1::PrintableString.new("abcdefghijklmnopqrstuvwxyz"),
    Krypt::ASN1::T61String.new("abcdefghijklmnopqrstuvwxyz"),
    Krypt::ASN1::VideotexString.new("abcdefghijklmnopqrstuvwxyz"),
    Krypt::ASN1::IA5String.new("abcdefghijklmnopqrstuvwxyz"),
    Krypt::ASN1::GraphicString.new("abcdefghijklmnopqrstuvwxyz"),
    Krypt::ASN1::ISO64String.new("abcdefghijklmnopqrstuvwxyz"),
    Krypt::ASN1::GeneralString.new("abcdefghijklmnopqrstuvwxyz"),
    Krypt::ASN1::UniversalString.new("abcdefghijklmnopqrstuvwxyz"),
    Krypt::ASN1::BMPString.new("abcdefghijklmnopqrstuvwxyz")
  ]
end

Benchmark.bm do |bm|

  filename = "bmtmp"

  file = File.open(filename, "wb")
  n = 100_000

  krypt_cert = Krypt::ASN1.decode_der(Resources.certificate)
  ossl_cert = OpenSSL::ASN1.decode(Resources.certificate)
  ossl_x509 = OpenSSL::X509::Certificate.new(Resources.certificate)
 
  bm.report("X509 encode parsed certificate(n=#{n})             ") { n.times { ossl_x509.to_der } }
  bm.report("OpenSSL encode parsed certificate(n=#{n})          ") { n.times { ossl_cert.to_der } }
  bm.report("Krypt encode parsed certificate(n=#{n})            ") { n.times { krypt_cert.to_der } }
  
  krypt_seq = Krypt::ASN1::Sequence.new(krypt_content)
  krypt_set = Krypt::ASN1::Set.new(krypt_content)
  krypt_asn1 = Krypt::ASN1::Sequence.new([krypt_seq, krypt_set])

  ossl_seq = OpenSSL::ASN1::Sequence.new(ossl_content)
  ossl_set = OpenSSL::ASN1::Set.new(ossl_content)
  ossl_asn1 = OpenSSL::ASN1::Sequence.new([ossl_seq, ossl_set])

  bm.report("OpenSSL encode generated once(n=#{n})              ") { n.times { ossl_asn1.to_der } }
  bm.report("Krypt encode generated once(n=#{n})                ") { n.times { krypt_asn1.to_der } }
  
  bm.report("OpenSSL encode generated n times(n=#{n})           ") do
    n.times do
      ossl_seq = OpenSSL::ASN1::Sequence.new(ossl_content)
      ossl_set = OpenSSL::ASN1::Set.new(ossl_content)
      OpenSSL::ASN1::Sequence.new([ossl_seq, ossl_set]).to_der
    end
  end

  bm.report("Krypt encode generated n times(n=#{n})             ") do
    n.times do
      krypt_seq = Krypt::ASN1::Sequence.new(krypt_content)
      krypt_set = Krypt::ASN1::Set.new(krypt_content)
      Krypt::ASN1::Sequence.new([krypt_seq, krypt_set]).to_der
    end
  end

  bm.report("Krypt encode generated n times SEQ(n=#{n})         ") do
    n.times do
      krypt_seq1 = Krypt::ASN1::Sequence.new(krypt_content)
      krypt_seq2 = Krypt::ASN1::Sequence.new(krypt_content)
      Krypt::ASN1::Sequence.new([krypt_seq1, krypt_seq2]).to_der
    end
  end

  bm.report("Krypt encode generated n times SET(n=#{n})         ") do
    n.times do
      krypt_set1 = Krypt::ASN1::Set.new(krypt_content)
      krypt_set2 = Krypt::ASN1::Set.new(krypt_content)
      Krypt::ASN1::Sequence.new([krypt_set1, krypt_set2]).to_der
    end
  end

  bm.report("Krypt encode parsed certificate to file(n=#{n})    ") { n.times { krypt_cert.encode_to(file) } }
  file.rewind
  bm.report("Krypt encode generated once to file(n=#{n})        ") { n.times { krypt_asn1.encode_to(file) } }
  file.rewind
  bm.report("Krypt encode generated n times to file(n=#{n})     ") do
    n.times do
      krypt_seq = Krypt::ASN1::Sequence.new(krypt_content)
      krypt_set = Krypt::ASN1::Set.new(krypt_content)
      Krypt::ASN1::Sequence.new([krypt_seq, krypt_set]).encode_to(file)
    end
  end

  bm.report("Krypt encode parsed certificate to StringIO(n=#{n})") { n.times { krypt_cert.encode_to(StringIO.new) } }
  bm.report("Krypt encode generated once to StringIO(n=#{n})    ") { n.times { krypt_asn1.encode_to(StringIO.new) } }
  bm.report("Krypt encode generated n times to StringIO(n=#{n}) ") do
    n.times do
      krypt_seq = Krypt::ASN1::Sequence.new(krypt_content)
      krypt_set = Krypt::ASN1::Set.new(krypt_content)
      Krypt::ASN1::Sequence.new([krypt_seq, krypt_set]).encode_to(StringIO.new)
    end
  end

  File.delete(filename)
end

