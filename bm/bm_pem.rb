require 'krypt'
require 'stringio'
require 'openssl'
require 'benchmark'

pem = <<-EOF
-----BEGIN CERTIFICATE-----
MIIDzzCCAregAwIBAgIDAWweMA0GCSqGSIb3DQEBBQUAMIGNMQswCQYDVQQGEwJB
VDFIMEYGA1UECgw/QS1UcnVzdCBHZXMuIGYuIFNpY2hlcmhlaXRzc3lzdGVtZSBp
bSBlbGVrdHIuIERhdGVudmVya2VociBHbWJIMRkwFwYDVQQLDBBBLVRydXN0LW5R
dWFsLTAzMRkwFwYDVQQDDBBBLVRydXN0LW5RdWFsLTAzMB4XDTA1MDgxNzIyMDAw
MFoXDTE1MDgxNzIyMDAwMFowgY0xCzAJBgNVBAYTAkFUMUgwRgYDVQQKDD9BLVRy
dXN0IEdlcy4gZi4gU2ljaGVyaGVpdHNzeXN0ZW1lIGltIGVsZWt0ci4gRGF0ZW52
ZXJrZWhyIEdtYkgxGTAXBgNVBAsMEEEtVHJ1c3QtblF1YWwtMDMxGTAXBgNVBAMM
EEEtVHJ1c3QtblF1YWwtMDMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQCtPWFuA/OQO8BBC4SAzewqo51ru27CQoT3URThoKgtUaNR8t4j8DRE/5TrzAUj
lUC5B3ilJfYKvUWG6Nm9wASOhURh73+nyfrBJcyFLGM/BWBzSQXgYHiVEEvc+RFZ
znF/QJuKqiTfC0Li21a8StKlDJu3Qz7dg9MmEALP6iPESU7l0+m0iKsMrmKS1GWH
2WrX9IWf5DMiJaXlyDO6w8dB3F/GaswADm0yqLaHNgBid5seHzTLkDx4iHQF63n1
k3Flyp3HaxgtPVxO59X4PzF9j4fsCiIvI+n+u33J4PTs63zEsMMtYrWacdaxaujs
2e3Vcuy+VwHOBVWf3tFgiBCzAgMBAAGjNjA0MA8GA1UdEwEB/wQFMAMBAf8wEQYD
VR0OBAoECERqlWdVeRFPMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQUFAAOC
AQEAVdRU0VlIXLOThaq/Yy/kgM40ozRiPvbY7meIMQQDbwvUB/tOdQ/TLtPAF8fG
KOwGDREkDg6lXb+MshOWcdzUzg4NCmgybLlBMRmrsQd7TZjTXLDR8KdCoLXEjq/+
8T/0709GAHbrAvv5ndJAlseIOrifEXnzgGWovR/TeIGgUUw3tKZdJXDRZslo+S4R
FGjxVJgIrCaSD96JntT6s3kr0qN51OyLrIdTaEJMUVF0HhsnLuP1Hyl0Te2v9+GS
mYHovjrHF1D2t8b8m7CKa9aIA5GPBnc6hQLdmNVDeD/GMBWsm2vLV7eJUYs66MmE
DNuxUCAKGkq6ahq97BvIxYSazQ==
-----END CERTIFICATE-----
EOF

Benchmark.bm do |bm|
  n = 100000

  bytes = Krypt::PEM.decode(pem)[0]

  bm.report("Krypt::ASN1.decode_der      ") do
    n.times do
      Krypt::ASN1.decode_der(bytes)
    end
  end

  bm.report("Krypt::ASN1.decode_pem      ") do
    n.times do
      Krypt::ASN1.decode_pem(pem)
    end
  end

  bm.report("Krypt::ASN1.decode with der ") do
    n.times do
      Krypt::ASN1.decode(bytes)
    end
  end

  bm.report("Krypt::ASN1.decode with pem ") do
    n.times do
      Krypt::ASN1.decode(pem)
    end
  end

  bm.report("Krypt::PEM.decode only      ") do
    n.times do
      Krypt::PEM.decode(pem)
    end
  end

  bm.report("Krypt::PEM.decode, then ASN1") do
    n.times do
      der = Krypt::PEM.decode(pem)
      Krypt::ASN1.decode(der[0])
    end
  end

  bm.report("OpenSSL::X509               ") do
    n.times do
     OpenSSL::X509::Certificate.new(pem)
    end
  end
end
 
