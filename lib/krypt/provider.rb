require_relative 'provider/provider'

begin
  require_relative 'provider/ffi'
rescue LoadError => e
  # cf. https://github.com/krypt/krypt/issues/47
  warn "FFI provider could not be loaded. Error message: #{e}"
end
