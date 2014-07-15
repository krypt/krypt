require_relative 'provider/provider'

##
# If JRuby is configured with native API access disabled, requiring the FFI
# provider will result in a LoadError. The FFI provider is not required at
# runtime as there is always a default (Java-based) provider.
#

def java?
  !! (RUBY_PLATFORM =~ /java/)
end

def native_disabled?
  require 'jruby'
  !JRuby.runtime.instance_config.native_enabled
end

begin
  require_relative 'provider/ffi'
rescue LoadError => e
  if java? && native_disabled?
    # Do not use the FFI provider with JRuby and native API access disabled
  elsif java?
    warn "FFI support not available for #{RUBY_PLATFORM}"
  else
    raise e
  end
end
