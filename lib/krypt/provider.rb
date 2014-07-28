require_relative 'provider/provider'

##
# For JRuby the FFI provider is not required at
# runtime as there is always a default (Java-based) provider.
#

def java?
  !! (RUBY_PLATFORM =~ /java/)
end

unless java?
  require_relative 'provider/ffi'
end
