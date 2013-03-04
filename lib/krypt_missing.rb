unless Kernel.respond_to? :private_constant
  module Kernel
    def private_constant(*)
      # TODO delete when sufficiently supported
      nil
    end
  end
end

module Krypt
 module Helper
  
   #:nodoc:  
   # Some helpers are implemented in native code in krypt-core.  
  
 end
end

