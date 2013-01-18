module Krypt
  class PBKDF2
    include Krypt::Helper::XOR
    
    MAX_FACTOR = (2 ** 32) - 1

    def initialize(digest)
      @digest = digest
      @block_size = digest.digest_length
    end

    def generate(pwd, salt, iter, outlen)
      raise "outlen too large" if outlen > MAX_FACTOR * @block_size

      num_blocks = (outlen.to_f / @block_size).ceil
      result = String.new # enforces ASCII-8BIT

      1.upto(num_blocks) do |i|
        result << f(pwd, salt, iter, i)
      end

      @digest.reset
      result.slice(0, outlen)
    end

    def generate_hex(pwd, salt, iter, outlen)
      Krypt::Hex.encode(generate(pwd, salt, iter, outlen))
    end

    private

      def f(pwd, salt, iter, i)
        u = salt + [i].pack("L>")
        result = "\0" * @block_size
        1.upto(iter) do |i|
          u = Krypt::HMAC.digest(@digest, pwd, u)
          result = xor(result, u)
        end
        result
      end

  end
end

