require 'OpenSSL'
require 'pkcs5'

def hash_calculator(key)
  y = "0000000000000000"
  key = key
  h = cipher.update(y) + cipher.final
end

def ghash(input,h)
  y_new = y
  n = (input.length/16).ceil
  n.times do
    block = input.slice(0..15)
    y_new = xor(y_new,input)
    hash = block_mult(y_new,h) #Not sure how I should handle padding
    y = y << hash
  end
end
