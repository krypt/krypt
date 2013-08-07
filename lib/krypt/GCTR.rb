require 'openSSL'
plaintext = "two if by land"
#I believe this is what they're looking for with the inc function
def inc(cb)
  c = 0
  additive = 0
  left_32 = cb.slice(12..15)
  left_32.each_byte do |a|
    additive +=  left_32.getbyte(a)
  end
  additive %= 4
  cb.setbyte(15,additive)
end

def gctr(plaintext)
  cipher = OpenSSL::Cipher::AES.new(128)
  cipher.encrypt
  key = cipher.random_key
  cb = cipher.random_iv  
  cb = cipher.update(cb) + cipher.final
  if plaintext.length <= 16
    encrpyted = xor(cb,plaintext)
  end
  else
    encrypted = xor(cb,plaintext) 
    inc(cb)
end
