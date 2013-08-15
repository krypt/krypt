require 'openSSL'
require 'pkcs5'
plaintext = "testMess"
#I believe this is what they're looking for with the inc function
def inc(cb)
  c = 0
  additive = 0
  left_32 = cb.slice(12..15)
  while c<=4
    additive += left_32(c)
    c+=1
  end
  additive %= 4
  cb = cb.setbyte(15,additive)
end

class GCTR
  def gctr(plaintext)
    cipher = OpenSSL::Cipher::AES.new(128)
    cipher.encrypt
    key = cipher.random_key
    cb = cipher.random_iv  
    cb = cipher.update(cb) + cipher.final
    if plaintext.length <= 16
      $encrpyted = xor(cb,plaintext)
      puts encrypted
    else
      $encrypted = xor(cb,plaintext) 
      inc(cb)
      puts encrypted
      end
    end
end
