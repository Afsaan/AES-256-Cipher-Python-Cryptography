import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import os




class Encryption:
    def __init__(self , block_size):
        self.block_size = block_size

    
# pad with spaces at the end of the text beacuse AES needs 16 byte blocks
    def pad(self , s):
        remainder = len(s) % self.block_size
        padding_needed = self.block_size - remainder
        return s+padding_needed*' '

# remove the extra spaces at the end
    def unpad(self , s): 
        return s.rstrip()

    
    def encrypt( self , plain_text, password , type = 'JSON'):
    # generate a random salt
        salt = os.urandom(AES.block_size)

        # generate a random iv
        iv = Random.new().read(AES.block_size)

        # use the Scrypt KDF to get a private key from the password
        private_key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

        # pad text with spaces to be valid for AES CBC mode
        padded_text = self.pad(plain_text)
        
        # create cipher config
        cipher_config = AES.new(private_key, AES.MODE_CBC, iv)

        # return a dictionary with the encrypted text
        return {
            'cipher_text': base64.b64encode(cipher_config.encrypt(padded_text)),
            'salt': base64.b64encode(salt),
            'iv': base64.b64encode(iv)
        }

    def decrypt(self , enc_dict, password , Type = 'JSON'):
        # decode the dictionary entries from base64
        salt = base64.b64decode(enc_dict['salt'])
        enc = base64.b64decode(enc_dict['cipher_text'])
        iv = base64.b64decode(enc_dict['iv'])

        # generate the private key from the password and salt
        private_key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

        # create the cipher config
        cipher = AES.new(private_key, AES.MODE_CBC, iv)

        # decrypt the cipher text
        decrypted = cipher.decrypt(enc)

        # unpad the text to remove the added spaces
        original = self.unpad(decrypted)

        return original




message = Encryption(block_size = 16)

enc_dict = message.encrypt('hello world', '1234')
print(enc_dict)

decrypted_message = message.decrypt(enc_dict , '1234')
print(decrypted_message)



