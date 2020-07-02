import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import os
import json


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

    
    def encrypt( self , message, password , type = 'json'):
        # generate a random salt
        salt = os.urandom(AES.block_size)

        # generate a random iv
        iv = Random.new().read(AES.block_size)

        # use the Scrypt KDF to get a private key from the password
        private_key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

        if type == 'json':
            json_string = json.dumps(message)
            padded_message = self.pad(json_string)
            cipher_config = AES.new(private_key, AES.MODE_CBC, iv)

        else:
            # pad text with spaces to be valid for AES CBC mode
            padded_message = self.pad(message)
            
            # create cipher config
            cipher_config = AES.new(private_key, AES.MODE_CBC, iv)

        # return a dictionary with the encrypted text
        return {
            'cipher_text': base64.b64encode(cipher_config.encrypt(padded_message)),
            'salt': base64.b64encode(salt),
            'iv': base64.b64encode(iv),
            'raw_salt' : salt,
            'raw_cipher' : cipher_config.encrypt(padded_message),
            'raw_iv' : iv
        }

    def decrypt(self , enc_dict, password , type):
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

        if type == 'json':
            string_json = self.unpad(decrypted)
            decoded_json_string = string_json.decode("utf-8")
            original_json = json.loads(decoded_json_string)
            return original_json

        else:
            original_message = self.unpad(decrypted)
            return original_message


message = Encryption(block_size = 16)

dic_message = {
    'name' : 'Afsan',
    'surname' : 'khan',
    'gender' : 'male',
}

string_message = 'hello world'

key = 'devil'




