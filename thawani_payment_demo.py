from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import base64


def encrypt_message(data, publickey):
    cipher = PKCS1_v1_5.new(publickey)
    ciphertext = cipher.encrypt(data)
    encoded_encrypted_data = base64.b64encode(ciphertext)
    return encoded_encrypted_data


# The data to be encrypted
to_encrypt_data = b'test data'

file = open("encrypted_data.txt", "a")

# Import Public Key
pu_key = RSA.import_key(open('public_pem.pem', 'r').read())
encrypted_msg = encrypt_message(to_encrypt_data, pu_key)

# Save encrypted data to a file
file.write('"{0}": "{1}",\n' .format(to_encrypt_data, encrypted_msg))
print("{0}: {1}" .format(to_encrypt_data, encrypted_msg))
