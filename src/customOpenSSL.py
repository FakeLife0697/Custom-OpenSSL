from OpenSSL import crypto
from Cryptodome.Cipher import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Util import number
from enum import Enum

class CryptoType(Enum):
    Private_RSA_key = 0
    Public_RSA_key = 1

class custom_Key_OpenSSL():
    def __init__(self):
        self.filename = None
        self.length = None
        self.type = None
        self.key = None
        self.data = None
        self.mod = None
        self.priv_exp = None
        self.pub_exp = None
        
    #Print detail
    def detail_info(self):
        print("Filename: {0}\n".format(self.filename if self.filename is not None else "Unidentified"))
        if self.type == CryptoType.Private_RSA_key:
            print("Type: Private RSA key\n")
            print("Mod: {0}\n".format(self.mod if self.mod is not None else "Unidentified"))
            print("Private exponent: {0}\n".format(self.priv_exp if self.priv_exp is not None else "Unidentified"))
        elif self.type == CryptoType.Public_RSA_key:
            print("Type: Public RSA key\n")
            print("Mod: {0}\n".format(self.mod if self.mod is not None else "Unidentified"))
            print("Public exponent: {0}\n".format(self.pub_exp if self.pub_exp is not None else "Unidentified"))
        else:
            print("Type: Unidentified")
        
    def readPrivatePem(self, filename, overwrite = False):
        # No data or want to overwrite
        if self.filename == None or overwrite:
            try:
                self.filename = filename
                self.type = CryptoType.Private_RSA_key
                with open(self.filename, "rb") as key_file:
                    key_data = key_file.read()
                    # Get the RSA key
                    self.key = crypto.load_privatekey(
                        crypto.FILETYPE_PEM, key_data)
                    
                    # Get the number
                    public_num = self.key.to_cryptography_key().public_key().public_numbers()
                    private_num = self.key.to_cryptography_key().private_numbers()
                    
                    modulus = public_num.n
                    private_exp = private_num.d
                    
                    # Convert from binary to decimal
                    self.mod = int.from_bytes(modulus.to_bytes((modulus.bit_length() + 7) // 8, 'big'), 'big')
                    self.priv_exp = int.from_bytes(private_exp.to_bytes((private_exp.bit_length() + 7) // 8, 'big'), 'big')
                    
                # Readable data
                self.data = crypto.dump_privatekey(
                    crypto.FILETYPE_PEM, self.key
                ).decode("utf-8")
                
                self.length = len(self.data)
                self.pub_exp = None
                
            except Exception as e:
                print("Private key reading failed")
                print(e)
        else:
            print("You can't overwrite this key")

    def readPublicPem(self, filename, overwrite = False):
        # No data or want to overwrite
        if self.filename == None or overwrite:
            try:
                self.filename = filename
                self.type = CryptoType.Public_RSA_key
                with open(self.filename, "rb") as key_file:
                    key_data = key_file.read()
                    # Get the RSA key
                    self.key = crypto.load_publickey(
                        crypto.FILETYPE_PEM, key_data)
                    
                    # Get the number
                    public_num = self.key.to_cryptography_key().public_numbers()
                    
                    modulus = public_num.n
                    public_exp = public_num.e
                    
                    # Convert from binary to decimal
                    self.mod = int.from_bytes(modulus.to_bytes((modulus.bit_length() + 7) // 8, 'big'), 'big')
                    self.pub_exp = int.from_bytes(public_exp.to_bytes((public_exp.bit_length() + 7) // 8, 'big'), 'big')
                
                # Readable data    
                self.data = crypto.dump_publickey(
                    crypto.FILETYPE_PEM, self.key
                ).decode("utf-8")
                
                self.length = len(self.data)
                self.priv_exp = None
                
            except Exception as e:
                print("Public key reading failed")
                print(e)
        else:
            print("You can't overwrite this key")
        
    def RSA_v1_5_encrypt(self, plainfile, cipherfile):
        if self.type == CryptoType.Public_RSA_key:
            try:
                # Read file
                with open(plainfile, "rb") as plain_file:
                    plain_data = plain_file.read()
                
                #Import values
                cipher_text = None
                plain_length = len(plain_data)
                pub_key = RSA.import_key(self.data)
                pub_data = PKCS1_v1_5.new(key = pub_key)
                modBits = number.size(pub_data._key.n)
                # Condition check
                k = number.ceil_div(modBits, 8)
                chunk_length = k - 11 # RFC 8017
                
                if plain_length <= chunk_length:
                    # Encrypt
                    cipher_text = pub_data.encrypt(plain_data)
                    with open(cipherfile, "wb") as cipher_file:
                        cipher_file.write(cipher_text)
                    print("Data encrypted")
                    
                else:
                    print("Plaintext is too long")
            except Exception as e:
                print("Encryption failed")
                print(e)
        else: 
            print("This is not a public RSA key. You can't use this method.\n")
    
    def RSA_v1_5_decrypt(self, cipherfile, plainfile):
        if self.type == CryptoType.Private_RSA_key:
            try:
                # Read files
                with open(cipherfile, "rb") as cipher_file:
                    cipher_data = cipher_file.read()
    
                # Import values
                plain_text = None
                cipher_length = len(cipher_data)
                priv_key = RSA.import_key(self.data)
                priv_data = PKCS1_v1_5.new(key = priv_key)
                # Condition check
                modBits = number.size(priv_data._key.n)
                k = number.ceil_div(modBits, 8) # RFC 8017
                
                if cipher_length == k and k >= 11:
                    # Decrypt
                    plain_text = priv_data.decrypt(cipher_data, sentinel = str)
                    with open(plainfile, "wb") as plain_file:
                        plain_file.write(plain_text)
                    print("Cipher decrypted")
                        
                else:
                    print("Ciphertext's length is incorrect")
                    print(f"Cipher length: {cipher_length}")
                    print(f"Expected: {k}")
            except Exception as e:
                print("Decryption failed")
                print(e)
            
        else:
            print("This is not a private RSA key. You can't use this method.\n")
      
    def RSA_v1_5_sign(self, messagefile, signaturefile):
        if self.type == CryptoType.Private_RSA_key:
            try:
                #Read files
                with open(messagefile, "rb") as message_file:
                    message_data = message_file.read()

                #Import values
                message_length = len(message_data)
                priv_key = RSA.import_key(self.data)
                priv_data = PKCS1_v1_5.new(key = priv_key)
                modBits = number.size(priv_data._key.n)
                k = number.ceil_div(modBits, 8)
                
                if message_length <= k - 11:
                    priv_sign = RSA.import_key(self.data)
                    signer = pkcs1_15.new(priv_sign)
                    
                    digest = SHA256.new()
                    digest.update(message_data)
                    signature = signer.sign(digest)
                    
                    with open(signaturefile, "wb") as signature_file:
                        signature_file.write(signature)
                    print("Signing completed")
                
                else:
                    print("Signing failed")
            except Exception as e:
                print("Signing failed")
                print(e)
        else:
            print("This is not a private RSA key. You can't use this method.\n")
    
    def RSA_v1_5_verify(self, messagefile, signaturefile):
        if self.type == CryptoType.Public_RSA_key:
            try:
                with open(messagefile, "rb") as message_file:
                    message_data = message_file.read()
                
                with open(signaturefile, "rb") as signature_file:
                    signature = signature_file.read()
                
                pub_key = RSA.import_key(self.data)
                verifier = pkcs1_15.new(pub_key)
                digest = SHA256.new()
                digest.update(message_data)
            
                valid = verifier.verify(digest, signature)
                print("Signature verified successfully")
            except Exception as e:
                print("Verification failed")
                print(e)
            
        else:
            print("This is not a public RSA key. You can't use this method.\n")