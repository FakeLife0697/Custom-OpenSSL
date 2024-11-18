import os
from customOpenSSL import custom_Key_OpenSSL

def main():
    try:
        menu = True
        key = custom_Key_OpenSSL()
        while menu:
            os.system("cls || clear")
            print("Custom OpenSSL")
            print("--------------------------------")
            print("1. Read public key")
            print("2. Read private key")
            print("3. RSA Encrypt")
            print("4. RSA Decrypt")
            print("5. RSA Sign")
            print("6. RSA Verify")
            print("7. Read file")
            print("8. Key info")
            print("0. Exit")
            print("--------------------------------")
            print("(Press Ctrl+C to abort any further processing)")
            
            choice = int(input("Your choice: "))
            if choice == 1:
                public_key_file = str(input("Public key file: "))
                overwrite = bool(int(input("Overwrite? (1: yes/ 0: no): ")))
                key.readPublicPem(public_key_file, overwrite)
            elif choice == 2:
                private_key_file = str(input("Private key file: "))
                overwrite = bool(int(input("Overwrite? (1: yes/ 0: no): ")))
                key.readPrivatePem(private_key_file, overwrite)
            elif choice == 3:
                plain_file = str(input("Plain file: "))
                cipher_file = str(input("Cipher file: "))
                key.RSA_v1_5_encrypt(plain_file, cipher_file)
            elif choice == 4:
                cipher_file = str(input("Cipher file: "))
                plain_file = str(input("Plain file: "))
                key.RSA_v1_5_decrypt(cipher_file, plain_file)
            elif choice == 5:
                plain_file = str(input("Plain file: "))
                sign_file = str(input("Sign file: "))
                key.RSA_v1_5_sign(plain_file, sign_file)
            elif choice == 6:
                plain_file = str(input("Plain file: "))
                sign_file = str(input("Sign file: "))
                key.RSA_v1_5_verify(plain_file, sign_file)
            elif choice == 7:
                file = str(input("File: "))
                with open(file, "rb") as f:
                    content = f.read()
                print("Content:")
                print(content)
            elif choice == 8:
                key.detail_info()
            elif choice == 0:
                os.system("cls || clear")
                print("Exited")
                menu = False
            else:
                print("Invalid choice. Try again.")
                
            input("Press Enter to continue...")
            
    except Exception as e:
        print("Aborted")
        print(e)
    except KeyboardInterrupt:
        print("Aborted")

if __name__ == "__main__":
    main()