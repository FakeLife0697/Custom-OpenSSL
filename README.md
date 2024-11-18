Before using the program, run these commands on your terminal at Source folder
```pip install pipreqs```
```pipreqs --encoding utf-8 --force```
```pip install -r "./requirements.txt"```
To start the program:
```py "./src/main.py"```
To generate the RSA private key:
```openssl genpkey -out priv.pem -algorithm RSA -pkeyopt rsa_keygen_bits:4096```
To generate the RSA public key:
```openssl pkey -in priv.pem -out pub.pem -pubout```
To encrypt file:
```openssl pkeyutl -in plain.txt -out cipher.txt -inkey pub.pem -pubin -encrypt```
To decrypt file:
```openssl pkeyutl -in cipher.txt -out plain2.txt -inkey priv.pem -decrypt```
To sign file using RSA:
```openssl pkeyutl -in plain.txt -out sign.sig -inkey priv.pem -sign```
To verify the signature:
```openssl pkeyutl -in plain.txt -sigfile sign.sig -inkey pub.pem -pubin -verify```
