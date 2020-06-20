# Cryptographic Scheme
The goal of the project is to develop an efficient cryptographic scheme to provide confidentiality, integrity, and authenticity. The tool encrypt the file provided by the user, hash the encrypted file and sign the hash. On receiver's end, the tool will verify the signature to check the integrity of the file, that is, not being modified while in transit and if the verification is successful, the tool will proceed to decrypt the encrypted file.

## Getting Started
To start with the process, a public-private key pair needs to be generated using asymmetric algorithm such as RSA with 4096-bit key as shown below:
```
openssl genrsa -out privateKey.pem 4096
```
Above openssl command will generate private and public RSA key in the file privateKey.pem. To separate the public key from the private key, below shown command can be used:
```
openssl rsa -in privateKey.pem -outform PEM -pubout -out publicKey.pem
```
The public key can be shared to use it for encryption and verifying the sender's signature of the encrypted file.


### Encryption
To perform encryption, the tool needs receiver's public key, sender's private key, file to be encrypted and name of the encrypted file as per the user.
Use below shown command for encryption:
```
./crypto.sh -e <receiver's_public_key> <sender's_private_key> <file_to_be_encrypted> <name_of_the_encrypted_file>
```
This will generate crypto_file.tar which consists of the encrypted file, signed hash file and encrypted session key.


### Decryption
To perform the decryption, the tool needs receiver's private key, sender's public key, tar file, and name of the file after decryption.
Use below shown command for decryption:
```
./crypto.sh -d <receiver's_private_key> <sender's_public_key> <crypto_file.tar> <name_of_the_file_after_decryption>
```
It will prompt user to provide the encrypted file name after extracting the file from crypto_file.tar. Provide the name of the encrypted file when asked as "Enter the encrypted file name:".
Once it receives the name of the encrypted file name, the tool will verify the signature and decrypt the file.

## Options
   -e: encryption\
   -d: decryption

