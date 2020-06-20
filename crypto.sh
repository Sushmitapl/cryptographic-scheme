#!/bin/bash

#Check the option passed are present

encryption(){
  # Checking if all the inputs are provided
  if [ -n "$1" ] && [ -n "$2" ] && [ -n "$3" ] && [ -n "$4" ]; then
    # Checking if the first input file is receiver's public key
	  if [[ "$1" == *"PUBLIC"* ]] || [[ "$1" == *"public"* ]]; then
	    # Checking if the second input file is sender's private key.
		  if [[ "$2" == *"PRIVATE"* ]] || [[ "$2" == *"private"* ]];then
  			receiver_public_key_file=$1;
        receiver_public_key=$(cat "$receiver_public_key_file");
	      sender_private_key_file=$2;
	      sender_private_key=$(cat "$sender_private_key_file");
	      plaintext_file=$3;
	      encrypted_file=$4;

  			# Generate random session Key
  			echo "Generating random session key..."
				gen_session_key;

				# Read the session key of the file
				session_key_file=sessionKey.key;
				session_key=$(cat "$session_key_file");

				# Encrypt the file symmetrically using the session Key
				echo "Encrypting the file..."
				encrypt_file $plaintext_file $encrypted_file $session_key;

				# Encrypt the Session Key with the Public key of the recipient
				echo "Encrypting the session key..."
        encrypt_session $session_key $receiver_public_key_file;

				# Sign the encrypted File with the Private Key of the sender
				echo "Signing the encrypted file..."
				sign_enc_file $sender_private_key_file $encrypted_file;

				#compress all the files generated
				echo "Compressing the files..."
        gen_tar_file $encrypted_file;

				#remove the files
				rm sessionKey.key "$encrypted_file" session_key_enc.out signed_file.sign

			else
  			echo "Sender's Private key is missing. Provide the Sender's Private key as the second input."
			fi
	  else
		  echo "Receiver's Public Key is missing. Provide the Receiver's Public Key as the first input."
		fi
	elif [ -n "$1" ] && [[ "$receiver_public_key" == *"PUBLIC"* ]]; then
	  if [ -n "$2" ]	&& [[ "$sender_private_key" == *"PRIVATE"* ]]; then
		  if [ -z "$3" ] || [ -z "$4" ]; then
			  echo "Plaintext or name of the encrypted file is missing."
			fi
		else
		  echo "Sender's Private key is missing. Provide the Sender's Private key as the second input."
		fi
	elif [ -n "$1" ] && [[ "$receiver_public_key" == *"PRIVATE"* ]]; then
	  echo "Receiver's Public Key is missing. Provide the Receiver's Public Key as the first input."
	fi
	exit
}

#Function to generate random session key
gen_session_key(){
  if !(openssl rand -hex 32 > sessionKey.key); then
	  echo "Error in generating the random number. Aborting !!!"
		exit 1
	else
	  echo "Successfully generated the session key."
	fi
}

#Fucntion to encrypt the file
encrypt_file(){
  plaintext_file=$1;
  encrypted_file=$2;
  session_key=$3;
  # OpenSSL Command to encrypt the plaintext file using session key as password
  if !(openssl enc -e -aes-256-cfb -pbkdf2 -iter 100000 -in "$plaintext_file" -out "$encrypted_file" -k "$session_key"); then
    echo "Error while Encrypting the file. Aborting !!!"
		exit 1
	else
	  echo "Succesfully Encrypted the file!!"
	fi
}

#Function to encrypt the session key
encrypt_session(){
  session_key=$1;
  receiver_public_key_file=$2;
  # OpenSSL command to encrypt the session key using the receiver's public key and save it in session_key_enc.out
  if ! (echo "$session_key" |openssl rsautl -encrypt -pubin -inkey "$receiver_public_key_file" > session_key_enc.out); then
	  echo "Error in encrypting the session key. Aborting !!!"
		exit 1
	else
	  echo "Succesfully encrypted the session key."
	fi
}

#Fucntion to sign the encrypted function
sign_enc_file(){
  sender_private_key_file=$1;
  encrypted_file=$2;
  # OpenSSL command to sign the encrypted file using sender's private key and generate the signed file as signed_file.sign
  if !(openssl dgst -sha512 -sign "$sender_private_key_file" -out "signed_file.sign" "$encrypted_file"); then
	  echo "Error in signing the encrypted file. Aborting !!!"
		exit 1
	else
	  echo "Succesfully signed the encrypted file."
	fi
}

#Fucntion to compress all the files
gen_tar_file(){
  encrypted_file=$1;
  #compress all the files - session key, encrypted file, encrypted session key, signed file
  echo "Performing comression on the following files: "
  if ! (tar -czvf crypto_file.tar "$encrypted_file" session_key_enc.out signed_file.sign); then
    echo "Error while compressing the files. Aborting !!!"
		exit 1
	else
	  echo "Compressed all the files in crypto_file.tar."
	fi
}

# Decryption Function
decryption(){
  # Checking if all the inputs are provided
  if [ -n "$1" ] && [ -n "$2" ] && [ -n "$3" ] && [ -n "$4" ]; then
		# Checking if the first input file is receiver's private key
	  if [[ "$1" == *"PRIVATE"* ]] || [[ "$1" == *"private"* ]]; then
	    # Checking if the second input file is sender's public key.
		  if [[ "$2" == *"public"* ]] || [[ "$2" == *"PUBLIC"* ]]; then
        receiver_private_key_file=$1;
		    receiver_private_key=$(cat "$receiver_private_key_file");
		    sender_public_key_file=$2;
		    sender_public_key=$(cat "$sender_public_key_file");
		    decrypted_file=$4;
        #Extract encrypted session key and signed files from tar
				echo "Extracting the required files..."
				extract_tar $3;

				# Decrypt the session Key with the private Key of the recipient
				echo "Decrypting the session key..."
				decrypt_session_key $receiver_private_key_file;

				# Verify the Signature using public key of the sender
				echo "Enter the encrypted file name:"
				read encrypted_file
				echo "File name inside decryption function : $encrypted_file"
				echo "Verifying the signature..."
        verify_sign $sender_public_key_file $encrypted_file;

				# Get the Session Key and decrypt the file
				echo "Decrypting the encrypted file..."
				decrypt_file $encrypted_file $decrypted_file;

				#remove the files
				rm session_key_enc.out session_key_dec.out signed_file.sign

			else
			  echo "Sender's Public key is missing. Provide the Sender's Public key as the second input."
			fi

		else
		  echo "Receiver's Private Key is missing. Provide the Receiver's Private Key as the first input."
		fi
	fi
}

# Function to extract files from crypto.tar
extract_tar(){
  crypto_file=$1
  # Check if the crypto_file.tar exists
	if [ -f "$crypto_file" ]; then
	  #Extract the files from tar.
	  if !(tar -xzvf $crypto_file); then
		  echo "Error in extracting the files from crypto_file.tar. Aborting !!!"
			exit 1
		else
		  echo "Succesfully extracted the files from crypto_file.tar."
		fi
	fi
}

#Function to decrypt the session key extracted for crypto.tar
decrypt_session_key(){
  session_file_enc=session_key_enc.out
  receiver_private_key_file=$1;
  #Check if the encrypted session key exists
  if test -f "$session_file_enc"; then
    #OpenSSL command to decrypt the session key using receiver private key.
    if !(openssl rsautl -decrypt -inkey "$receiver_private_key_file" -in session_key_enc.out -out session_key_dec.out); then
	    echo "Error in decrypting the session key. Might be due to incorrect receiver's private key or session key. Aborting !!!"
		  exit 1;
		else
		  echo "Successfully decrypted the session key."
		fi
	else
	  echo "Session Key is missing."
	fi
}

#Function to verify the signature of the sender using sender's public key
verify_sign(){
  signed_file=signed_file.sign
  sender_public_key_file=$1;
  encrypted_file=$2;
  echo "File in verify_sign function : $encrypted_file"
  #Check if the sign file exists
	if test -f "$signed_file"; then
	  # OpenSSL command to verify the signed encrypted file
	  if !(openssl dgst -sha512 -verify "$sender_public_key_file" -signature "signed_file.sign" "$encrypted_file"); then
		  echo "Error in verifying the signature. Aborting !!!"
			exit 1;
		else
		  echo "File Verified OK !!!"
		fi
	else
	  echo "Signed file is missing !!!  "
	fi
}

#Function to decrypt the file
decrypt_file(){
  session_key_file=session_key_dec.out;
  encrypted_file=$1;
  decrypted_file=$2;
	# Check if the session key file exists
	if test -f "$session_key_file"; then
	  session_key=$(cat "$session_key_file");	#session key retreived from the file
		# OpenSSL command to decrypt the encrypted file.
		if !(openssl enc -d -aes-256-cfb -pbkdf2 -iter 100000 -in "$encrypted_file" -out "$decrypted_file" -k "$session_key"); then
		  echo "Error while Decrypting the file. Aborting !!!"
			exit 1;
		else
		  echo "Succesfully decrypted the input file."
		fi
	else
	  echo "Couldn't find the session key. Aborting !!!"
		exit 1;
	fi
}

# Main Function
main(){
  # check the option is encryption or decryption
  if [ -n "$1" ]; then
    case "$1" in
      -e)
        if [ -n "$2" ] && [ -n "$3" ] && [ -n "$4" ] && [ -n "$5" ]; then
          encryption $2 $3 $4 $5
        else
          echo "Provide all the inputs in the form of ./crypto.sh -e <receiver's public key> <sender's private key> <plain-text file> <name of the encrypted file> in case of encryption"
        fi
        ;;
      -d)
        if [ -n "$2" ] && [ -n "$3" ] && [ -n "$4" ] && [ -n "$5" ]; then
          decryption $2 $3 $4 $5
        else
          echo "Provide all the inputs in the form of ./crypto.sh -d <receiver's private key> <sender's public key> <crypto_file.tar> <name of the plain-text file> in case of decryption"
        fi
        ;;
      *)
			  echo "Option is missing. Please provide -e for encryption or -d for decryption."
			  exit 1
			  ;;
	  esac
  else
    echo "Provide inputs in the form of ./crypto.sh -e <receiver's public key> <sender's private key> <plain-text file> <name of the encrypted file> in case of encryption or Provide inputs in the form of ./crypto.sh -d <receiver's private key> <sender's public key> <crypto_file.tar> <name of the plain-text file> in case of decryption"
  fi
}

main $1 $2 $3 $4 $5;



