"""
JWT-Hawk

Description:
This tool is used for decoding JWT tokens by trying multiple secrets from a provided list.

Usage:
python3 jwt_hawk.py <secrets_file>

Dependencies:
- jwt
- termcolor
- pyfiglet

Created by:
DL28 (NavidNaf)

Last Modified:
[date]

"""

import jwt
import sys
from termcolor import colored
import pyfiglet

# Extract and Print the Header Values
def JWTHeaderExtract(jwt_token):
    print("[##] JWT Header Values:\n")
    jwt_header = jwt.get_unverified_header(jwt_token)
    for Hkey, Hvalue in jwt_header.items():
            print(colored(f"{Hkey} ---- {Hvalue}", "green"))

# Extract and Print the Payload Valus, if the Secret matches
def JWTPayloadwithSecret(jwt_token, secretsList):
    for i in secretsList:
        try:
            decoded_payload = jwt.decode(jwt_token, i, algorithms=["HS256"])
            print("\n[##] JWT Payload Values:\n")
            for key,value in decoded_payload.items():
                    print(colored(f"{key} ---- {value}", "green"))
            print("\n[##] JWT Decoded Signature:\n")
            print(colored(f"{i}", "red"))
            return 1
        except:
            continue

# Prompt user for JWT token input and file name of secret list        
def main():
    try:
        jwt_token = input("JWT Token: ")
        file_name = sys.argv[1]

        with open(file_name) as secretFile:
            secretsList = secretFile.readlines()
        print(f"Total Secrets to be attempted: {len(secretsList)}\n") 
        
        JWTHeaderExtract(jwt_token=jwt_token)
        affirm = JWTPayloadwithSecret(jwt_token=jwt_token, secretsList=secretsList)
        if affirm == 1:
            pass
        else:
            print("[##] JWT Decoded Signature:")
            print(colored(f"Sorry, Did not find any Secret to Decode.","red"))
    except:
        pass

if __name__ == "__main__":
    # Print the name of the tool using pyfiglet
    text = pyfiglet.figlet_format("JWT-Hawk", font="slant")
    print(text)
    print("Created by DL28 (NavidNaf)")
    print("navidfazlerabbi@iut-dhaka.edu")
    print("\n")
    main()