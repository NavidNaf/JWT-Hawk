# JWT-Hawk

![JWT-Hawk](jwt-hack.png)

## Description
JWT-Hawk is a Python tool used for decoding JWT tokens by trying multiple secrets from a provided list. It extracts and prints the header values and payload values (if the secret matches) of a given JWT token. 

### Enhancements in Version 2.0:
- Added support for processing JWT tokens with 'alg' set to 'none' using the [none] mode.
- Implemented a brute-force decoding mode that allows users to attempt to decode JWT tokens using a list of secrets.
- Improved user interaction by providing clear usage instructions and examples.
- Updated dependencies to use `colorama` and `rich` for better console output.

## Dependencies
- `jwt`
- `colorama`
- `rich`

## Usage
1. Clone the repository: `git clone https://github.com/NavidNaf/JWT-Hawk`
2. Change the directory: `cd JWT-Hawk`
3. Install the dependencies: `pip3 install -r requirements.txt`
4. Create a file with the list of secrets that you want to try.
5. Run the script: `python3 jwt_hawk.py <mode> [options]`
   - `<mode>` can be:
     - [none](cci:1://file:///Users/navidfazle.rabbi/Documents/Project/smithy-visualizer/JWT-Hawk/jwt-hawk.py:24:0-40:42): Process a JWT token with 'alg' set to 'none'.
     - `brute`: Attempt to brute-force decode a JWT token using a list of secrets.
   - For brute mode, provide the secrets file as an additional argument: `python3 jwt_hawk.py brute <secrets_file>`
   - For none mode, enter the JWT token when prompted: `python3 jwt_hawk.py none`
6. The tool will attempt to decode the JWT token using the specified method.

## Examples
- To process a JWT token with 'alg' set to 'none':
  ```bash
  python3 jwt_hawk.py none
- To brute-force decode a JWT token using a list of secrets:
  ```bash
  python3 jwt_hawk.py brute sample-secrets.txt

