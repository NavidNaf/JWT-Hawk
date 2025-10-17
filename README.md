# JWT-Hawk

![JWT-Hawk](jwt-hack.png)

## Description
JWT-Hawk is a Python tool used for decoding JWT tokens by trying multiple secrets from a provided list. It extracts and prints the header values and payload values (if the secret matches) of a given JWT token. 

### Release Notes
| Version | Change Type | Details |
| --- | --- | --- |
| 2.3 | Enhancement | Added a standalone Tkinter GUI (`gui/jwt_hawk_gui.py`) covering the `none` and `brute` workflows with inline status output and secrets-file picker. |
| 2.3 | Enhancement | Centralized the “RedHawks Cyber Research Tool by DL28” author attribution so both CLI and GUI share the same banner text. |
| 2.2 | Enhancement | Added a `--token` CLI option so brute-force runs can supply JWTs non-interactively. |
| 2.2 | Enhancement | Ignores blank secrets and trims whitespace once to speed up brute-force wordlists. |
| 2.1 | Enhancement | Brute-force mode now auto-detects the JWT header’s HMAC algorithm and falls back to common HS variants when the header is silent. |
| 2.1 | Bug Fix | Ignores `exp`, `nbf`, and `iat` claim failures during brute force and reports malformed headers instead of aborting. |
| 2.0 | Enhancement | Added the `none` mode for processing tokens with the `alg` header set to `none`. |
| 2.0 | Enhancement | Introduced the brute-force mode for testing multiple shared secrets. |
| 2.0 | Enhancement | Improved console UX and project documentation, and adopted `colorama`/`rich` for styled output. |

## Dependencies
- `jwt`
- `colorama`
- `rich`
- `tkinter` (bundled with most Python installations; required for the GUI)

## Usage
1. Clone the repository: `git clone https://github.com/NavidNaf/JWT-Hawk`
2. Change the directory: `cd JWT-Hawk`
3. Install the dependencies: `pip3 install -r requirements.txt`
4. Create a file with the list of secrets that you want to try.
5. Run the script: `python3 jwt-hawk.py <mode> [options]`
   - `<mode>` can be:
     - `none`: Process a JWT token with 'alg' set to 'none'.
     - `brute`: Attempt to brute-force decode a JWT token using a list of secrets.
   - For brute mode, provide the secrets file as an additional argument: `python3 jwt-hawk.py brute <secrets_file>`
   - Optionally supply the JWT inline to brute mode: `python3 jwt-hawk.py brute <secrets_file> --token <jwt>`
   - For none mode, enter the JWT token when prompted: `python3 jwt-hawk.py none`
6. The tool will attempt to decode the JWT token using the specified method.

## GUI Usage
1. Ensure the dependencies above are installed and that your Python build includes `tkinter`.
2. Launch the GUI: `python3 gui/jwt_hawk_gui.py`
3. Pick a mode (`none` or `brute`) from the dropdown.
4. Paste the JWT token into the token field.
5. For brute mode, use **Browse…** to select your secrets wordlist.
6. Click **Run** to view the decoded header/payload or the rewritten token in the output panel.

## Examples
- To process a JWT token with 'alg' set to 'none':
  ```bash
  python3 jwt-hawk.py none
  ```
- To brute-force decode a JWT token using a list of secrets:
  ```bash
  python3 jwt-hawk.py brute sample-secrets.txt
  ```
- To brute-force decode non-interactively:
  ```bash
  python3 jwt-hawk.py brute sample-secrets.txt --token <jwt>
  ```
