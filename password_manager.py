#!/usr/bin/env python3
"""
Syntecxhub Cyber Security Internship - Project 2: Local Password Manager (v2)

Security
  * Master password -> 256-bit key with scrypt (slow, salted key derivation)
  * AES-256-GCM encryption (secret + tamper detection), fresh nonce on every save
  * Everything (site names, usernames, passwords, notes) is inside the encrypted blob
  * Atomic saves, owner-only file permission, automatic .bak backup

Features
  * init, add, get, delete, search, list
  * password strength check, random password generator
  * audit: finds weak, reused and old passwords
  * change-master: re-encrypts the vault with a new master password
  * get --copy: copy to clipboard and clear it automatically
  * shell: interactive mode that unlocks once and auto-locks when idle
  * 3 attempts with growing delay when the master password is wrong

Requires:  pip install cryptography   (optional: pyperclip for --copy)
"""

import argparse
import base64
import cmd
import getpass
import hmac
import json
import math
import os
import secrets
import shlex
import shutil
import string
import sys
import tempfile
import time
from datetime import datetime

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VAULT_VERSION = 1
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1  # key-derivation cost
KEY_LEN = 32  # 32 bytes = AES-256
DEFAULT_VAULT = "vault.json"
MIN_MASTER_LEN = 8
SYMBOLS = "!@#$%^&*-_=+"
OLD_AFTER_DAYS = 180

COMMON_PASSWORDS = {
    "password",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "abc123",
    "letmein",
    "111111",
    "iloveyou",
    "admin",
    "welcome",
    "monkey",
    "dragon",
    "password1",
    "qwerty123",
    "football",
    "baseball",
    "sunshine",
    "princess",
    "login",
    "passw0rd",
    "master",
    "hello",
    "freedom",
    "whatever",
    "trustno1",
    "000000",
    "1q2w3e4r",
    "zaq12wsx",
    "admin123",
    "p@ssw0rd",
    "changeme",
    "secret",
}


class VaultError(Exception):
    """Any problem with the vault (missing file, bad input, ...)."""


class WrongPassword(VaultError):
    """Master password is wrong (or the file was changed)."""


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def derive_key(password: str, salt: bytes, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P) -> bytes:
    """Master password + salt -> 32-byte key."""
    return Scrypt(salt=salt, length=KEY_LEN, n=n, r=r, p=p).derive(password.encode("utf-8"))


# --------------------------------------------------------------------------
# Password tools
# --------------------------------------------------------------------------
def password_strength(pw: str) -> dict:
    """Estimate strength. Returns {"entropy": bits, "label": str, "tips": [..]}."""
    if not pw:
        return {"entropy": 0.0, "label": "Very weak", "tips": ["Password is empty."]}
    lower = any(c.islower() for c in pw)
    upper = any(c.isupper() for c in pw)
    digit = any(c.isdigit() for c in pw)
    other = any(not c.isalnum() for c in pw)
    pool = 26 * lower + 26 * upper + 10 * digit + 33 * other
    entropy = len(pw) * math.log2(pool)

    low = pw.lower()
    if len(set(pw)) < len(pw) / 2:  # lots of repeated characters
        entropy *= 0.5
    if any(seq in low for seq in ("1234", "abcd", "qwer", "asdf", "0000", "1111")):
        entropy *= 0.6
    if low in COMMON_PASSWORDS or low.rstrip(string.digits + SYMBOLS) in COMMON_PASSWORDS:
        entropy = min(entropy, 10.0)

    tips = []
    if len(pw) < 12:
        tips.append("Use at least 12 characters.")
    if not (lower and upper):
        tips.append("Mix upper and lower case letters.")
    if not digit:
        tips.append("Add numbers.")
    if not other:
        tips.append("Add symbols like ! @ # $.")
    if entropy <= 10.0 and (
        low in COMMON_PASSWORDS or low.rstrip(string.digits + SYMBOLS) in COMMON_PASSWORDS
    ):
        tips.insert(0, "This is a very common password. Never use it.")

    label = (
        "Very weak"
        if entropy < 28
        else "Weak"
        if entropy < 36
        else "Fair"
        if entropy < 60
        else "Strong"
        if entropy < 80
        else "Very strong"
    )
    return {"entropy": round(entropy, 1), "label": label, "tips": tips}


def is_weak(pw: str) -> bool:
    return password_strength(pw)["label"] in ("Very weak", "Weak")


def generate_password(length=16, symbols=True) -> str:
    """Random password using the secrets module (safe for security use)."""
    if length < 8:
        raise VaultError("Password length must be at least 8.")
    extra = SYMBOLS if symbols else ""
    alphabet = string.ascii_letters + string.digits + extra
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pw)
            and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw)
            and (not symbols or any(c in SYMBOLS for c in pw))
        ):
            return pw


def copy_to_clipboard(text, clear_after=20, sleep=time.sleep, say=print):
    """Copy text, wait, then clear the clipboard (only if we still own it)."""
    try:
        import pyperclip
    except ImportError:
        raise VaultError("Clipboard needs pyperclip:  pip install pyperclip") from None
    try:
        pyperclip.copy(text)
    except Exception as exc:  # no clipboard on this system
        raise VaultError(f"Clipboard not available: {exc}") from None
    say(f"Password copied. Clipboard will be cleared in {clear_after}s (Ctrl+C = clear now).")
    try:
        sleep(clear_after)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if pyperclip.paste() == text:
                pyperclip.copy("")
                say("Clipboard cleared.")
        except Exception:
            pass


# --------------------------------------------------------------------------
# Vault
# --------------------------------------------------------------------------
class Vault:
    """Encrypted password store. Entries are in memory only while unlocked."""

    def __init__(self, path=DEFAULT_VAULT):
        self.path = path
        self.entries = {}  # {site: {"username","password","notes","updated"}}
        self._salt = None
        self._key = None

    # ----- create / open -----
    def create(self, master_password: str):
        if os.path.exists(self.path):
            raise VaultError(f"'{self.path}' already exists. Move or delete it first.")
        self._check_master_rules(master_password)
        self._salt = secrets.token_bytes(16)
        self._key = derive_key(master_password, self._salt)
        self.entries = {}
        self.save()

    def open(self, master_password: str):
        try:
            with open(self.path, encoding="utf-8") as f:
                doc = json.load(f)
        except FileNotFoundError:
            raise VaultError(f"No vault found at '{self.path}'. Run 'init' first.") from None
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise VaultError("Vault file is damaged (not valid JSON).") from None

        try:
            if doc["version"] != VAULT_VERSION:
                raise VaultError("Unsupported vault version.")
            kdf = doc["kdf"]
            salt = b64d(doc["salt"])
            key = derive_key(master_password, salt, kdf["n"], kdf["r"], kdf["p"])
            nonce, blob = b64d(doc["nonce"]), b64d(doc["ciphertext"])
        except (KeyError, TypeError, ValueError):
            raise VaultError("Vault file is damaged (missing or bad fields).") from None

        try:
            plain = AESGCM(key).decrypt(nonce, blob, self._header_bytes())
        except InvalidTag:
            raise WrongPassword("Wrong master password, or the vault file was changed.") from None
        self._salt, self._key = salt, key
        self.entries = json.loads(plain.decode("utf-8"))

    @staticmethod
    def _check_master_rules(pw):
        if len(pw) < MIN_MASTER_LEN:
            raise VaultError(f"Master password must be at least {MIN_MASTER_LEN} characters.")
        if is_weak(pw):
            raise VaultError(
                "Master password is too weak. Use a longer passphrase with mixed characters."
            )

    def verify_master(self, master_password: str) -> bool:
        """Check a typed master password against the unlocked key."""
        if self._key is None:
            return False
        return hmac.compare_digest(derive_key(master_password, self._salt), self._key)

    def change_master(self, new_password: str):
        """Re-encrypt the whole vault with a new master password and new salt."""
        if self._key is None:
            raise VaultError("Vault is locked.")
        self._check_master_rules(new_password)
        self._salt = secrets.token_bytes(16)
        self._key = derive_key(new_password, self._salt)
        self.save()
        try:  # the .bak is still encrypted with the OLD password
            os.remove(self.path + ".bak")
        except OSError:
            pass

    # ----- save -----
    @staticmethod
    def _header_bytes() -> bytes:
        # Authenticated (not secret) data: changing it breaks decryption.
        return f"syntecxhub-vault-v{VAULT_VERSION}".encode()

    def save(self):
        if self._key is None:
            raise VaultError("Vault is locked.")
        nonce = secrets.token_bytes(12)  # new random nonce on every save
        plain = json.dumps(self.entries).encode("utf-8")
        blob = AESGCM(self._key).encrypt(nonce, plain, self._header_bytes())
        doc = {
            "version": VAULT_VERSION,
            "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
            "salt": b64e(self._salt),
            "nonce": b64e(nonce),
            "ciphertext": b64e(blob),
        }
        if os.path.exists(self.path):  # keep the previous version as a backup
            try:
                shutil.copy2(self.path, self.path + ".bak")
            except OSError:
                pass
        # Write to a temp file, then replace: a crash cannot leave a half-written vault.
        folder = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(dir=folder, prefix=".vault-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=2)
            try:
                os.chmod(tmp, 0o600)  # owner read/write only (ignored on Windows)
            except OSError:
                pass
            os.replace(tmp, self.path)
        except Exception:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise

    # ----- operations -----
    def add(self, site, username, password, notes="", overwrite=False):
        if not site or not site.strip():
            raise VaultError("Site name cannot be empty.")
        if not password:
            raise VaultError("Password cannot be empty.")
        if site in self.entries and not overwrite:
            raise VaultError(f"'{site}' already exists. Use --overwrite to replace it.")
        self.entries[site] = {
            "username": username,
            "password": password,
            "notes": notes,
            "updated": datetime.now().isoformat(timespec="seconds"),
        }
        self.save()

    def get(self, site):
        if site not in self.entries:
            raise VaultError(f"No entry named '{site}'.")
        return self.entries[site]

    def delete(self, site):
        if site not in self.entries:
            raise VaultError(f"No entry named '{site}'.")
        del self.entries[site]
        self.save()

    def search(self, text):
        text = text.lower()
        return sorted(
            site
            for site, e in self.entries.items()
            if text in site.lower()
            or text in e["username"].lower()
            or text in e.get("notes", "").lower()
        )

    def audit(self, old_after_days=OLD_AFTER_DAYS, now=None):
        """Find weak, reused and old passwords."""
        now = now or datetime.now()
        weak = sorted(s for s, e in self.entries.items() if is_weak(e["password"]))
        groups = {}
        for site, e in self.entries.items():
            groups.setdefault(e["password"], []).append(site)
        reused = sorted(sorted(sites) for sites in groups.values() if len(sites) > 1)
        old = []
        for site, e in self.entries.items():
            try:
                age = (now - datetime.fromisoformat(e["updated"])).days
            except (KeyError, ValueError):
                continue
            if age > old_after_days:
                old.append(site)
        return {"weak": weak, "reused": reused, "old": sorted(old)}


# --------------------------------------------------------------------------
# Interactive shell
# --------------------------------------------------------------------------
class VaultShell(cmd.Cmd):
    """Unlock once, then run many commands. Locks again after idle_limit seconds."""

    intro = "Syntecxhub vault shell. Type 'help' for commands, 'quit' to lock and exit."
    prompt = "vault> "

    def __init__(self, vault, idle_limit=300, stdout=None, ask=None, read_secret=None):
        super().__init__(stdout=stdout)
        self.use_rawinput = stdout is None
        self.vault = vault
        self.idle_limit = idle_limit
        self.ask = ask or (lambda: getpass.getpass("Master password (locked): "))
        self.read_secret = read_secret or getpass.getpass
        self.last_activity = time.monotonic()

    def say(self, text=""):
        self.stdout.write(text + "\n")

    def precmd(self, line):
        if line.strip() and time.monotonic() - self.last_activity > self.idle_limit:
            self.say("Locked after inactivity.")
            if not self.vault.verify_master(self.ask()):
                self.say("Wrong master password. Closing the vault.")
                return "quit"
        self.last_activity = time.monotonic()
        return line

    def onecmd(self, line):
        try:
            return super().onecmd(line)
        except VaultError as exc:
            self.say(f"Error: {exc}")
        except ValueError as exc:  # shlex problems (open quote, ...)
            self.say(f"Error: {exc}")
        return False

    def emptyline(self):
        return False

    def do_list(self, arg):
        "list: show all site names"
        sites = sorted(self.vault.entries)
        self.say("\n".join(sites) if sites else "Vault is empty.")

    def do_get(self, arg):
        "get <site>: show an entry"
        site = " ".join(shlex.split(arg))
        e = self.vault.get(site)
        self.say(f"Username: {e['username']}")
        self.say(f"Password: {e['password']}")
        if e.get("notes"):
            self.say(f"Notes:    {e['notes']}")
        self.say(f"Updated:  {e['updated']}")

    def do_add(self, arg):
        "add <site> <username>: add an entry (empty password = generate one)"
        parts = shlex.split(arg)
        if len(parts) != 2:
            self.say("Usage: add <site> <username>")
            return
        pw = self.read_secret("Entry password (empty = generate): ")
        if not pw:
            pw = generate_password()
            self.say(f"Generated password: {pw}")
        self.vault.add(parts[0], parts[1], pw)
        info = password_strength(pw)
        self.say(f"Saved '{parts[0]}'. Strength: {info['label']} ({info['entropy']} bits)")

    def do_delete(self, arg):
        "delete <site>: remove an entry"
        self.vault.delete(" ".join(shlex.split(arg)))
        self.say("Deleted.")

    def do_search(self, arg):
        "search <text>: find in site, username or notes"
        hits = self.vault.search(arg.strip())
        self.say("\n".join(hits) if hits else "No matches.")

    def do_audit(self, arg):
        "audit: find weak, reused and old passwords"
        for line in format_audit(self.vault.audit()):
            self.say(line)

    def do_generate(self, arg):
        "generate [length]: print a random password"
        self.say(generate_password(int(arg) if arg.strip() else 16))

    def do_quit(self, arg):
        "quit: lock the vault and leave"
        self.say("Vault locked.")
        return True

    do_exit = do_quit
    do_EOF = do_quit


def format_audit(report):
    lines = []
    if not any(report.values()):
        return ["Audit passed: no weak, reused or old passwords found."]
    if report["weak"]:
        lines.append(f"Weak passwords ({len(report['weak'])}): " + ", ".join(report["weak"]))
    for group in report["reused"]:
        lines.append("Reused password: " + ", ".join(group))
    if report["old"]:
        lines.append(
            f"Older than {OLD_AFTER_DAYS} days ({len(report['old'])}): " + ", ".join(report["old"])
        )
    return lines


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------
def ask_master(confirm=False, prompt="Master password: "):
    pw = getpass.getpass(prompt)
    if confirm and pw != getpass.getpass("Repeat master password: "):
        raise VaultError("Passwords do not match.")
    return pw


def unlocked(path, attempts=3, sleep=time.sleep):
    """Ask for the master password (3 tries, delay grows after each mistake)."""
    vault = Vault(path)
    if not os.path.exists(path):
        raise VaultError(f"No vault found at '{path}'. Run 'init' first.")
    for i in range(attempts):
        try:
            vault.open(ask_master())
            return vault
        except WrongPassword:
            if i == attempts - 1:
                raise WrongPassword("Too many wrong attempts.") from None
            wait = 2**i
            print(f"Wrong master password. Try again in {wait}s ({attempts - 1 - i} left).")
            sleep(wait)


def build_parser():
    p = argparse.ArgumentParser(description="Local encrypted password manager (AES-256-GCM).")
    p.add_argument("-f", "--file", default=DEFAULT_VAULT, help="vault file (default vault.json)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create a new vault")

    a = sub.add_parser("add", help="add an entry")
    a.add_argument("site")
    a.add_argument("username")
    a.add_argument(
        "--password",
        help="password (unsafe: stays in shell history; omit it to be asked, or use --generate)",
    )
    a.add_argument(
        "--generate",
        type=int,
        nargs="?",
        const=16,
        metavar="LENGTH",
        help="make a random password (default length 16)",
    )
    a.add_argument("--no-symbols", action="store_true", help="generated password without symbols")
    a.add_argument("--notes", default="")
    a.add_argument("--overwrite", action="store_true")

    g = sub.add_parser("get", help="show an entry")
    g.add_argument("site")
    g.add_argument("--hide", action="store_true", help="do not print the password")
    g.add_argument("--copy", action="store_true", help="copy password to clipboard (auto-clears)")
    g.add_argument("--clear-after", type=int, default=20, help="seconds before clipboard clears")

    d = sub.add_parser("delete", help="delete an entry")
    d.add_argument("site")

    s = sub.add_parser("search", help="search site / username / notes")
    s.add_argument("text")

    sub.add_parser("list", help="list all site names")
    sub.add_parser("audit", help="find weak, reused and old passwords")
    sub.add_parser("change-master", help="change the master password")
    sub.add_parser("shell", help="interactive mode (unlock once, auto-lock when idle)")
    sub.add_parser("check", help="check the strength of a password you type")

    gen = sub.add_parser("generate", help="print a random password (no vault needed)")
    gen.add_argument("length", type=int, nargs="?", default=16)
    gen.add_argument("--no-symbols", action="store_true")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "generate":
            print(generate_password(args.length, not args.no_symbols))
        elif args.cmd == "check":
            info = password_strength(getpass.getpass("Password to check: "))
            print(f"Strength: {info['label']} (about {info['entropy']} bits)")
            for tip in info["tips"]:
                print(f"  - {tip}")
        elif args.cmd == "init":
            v = Vault(args.file)
            v.create(ask_master(confirm=True))
            print(f"Vault created: {args.file}")
            print("Remember your master password. It cannot be recovered.")
        elif args.cmd == "add":
            v = unlocked(args.file)
            if args.generate is not None:
                pw = generate_password(args.generate, not args.no_symbols)
                print(f"Generated password: {pw}")
            else:
                pw = args.password or getpass.getpass("Entry password: ")
            v.add(args.site, args.username, pw, args.notes, args.overwrite)
            info = password_strength(pw)
            print(f"Saved '{args.site}'. Strength: {info['label']} ({info['entropy']} bits)")
            for tip in info["tips"] if is_weak(pw) else []:
                print(f"  - {tip}")
        elif args.cmd == "get":
            e = unlocked(args.file).get(args.site)
            hide = args.hide or args.copy
            print(f"Site:     {args.site}")
            print(f"Username: {e['username']}")
            print(f"Password: {'********' if hide else e['password']}")
            if e["notes"]:
                print(f"Notes:    {e['notes']}")
            print(f"Updated:  {e['updated']}")
            if args.copy:
                copy_to_clipboard(e["password"], args.clear_after)
        elif args.cmd == "delete":
            unlocked(args.file).delete(args.site)
            print(f"Deleted '{args.site}'.")
        elif args.cmd == "search":
            hits = unlocked(args.file).search(args.text)
            print("\n".join(hits) if hits else "No matches.")
        elif args.cmd == "list":
            sites = sorted(unlocked(args.file).entries)
            print("\n".join(sites) if sites else "Vault is empty.")
        elif args.cmd == "audit":
            print("\n".join(format_audit(unlocked(args.file).audit())))
        elif args.cmd == "change-master":
            v = unlocked(args.file)
            v.change_master(ask_master(confirm=True, prompt="NEW master password: "))
            print("Master password changed. The old backup was removed.")
        elif args.cmd == "shell":
            VaultShell(unlocked(args.file)).cmdloop()
    except VaultError as exc:
        sys.exit(f"Error: {exc}")
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
