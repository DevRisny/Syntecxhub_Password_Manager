# Syntecxhub_Password_Manager

[![CI](https://github.com/DevRisny/Syntecxhub_Password_Manager/actions/workflows/ci.yml/badge.svg)](https://github.com/DevRisny/Syntecxhub_Password_Manager/actions)
![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Crypto](https://img.shields.io/badge/crypto-AES--256--GCM%20%2B%20scrypt-blue)

Project 2 of the **Syntecxhub Cyber Security Internship**: a local, command-line **password manager** in Python. All credentials are stored **encrypted on disk** with AES-256-GCM. The master password is never saved.

## Security design
| Part | What I used | Why |
|---|---|---|
| Encryption | **AES-256-GCM** (`cryptography` library) | Strong symmetric encryption. GCM also detects if the file was changed. |
| Key from master password | **scrypt** (`n=2^15, r=8, p=1`) + random 16-byte salt | Slow on purpose, so guessing the master password is expensive. |
| Nonce | New random 12-byte nonce on **every** save | Never reuse a nonce with the same key. |
| What is encrypted | Site names, usernames, passwords, notes, dates | The file shows only version, salt, nonce and ciphertext. |
| Safe saving | Write temp file, then replace. Owner-only permission (`600`). `.bak` backup. | A crash cannot leave a half-written vault. |
| Brute force | 3 attempts, delay 1s then 2s after a wrong master password | Slows down guessing in the program itself. |
| Master password rules | At least 8 characters and not weak | A weak master password makes strong encryption useless. |
| Secrets handling | `getpass` (hidden typing), `secrets` module for random passwords | No password on screen. No weak random numbers. |
| Clipboard | `get --copy` clears the clipboard after 20s (only if it still holds the password) | Passwords do not stay in the clipboard. |
| Auto-lock | Shell asks for the master password again after 5 idle minutes | Protects an unlocked, unattended terminal. |

## Features
- `init`, `add`, `get`, `delete`, `search`, `list`
- `add --generate` makes a random password (`--no-symbols` option)
- **Strength check** on every new password (entropy estimate, common-password detection, tips) and a `check` command
- **`audit`**: finds *weak*, *reused* and *old* (180+ days) passwords
- **`change-master`**: re-encrypts the vault with a new master password and new salt
- **`shell`**: interactive mode, unlock once, many commands
- 37 unit tests

## Install
```bash
pip install -r requirements.txt
```
`pyperclip` is optional and only needed for `get --copy`.

## Install as a command (optional)
```bash
pip install .                  # adds the `pwmanager` command
pip install ".[clipboard]"     # also installs pyperclip for `get --copy`
pwmanager init
```
You can also run it directly: `python password_manager.py ...` (examples below use this form).

## Usage
```bash
python password_manager.py init                              # create vault (asks master password)
python password_manager.py add github.com risny --generate   # random 16-character password
python password_manager.py add gmail.com risny               # asks for the password (hidden)
python password_manager.py get github.com                    # show entry
python password_manager.py get github.com --copy             # copy, clipboard clears in 20s
python password_manager.py search git                        # site / username / notes
python password_manager.py list
python password_manager.py audit                             # weak / reused / old passwords
python password_manager.py change-master
python password_manager.py shell                             # interactive mode
python password_manager.py check                             # test the strength of a password
python password_manager.py generate 20 --no-symbols          # random password only
python password_manager.py -f other_vault.json list          # use another vault file
```

### Example session (real output)
```
$ python password_manager.py add old-forum.com suha
Entry password:
Saved 'old-forum.com'. Strength: Very weak (10.0 bits)
  - This is a very common password. Never use it.
  - Use at least 12 characters.

$ python password_manager.py audit
Weak passwords (1): old-forum.com
Reused password: site-a.com, site-b.com

$ python password_manager.py shell
vault> list
github.com
old-forum.com
vault> search forum
old-forum.com
vault> quit
Vault locked.
```

## How it works
```
 master password ──scrypt(+salt)──► 256-bit key ──► AES-256-GCM ──► vault.json
                                                      ▲   │
                    entries (JSON, in memory only) ───┘   └── nonce + ciphertext + tag
```
1. **Unlock:** read `vault.json`, derive the key from the typed master password, decrypt. A wrong password or edited file fails the GCM authentication check.
2. **Change data:** entries live in memory only while unlocked.
3. **Save:** encrypt again with a new nonce, write to a temp file, replace the old file atomically.

### Vault file format
```json
{
  "version": 1,
  "kdf": {"name": "scrypt", "n": 32768, "r": 8, "p": 1},
  "salt": "<base64>",
  "nonce": "<base64>",
  "ciphertext": "<base64 of AES-256-GCM encrypted JSON>"
}
```

## Run the tests
```bash
python -m unittest -v
```
Tests cover: round trip after reopen, no plain text in the file, wrong master password, tampered/damaged files, nonce changes, backups and file permissions, change-master, strength rules, generator, audit (weak/reused/old), clipboard auto-clear (with a fake clipboard), shell commands and auto-lock, and the 3-attempt delay.

## More
- [SECURITY.md](SECURITY.md): threat model and what is *not* protected
- [CHANGELOG.md](CHANGELOG.md): version history

## Limits (honest notes)
- The master password cannot be recovered. If you forget it, the data is gone.
- Python cannot fully erase secrets from memory.
- Keep `vault.json` out of Git (already in `.gitignore`).
- `.bak` is the previous version of the vault. After `change-master` it is deleted automatically, because it was encrypted with the old password.
- Entropy numbers are estimates, not guarantees.

## What I learned
Authenticated encryption (AES-GCM), key derivation (scrypt, salts, nonces), safe file handling, threat modelling (brute force, tampering, shoulder surfing, clipboard leaks), and testing security features with unit tests.
