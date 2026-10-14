# Security policy

## Threat model
| Threat | Protection |
|---|---|
| Someone copies `vault.json` | Everything is encrypted with AES-256-GCM. The key comes from the master password with scrypt and a random salt. |
| Offline password guessing | scrypt is deliberately slow and memory-hard. Weak master passwords are rejected. |
| File is edited or corrupted | GCM authentication fails, so the vault refuses to open (a `.bak` copy is kept). |
| Guessing at the prompt | 3 attempts with a growing delay. |
| Unattended open terminal | `shell` locks after 5 idle minutes and asks for the master password again. |
| Password left in clipboard | `get --copy` clears it after 20 seconds. |

## Not protected against
- Malware or a keylogger on your computer
- Someone watching your screen while a password is printed (use `--hide` or `--copy`)
- A forgotten master password (it cannot be recovered)
- Secrets staying in Python memory until the process ends

## Reporting a problem
Open a GitHub issue. Do not post real passwords or vault files in it.
