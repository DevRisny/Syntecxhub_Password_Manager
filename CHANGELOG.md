# Changelog

## 2.0.0
- Password strength estimate and common-password detection
- `audit` command: weak, reused and old passwords
- `change-master` command (new salt, old backup removed)
- `get --copy` with automatic clipboard clearing
- Interactive `shell` with idle auto-lock
- 3 attempts with growing delay for a wrong master password
- Weak master passwords are rejected
- Automatic `.bak` backup, atomic saves, owner-only file permission
- `pwmanager` console command via `pip install .`
- 37 unit tests, ruff lint and format checks, GitHub Actions CI

## 1.0.0
- First version: AES-256-GCM encrypted vault with scrypt, add/get/delete/search/list
