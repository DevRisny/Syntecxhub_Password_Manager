"""Tests for the password manager. Run:  python -m unittest -v"""

import base64
import io
import json
import os
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta
from unittest import mock

import password_manager as pm
from password_manager import Vault, VaultError, WrongPassword, generate_password

MASTER = "correct horse battery"


def read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_json(path, doc):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f)


class VaultBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "vault.json")

    def tearDown(self):
        self.dir.cleanup()

    def make(self):
        v = Vault(self.path)
        v.create(MASTER)
        return v

    def reopen(self, pw=MASTER):
        v = Vault(self.path)
        v.open(pw)
        return v


class VaultTests(VaultBase):
    def test_add_get_survive_reopen(self):
        v = self.make()
        v.add("github.com", "risny", "S3cret!pass", "work")
        e = self.reopen().get("github.com")
        self.assertEqual((e["username"], e["password"]), ("risny", "S3cret!pass"))

    def test_file_has_no_plaintext(self):
        v = self.make()
        v.add("github.com", "risny", "S3cret!pass", "my-notes")
        with open(self.path, encoding="utf-8") as f:
            raw = f.read()
        for secret in ("github.com", "risny", "S3cret!pass", "my-notes"):
            self.assertNotIn(secret, raw)

    def test_wrong_master_password(self):
        self.make()
        with self.assertRaises(WrongPassword):
            self.reopen("wrong password!")

    def test_tampered_ciphertext_detected(self):
        v = self.make()
        v.add("a", "b", "c")
        doc = read_json(self.path)
        ct = bytearray(base64.b64decode(doc["ciphertext"]))
        ct[0] ^= 1
        doc["ciphertext"] = base64.b64encode(bytes(ct)).decode()
        write_json(self.path, doc)
        with self.assertRaises(VaultError):
            self.reopen()

    def test_damaged_files(self):
        self.make()
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("not json at all")
        with self.assertRaises(VaultError):
            self.reopen()
        write_json(self.path, {"version": 1})
        with self.assertRaises(VaultError):
            self.reopen()

    def test_delete_and_search(self):
        v = self.make()
        v.add("github.com", "risny", "p1")
        v.add("gitlab.com", "suha", "p2")
        v.add("gmail.com", "risny", "p3", "personal")
        self.assertEqual(v.search("git"), ["github.com", "gitlab.com"])
        self.assertEqual(v.search("RISNY"), ["github.com", "gmail.com"])
        self.assertEqual(v.search("personal"), ["gmail.com"])
        v.delete("gitlab.com")
        self.assertNotIn("gitlab.com", self.reopen().entries)
        with self.assertRaises(VaultError):
            v.get("gitlab.com")
        with self.assertRaises(VaultError):
            v.delete("gitlab.com")

    def test_duplicate_needs_overwrite(self):
        v = self.make()
        v.add("x.com", "u", "p")
        with self.assertRaises(VaultError):
            v.add("x.com", "u", "new")
        v.add("x.com", "u", "new", overwrite=True)
        self.assertEqual(v.get("x.com")["password"], "new")

    def test_empty_inputs_rejected(self):
        v = self.make()
        with self.assertRaises(VaultError):
            v.add("  ", "u", "p")
        with self.assertRaises(VaultError):
            v.add("x.com", "u", "")

    def test_nonce_changes_each_save(self):
        v = self.make()
        n1 = read_json(self.path)["nonce"]
        v.add("x", "y", "z")
        n2 = read_json(self.path)["nonce"]
        self.assertNotEqual(n1, n2)

    def test_master_rules_and_missing_vault(self):
        with self.assertRaises(VaultError):
            Vault(self.path).create("short")
        with self.assertRaises(VaultError):
            Vault(self.path).create("password1")  # long enough but too weak
        with self.assertRaises(VaultError):
            Vault(self.path).open(MASTER)  # no file yet

    def test_create_does_not_overwrite(self):
        self.make()
        with self.assertRaises(VaultError):
            Vault(self.path).create(MASTER)

    def test_backup_is_created_on_save(self):
        v = self.make()
        self.assertFalse(os.path.exists(self.path + ".bak"))
        v.add("a", "b", "c")
        v.add("d", "e", "f")
        self.assertTrue(os.path.exists(self.path + ".bak"))
        backup = Vault(self.path + ".bak")
        backup.open(MASTER)
        self.assertIn("a", backup.entries)

    def test_owner_only_permissions(self):
        if os.name != "posix":
            self.skipTest("POSIX permissions only")
        self.make()
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)


class MasterPasswordTests(VaultBase):
    def test_verify_master(self):
        v = self.make()
        self.assertTrue(v.verify_master(MASTER))
        self.assertFalse(v.verify_master("not the password"))
        self.assertFalse(Vault(self.path).verify_master(MASTER))  # locked vault

    def test_change_master(self):
        v = self.make()
        v.add("a", "b", "c-password-1")
        old_salt = read_json(self.path)["salt"]
        v.change_master("new passphrase 2026!")
        self.assertNotEqual(old_salt, read_json(self.path)["salt"])
        with self.assertRaises(WrongPassword):
            self.reopen(MASTER)  # old password is dead
        self.assertEqual(self.reopen("new passphrase 2026!").get("a")["password"], "c-password-1")
        self.assertFalse(os.path.exists(self.path + ".bak"))  # old-key backup removed

    def test_change_master_rejects_weak(self):
        v = self.make()
        with self.assertRaises(VaultError):
            v.change_master("12345678")
        self.assertEqual(self.reopen().entries, {})  # nothing changed


class StrengthTests(unittest.TestCase):
    def test_labels(self):
        self.assertEqual(pm.password_strength("")["label"], "Very weak")
        self.assertEqual(pm.password_strength("password")["label"], "Very weak")
        self.assertIn(pm.password_strength("abc123")["label"], ("Very weak", "Weak"))
        self.assertIn(pm.password_strength("Tr0ub4dor&3xyz")["label"], ("Strong", "Very strong"))
        self.assertEqual(pm.password_strength(generate_password(24))["label"], "Very strong")

    def test_common_password_flagged(self):
        info = pm.password_strength("Password1")
        self.assertTrue(pm.is_weak("Password1"))
        self.assertTrue(any("common" in t for t in info["tips"]))

    def test_repeats_and_sequences_lower_score(self):
        self.assertLess(
            pm.password_strength("aaaaaaaaaaaa")["entropy"],
            pm.password_strength("kXq7mWpT9zLb")["entropy"],
        )
        self.assertLess(
            pm.password_strength("Qwer1234Zx9!")["entropy"],
            pm.password_strength("Hk3vQm9xZp2!")["entropy"],
        )


class GeneratorTests(unittest.TestCase):
    def test_length_and_variety(self):
        pw = generate_password(20)
        self.assertEqual(len(pw), 20)
        self.assertNotEqual(pw, generate_password(20))
        self.assertTrue(any(c in pm.SYMBOLS for c in pw))

    def test_no_symbols(self):
        for _ in range(20):
            self.assertTrue(generate_password(16, symbols=False).isalnum())

    def test_too_short(self):
        with self.assertRaises(VaultError):
            generate_password(4)


class AuditTests(VaultBase):
    def test_audit_finds_problems(self):
        v = self.make()
        v.add("weak.com", "u", "123456")
        v.add("a.com", "u", "Sh4red!Passw0rd#x")
        v.add("b.com", "u", "Sh4red!Passw0rd#x")
        v.add("good.com", "u", generate_password(20))
        v.add("ancient.com", "u", generate_password(20))
        v.entries["ancient.com"]["updated"] = (datetime.now() - timedelta(days=400)).isoformat()
        report = v.audit()
        self.assertEqual(report["weak"], ["weak.com"])
        self.assertEqual(report["reused"], [["a.com", "b.com"]])
        self.assertEqual(report["old"], ["ancient.com"])

    def test_clean_vault_passes(self):
        v = self.make()
        v.add("good.com", "u", generate_password(20))
        report = v.audit()
        self.assertEqual(
            pm.format_audit(report), ["Audit passed: no weak, reused or old passwords found."]
        )

    def test_audit_with_custom_clock(self):
        v = self.make()
        v.add("x.com", "u", generate_password(20))
        future = datetime.now() + timedelta(days=200)
        self.assertEqual(v.audit(now=future)["old"], ["x.com"])


class ClipboardTests(unittest.TestCase):
    def fake_pyperclip(self):
        mod = types.ModuleType("pyperclip")
        mod.store = ""
        mod.copy = lambda text: setattr(mod, "store", text)
        mod.paste = lambda: mod.store
        return mod

    def test_copy_then_clear(self):
        fake = self.fake_pyperclip()
        seen = []
        with mock.patch.dict(sys.modules, {"pyperclip": fake}):
            pm.copy_to_clipboard(
                "secret",
                clear_after=5,
                sleep=lambda s: seen.append((s, fake.store)),
                say=lambda *_: None,
            )
        self.assertEqual(seen, [(5, "secret")])  # it held the secret while waiting
        self.assertEqual(fake.store, "")  # and cleared it afterwards

    def test_does_not_clear_if_user_copied_something_else(self):
        fake = self.fake_pyperclip()

        def user_copies_other(_):
            fake.store = "something else"

        with mock.patch.dict(sys.modules, {"pyperclip": fake}):
            pm.copy_to_clipboard("secret", sleep=user_copies_other, say=lambda *_: None)
        self.assertEqual(fake.store, "something else")

    def test_missing_pyperclip(self):
        with mock.patch.dict(sys.modules, {"pyperclip": None}):
            with self.assertRaises(VaultError):
                pm.copy_to_clipboard("secret", say=lambda *_: None)


class ShellTests(VaultBase):
    def shell(self, vault, **kw):
        out = io.StringIO()
        sh = pm.VaultShell(vault, stdout=out, read_secret=kw.pop("read_secret", lambda p: ""), **kw)
        return sh, out

    def test_commands(self):
        v = self.make()
        secrets_given = iter(["My-Sh3ll!Pass"])
        sh, out = self.shell(v, read_secret=lambda prompt: next(secrets_given))
        sh.onecmd("add github.com risny")
        sh.onecmd("list")
        sh.onecmd("get github.com")
        sh.onecmd("search git")
        sh.onecmd("audit")
        sh.onecmd("delete github.com")
        sh.onecmd("list")
        text = out.getvalue()
        self.assertIn("Saved 'github.com'", text)
        self.assertIn("Password: My-Sh3ll!Pass", text)
        self.assertIn("Vault is empty.", text)

    def test_add_with_empty_password_generates(self):
        v = self.make()
        sh, out = self.shell(v)
        sh.onecmd("add site.com me")
        self.assertIn("Generated password:", out.getvalue())
        self.assertGreaterEqual(len(v.get("site.com")["password"]), 16)

    def test_errors_do_not_crash_shell(self):
        v = self.make()
        sh, out = self.shell(v)
        self.assertFalse(sh.onecmd("get nothing"))
        self.assertFalse(sh.onecmd('get "unclosed'))
        self.assertFalse(sh.onecmd("add onlyone"))
        text = out.getvalue()
        self.assertIn("Error: No entry named 'nothing'", text)
        self.assertIn("Usage: add", text)

    def test_quit(self):
        sh, _ = self.shell(self.make())
        self.assertTrue(sh.onecmd("quit"))

    def test_auto_lock_with_correct_password(self):
        v = self.make()
        sh, out = self.shell(v, idle_limit=60, ask=lambda: MASTER)
        sh.last_activity -= 1000  # pretend we were idle
        self.assertEqual(sh.precmd("list"), "list")
        self.assertIn("Locked after inactivity", out.getvalue())

    def test_auto_lock_with_wrong_password_closes(self):
        v = self.make()
        sh, out = self.shell(v, idle_limit=60, ask=lambda: "wrong")
        sh.last_activity -= 1000
        self.assertEqual(sh.precmd("list"), "quit")


class UnlockTests(VaultBase):
    def test_three_attempts_with_delay(self):
        self.make()
        delays = []
        with mock.patch.object(pm, "ask_master", side_effect=["bad1", "bad2", "bad3"]):
            with mock.patch("builtins.print"):
                with self.assertRaises(WrongPassword):
                    pm.unlocked(self.path, sleep=delays.append)
        self.assertEqual(delays, [1, 2])  # growing wait, no wait after the last try

    def test_success_on_second_try(self):
        self.make()
        with mock.patch.object(pm, "ask_master", side_effect=["bad", MASTER]):
            with mock.patch("builtins.print"):
                v = pm.unlocked(self.path, sleep=lambda s: None)
        self.assertEqual(v.entries, {})

    def test_missing_vault(self):
        with self.assertRaises(VaultError):
            pm.unlocked(self.path)


if __name__ == "__main__":
    unittest.main()
