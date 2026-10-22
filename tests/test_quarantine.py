"""Quarantine vault tests.

Two critical defects from v3.0 are verified here:

* the "encryption" was ``base64(reverse(bytes))`` - it is now AES-256-GCM,
* the original was deleted **without verifying** the encrypted copy -
  now the original stays in place when verification fails.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os

import pytest

from sentinel.quarantine import MAGIC, QuarantineManager, VaultError

pytest.importorskip("cryptography")

SECRET = "Customer ID: 10000000146\nCard: 4111111111111111\n"


def _read(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _write(path: str, data: bytes):
    # The vault directory is created on first write, so a test planting a
    # pre-existing v3.0 file has to create it the way an old install did.
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)


@pytest.fixture
def vault(tmp_path, monkeypatch):
    """Every test uses an isolated vault and key."""
    key = base64.b64encode(os.urandom(32)).decode("ascii")
    monkeypatch.setenv("SENTINEL_VAULT_KEY", key)
    return QuarantineManager(str(tmp_path / "vault"))


@pytest.fixture
def victim(tmp_path):
    """Write the victim file **as bytes**.

    On Windows `write_text` translates `\\n` to `\\r\\n`, so the bytes on
    disk differ from `SECRET.encode()`. Because the vault (correctly)
    hashes the *file bytes*, the manifest test failed on Windows only.
    Writing the fixture byte-exactly makes the test platform
    independent without weakening what it measures (a forensic hash).
    """
    path = tmp_path / "data" / "secret.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(SECRET.encode("utf-8"))
    return path


class TestQuarantine:
    def test_moves_and_removes_original(self, vault, victim):
        ok, enc_path = vault.quarantine_file(str(victim))
        assert ok, enc_path
        assert not victim.exists()
        assert os.path.isfile(enc_path)

    def test_encrypted_blob_is_not_readable(self, vault, victim):
        """The core point: the file must be encrypted, not obfuscated."""
        ok, enc_path = vault.quarantine_file(str(victim))
        assert ok
        blob = _read(enc_path)

        assert blob.startswith(MAGIC)
        assert b"10000000146" not in blob
        assert b"4111111111111111" not in blob
        # The v3.0 cipher was reversible in one line; it must not be now.
        try:
            naive = base64.b64decode(blob)[::-1]
        except Exception:
            naive = b""
        assert b"10000000146" not in naive

    def test_roundtrip_restores_byte_for_byte(self, vault, victim):
        original = victim.read_bytes()
        ok, enc_path = vault.quarantine_file(str(victim))
        assert ok

        ok, restored_path = vault.restore_file(enc_path)
        assert ok, restored_path
        assert os.path.abspath(restored_path) == os.path.abspath(str(victim))
        assert victim.read_bytes() == original

    def test_manifest_records_provenance(self, vault, victim):
        # Check first that the fixture wrote byte-exactly: otherwise the
        # hash comparison below varies by platform and the failure turns
        # into a confusing message that blames the vault.
        assert victim.read_bytes() == SECRET.encode("utf-8")

        ok, enc_path = vault.quarantine_file(str(victim))
        assert ok
        items = vault.list_items()
        assert len(items) == 1
        entry = items[0]
        assert entry["original_path"] == os.path.abspath(str(victim))
        assert entry["sha256"] == hashlib.sha256(SECRET.encode()).hexdigest()
        assert entry["algorithm"] == "AES-256-GCM"

    def test_missing_file(self, vault, tmp_path):
        ok, message = vault.quarantine_file(str(tmp_path / "missing.txt"))
        assert not ok
        assert "not found" in message


class TestIntegrity:
    def test_wrong_key_cannot_decrypt(self, vault, victim, monkeypatch, tmp_path):
        ok, enc_path = vault.quarantine_file(str(victim))
        assert ok

        other_key = base64.b64encode(os.urandom(32)).decode("ascii")
        monkeypatch.setenv("SENTINEL_VAULT_KEY", other_key)
        intruder = QuarantineManager(vault.q_dir)

        ok, message = intruder.restore_file(enc_path)
        assert not ok
        assert "Decryption failed" in message

    def test_tampered_ciphertext_is_detected(self, vault, victim):
        """AES-GCM is authenticated: a single flipped bit is caught."""
        ok, enc_path = vault.quarantine_file(str(victim))
        assert ok

        blob = bytearray(_read(enc_path))
        blob[-5] ^= 0x01
        _write(enc_path, bytes(blob))

        ok, message = vault.restore_file(enc_path)
        assert not ok
        assert "tampered" in message or "failed" in message

    def test_tampered_header_is_detected(self, vault, victim):
        """The header is bound as AAD; the manifest cannot be tampered with."""
        ok, enc_path = vault.quarantine_file(str(victim))
        assert ok

        blob = _read(enc_path)
        tampered = blob.replace(b'"size"', b'"xize"', 1)
        assert tampered != blob
        _write(enc_path, tampered)

        ok, _ = vault.restore_file(enc_path)
        assert not ok

    def test_original_survives_when_verification_fails(
        self, vault, victim, monkeypatch
    ):
        """The most important behaviour: on failed verification the original is NOT deleted."""
        monkeypatch.setattr(
            QuarantineManager,
            "_decrypt",
            lambda self, blob: (b"wrong-content", {}),
        )
        ok, message = vault.quarantine_file(str(victim))
        assert not ok
        assert "original kept" in message
        assert victim.exists()
        assert victim.read_text(encoding="utf-8") == SECRET
        # A corrupt .enc must not be left in the vault.
        assert not any(name.endswith(".enc") for name in os.listdir(vault.q_dir))

    def test_verify_all(self, vault, victim):
        ok, _ = vault.quarantine_file(str(victim))
        assert ok
        results = vault.verify_all()
        assert len(results) == 1
        assert results[0]["ok"]


class TestRestoreSafety:
    def test_refuses_to_overwrite(self, vault, victim):
        ok, enc_path = vault.quarantine_file(str(victim))
        assert ok
        victim.write_text("new content", encoding="utf-8")

        ok, message = vault.restore_file(enc_path)
        assert not ok
        assert "not overwritten" in message
        assert victim.read_text(encoding="utf-8") == "new content"

    def test_force_overwrites(self, vault, victim):
        ok, enc_path = vault.quarantine_file(str(victim))
        assert ok
        victim.write_text("new content", encoding="utf-8")

        ok, _ = vault.restore_file(enc_path, force=True)
        assert ok
        assert victim.read_text(encoding="utf-8") == SECRET

    def test_recreates_deleted_directory(self, vault, victim):
        import shutil

        ok, enc_path = vault.quarantine_file(str(victim))
        assert ok
        shutil.rmtree(victim.parent)

        ok, restored = vault.restore_file(enc_path)
        assert ok
        assert os.path.isfile(restored)

    def test_restore_to_explicit_target(self, vault, victim, tmp_path):
        ok, enc_path = vault.quarantine_file(str(victim))
        assert ok
        target = tmp_path / "elsewhere" / "file.txt"

        ok, restored = vault.restore_file(enc_path, str(target))
        assert ok
        assert target.read_text(encoding="utf-8") == SECRET

    def test_restore_by_bare_name(self, vault, victim):
        ok, enc_path = vault.quarantine_file(str(victim))
        assert ok
        ok, _ = vault.restore_file(os.path.basename(enc_path))
        assert ok


class TestSideEffectsOnConstruction:
    """Building a manager must not touch the filesystem."""

    def test_constructing_creates_no_directory(self, tmp_path):
        # The GUI builds a manager at startup whether or not quarantine
        # is ever used. It used to leave an empty vault folder in
        # whatever directory the user launched from.
        target = tmp_path / "vault"
        QuarantineManager(str(target))
        assert not target.exists()

    def test_listing_a_missing_vault_is_empty_not_an_error(self, tmp_path):
        manager = QuarantineManager(str(tmp_path / "vault"))
        assert manager.list_items() == []
        assert manager.purge() == 0
        assert not (tmp_path / "vault").exists()

    def test_first_quarantine_creates_the_directory(self, vault, victim):
        assert not os.path.exists(vault.q_dir)
        ok, _ = vault.quarantine_file(str(victim))
        assert ok
        assert os.path.isdir(vault.q_dir)

    def test_default_directory_name_is_english(self):
        from sentinel.config import ScanConfig

        assert QuarantineManager.__init__.__defaults__[0] == "QUARANTINE_ZONE"
        assert ScanConfig().quarantine_dir == "QUARANTINE_ZONE"
        # The old name stays readable for vaults already on disk.
        assert "KARANTINA_BOLGESI" in QuarantineManager.LEGACY_DIRS


class TestLegacyCompatibility:
    def test_reads_v3_base64_format(self, vault, tmp_path):
        """Old files in users' vaults must stay readable."""
        legacy_blob = base64.b64encode(SECRET.encode("utf-8")[::-1])
        enc_path = os.path.join(vault.q_dir, "1700000000_legacy.txt.enc")
        _write(enc_path, legacy_blob)

        target = tmp_path / "restored" / "old.txt"
        ok, restored = vault.restore_file(enc_path, str(target))
        assert ok, restored
        assert target.read_text(encoding="utf-8") == SECRET

    def test_reads_v3_json_manifest(self, vault, tmp_path):
        legacy_blob = base64.b64encode(b"data"[::-1])
        name = "1700000000_legacy.txt.enc"
        _write(os.path.join(vault.q_dir, name), legacy_blob)

        target = tmp_path / "destination" / "old.txt"
        with open(vault.legacy_log_file, "w", encoding="utf-8") as handle:
            json.dump({name: {"original_path": str(target)}}, handle)

        ok, restored = vault.restore_file(name)
        assert ok
        assert os.path.abspath(restored) == os.path.abspath(str(target))

    def test_reads_enc_meta_sidecar(self, vault, tmp_path):
        """The `.enc.meta` sidecar files in a QUARANTINE_ZONE directory."""
        name = "New Text Document.txt.enc"
        _write(os.path.join(vault.q_dir, name), base64.b64encode(b"content"[::-1]))
        target = tmp_path / "meta_target.txt"
        with open(
            os.path.join(vault.q_dir, f"{name}.meta"), "w", encoding="utf-8"
        ) as handle:
            handle.write(str(target))

        items = vault.list_items()
        assert items[0]["original_path"] == str(target)
        assert items[0]["legacy"] is True

        ok, restored = vault.restore_file(name)
        assert ok
        assert os.path.abspath(restored) == os.path.abspath(str(target))

    def test_legacy_blob_rejects_garbage(self, vault):
        enc_path = os.path.join(vault.q_dir, "corrupt.enc")
        _write(enc_path, b"\xff\xfe this is not base64 \x00")
        ok, _ = vault.restore_file(enc_path)
        assert not ok


class TestPurge:
    def test_purge_single(self, vault, victim):
        ok, enc_path = vault.quarantine_file(str(victim))
        assert ok
        assert vault.purge(os.path.basename(enc_path)) == 1
        assert vault.list_items() == []

    def test_purge_all(self, vault, tmp_path):
        for index in range(3):
            path = tmp_path / f"d{index}.txt"
            path.write_text(SECRET, encoding="utf-8")
            vault.quarantine_file(str(path))
        assert vault.purge() == 3
        assert vault.list_items() == []

    def test_shred_removes_the_file(self, vault, victim):
        ok, enc_path = vault.quarantine_file(str(victim), shred=False)
        assert ok
        assert vault.purge(os.path.basename(enc_path), shred=True) == 1
        assert not os.path.exists(enc_path)


class TestKeyManagement:
    def test_keyfile_is_created_with_restrictive_permissions(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SENTINEL_VAULT_KEY", raising=False)
        monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))

        from sentinel.quarantine import default_key_path, load_or_create_key

        key = load_or_create_key()
        assert len(key) == 32

        path = default_key_path()
        assert os.path.isfile(path)
        if os.name != "nt":
            assert oct(os.stat(path).st_mode)[-3:] == "600"

        # The same key must load again, or an old vault cannot be opened.
        assert load_or_create_key() == key

    def test_key_is_stored_outside_the_vault(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SENTINEL_VAULT_KEY", raising=False)
        monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "home"))

        from sentinel.quarantine import default_key_path

        manager = QuarantineManager(str(tmp_path / "vault"))
        assert not default_key_path().startswith(manager.q_dir)

    def test_passphrase_is_derived_deterministically(self, monkeypatch):
        from sentinel.quarantine import load_or_create_key

        monkeypatch.setenv("SENTINEL_VAULT_KEY", "my-long-secret-passphrase")
        first = load_or_create_key()
        second = load_or_create_key()
        assert first == second
        assert len(first) == 32

    def test_hex_key_is_accepted(self, monkeypatch):
        from sentinel.quarantine import load_or_create_key

        raw = os.urandom(32)
        monkeypatch.setenv("SENTINEL_VAULT_KEY", raw.hex())
        assert load_or_create_key() == raw


class TestEngineIntegration:
    def test_scanner_quarantines_only_above_threshold(self, tmp_path, monkeypatch):
        monkeypatch.setenv(
            "SENTINEL_VAULT_KEY", base64.b64encode(os.urandom(32)).decode("ascii")
        )
        from sentinel.config import ScanConfig
        from sentinel.engine import Scanner
        from sentinel.severity import Severity

        (tmp_path / "critical.txt").write_text(
            "Card: 4111111111111111\n", encoding="utf-8"
        )
        (tmp_path / "low.txt").write_text("mail: a@university.edu\n", encoding="utf-8")

        config = ScanConfig(
            min_severity=Severity.INFO.value,
            entropy_scan=False,
            yara_enabled=False,
            workers=1,
            executor="serial",
            quarantine=True,
            quarantine_dir=str(tmp_path / "vault"),
            quarantine_min_severity=Severity.CRITICAL.value,
        )
        result = Scanner(str(tmp_path), config=config).scan()

        assert len(result.quarantined) == 1
        assert not (tmp_path / "critical.txt").exists()
        assert (tmp_path / "low.txt").exists()

    def test_reveal_does_not_raise(self, vault, tmp_path):
        """v3.0 forgot to import `subprocess` here."""
        path = tmp_path / "x.txt"
        path.write_text("x", encoding="utf-8")
        assert isinstance(vault.reveal(str(path)), bool)


def test_vault_error_is_an_exception():
    assert issubclass(VaultError, Exception)
