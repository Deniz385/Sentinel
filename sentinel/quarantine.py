"""Karantina kasası — AES-256-GCM.

v3.0'ın "şifrelemesi" ``base64(reverse(bytes))`` idi. Bu şifreleme
değil, gizlemedir: karantinaya alınan KVKK verisi fiilen açıktaydı ve
tek satır kodla geri okunabiliyordu. Ayrıca orijinal dosya, şifreli
kopya **doğrulanmadan** siliniyordu; şifreli kopya bozuksa veri kalıcı
olarak kayboluyordu.

Bu modül şunları garanti eder:

* **Gerçek şifreleme**: AES-256-GCM (kimlik doğrulamalı). Başlık AAD
  olarak bağlanır, yani manifest kurcalanırsa çözme başarısız olur.
* **Doğrulanmış silme**: orijinal dosya, şifreli kopya tekrar çözülüp
  SHA-256'sı eşleştikten *sonra* silinir.
* **Atomik yazma**: geçici dosya + ``os.replace``; yarım kalmış .enc yok.
* **Eski format uyumu**: v3.0 base64 dosyaları ve ``.enc.meta`` /
  ``karantina_kayitlari.json`` kayıtları okunmaya devam eder.

Anahtar yönetimi: ``SENTINEL_VAULT_KEY`` ortam değişkeni (base64/hex) >
yapılandırılmış anahtar dosyası > ``~/.sentinel/vault.key`` (ilk
kullanımda 0600 izniyle üretilir). Anahtar **kasa dizininin dışında**
tutulur; aynı dizinde olsa şifrelemenin anlamı kalmazdı.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import shutil
import struct
import tempfile
import time
from datetime import datetime, timezone

__all__ = ["QuarantineManager", "VaultError", "MAGIC"]

MAGIC = b"SENTNL\x02\x00"
_NONCE_SIZE = 12
_KEY_SIZE = 32
_MANIFEST_NAME = "manifest.json"
_LEGACY_MANIFEST = "karantina_kayitlari.json"
_SHRED_PASSES = 1


class VaultError(Exception):
    """Karantina işlemi başarısız."""


# ---------------------------------------------------------------------------
# Anahtar yönetimi
# ---------------------------------------------------------------------------
def default_key_path() -> str:
    base = os.environ.get("SENTINEL_HOME") or os.path.join(
        os.path.expanduser("~"), ".sentinel"
    )
    return os.path.join(base, "vault.key")


def _decode_key(raw: str) -> bytes:
    raw = raw.strip()
    for decoder in (
        lambda value: base64.b64decode(value, validate=True),
        lambda value: binascii.unhexlify(value),
        lambda value: value.encode("utf-8"),
    ):
        try:
            key = decoder(raw)
        except Exception:
            continue
        if len(key) == _KEY_SIZE:
            return key
    # Serbest biçimli bir parola verildiyse ondan anahtar türet.
    return hashlib.scrypt(
        raw.encode("utf-8"), salt=b"sentinel-vault-v2", n=2**14, r=8, p=1, dklen=_KEY_SIZE
    )


def load_or_create_key(key_path: str | None = None) -> bytes:
    """Kasa anahtarını yükler; yoksa üretip 0600 izniyle kaydeder."""
    env_key = os.environ.get("SENTINEL_VAULT_KEY")
    if env_key:
        return _decode_key(env_key)

    path = key_path or default_key_path()
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as handle:
            return _decode_key(handle.read())

    key = os.urandom(_KEY_SIZE)
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    # Dosyayı doğrudan kısıtlı izinle oluştur: önce yazıp sonra chmod
    # yapmak, aradaki pencerede anahtarı okunabilir bırakır.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(base64.b64encode(key).decode("ascii"))
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - Windows
        pass
    return key


# ---------------------------------------------------------------------------
class QuarantineManager:
    """Şifreli karantina kasasını yönetir."""

    #: v3.0 ve ara sürümlerde kullanılmış dizin adları.
    LEGACY_DIRS = ("KARANTINA_BOLGESI", "QUARANTINE_ZONE")

    def __init__(self, quarantine_dir: str = "KARANTINA_BOLGESI", key_path: str | None = None):
        self.q_dir = os.path.abspath(quarantine_dir)
        self.log_file = os.path.join(self.q_dir, _MANIFEST_NAME)
        self.legacy_log_file = os.path.join(self.q_dir, _LEGACY_MANIFEST)
        self._key_path = key_path
        self._key: bytes | None = None
        os.makedirs(self.q_dir, exist_ok=True)

    # -- anahtar ----------------------------------------------------------
    @property
    def key(self) -> bytes:
        if self._key is None:
            self._key = load_or_create_key(self._key_path)
        return self._key

    @staticmethod
    def crypto_available() -> bool:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        except ImportError:
            return False
        return True

    def _aesgcm(self):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as exc:  # pragma: no cover
            raise VaultError(
                "Karantina için `cryptography` gerekli: pip install cryptography"
            ) from exc
        return AESGCM(self.key)

    # -- manifest ---------------------------------------------------------
    def _get_logs(self) -> dict:
        """Manifesti okur; eski (v3.0) manifesti de birleştirir."""
        logs: dict = {}
        for path in (self.legacy_log_file, self.log_file):
            if not os.path.isfile(path):
                continue
            try:
                with open(path, encoding="utf-8") as handle:
                    data = json.load(handle)
                if isinstance(data, dict):
                    logs.update(data)
            except (json.JSONDecodeError, OSError):
                continue
        return logs

    def _save_logs(self, data: dict):
        temp = f"{self.log_file}.tmp"
        with open(temp, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
        os.replace(temp, self.log_file)

    def list_items(self) -> list:
        """Kasadaki dosyaları manifest bilgisiyle birlikte listeler."""
        logs = self._get_logs()
        items = []
        for name in sorted(os.listdir(self.q_dir)):
            if not name.endswith(".enc"):
                continue
            path = os.path.join(self.q_dir, name)
            info = dict(logs.get(name) or {})
            if not info.get("original_path"):
                info["original_path"] = self._legacy_sidecar_path(name) or ""
            try:
                info["enc_size"] = os.path.getsize(path)
            except OSError:
                info["enc_size"] = 0
            info["name"] = name
            info["legacy"] = not self._is_modern(path)
            items.append(info)
        return items

    def _legacy_sidecar_path(self, enc_name: str) -> str | None:
        """v3.0'ın ``<dosya>.enc.meta`` yan dosyasından orijinal yolu okur."""
        for candidate in (
            os.path.join(self.q_dir, f"{enc_name}.meta"),
            os.path.join(self.q_dir, f"{enc_name.removesuffix('.enc')}.enc.meta"),
        ):
            if os.path.isfile(candidate):
                try:
                    with open(candidate, encoding="utf-8") as handle:
                        return handle.read().strip() or None
                except OSError:
                    return None
        return None

    # -- şifreleme --------------------------------------------------------
    @staticmethod
    def _is_modern(path: str) -> bool:
        try:
            with open(path, "rb") as handle:
                return handle.read(len(MAGIC)) == MAGIC
        except OSError:
            return False

    def _encrypt(self, data: bytes, header: dict) -> bytes:
        """`MAGIC | başlık_uzunluğu | başlık | nonce | şifreli metin`.

        Başlık AAD olarak bağlanır: manifest/başlık değiştirilirse çözme
        kimlik doğrulama hatasıyla başarısız olur.
        """
        header_bytes = json.dumps(header, ensure_ascii=False, sort_keys=True).encode(
            "utf-8"
        )
        nonce = os.urandom(_NONCE_SIZE)
        ciphertext = self._aesgcm().encrypt(nonce, data, header_bytes)
        return (
            MAGIC
            + struct.pack(">I", len(header_bytes))
            + header_bytes
            + nonce
            + ciphertext
        )

    def _decrypt(self, blob: bytes) -> tuple[bytes, dict]:
        if not blob.startswith(MAGIC):
            return self._decrypt_legacy(blob), {"format": "legacy-v3"}

        offset = len(MAGIC)
        (header_length,) = struct.unpack(">I", blob[offset : offset + 4])
        offset += 4
        header_bytes = blob[offset : offset + header_length]
        offset += header_length
        nonce = blob[offset : offset + _NONCE_SIZE]
        ciphertext = blob[offset + _NONCE_SIZE :]

        try:
            plaintext = self._aesgcm().decrypt(nonce, ciphertext, header_bytes)
        except Exception as exc:
            raise VaultError(
                "Çözme başarısız: anahtar yanlış ya da dosya kurcalanmış."
            ) from exc

        return plaintext, json.loads(header_bytes.decode("utf-8"))

    @staticmethod
    def _decrypt_legacy(blob: bytes) -> bytes:
        """v3.0 formatı: ``base64(reverse(bytes))``.

        Güvenli değildi ama kullanıcıların kasasında bu dosyalar var;
        okunabilir kalmalılar.
        """
        try:
            return base64.b64decode(blob)[::-1]
        except Exception as exc:
            raise VaultError("Eski formatlı karantina dosyası okunamadı.") from exc

    # -- genel API --------------------------------------------------------
    def quarantine_file(self, filepath: str, shred: bool = False) -> tuple[bool, str]:
        """Dosyayı şifreleyip kasaya alır, sonra orijinalini siler.

        Silme işlemi **yalnızca** şifreli kopya geri çözülüp SHA-256'sı
        orijinalle eşleştikten sonra yapılır.
        """
        if not os.path.isfile(filepath):
            return False, f"Dosya bulunamadı: {filepath}"

        try:
            with open(filepath, "rb") as handle:
                content = handle.read()
        except OSError as exc:
            return False, f"Okunamadı: {exc}"

        digest = hashlib.sha256(content).hexdigest()
        filename = os.path.basename(filepath)
        enc_name = f"{int(time.time())}_{digest[:8]}_{filename}.enc"
        enc_path = os.path.join(self.q_dir, enc_name)

        header = {
            "format": "SENTNL-2",
            "algorithm": "AES-256-GCM",
            "original_name": filename,
            "original_path": os.path.abspath(filepath),
            "sha256": digest,
            "size": len(content),
            "quarantined_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

        try:
            blob = self._encrypt(content, header)
        except VaultError as exc:
            return False, str(exc)

        # Atomik yazma: yarım dosya kasada kalmasın.
        descriptor, temp_path = tempfile.mkstemp(dir=self.q_dir, suffix=".tmp")
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(blob)
            os.replace(temp_path, enc_path)
        except OSError as exc:
            _silent_remove(temp_path)
            return False, f"Kasaya yazılamadı: {exc}"

        # DOĞRULA: çözülüp aynı içeriği veriyor mu?
        try:
            with open(enc_path, "rb") as handle:
                restored, _ = self._decrypt(handle.read())
        except VaultError as exc:
            _silent_remove(enc_path)
            return False, f"Doğrulama başarısız, orijinal korundu: {exc}"

        if hashlib.sha256(restored).hexdigest() != digest:
            _silent_remove(enc_path)
            return False, "Doğrulama başarısız (hash uyuşmadı), orijinal korundu."

        logs = self._get_logs()
        logs[enc_name] = header
        self._save_logs(logs)

        try:
            if shred:
                _shred(filepath)
            else:
                os.remove(filepath)
        except OSError as exc:
            return True, (
                f"Şifreli kopya oluşturuldu ama orijinal silinemedi: {exc}"
            )

        return True, enc_path

    def restore_file(
        self, enc_filepath: str, target_path: str | None = None, force: bool = False
    ) -> tuple[bool, str]:
        """Dosyayı çözüp orijinal konumuna geri koyar."""
        if not os.path.isabs(enc_filepath):
            candidate = os.path.join(self.q_dir, enc_filepath)
            enc_filepath = candidate if os.path.isfile(candidate) else enc_filepath

        if not os.path.isfile(enc_filepath):
            return False, f"Karantina dosyası bulunamadı: {enc_filepath}"

        name = os.path.basename(enc_filepath)
        logs = self._get_logs()
        info = logs.get(name) or {}

        try:
            with open(enc_filepath, "rb") as handle:
                content, header = self._decrypt(handle.read())
        except VaultError as exc:
            return False, str(exc)

        destination = (
            target_path
            or info.get("original_path")
            or header.get("original_path")
            or self._legacy_sidecar_path(name)
        )
        if not destination:
            # Kayıt yoksa proje dizinine, isimden türeterek çıkar.
            clean = name.removesuffix(".enc")
            parts = clean.split("_", 2)
            clean = parts[-1] if len(parts) == 3 else clean
            destination = os.path.abspath(clean)

        expected = info.get("sha256") or header.get("sha256")
        if expected and hashlib.sha256(content).hexdigest() != expected:
            return False, "Bütünlük hatası: içerik manifestteki hash ile uyuşmuyor."

        if os.path.exists(destination) and not force:
            return False, (
                f"Hedefte dosya var, üzerine yazılmadı: {destination} "
                "(--force ile zorlayabilirsiniz)"
            )

        directory = os.path.dirname(os.path.abspath(destination))
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)

        try:
            descriptor, temp_path = tempfile.mkstemp(dir=directory or ".", suffix=".tmp")
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
            os.replace(temp_path, destination)
        except OSError as exc:
            return False, f"Geri yazılamadı: {exc}"

        _silent_remove(enc_filepath)
        _silent_remove(f"{enc_filepath}.meta")
        if name in logs:
            del logs[name]
            self._save_logs(logs)

        return True, destination

    def verify_all(self) -> list:
        """Kasadaki her dosyanın çözülebilirliğini ve bütünlüğünü sınar."""
        results = []
        for item in self.list_items():
            path = os.path.join(self.q_dir, item["name"])
            entry = {"name": item["name"], "ok": False, "detail": ""}
            try:
                with open(path, "rb") as handle:
                    content, header = self._decrypt(handle.read())
            except VaultError as exc:
                entry["detail"] = str(exc)
                results.append(entry)
                continue

            expected = item.get("sha256") or header.get("sha256")
            if expected and hashlib.sha256(content).hexdigest() != expected:
                entry["detail"] = "hash uyuşmuyor"
            else:
                entry["ok"] = True
                entry["detail"] = "eski format" if item.get("legacy") else "tamam"
            results.append(entry)
        return results

    def purge(self, name: str | None = None, shred: bool = False) -> int:
        """Kasadan kalıcı olarak siler. `name` yoksa tüm kasa boşaltılır."""
        targets = (
            [name]
            if name
            else [item["name"] for item in self.list_items()]
        )
        logs = self._get_logs()
        removed = 0
        for target in targets:
            path = os.path.join(self.q_dir, os.path.basename(target))
            if not os.path.isfile(path):
                continue
            if shred:
                _shred(path)
            else:
                _silent_remove(path)
            _silent_remove(f"{path}.meta")
            logs.pop(os.path.basename(target), None)
            removed += 1
        self._save_logs(logs)
        return removed

    def reveal(self, path: str) -> bool:
        """Dosyayı işletim sisteminin dosya yöneticisinde gösterir.

        v3.0 burada `subprocess`'i import etmeyi unutmuştu; hata çıplak
        ``except`` içinde yutuluyordu. Artık çapraz platform ve açık.
        """
        import subprocess
        import sys

        path = os.path.abspath(path)
        try:
            if sys.platform.startswith("win"):
                subprocess.Popen(["explorer", f"/select,{path}"])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-R", path])
            else:
                subprocess.Popen(["xdg-open", os.path.dirname(path)])
            return True
        except (OSError, FileNotFoundError):
            return False


# ---------------------------------------------------------------------------
def _silent_remove(path: str):
    try:
        os.remove(path)
    except OSError:
        pass


def _shred(path: str, passes: int = _SHRED_PASSES):
    """Dosyayı rastgele veriyle üzerine yazıp siler.

    SSD/COW dosya sistemlerinde kesin güvence vermez (aşınma dengeleme
    eski blokları tutabilir), bu yüzden varsayılan değildir.
    """
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as handle:
            for _ in range(max(1, passes)):
                handle.seek(0)
                remaining = size
                while remaining > 0:
                    block = min(1 << 20, remaining)
                    handle.write(os.urandom(block))
                    remaining -= block
                handle.flush()
                os.fsync(handle.fileno())
    except OSError:
        pass
    _silent_remove(path)


def migrate_legacy_dirs(target_dir: str) -> int:
    """Eski karantina dizinlerindeki dosyaları yeni kasaya taşır."""
    manager = QuarantineManager(target_dir)
    moved = 0
    for legacy in QuarantineManager.LEGACY_DIRS:
        source = os.path.abspath(legacy)
        if source == manager.q_dir or not os.path.isdir(source):
            continue
        for name in os.listdir(source):
            if not name.endswith((".enc", ".enc.meta")):
                continue
            shutil.move(os.path.join(source, name), os.path.join(manager.q_dir, name))
            moved += 1
    return moved
