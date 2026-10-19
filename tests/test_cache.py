"""Artımlı tarama önbelleği testleri.

Bir güvenlik aracında önbellek, yanlış kurgulandığında sızıntıyı
*görünmez* yapar. Bu yüzden testlerin ağırlığı "hızlandı mı"da değil,
**ne zaman güvenilmemesi gerektiği**nde: kural değişimi, geçici hata,
karantina ve mtime'ın sınırları.
"""

from __future__ import annotations

import json
import os

from sentinel.cache import ScanCache, clear_cache, config_fingerprint
from sentinel.config import ScanConfig
from sentinel.engine import FileReport, Scanner
from sentinel.severity import Severity
from tests.conftest import VALID_TCKN, VALID_VISA


def make_config(cache_path, **overrides):
    settings = {
        "min_severity": Severity.INFO.value,
        "entropy_scan": False,
        "yara_enabled": False,
        "workers": 1,
        "executor": "serial",
        "incremental": True,
        "cache_path": str(cache_path),
    }
    settings.update(overrides)
    return ScanConfig(**settings)


def run(target, cache_path, **overrides):
    config = make_config(cache_path, **overrides)
    return Scanner(str(target), config=config).scan()


def touch_older(path, seconds: int = 10):
    """Dosyanın mtime'ını geriye alır (çözünürlük bağımsız tazelik kontrolü)."""
    info = os.stat(path)
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns - seconds * 1_000_000_000))


class TestCacheHits:
    def test_second_scan_reads_nothing_and_finds_the_same(self, tree, tmp_path):
        target = tree({"a.txt": f"TC: {VALID_TCKN}\n", "b.txt": f"Kart: {VALID_VISA}\n"})
        cache = tmp_path / "onbellek.json"

        first = run(target, cache)
        assert first.files_cached == 0
        assert cache.is_file()

        second = run(target, cache)
        assert second.files_cached == first.files_scanned
        assert second.files_scanned == first.files_scanned
        assert [f.fingerprint for f in second.findings] == [
            f.fingerprint for f in first.findings
        ]

    def test_cached_findings_round_trip_completely(self, tree, tmp_path):
        target = tree({"a.txt": f"TC: {VALID_TCKN}\n"})
        cache = tmp_path / "c.json"

        before = run(target, cache).findings[0]
        after = run(target, cache).findings[0]

        for attribute in (
            "file",
            "line",
            "column",
            "type",
            "title",
            "severity",
            "content_masked",
            "fingerprint",
            "snippet",
            "validated",
            "sha256",
            "real_path",
        ):
            assert getattr(after, attribute) == getattr(before, attribute), attribute

    def test_changed_file_is_rescanned(self, tree, tmp_path):
        target = tree({"a.txt": "temiz içerik\n"})
        cache = tmp_path / "c.json"

        assert run(target, cache).findings == []

        (target / "a.txt").write_bytes(f"TC: {VALID_TCKN}\n".encode())
        second = run(target, cache)
        assert len(second.findings) == 1
        assert second.files_cached == 0

    def test_only_the_changed_file_is_rescanned(self, tree, tmp_path):
        target = tree({f"d{i}.txt": f"dosya {i}\n" for i in range(6)})
        cache = tmp_path / "c.json"
        run(target, cache)

        (target / "d3.txt").write_bytes(f"Kart: {VALID_VISA}\n".encode())
        second = run(target, cache)

        assert second.files_cached == 5
        assert len(second.findings) == 1

    def test_new_file_is_scanned_without_losing_the_cache(self, tree, tmp_path):
        target = tree({"a.txt": "bir\n", "b.txt": "iki\n"})
        cache = tmp_path / "c.json"
        run(target, cache)

        (target / "c.txt").write_bytes(f"TC: {VALID_TCKN}\n".encode())
        second = run(target, cache)

        assert second.files_cached == 2
        assert second.files_scanned == 3
        assert len(second.findings) == 1

    def test_deleted_file_disappears_from_results(self, tree, tmp_path):
        target = tree({"a.txt": f"TC: {VALID_TCKN}\n", "b.txt": "temiz\n"})
        cache = tmp_path / "c.json"
        run(target, cache)

        os.unlink(target / "a.txt")
        second = run(target, cache)
        # Önbellekte kaydı olsa bile dosya artık ağaçta olmadığı için
        # hiç sorulmaz; eski bulgu rapora sızmamalı.
        assert second.findings == []


class TestInvalidation:
    def test_rule_or_setting_change_drops_the_whole_cache(self, tree, tmp_path):
        target = tree({"a.txt": f"TC: {VALID_TCKN}\n"})
        cache = tmp_path / "c.json"
        run(target, cache)

        # Entropi taramasını açmak yeni bulgu türü demek: eski kararlar
        # geçersizdir, yoksa yeni kuralın bulacağı sır gizli kalır.
        second = run(target, cache, entropy_scan=True)
        assert second.files_cached == 0

    def test_min_severity_change_drops_the_cache(self, tree, tmp_path):
        target = tree({"a.txt": f"TC: {VALID_TCKN}\nmail: a@b.com\n"})
        cache = tmp_path / "c.json"
        run(target, cache, min_severity=Severity.HIGH.value)

        second = run(target, cache, min_severity=Severity.INFO.value)
        assert second.files_cached == 0
        assert any(f.type == "EMAIL" for f in second.findings)

    def test_fingerprint_ignores_settings_that_cannot_change_results(self):
        base = ScanConfig(entropy_scan=False)
        assert config_fingerprint(base) == config_fingerprint(
            base.replace(workers=7, executor="thread", target="/baska/yer")
        )

    def test_fingerprint_follows_settings_that_can(self):
        base = ScanConfig()
        for changed in (
            base.replace(entropy_threshold=3.0),
            base.replace(entropy_scan=not base.entropy_scan),
            base.replace(exclude_rules=("EMAIL",)),
            base.replace(fingerprint_salt="tuz"),
            base.replace(max_line_length=100),
        ):
            assert config_fingerprint(base) != config_fingerprint(changed)

    def test_editing_a_yara_rule_drops_the_cache(self, tmp_path):
        # Yapılandırmada yalnızca dizin yolu durur; kural dosyasının
        # kendisi değişince de önbellek düşmeli.
        rules = tmp_path / "kurallar"
        rules.mkdir()
        rule = rules / "test.yar"
        rule.write_text('rule A { strings: $a = "x" condition: $a }', encoding="utf-8")

        config = ScanConfig(yara_enabled=True, yara_rules_dir=str(rules))
        before = config_fingerprint(config)

        rule.write_text(
            'rule A { strings: $a = "xy" condition: $a }', encoding="utf-8"
        )
        os.utime(rule, ns=(0, 10**18))
        assert config_fingerprint(config) != before

    def test_yara_signature_ignored_when_yara_is_off(self, tmp_path):
        rules = tmp_path / "kurallar"
        rules.mkdir()
        (rules / "test.yar").write_text("rule A { condition: true }", encoding="utf-8")

        config = ScanConfig(yara_enabled=False, yara_rules_dir=str(rules))
        before = config_fingerprint(config)
        (rules / "test.yar").write_text("rule B { condition: false }", encoding="utf-8")
        assert config_fingerprint(config) == before

    def test_missing_rules_directory_does_not_raise(self, tmp_path):
        config = ScanConfig(yara_enabled=True, yara_rules_dir=str(tmp_path / "yok"))
        assert config_fingerprint(config)

    def test_version_is_part_of_the_fingerprint(self, monkeypatch):
        # Yükseltme doğrulayıcıları ya da entropi buluşsallarını
        # değiştirmiş olabilir; yeni sürüm eski kararları devralmaz.
        import sentinel.cache as cache_module

        config = ScanConfig()
        before = config_fingerprint(config)
        monkeypatch.setattr(cache_module, "__version__", "99.9.9")
        assert config_fingerprint(config) != before

    def test_corrupt_cache_file_falls_back_to_full_scan(self, tree, tmp_path):
        target = tree({"a.txt": f"TC: {VALID_TCKN}\n"})
        cache = tmp_path / "c.json"
        cache.write_text("{ bu gecerli json degil", encoding="utf-8")

        result = run(target, cache)
        assert result.files_cached == 0
        assert len(result.findings) == 1

    def test_unknown_schema_is_ignored(self, tmp_path):
        cache = tmp_path / "c.json"
        config = make_config(cache)
        cache.write_text(
            json.dumps(
                {
                    "schema": 9999,
                    "config_hash": config_fingerprint(config),
                    "entries": {"/a": {"mtime_ns": 1, "size": 1, "findings": []}},
                }
            ),
            encoding="utf-8",
        )
        assert ScanCache.open(str(cache), config).entries == {}

    def test_mismatched_hash_is_flagged_as_invalidated(self, tmp_path):
        cache = tmp_path / "c.json"
        config = make_config(cache)
        cache.write_text(
            json.dumps({"schema": 1, "config_hash": "baska", "entries": {"/a": {}}}),
            encoding="utf-8",
        )
        opened = ScanCache.open(str(cache), config)
        assert opened.invalidated is True
        assert opened.entries == {}


class TestSafety:
    def test_quarantine_disables_the_cache(self, tree, tmp_path):
        target = tree({"a.txt": f"TC: {VALID_TCKN}\n"})
        cache = tmp_path / "c.json"
        config = make_config(
            cache, quarantine=True, quarantine_dir=str(tmp_path / "kasa")
        )

        scanner = Scanner(str(target), config=config)
        # Veri SİLEN bir karar bayat kanıta dayanamaz.
        assert scanner._cache is None

    def test_transient_errors_are_not_remembered(self, tmp_path):
        cache = ScanCache(path=str(tmp_path / "c.json"), config_hash="h")
        victim = tmp_path / "a.txt"
        victim.write_bytes(b"icerik")

        cache.remember(
            FileReport(path=str(victim), error="OSError: kilitli", findings=[])
        )
        # Kilitli bir dosya sonsuza kadar görünmez olmamalı.
        assert cache.entries == {}

    def test_cache_file_is_not_scanned(self, tree, tmp_path):
        # Önbellek hedefin *içinde* duruyorsa kendi kendini taramamalı.
        target = tree({"a.txt": f"TC: {VALID_TCKN}\n"})
        cache = target / ".sentinel-cache.json"

        run(target, cache)
        second = run(target, cache)

        assert cache.is_file()
        assert all(".sentinel-cache" not in f.file for f in second.findings)
        assert second.files_scanned == 1

    def test_baseline_still_suppresses_cached_findings(self, tree, tmp_path):
        target = tree({"a.txt": f"TC: {VALID_TCKN}\n"})
        cache = tmp_path / "c.json"
        baseline = tmp_path / "baseline.txt"

        first = run(target, cache)
        from sentinel.allowlist import save_baseline

        save_baseline(str(baseline), first.findings)

        # Baz çizgisi önbellekten *sonra* uygulanır: önbellek isabet
        # etse de bastırma çalışmalı.
        second = run(target, cache, baseline_path=str(baseline))
        assert second.files_cached == 1
        assert second.findings == []

    def test_mtime_rollback_is_a_known_limitation(self, tree, tmp_path):
        """Tazelik ölçütü ``(mtime, boyut)``; bu bir sezgidir, kanıt değil.

        mtime'ı geri alan ve boyutu koruyan bir değişiklik önbelleği
        atlatır. Davranışı burada açıkça çiviliyoruz: belgelenmiş bir
        ödün, keşfedilmemiş bir hata değil. Adli kesinlik gerektiğinde
        ``incremental`` kapalı kalmalı (varsayılan).
        """
        target = tree({"a.txt": "aaaaaaaaaaaaaaaa\n"})
        cache = tmp_path / "c.json"
        run(target, cache)

        original = os.stat(target / "a.txt")
        payload = f"TC:{VALID_TCKN}\n".encode()
        payload = payload.ljust(original.st_size, b" ")[: original.st_size]
        (target / "a.txt").write_bytes(payload)
        os.utime(target / "a.txt", ns=(original.st_atime_ns, original.st_mtime_ns))

        stale = run(target, cache)
        assert stale.files_cached == 1
        assert stale.findings == []  # kaçırıldı — bilinen ödün

        # Artımlı tarama kapalıyken aynı dosya bulunur.
        full = run(target, cache, incremental=False)
        assert len(full.findings) == 1

    def test_disabled_by_default(self, tree, tmp_path):
        target = tree({"a.txt": f"TC: {VALID_TCKN}\n"})
        scanner = Scanner(
            str(target),
            config=ScanConfig(entropy_scan=False, yara_enabled=False, executor="serial"),
        )
        assert scanner.config.incremental is False
        assert scanner._cache is None


class TestHousekeeping:
    def test_clear_cache_removes_the_file(self, tmp_path):
        cache = tmp_path / "c.json"
        cache.write_text("{}", encoding="utf-8")
        assert clear_cache(str(cache)) is True
        assert not cache.exists()
        assert clear_cache(str(cache)) is False

    def test_save_is_atomic_and_leaves_no_temp_file(self, tmp_path):
        cache = ScanCache(path=str(tmp_path / "c.json"), config_hash="h")
        assert cache.save() is True
        assert not (tmp_path / "c.json.tmp").exists()

    def test_unwritable_location_does_not_raise(self, tmp_path):
        # Önbellek yazılamıyorsa tarama yine de tamamlanmalı.
        cache = ScanCache(path=str(tmp_path / "a.txt" / "c.json"), config_hash="h")
        (tmp_path / "a.txt").write_bytes(b"dosya, dizin degil")
        assert cache.save() is False

    def test_stats_separate_stale_from_missing(self, tree, tmp_path):
        target = tree({"a.txt": "bir\n", "b.txt": "iki\n"})
        cache_path = tmp_path / "c.json"
        run(target, cache_path)

        touch_older(target / "a.txt")
        (target / "c.txt").write_bytes(b"uc\n")

        config = make_config(cache_path)
        scanner = Scanner(str(target), config=config)
        scanner.scan()
        stats = scanner._cache.stats
        assert stats.hits == 1  # b.txt
        assert stats.stale == 1  # a.txt (mtime değişti)
        assert stats.misses == 1  # c.txt (kayıt yok)

    def test_oversized_cache_keeps_the_newest_entries(self, tmp_path, monkeypatch):
        import sentinel.cache as cache_module

        monkeypatch.setattr(cache_module, "MAX_ENTRIES", 3)
        cache = ScanCache(path=str(tmp_path / "c.json"), config_hash="h")
        for index in range(10):
            cache.entries[f"/dosya{index}"] = {
                "mtime_ns": 1,
                "size": 1,
                "findings": [],
                "last_seen": index,
            }
        cache.save()

        written = json.loads((tmp_path / "c.json").read_text(encoding="utf-8"))
        assert len(written["entries"]) == 3
        assert set(written["entries"]) == {"/dosya9", "/dosya8", "/dosya7"}
