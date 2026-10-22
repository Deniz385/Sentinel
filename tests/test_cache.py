"""Incremental scan cache tests.

In a security tool a cache, built carelessly, makes a leak
*invisible*. So the weight of these tests is not on "is it faster"
but on **when it must not be trusted**: a rule change, a transient
error, quarantine, and the limits of mtime.
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
    """Move the file's mtime back (a resolution-independent freshness check)."""
    info = os.stat(path)
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns - seconds * 1_000_000_000))


class TestCacheHits:
    def test_second_scan_reads_nothing_and_finds_the_same(self, tree, tmp_path):
        target = tree({"a.txt": f"ID: {VALID_TCKN}\n", "b.txt": f"Card: {VALID_VISA}\n"})
        cache = tmp_path / "scan-cache.json"

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
        target = tree({"a.txt": f"ID: {VALID_TCKN}\n"})
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
        target = tree({"a.txt": "clean content\n"})
        cache = tmp_path / "c.json"

        assert run(target, cache).findings == []

        (target / "a.txt").write_bytes(f"ID: {VALID_TCKN}\n".encode())
        second = run(target, cache)
        assert len(second.findings) == 1
        assert second.files_cached == 0

    def test_only_the_changed_file_is_rescanned(self, tree, tmp_path):
        target = tree({f"d{i}.txt": f"file {i}\n" for i in range(6)})
        cache = tmp_path / "c.json"
        run(target, cache)

        (target / "d3.txt").write_bytes(f"Card: {VALID_VISA}\n".encode())
        second = run(target, cache)

        assert second.files_cached == 5
        assert len(second.findings) == 1

    def test_new_file_is_scanned_without_losing_the_cache(self, tree, tmp_path):
        target = tree({"a.txt": "one\n", "b.txt": "two\n"})
        cache = tmp_path / "c.json"
        run(target, cache)

        (target / "c.txt").write_bytes(f"ID: {VALID_TCKN}\n".encode())
        second = run(target, cache)

        assert second.files_cached == 2
        assert second.files_scanned == 3
        assert len(second.findings) == 1

    def test_deleted_file_disappears_from_results(self, tree, tmp_path):
        target = tree({"a.txt": f"ID: {VALID_TCKN}\n", "b.txt": "clean\n"})
        cache = tmp_path / "c.json"
        run(target, cache)

        os.unlink(target / "a.txt")
        second = run(target, cache)
        # Even with an entry in the cache, the file is no longer in the
        # tree, so it is never asked about; the old finding must not leak.
        assert second.findings == []


class TestInvalidation:
    def test_rule_or_setting_change_drops_the_whole_cache(self, tree, tmp_path):
        target = tree({"a.txt": f"ID: {VALID_TCKN}\n"})
        cache = tmp_path / "c.json"
        run(target, cache)

        # Enabling entropy scanning means a new finding type: the old
        # verdicts are void, or the new rule's secret stays hidden.
        second = run(target, cache, entropy_scan=True)
        assert second.files_cached == 0

    def test_min_severity_change_drops_the_cache(self, tree, tmp_path):
        target = tree({"a.txt": f"ID: {VALID_TCKN}\nmail: a@b.com\n"})
        cache = tmp_path / "c.json"
        run(target, cache, min_severity=Severity.HIGH.value)

        second = run(target, cache, min_severity=Severity.INFO.value)
        assert second.files_cached == 0
        assert any(f.type == "EMAIL" for f in second.findings)

    def test_fingerprint_ignores_settings_that_cannot_change_results(self):
        base = ScanConfig(entropy_scan=False)
        assert config_fingerprint(base) == config_fingerprint(
            base.replace(workers=7, executor="thread", target="/elsewhere")
        )

    def test_fingerprint_follows_settings_that_can(self):
        base = ScanConfig()
        for changed in (
            base.replace(entropy_threshold=3.0),
            base.replace(entropy_scan=not base.entropy_scan),
            base.replace(exclude_rules=("EMAIL",)),
            base.replace(fingerprint_salt="salt"),
            base.replace(max_line_length=100),
        ):
            assert config_fingerprint(base) != config_fingerprint(changed)

    def test_editing_a_yara_rule_drops_the_cache(self, tmp_path):
        # The configuration holds only the directory path; the cache must
        # also drop when a rule file itself changes.
        rules = tmp_path / "rules"
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
        rules = tmp_path / "rules"
        rules.mkdir()
        (rules / "test.yar").write_text("rule A { condition: true }", encoding="utf-8")

        config = ScanConfig(yara_enabled=False, yara_rules_dir=str(rules))
        before = config_fingerprint(config)
        (rules / "test.yar").write_text("rule B { condition: false }", encoding="utf-8")
        assert config_fingerprint(config) == before

    def test_missing_rules_directory_does_not_raise(self, tmp_path):
        config = ScanConfig(yara_enabled=True, yara_rules_dir=str(tmp_path / "missing"))
        assert config_fingerprint(config)

    def test_version_is_part_of_the_fingerprint(self, monkeypatch):
        # An upgrade may have changed the validators or the entropy
        # heuristics; a new version does not inherit the old verdicts.
        import sentinel.cache as cache_module

        config = ScanConfig()
        before = config_fingerprint(config)
        monkeypatch.setattr(cache_module, "__version__", "99.9.9")
        assert config_fingerprint(config) != before

    def test_corrupt_cache_file_falls_back_to_full_scan(self, tree, tmp_path):
        target = tree({"a.txt": f"ID: {VALID_TCKN}\n"})
        cache = tmp_path / "c.json"
        cache.write_text("{ this is not valid json", encoding="utf-8")

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
            json.dumps({"schema": 1, "config_hash": "different", "entries": {"/a": {}}}),
            encoding="utf-8",
        )
        opened = ScanCache.open(str(cache), config)
        assert opened.invalidated is True
        assert opened.entries == {}


class TestSafety:
    def test_quarantine_disables_the_cache(self, tree, tmp_path):
        target = tree({"a.txt": f"ID: {VALID_TCKN}\n"})
        cache = tmp_path / "c.json"
        config = make_config(
            cache, quarantine=True, quarantine_dir=str(tmp_path / "vault")
        )

        scanner = Scanner(str(target), config=config)
        # A decision that DELETES data cannot rest on stale evidence.
        assert scanner._cache is None

    def test_transient_errors_are_not_remembered(self, tmp_path):
        cache = ScanCache(path=str(tmp_path / "c.json"), config_hash="h")
        victim = tmp_path / "a.txt"
        victim.write_bytes(b"content")

        cache.remember(
            FileReport(path=str(victim), error="OSError: locked", findings=[])
        )
        # A locked file must not become invisible forever.
        assert cache.entries == {}

    def test_cache_file_is_not_scanned(self, tree, tmp_path):
        # With the cache *inside* the target, it must not scan itself.
        target = tree({"a.txt": f"ID: {VALID_TCKN}\n"})
        cache = target / ".sentinel-cache.json"

        run(target, cache)
        second = run(target, cache)

        assert cache.is_file()
        assert all(".sentinel-cache" not in f.file for f in second.findings)
        assert second.files_scanned == 1

    def test_baseline_still_suppresses_cached_findings(self, tree, tmp_path):
        target = tree({"a.txt": f"ID: {VALID_TCKN}\n"})
        cache = tmp_path / "c.json"
        baseline = tmp_path / "baseline.txt"

        first = run(target, cache)
        from sentinel.allowlist import save_baseline

        save_baseline(str(baseline), first.findings)

        # The baseline is applied *after* the cache: suppression must
        # still work on a cache hit.
        second = run(target, cache, baseline_path=str(baseline))
        assert second.files_cached == 1
        assert second.findings == []

    def test_mtime_rollback_is_a_known_limitation(self, tree, tmp_path):
        """The freshness test ``(mtime, size)`` is a heuristic, not proof.

        A change that restores mtime and preserves size slips past the
        cache. We pin the behaviour here explicitly: this is a documented
        trade-off, not an undiscovered bug. Where forensic certainty is
        required, ``incremental`` stays off (the default).
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
        assert stale.findings == []  # missed - the known trade-off

        # With incremental scanning off, the same file is found.
        full = run(target, cache, incremental=False)
        assert len(full.findings) == 1

    def test_disabled_by_default(self, tree, tmp_path):
        target = tree({"a.txt": f"ID: {VALID_TCKN}\n"})
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
        # When the cache cannot be written, the scan must still finish.
        cache = ScanCache(path=str(tmp_path / "a.txt" / "c.json"), config_hash="h")
        (tmp_path / "a.txt").write_bytes(b"a file, not a directory")
        assert cache.save() is False

    def test_stats_separate_stale_from_missing(self, tree, tmp_path):
        target = tree({"a.txt": "one\n", "b.txt": "two\n"})
        cache_path = tmp_path / "c.json"
        run(target, cache_path)

        touch_older(target / "a.txt")
        (target / "c.txt").write_bytes(b"uc\n")

        config = make_config(cache_path)
        scanner = Scanner(str(target), config=config)
        scanner.scan()
        stats = scanner._cache.stats
        assert stats.hits == 1  # b.txt
        assert stats.stale == 1  # a.txt (mtime changed)
        assert stats.misses == 1  # c.txt (no entry)

    def test_oversized_cache_keeps_the_newest_entries(self, tmp_path, monkeypatch):
        import sentinel.cache as cache_module

        monkeypatch.setattr(cache_module, "MAX_ENTRIES", 3)
        cache = ScanCache(path=str(tmp_path / "c.json"), config_hash="h")
        for index in range(10):
            cache.entries[f"/file{index}"] = {
                "mtime_ns": 1,
                "size": 1,
                "findings": [],
                "last_seen": index,
            }
        cache.save()

        written = json.loads((tmp_path / "c.json").read_text(encoding="utf-8"))
        assert len(written["entries"]) == 3
        assert set(written["entries"]) == {"/file9", "/file8", "/file7"}
