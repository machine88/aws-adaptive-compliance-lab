"""Offline read-only retirement: real disposable CMS, synthetic completion metadata, no live evidence."""
import copy
from functools import partial
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from research.catalog import canonical_sha256
from research.observer_recovery_preparation import VERSION as PREPARATION_VERSION
from research.preparation_operator import write_preparation_json
from research.readonly_retirement import (VERSION, readonly_lock_inventory, retirement_source_sha256,
                                         retire_readonly_preparation)
from research.recovery_intent import retain_recovery_intent
from research.recovery_review import private_directory, read_recovery_intent
from research.sandbox_readiness import BUCKET
from research.scenario_lock import RETIREMENT_GUARD, acquire_sandbox_lock
from scripts.retire_readonly_preparation import main
from tests import test_preparation_operator as fixtures
from tests.crypto_fixtures import synthetic_decrypt
from tests.test_sandbox_emptiness import fixture as listing_fixture
from tests.test_sandbox_readiness import fixture as metadata_fixture


class ReadonlyRetirementTests(unittest.TestCase):
    """Preserve encrypted recovery evidence and cooperative exclusion through archival failures."""

    @classmethod
    def setUpClass(cls):
        """Reuse disposable recipient creation without inheriting or duplicating unrelated tests.

        Inputs:
            cls: Test class receiving only synthetic recipient files and runtime paths.
        Outputs:
            None: Creates disposable crypto fixtures, never actual keys, profiles or Keychain items.
        """
        fixtures.PreparationOperatorTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        """Remove the disposable class-owned recipient.

        Inputs:
            cls: Test class owning temporary synthetic recipient files.
        Outputs:
            None: Deletes only test fixtures.
        """
        cls.keys.cleanup()

    def setUp(self):
        """Build a fresh synthetic completed read-only preparation for each test.

        Inputs:
            self: Test instance receiving historical metadata and a real disposable encrypted intent.
        Outputs:
            None: Creates temporary files only; no AWS call or real operational lock.
        """
        self.build_fixture()

    def build_fixture(self):
        """Compose one independently pinned synthetic completion and proposed retirement scope.

        Inputs:
            self: Test instance holding disposable class crypto and automatic cleanup registration.
        Outputs:
            None: Creates a temporary private completed-report fixture with actual CMS intent.
                Completion metadata is synthetic; no capture, AWS or real Keychain use is claimed.
        """
        fixtures.PreparationOperatorTests.setUp(self)
        self.preparation = self.scope
        run_id = self.preparation["observer"]["run_id"]
        lock_root = Path(self.preparation["lock_root"])
        self.lock = acquire_sandbox_lock(lock_root, run_id)
        self.guard = lock_root / RETIREMENT_GUARD
        root_info, lock_info = lock_root.stat(), self.lock.stat()
        manifest = {"human_review_sha256": self.preparation["human_review_sha256"],
            "local_lock_identity": {"root_device": root_info.st_dev, "root_inode": root_info.st_ino,
                                    "lock_device": lock_info.st_dev, "lock_inode": lock_info.st_ino}}
        self.manifest_pin = canonical_sha256(manifest)
        write_preparation_json(Path(self.preparation["binding_root"]) / (run_id + ".json"), manifest)
        self.commitment = retain_recovery_intent(lock_root, run_id, metadata_fixture(), listing_fixture(),
            self.manifest_pin, self.preparation["observer"]["capture"]["source_sha256"],
            self.pin, self.preparation["observer"]["certificate"], self.binary, 5)
        self.preparation_pin = canonical_sha256(self.preparation)
        self.result = {"version": PREPARATION_VERSION, "phase": "development", "run_id": run_id,
            "preparation_manifest_sha256": self.manifest_pin,
            "human_review_sha256": self.preparation["human_review_sha256"],
            "observer_scope_sha256": self.preparation["observer_scope_sha256"], "ciphertext_fingerprint": "d" * 64,
            "intent_commitment_sha256": canonical_sha256(self.commitment), "intent_sha256": self.commitment["intent_sha256"],
            "local_receipt_window_consistent": True, "lock_held": True, "intent_retained": True,
            "source_freshness_verified": False, "concurrent_writes_excluded": False,
            "recovery_credentials_verified": False, "live_execution_allowed": False, "research_trials": 0,
            "preparation_scope_sha256": self.preparation_pin, "retained_intent_consistency_verified": True}
        operator = Path(self.preparation["operator_root"])
        operator.mkdir(mode=0o700)
        write_preparation_json(operator / "scope.json", self.preparation)
        write_preparation_json(operator / "result.json", self.result)
        write_preparation_json(operator / "status.json", {"version": "preparation-operator-v0.1", "phase": "development",
            "run_id": run_id, "scope_sha256": self.preparation_pin, "worker_status": "success",
            "worker_report_verified": False, "live_execution_allowed": False, "research_trials": 0,
            "result_sha256": canonical_sha256(self.result)})
        archive = self.base / "retired"
        archive.mkdir(mode=0o700)
        descriptor = private_directory(self.lock)
        try:
            inventory = readonly_lock_inventory(descriptor, self.preparation, self.result)
        finally:
            os.close(descriptor)
        self.scope = {"version": VERSION, "phase": "development", "kind": "retire_completed_readonly_preparation",
            "preparation": self.preparation, "preparation_scope_sha256": self.preparation_pin,
            "preparation_result_sha256": canonical_sha256(self.result), "lock_inventory_sha256": inventory,
            "archive_root": str(archive), "source_sha256": retirement_source_sha256()}
        self.path = self.base / "retirement-scope.json"
        write_preparation_json(self.path, self.scope)
        self.target = archive / run_id

    def test_preview_and_intact_archive_roundtrip_before_reuse(self):
        """Archive every lock byte and retain compatibility with the existing intent reader.

        Inputs:
            self: Test instance with synthetic completed metadata and actual disposable CMS intent.
        Outputs:
            None: Asserts preview is side-effect free, old intent remains readable and reuse needs a new run.
        """
        before = {str(path.relative_to(self.lock)): path.read_bytes() for path in self.lock.rglob("*") if path.is_file()}
        with patch("scripts.retire_readonly_preparation.retire_readonly_preparation") as execute, \
                patch("research.readonly_retirement.completed_preparation") as inspect, \
                patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(main(["--scope", str(self.path)]), 0)
        execute.assert_not_called()
        inspect.assert_not_called()
        self.assertTrue(self.lock.exists())
        with patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit):
                main(["--scope", str(self.path), "--execute"])
        result = retire_readonly_preparation(self.scope, canonical_sha256(self.scope))
        self.assertTrue(result["lock_retired"] and result["cooperative_acquisition_unblocked"])
        self.assertFalse(result["restoration_verified"] or result["live_execution_allowed"])
        self.assertFalse(self.lock.exists() or self.guard.exists())
        archived = self.target / (BUCKET + ".lock")
        after = {str(path.relative_to(archived)): path.read_bytes() for path in archived.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        decrypt = partial(synthetic_decrypt, binary=self.binary, certificate=self.cert, key=self.key)
        read = read_recovery_intent(self.target, self.result["run_id"], decrypt, self.manifest_pin,
            self.preparation["observer"]["capture"]["source_sha256"], self.pin, canonical_sha256(self.commitment))
        self.assertEqual(read["intent_sha256"], self.result["intent_sha256"])
        acquire_sandbox_lock(self.preparation["lock_root"], "b" * 32)
        with self.assertRaises(ValueError):
            retire_readonly_preparation(self.scope, canonical_sha256(self.scope))
        self.assertTrue(archived.exists())

    def test_changed_pins_artifacts_and_existing_destinations_block_retirement(self):
        """Reject changed review/evidence and expanded lock layouts before archival.

        Inputs:
            self: Test instance injecting only changes in its temporary synthetic fixture.
        Outputs:
            None: Asserts original lock remains, no archive reservation and no guard cleanup occurs.
        """
        cipher = self.lock / "recovery-intent/record-00000.cms"
        original = cipher.read_bytes()
        for case in ("approval", "source", "result", "ciphertext", "closure", "destination", "guard"):
            scope = copy.deepcopy(self.scope)
            if case == "source":
                scope["source_sha256"] = "0" * 64
            if case == "result":
                scope["preparation_result_sha256"] = "0" * 64
            if case == "ciphertext":
                cipher.write_bytes(b"changed-synthetic-ciphertext")
            if case == "closure":
                (self.lock / "recovery-closure").mkdir(mode=0o700)
            if case == "destination":
                self.target.mkdir(mode=0o700)
            if case == "guard":
                self.guard.symlink_to(self.base / "nonexistent-guard-target")
            try:
                with self.subTest(case=case), self.assertRaises((ValueError, FileExistsError)):
                    retire_readonly_preparation(scope, "0" * 64 if case == "approval" else canonical_sha256(scope))
                self.assertTrue(self.lock.exists())
                if case != "destination":
                    self.assertFalse(self.target.exists())
            finally:
                cipher.write_bytes(original)
                if case == "closure":
                    (self.lock / "recovery-closure").rmdir()
                if case == "destination":
                    self.target.rmdir()
                if case == "guard":
                    self.guard.unlink()

        # A guard appearing after initial admission must prevent acquisition from returning success.
        from research.scenario_lock import require_no_retirement
        for stage in (2, 3):
            race_root = self.base / ("race-" + str(stage))
            race_root.mkdir(mode=0o700)
            checks = 0

            def guard_check(root):
                """Introduce retirement during acquisition rather than before its first guard check.

                Inputs:
                    root: Private disposable cooperative lock root passed by the real acquisition code.
                Outputs:
                    None: Delegates the real guard check after creating one timed test-only guard.
                """
                nonlocal checks
                checks += 1
                if checks == stage:
                    (Path(root) / RETIREMENT_GUARD).mkdir(mode=0o700)
                require_no_retirement(root)

            with patch("research.scenario_lock.require_no_retirement", side_effect=guard_check):
                with self.assertRaises(ValueError):
                    acquire_sandbox_lock(race_root, "b" * 32)
            self.assertTrue((race_root / (BUCKET + ".lock")).exists())
            self.assertTrue((race_root / RETIREMENT_GUARD).exists())

    def test_interrupted_archival_keeps_guard_and_preserves_original_bytes(self):
        """Block new acquisition if retirement fails before move, after move or before guard removal.

        Inputs:
            self: Test instance with disposable failures at filesystem transition boundaries.
        Outputs:
            None: Asserts intact cipher bytes and blocking through pre-release failures; a final sync
                error after guard removal is explicitly tested as committed archive/uncertain completion.
        """
        from research.readonly_retirement import write_retirement_record
        original_fsync = os.fsync
        for index, case in enumerate(("rename", "commitment", "guard_removal", "guard_contents", "archive_contents", "final_sync")):
            if index:
                self.build_fixture()
            original_cipher = (self.lock / "recovery-intent/record-00000.cms").read_bytes()

            def record(descriptor, name, value):
                """Fail only the archival commitment write after the entire lock has moved.

                Inputs:
                    descriptor: Held private test archive descriptor.
                    name: Fixed metadata filename selected by maintained code.
                    value: Metadata-only scope or commitment.
                Outputs:
                    None: Delegates writes except the selected synthetic commitment failure.
                """
                if case == "commitment" and name == "retirement.json":
                    raise OSError("synthetic commitment failure")
                write_retirement_record(descriptor, name, value)
                if name == "retirement.json" and case in {"guard_contents", "archive_contents"}:
                    changed = self.guard if case == "guard_contents" else self.target
                    (changed / "scope.json").write_bytes(b"{}")

            def sync(descriptor):
                """Fail only the final parent sync after guard removal, preserving committed archival data.

                Inputs:
                    descriptor: Directory or file descriptor selected by maintained retirement code.
                Outputs:
                    None: Performs real local fsync, then injects the explicitly uncertain final-boundary error.
                """
                original_fsync(descriptor)
                if not self.guard.exists() and (self.target / "retirement.json").exists():
                    raise OSError("synthetic final directory sync failure")

            target = {"rename": "research.readonly_retirement.os.rename",
                      "commitment": "research.readonly_retirement.write_retirement_record",
                      "guard_removal": "research.readonly_retirement.os.rmdir",
                      "guard_contents": "research.readonly_retirement.write_retirement_record",
                      "archive_contents": "research.readonly_retirement.write_retirement_record",
                      "final_sync": "research.readonly_retirement.os.fsync"}[case]
            effect = sync if case == "final_sync" else record if case in {"commitment", "guard_contents", "archive_contents"} else OSError("synthetic transition failure")
            with self.subTest(case=case), patch(target, side_effect=effect):
                with self.assertRaises((OSError, ValueError)):
                    retire_readonly_preparation(self.scope, canonical_sha256(self.scope))
            self.assertEqual(self.guard.exists(), case != "final_sync")
            preserved = self.lock if case == "rename" else self.target / (BUCKET + ".lock")
            self.assertEqual((preserved / "recovery-intent/record-00000.cms").read_bytes(), original_cipher)
            if case != "final_sync":
                with self.assertRaises(ValueError):
                    acquire_sandbox_lock(self.preparation["lock_root"], "b" * 32)
            else:
                self.assertTrue((self.target / "retirement.json").exists())
            self.assertEqual(self.lock.exists(), case == "rename")
