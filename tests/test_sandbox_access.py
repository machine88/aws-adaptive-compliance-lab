"""Regression checks for the dedicated sandbox's policy provenance and isolation."""
import hashlib
import json
import unittest
from pathlib import Path
from scripts.build_sandbox_boundary import build_policies

ROOT = Path(__file__).resolve().parents[1]


class SandboxAccessTests(unittest.TestCase):
    """Check resource and privilege boundaries without credentials or AWS requests."""

    def test_generated_policy_provenance_and_sizes(self):
        """Require reproducible candidate policies and bounded managed-policy sizes.

        Inputs:
            self: Test instance reading the maintained policy/provenance files.
        Outputs:
            None: Assertions fail for changed generated output, drift or oversize policies.
        """
        boundary, backend = build_policies(ROOT)
        for name, expected in [('sandbox-boundary.json', boundary), ('sandbox-state-and-read-policy.json', backend)]:
            self.assertEqual(json.loads((ROOT / 'infra/access' / name).read_text()), expected)
            self.assertLessEqual(len(json.dumps(expected, separators=(',', ':'))), 6144)
        generated = json.loads((ROOT / 'infra/access/generated-sandbox-policy.json').read_text())
        metadata = json.loads((ROOT / 'protocol/sandbox-policy-generation.json').read_text())
        self.assertEqual(hashlib.sha256(json.dumps(generated, sort_keys=True, separators=(',', ':')).encode()).hexdigest(), metadata['generated_policy_canonical_sha256'])
        self.assertFalse(metadata['deployable_plan'])

    def test_only_sandbox_and_exact_state_objects_escape_storage_deny(self):
        """Prevent object-body grants or cross-phase state access from escaping the explicit deny.

        Inputs:
            self: Test instance with fixed account/region resource expectations.
        Outputs:
            None: Assertions fail if a wildcard or unrelated resource enters the exceptions.
        """
        boundary, backend = build_policies(ROOT)
        bucket = 'arn:aws:s3:::dissertation-sandbox-653464153304-us-east-2-s3-01'
        state = 'arn:aws:s3:::dissertation-653464153304-us-east-2-state'
        key = state + '/dissertation/653464153304/us-east-2/development-sandbox/terraform.tfstate'
        denial = next(s for s in boundary['Statement'] if s['Sid'] == 'DenyOtherStorage')
        self.assertEqual(set(denial['NotResource']), {bucket, state, key, key + '.tflock'})
        writes = next(s for s in backend['Statement'] if s['Sid'] == 'B06')
        release = next(s for s in backend['Statement'] if s['Sid'] == 'B07')
        self.assertEqual(writes['Action'], ['s3:GetObject', 's3:PutObject'])
        self.assertEqual(set(writes['Resource']), {key, key + '.tflock'})
        self.assertEqual(release['Action'], ['s3:DeleteObject'])
        self.assertEqual(release['Resource'], [key + '.tflock'])
        self.assertNotIn('/baseline/', json.dumps(backend))

    def test_unsupported_generated_privileges_remain_explicitly_denied(self):
        """Keep broad generated extras outside the dedicated role's maximum action set.

        Inputs:
            self: Test instance inspecting the deny allowlist and bucket-specific grants.
        Outputs:
            None: Assertions fail for privilege escalation, deletion or unsupported-service grants.
        """
        boundary, _ = build_policies(ROOT)
        maximum = next(s['NotAction'] for s in boundary['Statement'] if s['Sid'] == 'DenyOtherActions')
        for action in ['iam:PassRole', 'iam:CreatePolicyVersion', 'sts:AssumeRole', 's3:DeleteBucket', 's3:DeleteBucketPolicy', 's3:PutObjectTagging', 'config:StartConfigurationRecorder']:
            self.assertNotIn(action, maximum)
        self.assertTrue(all(a.startswith('s3:') or a == 'sts:GetCallerIdentity' for a in maximum))
        grant = next(s for s in boundary['Statement'] if s['Sid'] == 'SandboxConfiguration')
        self.assertEqual(grant['Condition'], {'StringEquals': {'aws:RequestedRegion': 'us-east-2'}})
        self.assertEqual(grant['Resource'], ['arn:aws:s3:::dissertation-sandbox-653464153304-us-east-2-s3-01'])


    def test_generated_observer_and_writer_policies_match_source_and_provenance(self):
        """Reject stale runtime source bindings or edited generated observer/writer baselines.

        Inputs:
            self: Test instance reading maintained source and generation metadata only.
        Outputs:
            None: Asserts exact source sets/content, policy hashes and closed standalone/apply gates.
                Performs no IAM simulation, credential lookup or AWS call.
        """
        sources = {"observer": {"research/sandbox_capture.py", "scripts/sandbox_capture_worker.py"},
                   "writer": {"research/sandbox_writer.py"}}
        for name, expected_sources in sources.items():
            with self.subTest(role=name):
                metadata = json.loads((ROOT / f"protocol/{name}-policy-generation.json").read_text())
                generated = json.loads((ROOT / f"infra/{name}/generated-{name}-policy.json").read_text())
                self.assertEqual(set(metadata["source_sha256"]), expected_sources)
                for path, expected in metadata["source_sha256"].items():
                    self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), expected)
                digest = hashlib.sha256(json.dumps(generated, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                self.assertEqual(digest, metadata["generated_policy_canonical_sha256"])
                self.assertFalse(metadata["generated_policy_standalone_approved"])
                self.assertFalse(metadata["deployable_saved_plan"])
                self.assertFalse(metadata["aws_applied"])


if __name__ == '__main__':
    unittest.main()
