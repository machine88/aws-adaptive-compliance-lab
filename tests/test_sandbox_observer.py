"""Offline receipt composition safety tests; synthetic data and no cloud calls."""
import copy
import unittest
from research.sandbox_observer import ACCOUNT, ROLE, observer_requests, assemble_observer_prestate
from tests.test_sandbox_readiness import fixture as protections
from tests.test_sandbox_emptiness import fixture as empty_listings


def observation():
    """Compose synthetic response fixtures into the observer's ordered envelopes.

    Inputs:
        None: Uses existing independently specified protection and emptiness fixtures.
    Outputs:
        tuple: Synthetic identity and fresh receipt list; no IO or real evidence.
    """
    responses = protections()
    responses.update({key: value["response"] for key, value in empty_listings().items()})
    receipts = observer_requests()
    for receipt in receipts:
        response = responses[receipt["operation"]]
        response["ResponseMetadata"] = {"HTTPStatusCode": 200, "RequestId": "synthetic-request"}
        receipt.update(response=response, started_at="2026-10-31T00:00:00Z",
                       finished_at="2026-10-31T00:00:00Z", elapsed_ns=1)
    return {"Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{ROLE}/synthetic"}, receipts


class ObserverTests(unittest.TestCase):
    """Keep supplied observations inside exact scope without implying live authorization."""

    def test_composes_existing_predicates_without_rewriting_evidence(self):
        """Reuse protection and historical-empty predicates while preserving raw inputs.

        Inputs:
            self: Test instance using synthetic receipts.
        Outputs:
            None; asserts copied inputs, full coverage and closed scientific gates.
        """
        identity, receipts = observation()
        original = copy.deepcopy(receipts)
        report = assemble_observer_prestate(identity, receipts)
        self.assertEqual(receipts, original)
        self.assertEqual(len(receipts), 11)
        self.assertIs(report["live_execution_allowed"], False)
        self.assertIs(report["source_identity_verified"], False)
        receipts[0]["response"].clear()
        self.assertTrue(report["receipts"][0]["response"])
        identity, receipts = observation()
        next(item for item in receipts if item["operation"] == "list_object_versions")["response"]["DeleteMarkers"] = [{"Key": "synthetic"}]
        with self.assertRaises(ValueError):
            assemble_observer_prestate(identity, receipts)

    def test_rejects_scope_identity_and_incomplete_collection(self):
        """Reject wrong principals, modified requests, missing calls and failed service receipts.

        Inputs:
            self: Test instance varying one safety boundary at a time.
        Outputs:
            None; asserts every supplied out-of-scope observation is rejected.
        """
        for arn in (f"arn:aws:iam::{ACCOUNT}:root", f"arn:aws:sts::{ACCOUNT}:assumed-role/{ROLE}-extra/session", "other"):
            identity, receipts = observation()
            identity["Arn"] = arn
            with self.assertRaises(ValueError):
                assemble_observer_prestate(identity, receipts)
        for field, value in (("region", "us-east-1"), ("request", {"Bucket": "other"}),
                             ("response", {"ResponseMetadata": {"HTTPStatusCode": 403}})):
            identity, receipts = observation()
            receipts[0][field] = value
            with self.assertRaises(ValueError):
                assemble_observer_prestate(identity, receipts)
        identity, receipts = observation()
        with self.assertRaises(ValueError):
            assemble_observer_prestate(identity, receipts[:-1])

    def test_rejects_missing_request_ids_and_invalid_clocks(self):
        """Reject missing service attribution and malformed or reversed supplied timing.

        Inputs:
            self: Test instance changing receipt identifiers and clock fields.
        Outputs:
            None; asserts malformed timing never establishes a valid pre-state.
        """
        for field, value in (("started_at", "2026-10-31T00:00:01Z"),
                             ("finished_at", "2026-10-31T00:00:00"), ("elapsed_ns", True),
                             ("elapsed_ns", -1)):
            identity, receipts = observation()
            receipts[0][field] = value
            with self.assertRaises(ValueError):
                assemble_observer_prestate(identity, receipts)
        identity, receipts = observation()
        del receipts[0]["response"]["ResponseMetadata"]["RequestId"]
        with self.assertRaises(ValueError):
            assemble_observer_prestate(identity, receipts)
