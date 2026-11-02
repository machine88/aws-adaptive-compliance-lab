# Writer session timing budget

Status: offline metadata evaluator implemented and tested. No credential provider,
AWS session, bucket change or live admission is created by this component.

`research/writer_coverage.py` exposes `assess_writer_session_budget(sample,
expected_sample_sha256, run_id, assessed_at, monotonic_ns)`. It evaluates a supplied
expiration against a fixed development transport and recovery reserve. It never
reads keys, tokens, credentials, profiles, environment variables or private files.

```text
Future trusted adapter + retained provider evidence       NOT IMPLEMENTED
                         |
Nonsecret expiration metadata + independently retained fingerprint
                         |
Exact role/run + fresh consistent local clocks             IMPLEMENTED OFFLINE
                         |
2,400 s transport + 120 s recovery reserve + 1 s clock allowance
                         |
Declared timing budget sufficient                          PLANNING RESULT ONLY
                         |
Verified live provenance, lock, fresh source state and supervision STILL REQUIRED
```

## Inputs and output

The exact metadata frame has these fields; additional keys are rejected to avoid
accepting credential-bearing provider responses:

| Field | Meaning |
| --- | --- |
| `version` | `writer-session-budget-v0.1` |
| `phase` | `development`; pilot/confirmatory inputs are rejected |
| `run_id` | Fixed 32-character hexadecimal run ID matching the independent argument |
| `role_arn` | Exact assumed writer role/session in account 653464153304 |
| `sampled_at` | Timezone-aware local wall clock at metadata sampling |
| `sample_monotonic_ns` | Nonnegative integer from the same local process/clock domain as the assessment |
| `expires_at` | Supplied timezone-aware session expiration, not a configured requested duration |
| `source_record_sha256` | Fingerprint of separately retained source evidence; the evaluator does not open or authenticate it |

The independent metadata fingerprint covers the whole frame. Matching hashes
establish consistency only; a caller can invent metadata and its hash. Actual
provider evidence and clock-domain provenance must be verified by the future
trusted adapter. Do not use botocore private expiration attributes or a requested
3,600-second duration as a substitute for an authenticated expiration source.

The evaluator rejects negative/reversed monotonic clocks, backward wall clocks,
wall/monotonic elapsed differences above one second, or either elapsed clock
above 30 seconds. It charges the greater elapsed clock against the supplied
expiration, then requires at least **2,521 seconds** left: 2,400 seconds for the
entire existing transport lifetime, 120 seconds additional recovery reserve and
one second clock allowance. An expiration more than one hour after sampling is
rejected as inconsistent with the deployed role maximum. That check does not
prove the sample belongs to an actual session.

The 2,400-second transport already contains the proposed 1,800-second observation
horizon. These durations are not added together. The 120-second reserve and
30-second metadata-age policy are development engineering choices, not new study
outcomes or a formal protocol freeze. Future integration must budget dispatch,
trigger confirmation, process cleanup and recovery inside explicit deadlines;
this arithmetic cannot guarantee successful recovery or continuous network access.

A successful result reports `declared_budget_sufficient=true` but leaves
`provider_provenance_verified`, `credential_coverage_verified`,
`live_execution_allowed` and `restoration_verified` **false**, with zero research
trials. A result is not a reusable admission token: it is not accepted as an input
frame, has no writer/driver consumer and must never stand in for a new pre-change
assessment. The current SDK writer still reports its credential-coverage gate
false. No encrypted journal, operational lock or live runner is opened here.

## Validation and next step

Three focused tests cover independent-pin tampering, cross-run/role/phase reuse,
extra credential-like fields, stale and inconsistent clocks, expired/short or
implausible lifetimes, the exact conservative threshold and later reassessment.
They use synthetic metadata without AWS credentials or real waiting.

Next: build the trusted session-evidence adapter and bind the actual session used
for requests, its expiration source, encrypted retention and same-process clocks.
Then integrate fresh observer receipts, held intent/lock, supervision and
independent restoration/closure. Access deployment approval does not authorize a
new capture, versioning write or rehearsal. The [writer transport](sandbox-writer.md)
and [synthetic-only executor](versioning-cycle.md) retain their existing boundaries.
