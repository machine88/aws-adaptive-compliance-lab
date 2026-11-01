# Sandbox observer preparation

Status: **offline request adapter and encrypted library engine implemented; preview-first supervised operator implemented; permission deployment and live collection pending review**. The request adapter performs no AWS calls, reads no credentials and writes no evidence. Supplied responses are not authenticated observations.

`research/sandbox_observer.py` defines eleven distinct S3 requests for the dedicated Ohio development bucket. Eight read bucket protections/location/tags/policy; three list current objects, object versions/deletion markers, and unfinished multipart uploads. The current-object listing is reused by both existing predicates. Every request names the exact bucket and expected account owner. Listings cover the entire bucket from the first page with a 1000-entry ceiling, without filters or continuation. Nonempty or truncated listings fail the existing emptiness predicate; pagination cannot repair that result.

The adapter requires a supplied STS identity naming the proposed `dissertation-sandbox-observer` assumed role in account `653464153304`. It retains copies of that identity, all raw responses, service request IDs, request parameters, UTC start/end clocks and monotonic elapsed durations. It checks consistency and successful response status before invoking the existing pre-state predicates. These checks cannot authenticate the source, establish clock accuracy, exclude concurrent writes or authorize a scenario. Rejected inputs must eventually remain in a separate encrypted failure record; this adapter does not archive them.

## Proposed permission and collection review

No permission change is included in this change. The current evidence-reader role excludes this bucket. Do not bypass it using the provisioning user or widen it silently.

Before a live observation, prepare and review:

1. A separate narrow observer role and matching boundary, trusting only the existing approved non-root principal. Verify each IAM action against current AWS documentation; permit only the eleven metadata/listing operations on the exact bucket in Ohio. No object-body reads, writes, deletes, versioning changes or unrelated buckets.
2. Version-controlled Terraform and an isolated state key for that access change, with a saved plan showing only reviewed role/policy changes. Preserve existing baseline, state and telemetry access. Obtain explicit approval before applying it.
3. A reviewed operator integrating the library collector, a supervised process deadline and identity verification before S3, explicit SDK timeouts, one attempt per request, no retry/pagination fallback, a total deadline and encrypted success/failure retention. One normal pass has one STS identity call and eleven S3 calls, excluding any separately reviewed credential acquisition calls. Timeouts are not proof of a hard total process deadline.
4. An independently reviewed capture scope binding source, public recipient, role, requests, deadline, output location and call budget. Retain private raw responses and errors without printing provider data. Obtain explicit approval before live collection. Ordinary request charges may apply; no new compute or monitoring activation is proposed. The existing $100 account alert remains an alert, not a cutoff.
5. Independent review of identity attribution, timing, completeness and interference risks before using these observations for recovery. This is development evidence only, never pilot or confirmatory data.

## Inputs and outputs

`observer_requests()` returns fresh request descriptions. `assemble_observer_prestate(identity, receipts)` accepts the complete ordered receipts and returns private copied raw evidence plus the metadata/listing inputs accepted by recovery-intent preparation. Receipt envelopes add `response`, `started_at`, `finished_at` and integer `elapsed_ns` to each request description. Service responses require integer HTTP 200 and a nonempty `RequestId`.

The [supervised operator](sandbox-operator.md) now provides a preview-first command. Its existence is not live-capture approval. The evidence output explicitly leaves source identity, freshness and scenario execution unverified. Passing synthetic tests proves software behavior only.

## Encrypted capture engine

`research/sandbox_capture.py` now implements the library engine. The supervised wrapper is implemented and tested offline; observer access deployment, actual local scope review and live-capture approval remain open. It accepts an explicit SDK session and a new bounded `EncryptedArchive`; the existing evidence-reader collector remains unchanged.

`capture_scope(source_sha256, recipient_sha256)` describes the exact requests and limits. `capture_sandbox` checks the independently supplied scope hash, current maintained source and normalized recipient before constructing clients. A hash comparison cannot establish human approval. This engine scope does not yet bind the profile/credential chain, host or archive path: the wrapper supplies declared profile/path bindings, while actual credential-chain availability and host trust require separate review. Source fingerprints do not authenticate installed dependencies or the host.

The engine uses fixed regional HTTPS endpoints, verified TLS, disabled configured endpoint overrides/proxies, three-second connect and ten-second read timeouts, one SDK attempt and a five-second crypto subprocess timeout. A before-send guard blocks a second transport attempt, including redirects. A normal capture invokes one STS identity operation then eleven distinct S3 operations; location and exact project tags are checked before the remaining S3 reads. Credential-provider calls, including any profile role assumption or login, are outside that budget and must be reviewed separately.

The 120-second monotonic deadline is checked before operations, before wire attempts, after retained responses and before completion retention. It is **cooperative, not a hard process timeout**: credential lookup, DNS, an in-flight read, OS file synchronization or final encryption can outlast it. Failed captures attempt one encrypted failure record, which can also take additional time. Do not claim an exact wall-clock upper bound. The wrapper now supplies a 150-second supervised worker timeout; this does not impose an absolute end-to-end deadline on parent preparation, filesystem synchronization or process reaping.

Scope, identity receipt, each S3 receipt, composed pre-state and completion are retained separately as ciphertext: fifteen records on success. Complete means the supplied administrative predicates passed and receipts were retained; it does not mean authorized scenario execution, an atomic snapshot, independently verified freshness, or research readiness. Provider failures retain their raw SDK error response and supplied timing inside ciphertext when possible. Failure timing ends at failure handling and can include local validation/encryption time; it is not an inferred service-response timestamp. For other failures, only the error class is retained. The caller receives a generic failure. Partial archives remain for review; no retry, cleanup, mutation, lock release or recovery happens automatically. Failed archive writes cannot guarantee a failure record, so absence of a final acknowledgement must stay incomplete.

Offline integration tests use real SDK service models/stubs and disposable local certificates. They exercise ciphertext round trips, early identity/tag/provider/deadline rejection, scope/recipient mismatch and the one-attempt send guard. They do not establish live permissions, service availability or empirical study findings.

The [observer access review preparation](sandbox-observer-access-preparation.md) records the reproducible policy-analysis command and its rejected broad candidate. No access policy was applied.
