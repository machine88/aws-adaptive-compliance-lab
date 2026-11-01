# Sandbox observer preparation

Status: **offline request manifest and receipt adapter implemented; live collector and permission deployment pending review**. This component performs no AWS calls, reads no credentials and writes no evidence. Supplied responses are not authenticated observations.

`research/sandbox_observer.py` defines eleven distinct S3 requests for the dedicated Ohio development bucket. Eight read bucket protections/location/tags/policy; three list current objects, object versions/deletion markers, and unfinished multipart uploads. The current-object listing is reused by both existing predicates. Every request names the exact bucket and expected account owner. Listings cover the entire bucket from the first page with a 1000-entry ceiling, without filters or continuation. Nonempty or truncated listings fail the existing emptiness predicate; pagination cannot repair that result.

The adapter requires a supplied STS identity naming the proposed `dissertation-sandbox-observer` assumed role in account `653464153304`. It retains copies of that identity, all raw responses, service request IDs, request parameters, UTC start/end clocks and monotonic elapsed durations. It checks consistency and successful response status before invoking the existing pre-state predicates. These checks cannot authenticate the source, establish clock accuracy, exclude concurrent writes or authorize a scenario. Rejected inputs must eventually remain in a separate encrypted failure record; this adapter does not archive them.

## Proposed permission and collection review

No permission change is included in this change. The current evidence-reader role excludes this bucket. Do not bypass it using the provisioning user or widen it silently.

Before a live observation, prepare and review:

1. A separate narrow observer role and matching boundary, trusting only the existing approved non-root principal. Verify each IAM action against current AWS documentation; permit only the eleven metadata/listing operations on the exact bucket in Ohio. No object-body reads, writes, deletes, versioning changes or unrelated buckets.
2. Version-controlled Terraform and an isolated state key for that access change, with a saved plan showing only reviewed role/policy changes. Preserve existing baseline, state and telemetry access. Obtain explicit approval before applying it.
3. A bounded collector with identity verification before S3, explicit SDK timeouts, one attempt per request, no retry/pagination fallback, a total deadline and encrypted success/failure retention. One normal pass has one STS identity call and eleven S3 calls, excluding any separately reviewed credential acquisition calls. Timeouts are not proof of a hard total process deadline.
4. An independently reviewed capture scope binding source, public recipient, role, requests, deadline, output location and call budget. Retain private raw responses and errors without printing provider data. Obtain explicit approval before live collection. Ordinary request charges may apply; no new compute or monitoring activation is proposed. The existing $100 account alert remains an alert, not a cutoff.
5. Independent review of identity attribution, timing, completeness and interference risks before using these observations for recovery. This is development evidence only, never pilot or confirmatory data.

## Inputs and outputs

`observer_requests()` returns fresh request descriptions. `assemble_observer_prestate(identity, receipts)` accepts the complete ordered receipts and returns private copied raw evidence plus the metadata/listing inputs accepted by recovery-intent preparation. Receipt envelopes add `response`, `started_at`, `finished_at` and integer `elapsed_ns` to each request description. Service responses require integer HTTP 200 and a nonempty `RequestId`.

No live command is provided yet. The output explicitly leaves source identity, freshness and live execution unverified. Passing synthetic tests proves software behavior only.
