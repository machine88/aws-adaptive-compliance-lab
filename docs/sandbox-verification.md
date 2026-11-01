# Offline sandbox capture verification

`research/sandbox_verification.py` verifies a completed development observer pass against the independently retained approved scope and ciphertext inventory fingerprint. It uses the existing bounded archive reader and authenticated decryption callback. It makes no AWS request, repeats no capture and writes no plaintext.

## Inputs and outputs

| API | Inputs | Output |
| --- | --- | --- |
| `verify_sandbox_records` | Approved historical scope/hash, external inventory pin, decoded journal/capture records and their ciphertext receipts | Minimal consistency report; invalid bindings, requests, clocks, pre-state or completion chains fail |
| `verify_sandbox_archive` | Private declared output root, approved historical scope/hash, external inventory pin and trusted authenticated callback | Same report after bounded private-file reading and before/after inventory checks |

Success requires exactly two journal records and fifteen capture records. The verifier checks canonical contiguous ciphertext receipts, the enclosing operator scope, successful worker status and the capture's opening scope. It checks all twelve ordered request envelopes, service attribution for identity, clock consistency and bounded SDK durations. The existing administrative predicates reconstruct protections and all three full-bucket empty-listing receipts; that reconstructed pre-state must equal the retained pre-state. The final encrypted completion must name every predecessor receipt in order and retain development-only closed scientific/execution gates.

Journal ingestion permits at most 1 MiB and capture ingestion 4 MiB of cumulative certificate/ciphertext/plaintext bytes. Inventory checks reuse the existing 64 MiB ceiling. Private-file guards reject links, broad permissions, wrong ownership, changed files and noncanonical record sequences. Scope/inventory mismatches stop before invoking decryption where possible. The caller supplies trusted pins from outside the archives; self-declared values inside ciphertext are not an approval authority.

The callback can use the existing [Keychain bridge](keychain-ingestion.md). The native helper must match an independently retained executable fingerprint, public recipient and reviewed source. Its stdout must be captured privately in memory. Never invoke it as a display command, print decoded records, write plaintext evidence or return a private key/passphrase. Verification itself does not query arbitrary Keychain items or establish human approval.

Historical captures are verified against their retained approved scope. The verifier does not require today's capture source to equal an older source bundle: adding verification code must not erase valid historical evidence. A changed producer requires a new scope/review for another capture. Existing output remains exclusive and cannot silently be reused.

## What a successful report establishes

It establishes internal consistency of the retained encrypted records, expected request scope, supplied host clocks, bucket-protection predicates and complete empty supplied listings. It does not establish sender authenticity, independently attested AWS identity, synchronized clocks, freshness at a later time, simultaneous emptiness or exclusion of other writers. CMS authenticated decryption protects record integrity for the recipient; possession of a public encryption certificate is not a provider signature.

The report keeps source/freshness, concurrency, trigger, ML, formal-trial and live scenario-execution gates closed. No verified historical observation may silently become a fresh pre-mutation gate. The next runner integration needs prospective source/clock checks under the local lock, encrypted recovery intent, controlled restoration and a separately reviewed rehearsal.

## Actual development milestone

One explicitly approved observer pass completed in the dedicated short-lived role. It retained fifteen encrypted capture records and two encrypted operator journal records. Local verification through the previously trusted recipient/helper passed all binding and pre-state checks. The supplied responses showed preserved bucket protections and complete empty current-object, version/deletion-marker and unfinished-upload listings at their respective receipt times. No AWS configuration or scenario state was changed by this pass.

The raw responses, approvals, exact fingerprints, helper references and minimal verification report remain private. Plaintext evidence was not exported. These are administrative development observations; no pilot/confirmatory trial, trained study model, detection latency or comparative performance result is claimed. Existing integration coverage was extended for actual SDK/CMS composition, wrong inventory pins, substituted parent/request bindings, malformed clocks, changed pre-state, broken completion chains, wrong phase and failed worker status. Linux tests use disposable recipients and no real Keychain/AWS account.
