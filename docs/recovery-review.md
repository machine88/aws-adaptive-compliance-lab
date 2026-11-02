# Offline recovery reading and restoration review

`research/recovery_review.py` reads a retained recovery intent and can retain an encrypted restoration candidate. It performs no AWS calls, opens no private key itself, never writes plaintext evidence, and never releases a lock. The existing reader allowlists and IAM policies are unchanged.

## Independent inputs

The reader requires the expected run identifier, review-manifest/source/public-recipient fingerprints and the canonical hash of the preparation commitment. These pins must come from independently retained trusted records, not from whichever files the reader is currently inspecting. It also requires a trusted authenticated decryption callback with its own execution/output bounds. The [preview-first local operator](recovery-operator.md) now connects the existing dedicated Keychain callback when explicitly invoked under a reviewed scope. The separately approved supervised preparation has now verified an actual retained intent through the dedicated helper. This demonstrates that local decryption/readback path for that run; it does not establish AWS restoration credentials or actual restoration.

The default and maximum cumulative byte budget is 4 MiB. It includes owner metadata, certificate, commitment, ciphertext, returned plaintext and post-decryption rereads. Invalid limits fail before ingestion. The caller's decryptor must itself bound memory and execution time; the reader can reject oversized returned plaintext but cannot undo allocation inside an arbitrary callback.

## What is verified locally

The reader uses anchored directory descriptors and private regular-file checks. It requires an owned private root/lock/archive, exact owner identity and archive filenames, safe permissions, no file symlinks or hardlinks, and the normalized public certificate pin. Preparation commitment identity and ciphertext hash are checked before decryption. JSON parsing rejects duplicate keys, nonfinite values and non-object records. The decrypted record must exactly reconstruct the fixed development-only intent using independent pins, including its proposal identity and closed execution gates.

After the callback, the reader rechecks private contents, filenames, owner marker and directory identities, including root replacement. This catches inconsistent content and directory substitution during the read. It does not authenticate the author against a same-user actor who controls code, files and external pins. The returned record is private in-memory plaintext; callers must not log or publish it.

## Restoration candidates

`build_restoration_candidate` revalidates the intent and supplied post-state using the same protected Enabled baseline, full-empty listing and MFA boundaries as preparation. It copies and hashes the post-state and links it to the original intent. `supplied_restoration_matches_baseline=true` means supplied technical consistency only. Actual restoration, live execution, source identity/freshness and concurrent-writer exclusion remain unverified.

`retain_restoration_candidate` first reads the independently pinned intent, then writes the candidate using the original public recipient into one exclusive `recovery-closure/` archive beneath the held lock. It synchronizes ciphertext and a private commitment linking the candidate to the original preparation commitment. Repeated writes fail; partial archives remain for investigation. The original encrypted intent remains readable after candidate retention or a failed candidate write.

A candidate is not a closure certificate. Neither successful retention nor the existence of commitment.json authorizes unlock, proves a successful function return after an interrupted synchronization, or supplies the recovery planner's `restoration_verified` event. The owner-only lock release still refuses recovery material. No automated cleanup or recovery-aware release is added here.

## Remaining operational boundaries

Before a live rehearsal, validate the scoped Keychain connection using actual approved local artifacts, implement independent scoped AWS receipts and source clocks, freshness/deadline/credential coverage, actual protection/restoration verification and a reviewed closure/release procedure preserving the original recovery evidence. The lock remains cooperative and single-host; unrelated hosts, console users and unmodified Terraform commands are not excluded by this module. Existing live-run and research approval gates remain intact.

Ten new synthetic cases cover actual CMS roundtrips with a disposable test recipient, external pin/ciphertext mismatches before decryption, duplicate fields, private permissions and links, owner/root changes during decryption, byte limits, weakened restoration metadata, encrypted candidate linkage and synchronization failure. The shared recipient fixture never accesses a real Keychain item, AWS credential or study observation.


## Bounded reading of a retained restoration candidate

`read_restoration_candidate` accepts the independently retained run, original
manifest/source/recipient pins and **both** intent and candidate commitment pins.
It returns only hashes and a local consistency report, never raw post-state.
It does not derive trusted pins from the archive being inspected.

The reader verifies the original intent before and after candidate ingestion.
It checks the candidate's exact archive/commitment, ciphertext receipt, recipient,
intent linkage and full reconstructed protected post-state. Modified gates or
extra fields are rejected. Directory descriptors stay anchored across callbacks;
owner/inventory/content rereads and root/lock/intent/candidate identity checks
reject replacement and partial artifacts.

The cumulative default/maximum file-plus-plaintext budget is 4 MiB. It is divided
into three fixed portions: the first intent read, candidate ingestion/rereads,
and the second intent read. Unused capacity is not transferred between portions.
A large artifact can therefore fail its portion even if other portions are small;
the reader never truncates data to force acceptance. The caller must still bound
decryptor runtime/output allocation; this API is not a process supervisor.

`retained_candidate_consistent=true` leaves `restoration_verified=false`,
`source_freshness_verified=false` and `live_execution_allowed=false`. No planner
transition or lock release is added. Only synthetic recipients/post-states have
exercised this new reader; no actual restoration or release has occurred.
Regression coverage extends the existing encrypted candidate roundtrip and adds
bad external pins, budget exhaustion, changed ciphertext, altered/oversized
plaintext, intent replacement and candidate-directory substitution.
