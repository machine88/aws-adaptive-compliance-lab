# Encrypted archive acknowledgment and local durability

The existing CMS archive writer now synchronizes its public-recipient file, archive directory and parent entry during initialization. Each record is encrypted in memory using the existing mechanism, written exclusively, flushed and fsynced. The archive directory is then fsynced before a ciphertext receipt is appended or returned. Encryption format and receipt schema do not change.

If either synchronization fails, the exception propagates and no success receipt is returned for that record. Existing partial ciphertext remains in place, so a retry cannot silently overwrite it. A partially initialized or failed archive is for investigation; do not reuse it as a successful run. This is deliberately conservative retention, not automatic cleanup or recovery.

The OS synchronization calls improve persistence ordering. They do not prove survival of every power failure, guarantee hardware flushes, or supply cross-host/network-filesystem durability. Unsupported directory synchronization fails instead of silently skipping the safeguard. Historical captures are not modified or retrospectively certified by this change.

Two synthetic failure-boundary tests check acknowledgment ordering and failure at either file or directory synchronization. They mock encryption output and are not cryptographic proofs. The existing real CMS encryption/decryption roundtrip and regression suite remain the encryption checks.

The [recovery-intent preparer](recovery-intent.md) now uses this writer to retain an encrypted development pre-state and fixed action descriptions under a matching local lock. The emergency recovery reader, live scenario driver, verified restoration, recovery-aware release and live-run approval remain unimplemented. No AWS calls, private-key access, new recipient keys or study observations are introduced.
