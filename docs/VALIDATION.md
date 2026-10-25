# Validation and deployment boundaries

The release is an engineering preview. Offline validation exercises the pointer-free protocol, strict input lengths, reserved fields, UTF-16 boundaries and one million reproducible malformed-policy mutations per SDK. Release and AddressSanitizer results are recorded privately; public status reflects the tests actually completed.

The private driver builds with WDK, warnings-as-errors, PREfast and Control Flow Guard. This does not by itself validate a loaded driver. No guarantee of zero vulnerabilities, zero overhead or compatibility with every Windows build is made.

RegistryGuard has no assigned altitude. Its analysis-only binary rejects initialization; no INF/CAT/CAB package is generated and no registry callback was loaded in a VM.

Qualification before production delivery must also cover Windows 11, Secure Boot, HVCI, coexistence with endpoint security, repeated PnP removal, power transitions, install rollback and customer-specific policy scope. Run in an isolated lab first. Never disable production security settings to run an unsigned preview.

The kernel device grants access only to SYSTEM and administrators. One session owns the policy. Wire records contain no pointers; inputs have exact sizes and bounded capacities. Decisions have no network dependency. A bounded passive-level lock protects policy updates and the event ring; the callback performs no per-event heap allocation or user-mode round trip. Display/export may lag or lose records under load; the counters expose drops.

Deleting or stopping the client removes its rules; in-flight callbacks may complete a decision already made. This owner-lifetime behavior is intentional and is not persistent endpoint enforcement. Audited operations are observations of a pre-operation callback, not proofs that all downstream work succeeded.

When a production setup is available, it must verify the embedded Microsoft catalog and INF/SYS membership, elevate only for installation, report Windows errors and restart requirements, and uninstall only its own exact package. The provided setup source follows this package identity boundary; setup binaries are withheld until the corresponding driver is signed and qualified.

## Microsoft documentation

- [Configuration Manager registry callbacks](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/filtering-registry-calls)
- [CmRegisterCallbackEx and Microsoft altitude allocation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallbackex)
