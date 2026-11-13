# RegistryGuard operation schema

The unchanged product C++ SDK is called directly. Operations: `check`, `make_rule`, `start`, `set_rules`, `stop`, `status`, `read`, `event_path`. The dispatch source in `Bridge.cpp` lists exact argument keys and maps every operation to the original public SDK. Protocol structs retain their public-header field names, including case. UInt64 and Int64 fields are decimal strings; fixed arrays accept at most their capacity and omitted fields initialize to zero. Unknown fields and out-of-range values are rejected. SDK validators apply original protocol constraints.

Wire types and fields:

- `RG_RULE`: Id, Action, Chars, Reserved, Path
- `RG_POLICY`: Version, Size, Count, Reserved, Rules
- `RG_REQUEST`: Version, Size, Reserved
- `RG_STATS`: Version, Size, Active, RuleCount, Generation, Frequency, Produced, Denied, Dropped, UnknownNames, Available, Capacity, Reserved
- `RG_EVENT`: Sequence, Qpc, ProcessKey, Generation, ProcessId, ParentId, Operation, RuleId, Decision, Flags, Status, Chars, Path
- `RG_BATCH`: Stats, Count, Reserved, Events

Only explicit start/connect/policy calls start the corresponding operation. The C ABI session constructor is inert; one active session per product DLL. Always close. Capture receives are bounded when the native API accepts a timeout. SDK original licensing/trial checks remain unchanged. No driver is installed by packages.

Tests exercise synthetic wire inputs using the real production SDK validation/formatting helpers, rejected arguments, exact unsigned values and inert session lifecycle. No live capture, policy application, storage fault, traffic modification or driver activation is performed by these tests. Operational driver paths require a separate integration environment.

## Language client

The client calls the native SDK directly. Use the call method with an operation name and argument object. Calls are synchronous; only operations exposing a receive timeout are capped at100ms; use an application worker for responsive UI/event loops. Explicitly close the client after use. 64-bit identifiers and counters are decimal strings. Native errors expose their Windows code. Matching driver and licensing are separate requirements.
