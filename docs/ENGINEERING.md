# Engineering and verification

## Firmware and distribution boundary

This standalone application uses the actual [Momentum source at the default pin](https://github.com/Next-Flip/Momentum-Firmware/tree/d3f89dfe2ef6b01839201598e9be1590cba80322), API 87.1. It does not patch or flash the firmware. `dist/BUILD.txt` records the actual source revision and artifact SHA-256. A source override requires a matching installed firmware; the device's installed revision has not been established.

The build includes three separate, unmodified native Momentum apps: **MFKey**, **NFC Magic**, and **HID iClass (PicoPass)**. Their algorithms remain in those companions; the diagnostic app launches the appropriate native tool. The distribution retains their source icons, manifests, upstream descriptions, Momentum license and PicoPass component notices. `dist/vendor/SOURCE.txt` links the exact corresponding source revision. `scripts/setup-momentum.sh` fetches the pinned source and submodules; the full firmware checkout is not copied into the ZIP.

Every FAP import must be enabled in that checkout's `targets/f7/api_symbols.csv`. The diagnostics profile additionally forbids direct write and key-recovery imports, while allowing its bounded diagnostic listener APIs. Companion profiles allow native tool operations but still validate every import. FAP API metadata and each embedded launcher icon are checked. MFKey's asset bundle signature, embedded `mfkey_init_plugin.fal` and its imports are checked separately.

## NFC card evidence

Momentum's NFC scanner supports 15 protocols. Its multiple-result filter copies the wrong byte count at this pin (`lib/nfc/nfc_scanner.c`); the app discards multi-entry lists and uses independent identity probes. A scanner candidate is not a command-confirmed family. Scanner callbacks do not expose private selection or anticollision stages, and the app does not invent them.

| Protocol or family | Observable evidence | Limits |
| --- | --- | --- |
| ISO14443-A | Anticollision/select UID, ATQA, final SAK | Cascade count derives from UID length; no intermediate BCC/SAK trace or analog measurement |
| ISO14443-B | Activation and PUPI | PUPI may change between activations |
| ISO14443-4A / 4B | Transport activation; Type A ATS | Advertised capability alone remains a candidate |
| ISO15693 | Inventory UID | No password commands or writes in diagnostics |
| FeliCa | Polling IDm and PMm response | No authenticated service or key extraction |
| MIFARE Ultralight / NTAG2xx | Page-zero read and GET_VERSION | Older cards without GET_VERSION remain generic Type 2 candidates |
| MIFARE Classic | Four-byte nonce with the exact native AUTH-A block-zero response signature | Starts authentication, supplies no key and completes no authentication; 1K/4K capacity remains an inferred SAK hint |
| MIFARE Plus / DESFire | Read-only GET_VERSION with family/identity validation | ATS, SAK and ATQA alone never confirm; volatile identities reduce cross-activation correlation |
| SLIX | Scanner classification | UID-derived family classification remains a candidate |
| ST25TB | Initiate, select and GetUID | No block writing |
| NTAG4xx | Wrapped GET_VERSION with bounded application chaining | Firmware ISO-DEP WTX can delay transaction drain |
| Type 4 Tag | NDEF application selection | No diagnostic payload extraction |
| EMV | PPSE directory selection | No account or payment credential extraction |

A stable selected UID is checked before applying a later family result. ISO A four-byte `08xxxxxx` identifiers and ISO B PUPIs can change: the primary observed identity is retained, reduced correlation is explicit, and a version manufacturing UID does not replace it. A direct response proves behaviour during that activation, not chip authenticity or continuity across random identifiers.

PicoPass is absent from this 15-protocol scanner table. The separately bundled native app is an explicit compatibility tool, with its own supported identification/read/actions; launching it does not claim that this app scanned or confirmed PicoPass.

## 125 kHz RFID and reader diagnostics

LF card inspection uses Momentum's registered RFID protocol dictionary and native automatic ASK/PSK decoder. A decoded protocol ID and bytes are evidence; a field alone is not a decoded card. The app preserves up to 32 identity bytes for LF data and retains the exact decoder name. Native protocol encoding support does not guarantee that a particular writable blank or reader is compatible.

LF reader observation reports field presence and the frequency value supplied by the native RFID HAL. Its frequency count is converted to Hz using the firmware's own `counter * 10` implementation. Combined NFC/LF field observation follows Momentum's native detector hardware arrangement. Sampled presence durations are not waveform traces, calibrated strength, reader brand or decoding evidence.

NFC reader modes are bounded to 30 seconds:

- Passive NFC field monitor samples presence and durations.
- Synthetic Type A probe exposes selection, receive/request counts and timing metadata without storing command payloads or secrets.
- Classic listener collects native complete authentication contexts for a selected UID, or an explicitly synthetic random diagnostic UID when no card is supplied. It does not guess real UIDs. The native Classic listener does not expose all field/selection/RX totals; unavailable counters are labelled rather than synthesized.

Classic pairing requires the same CUID, sector and key type, with distinct complete Nt/Nr/Ar triples. Shared components, including a static card nonce, remain valid native MFKey inputs; identical full replays and duplicate pairs are rejected. Distinct exchanges do not prove statistical independence or recovery success. A four-byte card nonce alone is insufficient. At most 16 pending samples and eight pairs are retained. Callback events use a bounded queue of 32 entries; dropped events are counted. Callbacks perform no storage operations.

After the listener stops and releases the radio, the worker scans and appends standard native `Sec ... key ... cuid ... nt0 ... nr0 ... ar0 ... nt1 ... nr1 ... ar1 ...` records to `/ext/nfc/.mfkey32.log`. One exclusive append handle covers deduplication and publication. Existing bytes are never truncated or rewritten; an I/O failure may leave an incomplete new tail, which is reported. Log scans and each dictionary scan are capped at 1 MiB; oversized lines are skipped safely, incomplete counts are labelled, and keys are not displayed. MFKey handles any recovery through its native app and dictionary workflow; success is not promised.

NFC Magic supports its native list of rewritable targets, including supported Classic Gen1/Gen2 and Ultimate Magic Gen4 modes. It is not a universal NTAG, DESFire, NFC-V or modern-credential writer. Native NFC and LF apps enforce their own data, key and target requirements. Actions shown by the guide are routing capabilities, not proof that a write will succeed.

## Ownership, cancellation and storage

Each radio engine has one owning worker. Native resource allocation, stop/join and release occur on the same owning thread. Callbacks copy bounded events or data and never join themselves, access storage or touch UI. Shared model snapshots are mutex-protected. The controller runs operations sequentially and releases its engine before native app handoff. Configured listener identities remain private probe configuration, never observed card/reader identity fields. Workflow card evidence is owned by its originating card scan or validated saved source; standalone scans and reader probes cannot silently replace it.

NFC discovery has a 12-second application wait deadline; each direct stage has a 2.5-second wait deadline. LF operations have a 25-second window. These are application wait bounds, **not hard cancellation guarantees**: synchronous scanner probes, ISO-DEP WTX or a currently executing firmware operation may outlive them. Cancellation prevents more work and drains the native operation before freeing its data. Forced teardown would violate ownership.

Logs retain the newest 64 entries and count dropped entries. Repeat scans retain five compact observations including failures. Reports stream to storage. JSON/CSV exports use temporary files, sync/close checks and non-overwriting publication. `.nds` sessions use explicit bounded fields and CRC32; the current version supports LF's wider identity and reads legacy version-one sessions. CRC detects corruption, not forgery. Loaded confirmation is historical; simulation provenance remains visible.

The `.nfc` validator checks files up to 256 KiB with bounded lines and a conservative 32 KiB dynamic payload budget before calling Momentum's semantic decoder. String lengths are checked against native destinations before trimming, mandatory fields and order are enforced, and large ATS/DESFire fields are bounded. Larger legitimate dumps can be rejected with a safety-limit result. Free-heap and largest-block guards also reject unsafe native loads. Preflight lines grow by bounded malloc/copy/free, avoiding this pin's realloc over-read. Guards reject malformed short Classic blocks, unsafe Plus field order/security level, zero-sized DESFire key arrays and oversized FeliCa public blocks before native loaders can assert or overflow. Native LF `.rfid` inspection validates protocol and exact data length. File validity or saved-data equality is not proof of physical card identity, complete Classic keys, or reader acceptance. Browser imports preserve originals.

## Proof and remaining acceptance

`./scripts/test.sh` runs portable model, file/session, NFC and LF engine evidence, reader callback/nonce, workflow/capability and actual C renderer tests. Sanitizers run in the test scripts where supported. Native builds treat warnings as errors; import and icon checks are additional gates. Independent reviews cover evidence claims, callback ownership, validators, reader pairing and action routing.

`docs/captures/` contains the shared C renderer running with Momentum's u8g2 fonts on a host framebuffer. These are simulated states rendered by actual UI code, not physical LCD captures or complete firmware emulation. Build/test results and representative captures were regenerated after final integration; see `VERIFICATION.txt`.

Physical NFC/LF detection, reader interaction, radio contention, handoff behaviour, SD power-loss handling, USB streaming and Dolphin XP remain hardware acceptance checks. No connected Flipper was available for this work. No RSSI, calibrated field strength, impedance, antenna tuning, range, waveform, universal credential support or reader manufacturer/model inference is claimed.
