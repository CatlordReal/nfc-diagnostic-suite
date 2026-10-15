# Engineering and verification

## Firmware and distribution boundary

This standalone application targets the installed Momentum tag [`mntm-012`](https://github.com/Next-Flip/Momentum-Firmware/tree/e1784e7418d8b074e971983ceb6fef0f37e52ae4), commit `e1784e7418d8b074e971983ceb6fef0f37e52ae4`, API 87.1. Earlier development used commit `d3f89dfe2ef6b01839201598e9be1590cba80322`; required exports and relevant native/public interfaces were verified against `mntm-012`. The app does not patch or flash firmware. `dist/BUILD.txt` records the actual source revision and artifact SHA-256. A source override requires matching installed firmware.

The release distributes `nfc_diagnostic_suite.fap` with its own offline-tools plugin embedded as a native file asset, and an optional installer ZIP containing that FAP, README, license, icon and build record. Source and tests remain in the GitHub repository. It does not redistribute firmware or other Momentum apps. Guided actions can hand off to compatible tools installed separately; availability is checked at runtime and launching a tool does not prove completion. `scripts/setup-momentum.sh` fetches the pinned firmware source and submodules for building; the checkout is not copied into the ZIP.

The native loader extracts the embedded FAL to the suite assets directory. Offline recommendations, system selection and reader-history comparisons load it synchronously after radio release and free all mapped sections before the next RF operation. The embedded payload is checked byte-for-byte against the linked FAL, including its API metadata and enabled imports. The main FAP unloads optional theme asset packs through Momentum’s existing app flag while running.

Every suite FAP import must be enabled in that checkout's `targets/f7/api_symbols.csv`. The import gate forbids direct write and key-recovery imports while allowing bounded diagnostic listener APIs. FAP API metadata and the embedded launcher icon are checked.

## NFC card evidence

Momentum defines 15 NFC scanner protocols. On mntm-012, the broad scanner’s EMV detection invokes a native PPSE TLV parser with unchecked lengths. This suite avoids that path: it discovers the five base technologies through native pollers, then runs read-only family probes with bounds on its own response parsing. Native scanner byte-count semantics remain correct; they are not the reason for this change. Family hints stay candidates until a direct response confirms them. Private anticollision stages are not invented.

The pinned firmware’s ISO14443-A activation (`lib/nfc/protocols/iso14443_3a/iso14443_3a_poller_i.c`) does not bound repeated out-of-spec cascade-tag responses before copying into its UID array. Standard 4/7/10-byte cards remain the intended native-API inputs. This app does not harden that firmware routine against a malicious RF emulator; doing so requires a firmware fix or a replacement low-level stack. Firmware source remains unchanged. The app’s response/file validation cannot repair an overflow that happens inside native activation first.

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
| SLIX | Native UID-shape hint | UID-derived family classification remains a candidate |
| ST25TB | Initiate, select and GetUID | No block writing |
| NTAG4xx | Wrapped GET_VERSION with bounded application chaining | Firmware ISO-DEP WTX can delay transaction drain |
| Type 4 Tag | NDEF application selection | No diagnostic payload extraction |
| EMV | PPSE directory selection | No account or payment credential extraction |

A stable selected UID is checked before applying a later family result. ISO A four-byte `08xxxxxx` identifiers and ISO B PUPIs can change: the primary observed identity is retained, reduced correlation is explicit, and a version manufacturing UID does not replace it. A direct response proves behaviour during that activation, not chip authenticity or continuity across random identifiers.

PicoPass is absent from this 15-protocol scanner table. An optional handoff can open a separately installed compatible tool; launching it does not claim that this app scanned or confirmed PicoPass.

## 125 kHz RFID and reader diagnostics

LF card inspection uses Momentum's registered RFID protocol dictionary and native automatic ASK/PSK decoder. A decoded protocol ID and bytes are evidence; a field alone is not a decoded card. The app preserves up to 32 identity bytes for LF data and retains the exact decoder name. Native protocol encoding support does not guarantee that a particular writable blank or reader is compatible.

LF reader observation reports field presence and the frequency value supplied by the native RFID HAL. Its frequency count is converted to Hz using the firmware's own `counter * 10` implementation. Combined NFC/LF field observation follows Momentum's native detector hardware arrangement. Sampled presence durations are not waveform traces, calibrated strength, reader brand or decoding evidence.

NFC reader modes are bounded to 30 seconds:

- Passive NFC field monitor samples presence and durations.
- Synthetic Type A probe exposes selection, receive/request counts and timing metadata without storing command payloads or secrets.
- Classic listener collects native complete authentication contexts for a selected UID, or an explicitly synthetic random diagnostic UID when no card is supplied. It does not guess real UIDs. The native Classic listener does not expose all field/selection/RX totals; unavailable counters are labelled rather than synthesized.

Classic pairing requires the same CUID, sector and key type, with distinct complete Nt/Nr/Ar triples. Shared components, including a static card nonce, remain valid native MFKey inputs; identical full replays and duplicate pairs are rejected. Distinct exchanges do not prove statistical independence or recovery success. A four-byte card nonce alone is insufficient. At most 16 pending samples and eight pairs are retained. Callback events use a bounded queue of 32 entries; dropped events are counted. Callbacks perform no storage operations.

After the listener stops and releases the radio, the worker scans and appends standard native `Sec ... key ... cuid ... nt0 ... nr0 ... ar0 ... nt1 ... nr1 ... ar1 ...` records to `/ext/nfc/.mfkey32.log`. One exclusive append handle covers deduplication and publication. Existing bytes are never truncated or rewritten; an I/O failure may leave an incomplete new tail, which is reported. Log scans and each dictionary scan are capped at 1 MiB; oversized lines are skipped safely, incomplete counts are labelled, and keys are not displayed. A separately installed compatible recovery tool may consume the native log format; success is not promised.

A separately installed compatible writer may support specific rewritable targets, including some Classic Gen1/Gen2 and Ultimate Magic Gen4 modes. It is not a universal NTAG, DESFire, NFC-V or modern-credential writer. Native NFC and LF tools enforce their own data, key and target requirements. Actions shown by the guide are routing capabilities, not proof that a write will succeed.

## Ownership, cancellation and storage

Each radio engine has one owning worker. Native resource allocation, stop/join and release occur on the same owning thread. Callbacks copy bounded events or data and never join themselves, access storage or touch UI. Shared model snapshots are mutex-protected. The controller runs operations sequentially and releases its engine before native app handoff. Configured listener identities remain private probe configuration, never observed card/reader identity fields. Workflow card evidence is owned by its originating card scan or validated saved source; standalone scans and reader probes cannot silently replace it.

Each native NFC probe has a 2.5-second application wait deadline. Identification visits at most five base technologies per attempt; the card workflow retries NFC once, then falls back to LF if no identity appears. LF operations have a 25-second window. These are application wait bounds, **not hard cancellation guarantees**: synchronous native poller probes, ISO-DEP WTX or a currently executing firmware operation may outlive them. Cancellation prevents more work and drains the native operation before freeing its data. The pinned DESFire/Plus native command helper also follows AF continuation while the peer requests it; an out-of-spec peer can prevent return indefinitely. Forced teardown would violate ownership. These inherited limits require a firmware fix or a separate low-level implementation to make hard cancellation guarantees.

System groups hold new card/reader session, JSON/CSV and log reports under `apps_data/nfc_diagnostic_suite/systems/<name>/`; old reports stay in the ungrouped root. Native `.nfc` and `.rfid` sources are retained in their original locations. Names are bounded and FAT-safe, group creation is capped at 12, and current selection uses temporary/backup publication. Reader `.reader` sidecars use an explicit 70-byte CRC32 format, never native struct packing. Matching requires comparable modes, stimulus, sampling and sufficient evidence. At most 64 profiles across the root and 12 system folders are considered; top-three timing/rate similarities are heuristics, never identity or brand proof. Orphan sidecars are excluded.

Classic capture shows one usable pair as its minimum, with ideal coverage dependent on sector/key. Done cancels new RF work, drains, appends/syncs the native log and offers Decode only when a pair is durably available without storage error. Native notifications honor speaker/vibro/stealth settings: one brief rising success or falling failure tone and a subtle vibration; first live pair readiness pulses once without claiming a recovered key. Natural and manual capture completion share the same tested policy.

Logs retain the newest 64 entries and count dropped entries. Repeat scans retain five compact observations including failures. Reports stream to storage. Across NFC retry/LF fallback, earlier terminal attempt domain/code summaries are retained; full earlier per-protocol logs are visible live/streamed through native logging, but are not archived into the new band model. The final model retains its latest 64 entries and explicit dropped count. JSON/CSV exports use temporary files, sync/close checks and non-overwriting publication. `.nds` sessions use explicit bounded fields and CRC32; the current version supports LF's wider identity and reads legacy version-one sessions. CRC detects corruption, not forgery. Loaded confirmation is historical; simulation provenance remains visible.

The `.nfc` validator checks files up to 256 KiB with bounded lines and a conservative 32 KiB dynamic payload budget before calling Momentum's semantic decoder. String lengths are checked against native destinations before trimming, mandatory fields and order are enforced, and large ATS/DESFire fields are bounded. Larger legitimate dumps can be rejected with a safety-limit result. Free-heap and largest-block guards also reject unsafe native loads. Preflight lines grow by bounded malloc/copy/free, avoiding this pin's realloc over-read. Guards reject malformed short Classic blocks, unsafe Plus field order/security level, zero-sized DESFire key arrays and oversized FeliCa public blocks before native loaders can assert or overflow. Native LF `.rfid` inspection validates protocol and exact data length. File validity or saved-data equality is not proof of physical card identity, complete Classic keys, or reader acceptance. Browser imports preserve originals.

## Proof and remaining acceptance

`./scripts/test.sh` runs portable model, file/session, NFC and LF engine evidence, reader callback/nonce, workflow/capability and actual C renderer tests. Sanitizers run in the test scripts where supported. Native builds treat warnings as errors; import and icon checks are additional gates. Independent reviews cover evidence claims, callback ownership, validators, reader pairing and action routing.

`docs/captures/` contains the shared C renderer running with Momentum's u8g2 fonts on a host framebuffer. These are simulated states rendered by actual UI code, not physical LCD captures or complete firmware emulation. Build/test results and representative captures were regenerated after final integration; see `VERIFICATION.txt`.

Physical NFC/LF detection, reader interaction, radio contention, handoff behaviour, SD power-loss handling, USB streaming and Dolphin XP remain hardware acceptance checks. No connected Flipper was available for this work. No RSSI, calibrated field strength, impedance, antenna tuning, range, waveform, universal credential support or reader manufacturer/model inference is claimed.
