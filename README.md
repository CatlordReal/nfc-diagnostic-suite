# NFC Diagnostic Suite

Native NFC and 125 kHz RFID diagnostics for Flipper Zero with Momentum firmware. Inspect cards, observe readers, compare saved data, and follow guided actions for systems you own or are authorized to test. No expansion module is required. Support depends on the protocol, available source data, target card and reader; this is not a universal reader or cloning tool.

## Install and use

Download the [release ZIP](https://github.com/CatlordReal/nfc-diagnostic-suite/releases/latest), extract it, then copy the four files in `dist/apps/NFC/` to `SD/apps/NFC/` using qFlipper or an SD card reader:

- `nfc_diagnostic_suite.fap`: diagnostics, guided workflow, session reports and comparison.
- `mfkey.fap`: Momentum's native MFKey recovery app, including its embedded plugin.
- `nfc_magic.fap`: Momentum's native tool for supported rewritable NFC cards.
- `picopass.fap`: Momentum's **HID iClass (PicoPass)** app for its supported identification, reading and card actions.

Open **NFC Diagnostic Suite → Identify card (auto)**. It tries 13.56 MHz NFC, then native 125 kHz decoding if no NFC identity appears. **Scan 125 kHz RFID** starts LF directly; reader tests offer passive field observation, a synthetic Type A probe, and MIFARE Classic transcript collection. The guided workflow selects actions from the available evidence. Native NFC and 125 kHz RFID apps provide their supported reading, emulation and writing operations; the bundled companions provide their own supported operations. A successful read or matching saved file does not prove that an access system will accept a credential.

**Card workflow** starts with **I have a card** or **I have no card**. Follow **Guide / next steps**; only actions supported by the current evidence appear. Native tools open after this app releases its radio, then return to the saved workflow. Read and save the original, choose its source file, write a compatible blank in the native tool, read the blank into a different file, then **Verify saved copy**. Reader-only work may identify a band or collect supported exchanges; it cannot reconstruct missing card data.

**Repeat test** runs five inspections using the last decoded card band (NFC by default); **Set baseline** and **Compare sessions** compare diagnostic evidence.

**Up/Down** scrolls. **Back** cancels an operation or returns. Results distinguish confirmed responses, candidates, saved evidence and simulations. Unknown or protected protocols remain inconclusive. Reader manufacturer/model, RF strength and chip authenticity are not inferred.

Reports go to `SD/apps_data/nfc_diagnostic_suite/` as `.nds`, JSON and CSV. They contain observed identifiers. Saved NFC/RFID files can be inspected and compared without changing the originals. Full emulation or writing can require complete source data, known keys and a compatible target. A Classic size inferred from SAK is labelled as a hint.

Classic reader tests collect complete matching authentication transcript pairs, not just card nonces. Deduplicated pairs append to `SD/nfc/.mfkey32.log`; existing contents are preserved. Native MFKey consumes this format and writes recovered keys through its normal dictionary workflow. The library screen reports nonce and native dictionary counts without displaying keys. Recovery can fail; modern cryptography and protected systems are not bypassed by these diagnostics.

Dolphin XP uses normal NFC/LF read, successful-read and first-save deeds. Repeat batches award one success deed; passive monitoring, simulations, browsing and repeated saves award none.

For optional USB logs, run `log info` in the Flipper serial CLI, then enable USB diagnostics. Ctrl+C ends streaming. The app does not replace the USB configuration.

## Build and test

Requires Git, Python 3, `rg` and a C compiler for host tests. Momentum downloads its ARM toolchain on first build.

```sh
./scripts/setup-momentum.sh
./scripts/test.sh
./scripts/build.sh
python3 scripts/package.py
```

Optional UI galleries use Pillow: `python3 scripts/make-previews.py` after renderer tests.

The build produces the primary `dist/nfc_diagnostic_suite.fap`, all four apps under `dist/apps/NFC/`, source icons and license notices under `dist/vendor/`, and a source/distribution ZIP. Every app's imports, API metadata and embedded launcher icon are checked; MFKey's embedded plugin is checked separately.

The default source pin is Momentum commit `d3f89dfe2ef6b01839201598e9be1590cba80322`, API **87.1**. `dist/BUILD.txt` records the actual build revision and checksums. The installed device revision remains unknown without device access. To match another Momentum checkout:

```sh
MOMENTUM_DIR=/path/to/Momentum-Firmware ./scripts/build.sh
```

Builds, host tests and renderer captures do **not** prove physical NFC/LF operation. No connected Flipper hardware has been tested. Some firmware operations can delay cancellation while their current transaction drains. See [coverage, architecture and proof limits](docs/ENGINEERING.md).

![Host-rendered UI previews](docs/captures/gallery.png)

Host captures of the actual C renderer with simulated states; not hardware screenshots.
