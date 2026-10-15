# NFC Diagnostic Suite

Read the user's global AGENTS.md and installed caveman and cave-orchestrator skills before work.

Use Momentum firmware at the recorded source pin; do not assume upstream Flipper APIs match. The `.momentum` tree is a dependency, not this app's source. Keep its existing files unchanged.

Preserve exclusive radio ownership: callbacks copy bounded data; the owning worker stops and joins native operations before freeing resources. Never queue a native tool while retaining an active radio engine.

Keep scanner hints, command-confirmed evidence, saved records, simulations and unsupported capabilities distinct. Never infer a credential or reader model from a field, UID, ATQA or SAK. Guided actions must come from the capability planner. Writing and key recovery remain in explicitly launched native tools.

Every delivered FAP needs its custom launcher icon, source asset, metadata embedding check and enabled SDK import check. Run `scripts/test.sh` and `scripts/build.sh`; package with `python3 scripts/package.py`. Record physical-device limitations honestly. Host renderer captures are not hardware screenshots.

Do not publish local reports, nonce logs, dictionaries, private card files, build caches, firmware checkouts or backups. Only synthetic fixtures belong in tests or captures.
