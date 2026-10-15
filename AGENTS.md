# NFC Diagnostic Suite

Read the user's global AGENTS.md and installed caveman, cave-orchestrator and `${CODEX_HOME:-$HOME/.codex}/skills/flipper-apps/SKILL.md` before work. Its scoped NFC Suite reference records this project's full requirements.

Target installed Momentum `mntm-012` (`e1784e7418d8b074e971983ceb6fef0f37e52ae4`, API 87.1); do not assume upstream Flipper APIs match. The `.momentum` tree is a dependency, not this app's source. Keep its existing files unchanged.

Preserve exclusive radio ownership: callbacks copy bounded data; the owning worker stops and joins native operations before freeing resources. Never queue a native tool while retaining an active radio engine.

Keep scanner hints, command-confirmed evidence, saved records, simulations and unsupported capabilities distinct. Never infer a credential or reader model from a field, UID, ATQA or SAK. Guided actions must come from the capability planner. Writing and key recovery remain in explicitly launched native tools.

Every delivered FAP needs its custom launcher icon, source asset, metadata embedding check and enabled SDK import check. Run `scripts/test.sh` and `scripts/build.sh`; package with `python3 scripts/package.py`. Record physical-device limitations honestly. Host renderer captures are not hardware screenshots.

Do not publish local reports, nonce logs, dictionaries, private card files, build caches, firmware checkouts or backups. Only synthetic fixtures belong in tests or captures.

Keep Workflow first, About last. Integrate short results and final save into real card/reader steps, with File and active Log controls. Group saved-card tools and session tools. Keep production free of simulated tests, developer screens and generic control footers. Use native UI conventions, 10-pixel text spacing and wrapping menu navigation. Measure ARM RAM; retain one live model, allocate saved results only after radio drain.

Use native contextual button bars; hidden buttons must be inert. Preserve exact Back callers, source evidence on picker cancel, and cancellation drain before band switches or tool handoffs. Keep offline modules unloaded during radio operation. Before release, independently review UI/navigation, RF/evidence, storage, nonces/feedback and loading, then perform a fresh integration review; fix and re-review actionable app findings. Record inherited firmware and physical-test limitations explicitly.
