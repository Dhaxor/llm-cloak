# Contributing

Thanks for helping make LLM contexts safer.

## Setup

```bash
git clone https://github.com/Dhaxor/context-guard
cd context-guard
npm install
npm test        # vitest
npm run build   # tsc ESM + CJS into dist/
```

## Ground rules

- **Zero runtime dependencies.** Everything must run on the standard library.
  Dev dependencies (typescript, vitest, @types/node) are fine.
- **Every detector ships with tests** — at least one positive case and one
  checksum/negative case. False positives on ordinary prose are treated as
  bugs, not acceptable noise.
- **No catastrophic backtracking.** Keep regexes linear: no nested unbounded
  quantifiers. If you add a tricky one, add a pathological-input test too.
- **No telemetry, no network.** This library must remain fully local.

## Adding a detector

1. Add the `Detector` to `src/detectors/secrets.ts` or `src/detectors/pii.ts`.
2. Use `validate` for anything with a checksum or well-known structure.
3. Add tests in `tests/` with a realistic fake value (never a real key).
4. Run `npm test && npm run build` and update `README.md` if the list changed.

## Adding an injection rule

1. Add the rule to `src/injection.ts` with a weight that reflects how
   unambiguous the signal is (structural tricks > generic phrasing).
2. Add a positive test **and** a benign-lookalike negative test — rules that
   fire on ordinary business English get merged or dropped.

## Commit style

Conventional Commits (`feat:`, `fix:`, `docs:` …). CI runs build + tests on
Node 18/20/22/24 across Linux and Windows.
