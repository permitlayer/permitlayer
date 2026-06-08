# permitlayer CodeQL model pack

A [models-as-data](https://github.blog/changelog/2026-04-21-codeql-now-supports-sanitizers-and-validators-in-models-as-data/)
pack that encodes two project-specific sanitizer facts so the relevant
Rust security queries clear their alerts **at the source** while staying
fully live for all other code:

- `paths::canonical_dir_within_root` → path-traversal barrier
  (`rust/path-injection`).
- `AccountHint::masked` / `Display` → cleartext-logging barrier
  (`rust/cleartext-logging`).

This is the project's standing mechanism for verified false positives:
**never dismiss or rule-suppress — model the sanitizer.** New entries go
in `models/*.model.yml` using the schemas documented there.

## Why a pack (not inline suppression)

This repo uses CodeQL **default setup**. Inline `// codeql[...]`
suppression comments are inert under default setup (they require the
`AlertSuppression` query, which default setup does not run). A model pack
is the supported way to customize default-setup analysis.

## Publishing + enabling (one-time, then maintenance-free)

Model packs in **default setup** are consumed at the **org level**, not
auto-discovered from the repo. Steps:

1. **Publish to GHCR** (needs the CodeQL CLI + a token with
   `write:packages` on the `permitlayer` org):

   ```sh
   codeql pack publish .github/codeql/permitlayer-models
   # → ghcr.io/permitlayer/permitlayer-models
   ```

2. **Enable for default setup** (org admin, UI):
   `permitlayer` org → **Settings → Code security → CodeQL model packs**
   → add `permitlayer/permitlayer-models`. Default setup then injects the
   pack on every scan of eligible repos.

3. **Verify**: re-run code scanning on the PR; the modeled alerts clear.
   Tuning rounds (if any) edit `models/*.model.yml`, bump `version` in
   `qlpack.yml`, re-publish, re-scan.

## Schema quick-reference

From `github/codeql:rust/ql/lib/codeql/rust/dataflow/internal/ModelsAsData.qll`:

| predicate          | tuple                                        |
| ------------------ | -------------------------------------------- |
| `barrierModel`     | `path; output; kind; provenance`             |
| `barrierGuardModel`| `path; input; acceptingValue; kind; provenance` |

`path` = `crate::module::function` (free fn) or
`<crate::module::Type>::method` (method). Barrier `kind`s: `normalize-path`
(path-injection), `log-injection` (cleartext-logging).
