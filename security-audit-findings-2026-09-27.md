# RTK Security Audit — Secrets / Telemetry / Paths / CI

**Date:** 2026-09-27  
**Scope:** `src/core/tracking.rs`, telemetry, system cmds (env/read/find/ls/tree/log/search), `install.sh`, `.github/workflows/**`, `tee.rs`, `src/analytics/**`, `src/cmds/git/**`, `Cargo.toml`, hardcoded secrets, path traversal, tracking.db permissions, env dump  
**Skipped (already known):** TOML CI trust bypass, `sh -c` wrapper deny bypass, PATH-relative hooks, Claude project settings auto-allow  
**Bar:** MEDIUM+ only with real attacker→impact chains

---

## NEW MEDIUM+ FINDINGS

### F1 — HIGH: `rtk env` dumps secrets into LLM context (docs claim redaction)

**Components:** `src/cmds/system/env_cmd.rs`, `src/main.rs` (`Commands::Env`), `docs/usage/FEATURES.md`, `src/hooks/init.rs` (advertises `rtk env`)

**Evidence**

Docs promise masking that does not exist:

```943:948:docs/usage/FEATURES.md
rtk env                    # Toutes les variables (sensibles masquees)
rtk env -f AWS             # Filtrer par nom
rtk env --show-all         # Inclure les valeurs sensibles

Les variables sensibles (tokens, secrets, mots de passe) sont masquees par defaut : `AWS_SECRET_ACCESS_KEY=***`.
```

CLI has no `--show-all` and no redaction — only an optional name filter:

```254:258:src/main.rs
    Env {
        /// Filter by name (e.g. PATH, AWS)
        #[arg(short, long)]
        filter: Option<String>,
    },
```

Cloud/tool categories **preferentially surface** secret-bearing prefixes and print full values (AWS secrets are typically ≤40 chars, under the 100-char truncate):

```140:174:src/cmds/system/env_cmd.rs
fn is_cloud_var(key: &str) -> bool {
    let patterns = [
        "AWS", "AZURE", "GCP", "GOOGLE_CLOUD", "DOCKER", "KUBERNETES",
        "K8S", "HELM", "TERRAFORM", "VAULT", "CONSUL", "NOMAD",
    ];
    // ...
}
fn is_tool_var(key: &str) -> bool {
    let patterns = [
        // ...
        "CLAUDE", "ANTHROPIC",
    ];
```

Contrast: `src/cmds/dotnet/binlog.rs` implements `scrub_sensitive_env_vars()` for the same class of keys — env_cmd does not reuse it.

**Attack chain**

1. Coding agent (Claude Code / Cursor / etc.) runs `rtk env` or `rtk env -f AWS` during environment discovery (explicitly listed in `rtk init` help).
2. `env_cmd::run` categorizes `AWS_*`, `ANTHROPIC_*`, `CLAUDE_*`, `VAULT_*`, etc. as “relevant” and prints `KEY=value` to stdout.
3. Values enter the LLM conversation / session transcript (and any agent logging).
4. Impact: cloud credentials, API keys, session tokens usable for account takeover or cloud abuse. Docs falsely reassure users that secrets are masked.

**Why not lower:** intentional product path for agents + false security documentation + no redaction code at all.

---

### F2 — MEDIUM: Secret-bearing command lines persisted in `history.db` without `0o600`

**Components:** `src/core/tracking.rs`, `src/cmds/cloud/curl_cmd.rs`, `src/cmds/cloud/wget_cmd.rs`, `src/cmds/cloud/psql_cmd.rs`, `src/main.rs` (proxy / TOML fallback), `src/analytics/gain.rs`

**Evidence**

Full argv is stored in SQLite:

```82:87:src/cmds/cloud/curl_cmd.rs
    timer.track(
        &format!("curl {}", args.join(" ")),
        &format!("rtk curl {}", args.join(" ")),
        &raw,
        &shown,
    );
```

Same pattern for `rtk proxy …`, wget URLs (`format!("wget {}", url)`), psql args, parse-failure `raw_command`.

DB open creates the file with default umask permissions (typically `0644`). Salt file is explicitly `0o600`; history DB is not:

```180:189:src/core/telemetry.rs
            if let Ok(mut f) = std::fs::File::create(&salt_path) {
                let _ = f.write_all(salt.as_bytes());
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &salt_path,
                        std::fs::Permissions::from_mode(0o600),
                    );
```

`Tracker::new()` only `create_dir_all` + `Connection::open` — no `set_permissions`. Verified locally: SQLite create → mode `0644` under umask `022`.

`rtk gain --history` / `--failures` surfaces truncated `rtk_cmd` / `raw_command` from this DB.

**Attack chain**

1. User/agent runs e.g. `rtk curl -H "Authorization: Bearer ghp_…" https://api.github.com/…` or `rtk wget https://user:pass@host/file` or `rtk proxy curl …`.
2. Full command line (including headers/URL userinfo) is inserted into `~/.local/share/rtk/history.db`.
3. On a shared host, backup share, or stolen home directory, another local principal reads the world-readable DB (`sqlite3 … "SELECT original_cmd, rtk_cmd FROM commands"`).
4. Impact: recovered API tokens / basic-auth credentials / connection strings.

**Note:** Token *counts* of stdout are stored, not stdout bodies — the leak is argv, not response bodies (see F4 for tee bodies).

---

### F3 — MEDIUM: Telemetry `low_savings_commands` can exfiltrate args / credential URLs (violates stated policy)

**Components:** `src/core/tracking.rs` (`low_savings_commands`), `src/core/telemetry.rs` (`get_enriched_stats`), `docs/TELEMETRY.md`, `src/core/telemetry_cmd.rs`

**Evidence**

Privacy docs / consent copy claim command **names only, not arguments**:

```112:112:docs/TELEMETRY.md
- Full command lines or arguments (only tool names like "git", "cargo")
```

```88:88:src/core/telemetry_cmd.rs
    eprintln!("  What:    command names (not arguments), token savings, OS, version");
```

Implementation takes the first **three whitespace tokens** of full `rtk_cmd`:

```1053:1065:src/core/tracking.rs
    pub fn low_savings_commands(&self, limit: usize) -> Result<Vec<(String, f64)>> {
        // ...
            let short = cmd.split_whitespace().take(3).collect::<Vec<_>>().join(" ");
            Ok((short, sav))
```

Those strings are POSTed in the daily ping (`low_savings_commands` field).  
`top_commands` / `passthrough_top` correctly strip to tool names; this field does not.

For `rtk curl https://user:token@api.example.com/v1`, the three-token prefix is the full URL including credentials.

Requires prior telemetry consent (`consent_given == true` + enabled), then automatic daily ping.

**Attack chain**

1. User consents to telemetry (believing “names only”).
2. Agent runs low-savings curls/wgets with credential-bearing URLs (or unusual `rtk_cmd` shapes where arg3 is sensitive).
3. `maybe_ping` → `send_ping` includes `low_savings_commands: ["rtk curl https://user:token@…:N%"]`.
4. Impact: credentials leave the machine to the RTK telemetry collector; also GDPR/policy misrepresentation.

---

### F4 — MEDIUM: Tee recovery files store raw output without restrictive permissions

**Components:** `src/core/tee.rs`, callers via `force_tee_hint` / `tee_and_hint` (curl non-JSON TTY path, TOML filters, failures)

**Evidence**

`write_tee_file` uses `std::fs::write` with no `0o600`. Default tee dir: `~/.local/share/rtk/tee/`. Tee enabled by default (`TeeConfig::default` → `enabled: true`). Curl truncated non-JSON TTY responses call `force_tee_hint`, writing the **full** body and printing a path hint the agent is expected to read.

**Attack chain**

1. Command output containing secrets (API error pages, non-JSON token responses, failed tool dumps, etc.) exceeds tee thresholds / uses force-tee.
2. Full content written to `*.log` under default directory modes (`0644`).
3a. Local multi-user read of tee logs, **or**  
3b. Agent follows `[full output: ~/…/tee/….log]` via `rtk read` / `cat` → secrets re-enter LLM context after intentional truncation.
4. Impact: secret recovery from disk and/or agent context.

---

## DISCARDED (with reasons)

| Item | Reason |
|------|--------|
| Path traversal in `rtk read` / `rtk log` / `rtk find` / `rtk ls` / `rtk tree` / `rtk search` | Local CLI intentionally reads user-supplied paths with user privileges — equivalent to `cat`/`find`. No sandbox boundary claimed. |
| `find -exec` | Explicitly rejected; falls back with error (unsupported flags list). |
| Hardcoded API keys / webhook URLs in source | None found; telemetry URL/token via compile-time `option_env!` only. |
| Telemetry token extractable from release binaries | Client shared ingest credential by design; enables spam/pollution, not cross-user data read (device_hash is 256-bit). Below MEDIUM for this audit’s secret-theft bar. |
| `pull_request_target` in `next-release.yml` / `pr-target-check.yml` | No checkout of untrusted PR code; only metadata / labeling. `PR_*` passed via env (not shell-interpolated unsafely for RCE). |
| CI `doc-review` + `ANTHROPIC_API_KEY` on `pull_request` | Standard same-repo PR secret model; fork PRs don’t receive secrets. Workflow-modification exfil requires write access — not a novel RTK-specific chain above bar. |
| `install.sh` archive path check / checksum | Absolute/`..` entries rejected; SHA-256 verified against same-channel `checksums.txt`. Symlink-only attacks require compromised release (same as replacing the binary). |
| Device salt crypto / `getrandom` fallback | Salt file is `0o600`; hash is SHA-256(salt). Time+pid fallback is weaker entropy but local-only identifier, not a remote secret. |
| AWS `secretsmanager get-secret-value` printing `SecretString` | Intentional filter when user requests a secret; not an accidental dump path. |
| Lambda env stripping gaps | Tests assert secrets stripped for list/get-function filters; no broken chain found in reviewed paths. |
| Git credential helper / push password leakage in filters | No evidence of embedding credentials into filtered git output; argv tracking covered under F2. |
| SQL injection in tracking | Parameterized `params!` queries. |
| Project-path GLOB metacharacters | Attacker would need to control victim cwd path for self-DB confusion only — negligible impact. |
| `Cargo.toml` malicious deps | Standard crates (`ureq`, `rusqlite` bundled, `sha2`, `getrandom`); no suspicious pins. |
| TOML CI trust / `sh -c` deny / PATH hooks / Claude auto-allow | Explicitly out of scope (already known). |

---

## Suggested remediations (non-binding)

1. **F1:** Port `scrub_sensitive_env_vars` (or stronger allowlist) into `env_cmd`; default-mask; add real `--show-all`; align docs.
2. **F2/F4:** `chmod 0o600` on `history.db`, tee files, and parent dir `0700` after create (match salt handling); redact known secret patterns from `original_cmd`/`rtk_cmd` before INSERT.
3. **F3:** Emit only tool/subcommand tokens in `low_savings_commands` (same stripping as `top_commands`); never send URL userinfo or header values.
