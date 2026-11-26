# Repository Audit — `photo-mover`

- **Date:** 2026-11-26
- **Commit audited:** `8cee010` (`main`, fast-forwarded from `e6e47b0`)
- **Scope:** Full codebase (`src/main.rs`), dependencies (`Cargo.toml`, `Cargo.lock`), container setup (`Dockerfile`, `compose.yaml`, `.dockerignore`), CI/CD (`.github/workflows/*`), and documentation (`README.md`, `GLOSSARY.md`)
- **Verification run:**
  - `git pull` → updated `e6e47b0..8cee010` (added `.github/workflows/delete-merged-branches.yml` and `.github/workflows/purge-green-runs.yml`)
  - `cargo test` → **10 passed, 0 failed**
  - `cargo clippy --all-targets` → **0 warnings**

---

## Executive Summary

`photo-mover` is a remarkably clean, compact, single-file Rust service with a small dependency tree, minimal `unsafe` (only Linux `setpriority`/`ioprio_set` syscalls), solid core verification semantics (copy → SHA-256 read-back → atomic rename → delete), and passing tests with zero clippy warnings.

However, the audit identified several **data-safety, operational, security, and CI bugs** that should be addressed before relying on it for a primary photo archive:

- **3 High-severity data/workflow bugs**: partial-failure rollback gap in `file_one` + `recover()`, `prune_empty()` following symlinks outside `/inbox`, and `delete-merged-branches.yml` deleting unrelated branches that share a merged PR's commit SHA.
- **4 High-severity operational/security issues**: impossible Google Photos reconnection after 7-day Testing token expiry, state-mutating HTTP `GET` endpoints (CSRF/prefetch risk) with a single-threaded blocking server, wake-up race that silently resets `/overwrite/<policy>` back to default, and journal pruning causing held rolled-back files to silently re-move after `LOG_DAYS`.
- **Several Medium/Low findings**: lost file `mtime` on copy, upload token expiry/wiping bugs, sidecar stranding and `.ext.xmp` mismatches, missing graceful `SIGTERM` shutdown, container hardening, and CI supply-chain pinning.

---

## Findings

### High Severity

#### H1. Runtime failure in `file_one()` can orphan replaced files and corrupt `recover()` state
- **Location:** `src/main.rs:515-525`, `src/main.rs:263-295`
- **Issue:** `file_one()` writes an `"intent"` journal entry (line 515), stashes the existing library file into `replaced/<id1>` when `Policy::Overwrite` is active (line 519), and then calls `safe_move(path, &target)?` (line 521). If `safe_move(path, &target)` fails at runtime (e.g., `ENOSPC`, transient I/O error, checksum mismatch):
  1. `file_one()` returns `Err` without restoring `replaced/<id1>` back to `target` and without writing an `"abort"` journal record.
  2. On the next scan (while the process is still running, so `recover()` has not run), `target` no longer exists. `file_one()` moves `from` to `target` under a new `id2` with `replaced: false`.
  3. The original library file is permanently detached in `replaced/<id1>` (rolling back `id2` will not restore it, and `prune()` will eventually delete it).
  4. On the next container restart, `recover()` sees the unresolved `"intent"` for `id1`, sees `to.exists()` and `!from.exists()`, and records a bogus duplicate `"move"` event for `id1`.
  5. Even without `Policy::Overwrite`, any transient failure after line 515 leaves a dangling `"intent"` that turns into a phantom `"move"` after a later scan succeeds and the service restarts.
- **Recommendation:** Wrap the post-`intent` steps in `file_one()` so that on error: (a) any `.partial` file is removed, (b) if `stash` was created and `target` is missing, `stash` is restored to `target`, and (c) an `"abort"` record is written when the move did not complete.

#### H2. `prune_empty()` follows symlinks and can delete directories outside `/inbox`
- **Location:** `src/main.rs:553-562`
- **Issue:** While `walk()` carefully avoids symlinks via `fs::symlink_metadata()` and skips `.`/`@`/`#` system folders (lines 539–542), `prune_empty()` calls `entry.path().is_dir()` (line 555), which **follows symlinks**, and does not skip hidden or Synology system directories (`@eaDir`, `#recycle`). A symlink inside `/inbox` pointing to a directory tree elsewhere can cause `prune_empty()` to recursively remove empty subdirectories outside `/inbox`.
- **Recommendation:** Use `fs::symlink_metadata(entry.path())` and skip symlinks as well as `.`/`@`/`#` folders in `prune_empty()`.

#### H3. Google Photos cannot be reconnected from the UI after Testing-mode 7-day token expiry
- **Location:** `src/main.rs:365-367`, `src/main.rs:655-682`, `src/main.rs:931-945`, `README.md:35`
- **Issue:** `README.md` instructs Testing-mode users to *"repeat step 4 about once a week"* when Google expires the refresh token. However, `sh.connected()` only checks whether `/data/google.json` exists. Once connected, `page()` hides both the *Approve access* link and the `/code` form, and there is no `/disconnect` or reconnect UI. When the refresh token expires (`invalid_grant`), the page still claims *"Google Photos connected"* and users must shell into the NAS and manually delete `google.json` to reconnect.
- **Recommendation:** Add a reconnect/disconnect action on the page (or always show a "Reconnect" link/form when connected), and surface Google's actual OAuth error body (currently hidden because `ureq` converts HTTP 400 into `"http status: 400"` without reading the error JSON).

#### H4. State-mutating `GET` endpoints enable CSRF and browser-prefetch accidents
- **Location:** `src/main.rs:954`, `src/main.rs:961-974`, `src/main.rs:978-1022`
- **Issue:** Every destructive or state-changing operation (`/stop`, `/overwrite/overwrite`, `/rollback/<id>`, `/release`, `/interval/<n>`, `/code?url=...`) is triggered via plain HTTP `GET` links/forms without checking the HTTP method, without CSRF protection, and without Post-Redirect-Get (PRG):
  - Any webpage opened in a browser on the same LAN can silently issue `<img src="http://<nas>:8768/overwrite/overwrite">` or `/release` or `/stop`.
  - Browser link prefetching, hovering extensions, or refreshing the browser after `/rollback/<id>` or `/release` can trigger or repeat mutations.
  - `/code?url=...` puts the OAuth authorization code in browser history and server URL paths.
  - Any unknown path (e.g., `/robots.txt`, `/apple-touch-icon.png`, LAN scanners) wakes a sleeping service and returns `200 OK` (line 993).
- **Recommendation:** Require `POST` for all state-changing endpoints (using `<form method="post">`), validate `Origin`/`Host` or a per-process CSRF token, redirect (`303 See Other`) back to `/` after mutations, and only wake the service on known action endpoints (returning `404` for unknown paths).

#### H5. Waking the service via `/overwrite/<policy>` is immediately undone by `main()`
- **Location:** `src/main.rs:993-1005`, `src/main.rs:1095-1107`
- **Issue:** When the service is asleep and a user clicks `/overwrite/keep` (or `/overwrite/overwrite`), `answer()` sets `awake = true` and `policy = Keep`, and renders the page showing **`keep`** as active. Within 1 second, `main()` observes `awake != was_awake` (line 1096) and unconditionally executes `sh.policy.store(sh.default_policy as u8, Relaxed)` (line 1104), silently reverting the policy back to `skip`. (The unit test `page_wakes_on_calls_but_not_on_the_front_page` did not catch this because it does not run the `main()` loop.)
- **Recommendation:** Reset `policy` to `default_policy` when entering sleep (or inside `answer()` on wake *before* applying `/overwrite/<policy>`), rather than clobbering it asynchronously in `main()`. Also update `sleep_at` immediately on wake so the wake response does not display `"Sleeps in 0 min"`.

#### H6. `prune()` silently un-holds rolled-back files and can trigger re-uploads
- **Location:** `src/main.rs:319-348`, `src/main.rs:297-316`, `src/main.rs:351-363`
- **Issue:**
  1. `prune()` deletes all journal lines older than `LOG_DAYS` indiscriminately, including `"rollback"` events. After `LOG_DAYS`, a rolled-back file still sitting in `/inbox` drops out of `state.held` and is **silently moved back into the Library** even though the user never called `/release`.
  2. If a duplicate-content file (same SHA-256) was moved on Day 50 after an earlier copy was uploaded on Day 0, pruning Day 0's `"upload"` record on Day 61 causes Day 50's `"move"` to become pending and upload again.
  3. `prune()` rewrites `photo-mover.log` (lines 332–340) while `sh.log()` (lines 229–240) appends to `photo-mover.log` **without holding `self.file`**, creating a race where concurrent log lines written during pruning are lost to the unlinked inode.
- **Recommendation:** Protect `LOG_FILE` appends with a mutex (or `self.file`), retain active `rollback` hold records (or keep held hashes in a small state file) until `/release` or until the file is gone from `/inbox`, and prune `replaced/<id>` by checking whether `<id>` still exists in the surviving journal rather than relying on file `mtime`.

#### H7. `delete-merged-branches.yml` can delete unrelated branches sharing a commit SHA
- **Location:** `.github/workflows/delete-merged-branches.yml:43`, `.github/workflows/delete-merged-branches.yml:59`
- **Issue:** The scheduled/manual sweep collects `mergedShas` (only commit SHAs of merged PRs) and deletes **any** unprotected branch without an open PR whose tip matches a SHA in `mergedShas`. It does not verify that the branch name matches the merged PR's `head.ref`. A newly created feature/release/backup branch cut from a merged commit (before new commits are pushed) will be automatically deleted on the next Monday sweep.
- **Recommendation:** Match on both branch name and commit SHA (e.g., `mergedHeads.has(`${b.name}\0${b.commit.sha}`)`) instead of SHA alone.

---

### Medium Severity

#### M1. Original file `mtime` is lost during `safe_move()` / `copy_hashed()`, and parent dirs are not `fsync`ed
- **Location:** `src/main.rs:401-431`
- **Issue:**
  - `copy_hashed()` creates a new file without copying the source file's modification timestamp. Videos, screenshots, PNGs, and other non-EXIF files lose their original capture timestamp in the Library (affecting NAS gallery sorting), and if later rolled back and re-ingested, they will be filed into **today's** `YYYY/MM` instead of their original date.
  - `safe_move()` does not remove `.partial` if `copy_hashed()` errors midway (leaving orphaned `.partial` files in the Library).
  - After `fs::rename(&partial, to)`, the destination parent directory is not `fsync`ed before `fs::remove_file(from)`. On a sudden power loss across separate mounts, the source unlink can persist while the destination rename does not.
- **Recommendation:** Preserve `mtime` (e.g., `File::set_modified`, stabilized in Rust 1.75), clean up `.partial` on any `copy_hashed` failure, and `fsync` the target parent directory before deleting `from`.

#### M2. OAuth access token expiry mid-batch, 401 cache stickiness, and upload token bookkeeping bugs
- **Location:** `src/main.rs:655-682`, `src/main.rs:733-753`, `src/main.rs:757-795`, `src/main.rs:871-916`
- **Issue:**
  1. **Mid-batch expiry:** `access_token()` only requires 60 seconds of remaining lifetime, yet `upload_round()` can take 10–30 minutes to upload 50 photos on a slow uplink. If the token expires mid-round, remaining uploads and `batchCreate` fail with `401`. Moreover, a `401` never invalidates `self.access`, so a revoked/stale token stays cached until `expires`.
  2. **Token wipe on `access_token()` failure:** When `sh.access_token()` returns `Err`, line 878 synthesizes `Outcome { token: None, tried: true }` for all 50 items, which triggers `tokens.remove(&id)` (line 900) — discarding valid upload tokens saved from earlier rounds — and logs 50 separate failure lines.
  3. **Upload token TTL never expires on repeated failure:** When a cached `known` token fails `batchCreate` again, line 899 calls `tokens.insert(id, (token, unix_now()))`, resetting its creation time so the 20-hour expiry check (`unix_now() < when + 20 * 3600`) never triggers.
  4. **Brittle `batchCreate` status & overload checks:** `create_items()` checks `status.message` for `"Success" | "OK"` instead of checking `mediaItem.id` / `status.code.unwrap_or(0) == 0`; `overload()` string-matches `ureq`'s `Display` output (`"http status: 429"`) instead of matching `ureq::Error::StatusCode`, ignores `Retry-After`, and misses per-item `RESOURCE_EXHAUSTED` (gRPC code 8) errors inside HTTP 200 responses.
- **Recommendation:** Fetch/refresh `access_token()` with a larger margin (e.g., 5–10 minutes) or per worker / before `create_items()`, clear the cache on HTTP 401, skip updating `tokens` on `access_token()` errors, preserve original token creation timestamps, and handle typed `ureq::Error` + `status.code`.

#### M3. Sidecar handling strands late arrivals, misses `.ext.xmp`, and is non-deterministic with Live Photos
- **Location:** `src/main.rs:588-611`
- **Issue:**
  - `homes` is scoped to a single `scan()` call. If a sidecar (`IMG_1.xmp` / `IMG_1.aae`) finishes copying one scan pass after its photo, it will never match and remains stranded in `/inbox` forever.
  - Common double-extension sidecars (`IMG_1.JPG.xmp`, `IMG_1.CR3.xmp`) have stem `IMG_1.JPG`, which never matches photo stem `IMG_1`.
  - When `Policy::Keep` renames `IMG_1.jpg` → `IMG_1-1.jpg`, its sidecar stays `IMG_1.xmp`.
  - If a Live Photo pair (`IMG_1.heic` → `LIBRARY` and `IMG_1.mov` → `VIDEO_LIBRARY`) arrives with `IMG_1.aae`, `homes.insert(key, dir)` overwrites in filesystem `readdir` order, sending the sidecar non-deterministically to either library.
- **Recommendation:** Support `<stem>.<ext>.<sidecar>` matching, prioritize photo/RAW homes over video homes for sidecars, align sidecar naming with `Policy::Keep` renames, and optionally look up recent moves in the journal when a sidecar arrives shortly after its photo.

#### M4. Single-threaded HTTP server hangs on slow/POST clients or concurrent moves/OAuth calls
- **Location:** `src/main.rs:985-990`, `src/main.rs:1061-1065`
- **Issue:**
  - `answer()` runs sequentially on one thread. A `/rollback/<id>` while a multi-GB video is moving blocks the entire UI behind `sh.busy`, and `/code` blocks the UI for up to 300s (`timeout_global`) waiting on Google.
  - The header reader loops `while !request.ends_with(b"\r\n\r\n")`. Any request containing a body (such as `POST`) or pipelined bytes does not end with `\r\n\r\n`, causing `answer()` to stall until the 5-second read timeout and drop the connection without responding.
- **Recommendation:** Detect header end with `request.windows(4).any(|w| w == b"\r\n\r\n")` (and read `Content-Length` bytes when handling `POST`), and handle connections on bounded worker threads or short-lived threads.

#### M5. `google.json` refresh token written world-readable and non-atomically
- **Location:** `src/main.rs:703`
- **Issue:** `fs::write(self.data.join(GOOGLE), ...)` writes the OAuth refresh token with the default umask (typically `0644`) directly in place. On a shared NAS `/volume1/docker/photo-mover` volume, any local user or container with read access can read the refresh token.
- **Recommendation:** Write via a `.partial` temp file with `0o600` permissions (`OpenOptionsExt::mode(0o600)` on Unix) and atomically rename.

#### M6. `walk()` aborts the entire Inbox scan on a single unreadable file or transient `ENOENT`
- **Location:** `src/main.rs:534-550`
- **Issue:** Because `walk()` propagates every `read_dir` and `symlink_metadata` error with `?`, a single temporary file deleted mid-scan or one folder with bad permissions stalls processing of the entire `/inbox`.
- **Recommendation:** Log per-entry/per-directory errors and continue walking remaining entries.

#### M7. No graceful `SIGTERM` handling
- **Location:** `src/main.rs:1024-1133`, `compose.yaml:5`
- **Issue:** `compose.yaml` enables `init: true`, so `docker stop` delivers `SIGTERM` directly to `/photo-mover`, killing it immediately mid-move or right after Google's `batchCreate` succeeds (before `"upload"` is written to `transactions.jsonl`, causing duplicate uploads on restart).
- **Recommendation:** Handle `SIGTERM`/`SIGINT` cleanly by stopping new work and letting the active `file_one()` / `upload_round()` record its transaction before exiting.

#### M8. Repeated full-journal disk reads and `stat()` calls scale poorly
- **Location:** `src/main.rs:256-260`, `src/main.rs:351-363`, `src/main.rs:572`, `src/main.rs:862`
- **Issue:** While awake and connected, `upload_loop` reads and JSON-parses the entire 60-day `transactions.jsonl` file every **5 seconds** (plus `scan()` every `INTERVAL` seconds and every `/` page load), even when nothing has changed. On a NAS with tens of thousands of moves, this wastes CPU and prevents disk spindown.
- **Recommendation:** Cache `State` in memory behind `Shared`, updating it incrementally on `record()` / `prune()`.

---

### Low Severity & Hardening

#### L1. Non-monotonic move `id` generation
- **Location:** `src/main.rs:495`
- **Issue:** `id` uses `SystemTime::now()` nanoseconds. An NTP clock step backwards or low timer resolution can produce duplicate IDs, colliding in `replaced/<id>` and `transactions.jsonl`.
- **Recommendation:** Pair timestamp with a monotonic `AtomicU64` sequence counter (or random suffix).

#### L2. Minor logic & edge-case issues in `src/main.rs`
- **Interval change lag (`src/main.rs:1126-1131`):** Reducing `/interval/300` to `/interval/5` does not take effect until the current 300s sleep loop finishes, because `sh.interval.load()` is evaluated once in `for _ in 0..sh.interval.load(Relaxed)`. Re-check elapsed seconds against `sh.interval.load(Relaxed)` each second.
- **Active upload round can hit idle sleep (`src/main.rs:905`, `src/main.rs:1116-1124`):** `sh.touch()` is only called after an entire 50-photo `upload_round()` finishes. With a low `IDLE_MINUTES` and a slow uplink, the service can fall asleep mid-batch and abort the remaining workers.
- **Unbounded in-memory `failed` / `tokens` maps (`src/main.rs:844-848`):** Entries for rolled-back or deleted files are never evicted from `failed` or `tokens`.
- **Silent `PORT` truncation (`src/main.rs:1046`):** `number("PORT", 8768) as u16` silently wraps values > 65535.
- **Redundant call (`src/main.rs:1098-1099`):** `sh.touch(); sh.last_active.store(unix_now(), Relaxed);` — the first line is immediately overwritten by the second.
- **UTC `mtime` bucketing & `FROM scratch` timezone (`src/main.rs:461-466`, `Dockerfile:8`):** EXIF `DateTimeOriginal` uses camera local time, whereas `mtime` fallback uses UTC. Videos/screenshots taken near midnight on month/year boundaries can be filed in the previous/next month.
- **RAM usage on large photos (`src/main.rs:717`):** `upload_bytes()` loads full files into memory; up to `MAX_WORKERS` (8) concurrent large panoramas/PNGs can spike memory on low-RAM NAS units.
- **Unescaped `id` in HTML (`src/main.rs:954`):** `<a href=/rollback/{id}>` does not quote or escape `id` (low risk unless `transactions.jsonl` is tampered with).
- **URL fragment in `auth_code()` (`src/main.rs:125`):** A trailing `#fragment` on a pasted OAuth URL is not stripped from `code`.
- **Journal `size` TOCTOU (`src/main.rs:483`, `src/main.rs:524`):** `meta.len()` is captured before `safe_move()` rather than from the bytes actually hashed/copied.

#### L3. Container & Compose Hardening (`Dockerfile`, `compose.yaml`)
- `Dockerfile:1`: `FROM rust:1-alpine` is an unpinned floating tag; explicitly setting `RUSTFLAGS="-C target-feature=+crt-static"` ensures the binary remains statically linked for `FROM scratch`.
- `compose.yaml:13`: `ports: - "8768:8768"` binds all host interfaces (`0.0.0.0`); document binding to LAN/localhost or placing behind an authenticating reverse proxy.
- `compose.yaml`: Consider adding `read_only: true`, `cap_drop: [ALL]`, and `security_opt: [no-new-privileges:true]` (compatible with `FROM scratch` + bind mounts; verify `ioprio_set` behavior if needed).
- `src/main.rs:469-478`: `be_nice()` silently ignores `setpriority`/`ioprio_set` errors; note that some NAS container kernels/seccomp profiles may reject `ioprio_set` with `EPERM`.

#### L4. CI/CD Hardening (`.github/workflows/*`)
- **Unpinned Actions:** All three workflows use mutable major tags (`actions/checkout@v7`, `docker/*@v4/@v7`, `actions/github-script@v8`) alongside privileged permissions (`packages: write`, `contents: write`, `actions: write`). Pin actions to full commit SHAs.
- **No PR validation in `build.yml`:** `build.yml` only triggers on `push` to `main`. Add a `pull_request` trigger running `cargo test --locked` and `cargo clippy --all-targets -- -D warnings` (skipping image push on PRs).
- **Mutable `:latest` only (`build.yml:37-39`):** Publish immutable commit-SHA or version tags alongside `:latest` so NAS deployments can roll back cleanly. Also lowercase `github.repository` if the repo/owner name ever changes.
- **Missing `timeout-minutes`:** None of the workflow jobs set `timeout-minutes`.
- **Log retention trade-off (`purge-green-runs.yml`):** Purging logs of green `build` runs removes build/digest history for published images; consider excluding `build` or keeping recent runs.

#### L5. Documentation & Test Gaps
- **`README.md` discrepancies:**
  - Line 35 promises repeating step 4 weekly in Testing mode, which is blocked by H3.
  - Line 38 shows `state=…` in the redirect URL, but line 935 does not send a `state` parameter.
- **Test coverage gaps:** Add tests for real EXIF `DateTimeOriginal` extraction (currently only mtime fallback is tested), failed `file_one` recovery with `Policy::Overwrite`, `prune_empty` with symlinks, wake-up policy preservation, `POST`/body HTTP handling, and upload token expiry/error paths.

---

## Suggested Priority Order

1. **Fix data-safety bugs first:** H1 (`file_one`/`recover` cleanup & abort), H2 (`prune_empty` symlink safety), H6 (`prune` preserving holds & locking `LOG_FILE`), M1 (preserve `mtime` + `.partial` cleanup + dir `fsync`).
2. **Fix user-facing operational bugs:** H3 (Google reconnect + OAuth error display), H5 (wake-up `/overwrite/<policy>` reset), M2 (token expiry/401/TTL handling), H7 (`delete-merged-branches.yml` ref+SHA check).
3. **Harden HTTP & lifecycle:** H4 (`POST` + CSRF/PRG + 404 on unknown paths), M4 (header parsing & concurrency), M5 (`0600` on `google.json`), M7 (`SIGTERM` handling).
4. **Polish performance, CI, and tests:** M3 (sidecars), M6 (`walk` resilience), M8 (in-memory state cache), L4 (PR CI + SHA-pinned actions + immutable image tags), L5 (expanded tests).
