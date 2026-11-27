use std::collections::{HashMap, HashSet};
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use std::{env, fs, io, thread};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

// Uploaded to Google Photos, and moved.
const PHOTO: &[&str] = &["jpg", "jpeg", "png", "heic"];
// Moved only.
const VIDEO: &[&str] = &["mp4", "mov", "m4v", "avi", "mkv", "3gp"];
const RAW: &[&str] = &["cr2", "cr3", "nef", "arw", "dng", "orf", "rw2", "raf"];
// Follow the photo with the same name.
const SIDECAR: &[&str] = &["xmp", "aae"];

const LOG_FILE: &str = "photo-mover.log";
const JOURNAL: &str = "transactions.jsonl";
const GOOGLE: &str = "google.json";
const INTERVAL_FILE: &str = "interval";
const REDIRECT: &str = "http://127.0.0.1";
const SCOPE: &str = "https://www.googleapis.com/auth/photoslibrary.appendonly";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// Photos per upload round: Google takes up to 50 items per batchCreate call.
const BATCH: usize = 50;
/// Photos uploaded at the same time: start here, +1 after a clean round, halved when Google pushes back.
const START_WORKERS: usize = 4;
const MAX_WORKERS: usize = 8;
const CHUNK: usize = 1024 * 1024;
const MAX_HTTP_CLIENTS: usize = 16;
const MAX_HTTP_BODY: usize = 16 * 1024;

static NEXT_ID: AtomicU64 = AtomicU64::new(0);
static STOPPING: AtomicBool = AtomicBool::new(false);

fn next_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seq = NEXT_ID.fetch_add(1, Relaxed);
    format!("{nanos:x}-{seq:x}")
}

/// UTC "YYYY-MM-DD HH:MM:SS" for seconds since 1970 (days-to-date by Howard Hinnant).
fn timestamp(secs: u64) -> String {
    let (days, rem) = (secs / 86400 + 719_468, secs % 86400);
    let (era, doe) = (days / 146_097, days % 146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    let (h, m, s) = (rem / 3600, rem % 3600 / 60, rem % 60);
    format!("{year:04}-{month:02}-{day:02} {h:02}:{m:02}:{s:02}")
}

fn unix_now() -> u64 {
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);
    now.unwrap_or_default().as_secs()
}

fn secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn ext(p: &Path) -> String {
    p.extension()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase()
}

fn stem(p: &Path) -> String {
    p.file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// Base stem for matching a sidecar to its photo: "IMG_1.JPG.xmp" and "IMG_1.xmp" both yield "img_1".
fn sidecar_stem(p: &Path) -> String {
    let s = stem(p);
    let inner = Path::new(&s);
    let inner_ext = ext(inner);
    if [PHOTO, VIDEO, RAW].iter().any(|set| set.contains(&inner_ext.as_str())) {
        stem(inner).to_lowercase()
    } else {
        s.to_lowercase()
    }
}

fn es(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Percent-encode everything but unreserved characters.
fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn unescape(s: &str) -> String {
    let bytes = s.as_bytes();
    let (mut out, mut i) = (Vec::new(), 0);
    while i < bytes.len() {
        let hex = bytes.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok());
        match (bytes[i], hex.and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(b)) => {
                out.push(b);
                i += 3;
            }
            (b'+', _) => {
                out.push(b' ');
                i += 1;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The `code` of the URL Google redirected to, or a code pasted as it is.
fn auth_code(pasted: &str) -> Option<String> {
    let pasted = pasted.trim();
    let Some((_, query)) = pasted.split_once('?') else {
        let bare = pasted.split('#').next().unwrap_or(pasted);
        return Some(bare.to_string()).filter(|c| !c.is_empty() && !c.contains('='));
    };
    let query = query.split('#').next().unwrap_or(query);
    let code = query.split('&').find_map(|kv| kv.strip_prefix("code="))?;
    Some(unescape(code))
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Policy {
    Skip,
    Overwrite,
    Keep,
}

impl Policy {
    fn parse(s: &str) -> Option<Policy> {
        match s {
            "skip" => Some(Policy::Skip),
            "overwrite" => Some(Policy::Overwrite),
            "keep" => Some(Policy::Keep),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Policy::Skip => "skip",
            Policy::Overwrite => "overwrite",
            Policy::Keep => "keep",
        }
    }
}

/// Everything the scan loop, the upload worker and the web page share.
struct Shared {
    inbox: PathBuf,
    library: PathBuf,
    /// Where videos go; the same as `library` unless VIDEO_LIBRARY is set.
    video_library: PathBuf,
    data: PathBuf,
    default_policy: Policy,
    policy: AtomicU8,
    awake: AtomicBool,
    /// Seconds of inactivity before sleep; 0 is never.
    idle_secs: AtomicU64,
    /// Seconds since 1970 when the service falls asleep; 0 is never.
    sleep_at: AtomicU64,
    interval: AtomicU64,
    /// Last Move or Upload, so the idle timer sees the upload worker too.
    last_active: AtomicU64,
    /// Counts /upload/retry calls; the upload worker drops its backoff when it changes.
    retry_gen: AtomicU64,
    /// Active HTTP handler threads.
    active_http: AtomicUsize,
    /// Held while a file is moved or rolled back.
    busy: Mutex<()>,
    /// Held while the journal is read or written.
    file: Mutex<()>,
    /// Held while the log file is appended or pruned.
    log_file: Mutex<()>,
    /// One-shot status message shown after a POST redirect.
    note: Mutex<Option<String>>,
    /// Latest Google OAuth error, shown on the page so the user can reconnect.
    google_err: Mutex<Option<String>>,
    access: Mutex<Option<(String, u64)>>,
    client: Option<(String, String)>,
    agent: ureq::Agent,
}

/// What the journal says now.
#[derive(Default)]
struct State {
    moves: Vec<Value>,
    rolled: HashSet<String>,
    uploaded: HashSet<String>,
    /// (hash, size) of rolled-back files the scan must leave alone.
    held: Vec<(String, u64)>,
}

impl Shared {
    fn new(
        inbox: PathBuf,
        library: PathBuf,
        video_library: PathBuf,
        data: PathBuf,
        default_policy: Policy,
        client: Option<(String, String)>,
    ) -> Shared {
        Shared {
            inbox,
            library,
            video_library,
            data,
            default_policy,
            policy: AtomicU8::new(default_policy as u8),
            awake: AtomicBool::new(true),
            idle_secs: AtomicU64::new(0),
            sleep_at: AtomicU64::new(0),
            interval: AtomicU64::new(30),
            last_active: AtomicU64::new(unix_now()),
            retry_gen: AtomicU64::new(0),
            active_http: AtomicUsize::new(0),
            busy: Mutex::new(()),
            file: Mutex::new(()),
            log_file: Mutex::new(()),
            note: Mutex::new(None),
            google_err: Mutex::new(None),
            access: Mutex::new(None),
            client,
            // Uploads of large photos take longer than a page request.
            agent: ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(300)))
                .http_status_as_error(false)
                .build()
                .into(),
        }
    }

    fn policy(&self) -> Policy {
        [Policy::Skip, Policy::Overwrite, Policy::Keep][self.policy.load(Relaxed) as usize]
    }

    /// Wake a sleeping service and reset the session's overwrite policy and idle deadline.
    fn wake(&self) {
        if !self.awake.swap(true, Relaxed) {
            self.policy.store(self.default_policy as u8, Relaxed);
            let now = unix_now();
            self.last_active.store(now, Relaxed);
            let idle = self.idle_secs.load(Relaxed);
            self.sleep_at.store(if idle > 0 { now.saturating_add(idle) } else { 0 }, Relaxed);
        }
    }

    /// To stdout (the container log) and to the log file.
    fn log(&self, line: String) {
        println!("{line}");
        let _guard = self.log_file.lock().unwrap();
        let file = self.data.join(LOG_FILE);
        let written = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file)
            .and_then(|mut f| writeln!(f, "{} {line}", timestamp(unix_now())));
        if let Err(e) = written {
            eprintln!("cannot write {}: {e}", file.display());
        }
    }

    fn record(&self, mut event: Value) {
        event["t"] = json!(unix_now());
        let _guard = self.file.lock().unwrap();
        let file = self.data.join(JOURNAL);
        let written = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file)
            .and_then(|mut f| writeln!(f, "{event}"));
        if let Err(e) = written {
            self.log(format!("cannot write {}: {e}", file.display()));
        }
    }

    fn events(&self) -> Vec<Value> {
        let _guard = self.file.lock().unwrap();
        let text = fs::read_to_string(self.data.join(JOURNAL)).unwrap_or_default();
        text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
    }

    /// Finish what a crash cut short: a move that has an "intent" line but no "move" line.
    fn recover(&self) {
        let events = self.events();
        let done: HashSet<&str> = events.iter().filter(|e| e["kind"] == "move" || e["kind"] == "abort").filter_map(|e| e["id"].as_str()).collect();
        for e in events.iter().filter(|e| e["kind"] == "intent") {
            let id = e["id"].as_str().unwrap_or_default();
            if done.contains(id) {
                continue;
            }
            let path = |key: &str| PathBuf::from(e[key].as_str().unwrap_or_default());
            let (from, to) = (path("from"), path("to"));
            let mut partial = to.as_os_str().to_owned();
            partial.push(".partial");
            let _ = fs::remove_file(partial);
            let stash = self.data.join("replaced").join(id);
            // The copy never landed. An old file that was already set aside goes back.
            if !to.exists() {
                if !stash.exists() || safe_move(&stash, &to).is_ok() {
                    self.record(json!({"kind": "abort", "id": id}));
                    self.log(format!("{}: interrupted move, nothing lost", to.display()));
                }
                continue;
            }
            // A finished copy has its final name (the rename is atomic), so `to` is ours.
            let Ok(hash) = hash_file(&to) else { continue };
            if from.exists() && (hash_file(&from).ok().as_ref() != Some(&hash) || fs::remove_file(&from).is_err()) {
                self.log(format!("{}: interrupted move, left alone", from.display()));
                continue;
            }
            let size = fs::metadata(&to).map(|m| m.len()).unwrap_or(0);
            self.record(json!({"kind": "move", "id": id, "from": from, "to": to, "hash": hash, "size": size, "replaced": stash.exists()}));
            self.log(format!("{}: interrupted move finished", to.display()));
        }
    }

    fn state(&self) -> State {
        let mut state = State::default();
        for event in self.events() {
            let text = |key: &str| event[key].as_str().unwrap_or_default().to_string();
            match event["kind"].as_str() {
                Some("move") => state.moves.push(event),
                Some("rollback") => {
                    state.rolled.insert(text("id"));
                    let size = event["size"].as_u64().unwrap_or_default();
                    state.held.push((text("hash"), size));
                }
                Some("release") => state.held.clear(),
                Some("upload") => {
                    state.uploaded.insert(text("hash"));
                }
                _ => {}
            }
        }
        state
    }

    /// Drop journal and log lines older than `oldest`, and replaced files nobody can restore.
    /// Active rollback holds, upload records for surviving moves, and unresolved intents are kept.
    fn prune(&self, oldest: u64) -> io::Result<()> {
        {
            let _guard = self.file.lock().unwrap();
            let journal = self.data.join(JOURNAL);
            let mut surviving_ids: HashSet<String> = HashSet::new();
            if let Ok(text) = fs::read_to_string(&journal) {
                let parsed: Vec<(&str, Option<Value>)> = text
                    .split_inclusive('\n')
                    .map(|l| (l, serde_json::from_str::<Value>(l).ok()))
                    .collect();
                let last_release = parsed
                    .iter()
                    .enumerate()
                    .filter_map(|(i, (_, e))| (e.as_ref()?.get("kind")?.as_str() == Some("release")).then_some(i))
                    .next_back();
                let done_intents: HashSet<&str> = parsed
                    .iter()
                    .filter_map(|(_, e)| {
                        let e = e.as_ref()?;
                        matches!(e["kind"].as_str(), Some("move" | "abort")).then(|| e["id"].as_str())?
                    })
                    .collect();
                let mut surviving_move_hashes: HashSet<String> = HashSet::new();
                for (_, e) in &parsed {
                    let Some(e) = e else { continue };
                    let recent = e["t"].as_u64().is_none_or(|t| t >= oldest);
                    match e["kind"].as_str() {
                        Some("move") if recent => {
                            if let Some(id) = e["id"].as_str() {
                                surviving_ids.insert(id.to_string());
                            }
                            if let Some(h) = e["hash"].as_str() {
                                surviving_move_hashes.insert(h.to_string());
                            }
                        }
                        Some("intent") => {
                            if let Some(id) = e["id"].as_str()
                                && !done_intents.contains(id)
                            {
                                surviving_ids.insert(id.to_string());
                            }
                        }
                        _ => {}
                    }
                }
                let kept: String = parsed
                    .iter()
                    .enumerate()
                    .filter(|(i, (_, e))| match e {
                        None => true,
                        Some(e) => {
                            let recent = e["t"].as_u64().is_none_or(|t| t >= oldest);
                            if recent {
                                return true;
                            }
                            match e["kind"].as_str() {
                                // Keep held rollbacks that happened after the last release.
                                Some("rollback") => last_release.is_none_or(|r| *i > r),
                                // Keep upload records referenced by surviving moves.
                                Some("upload") => e["hash"].as_str().is_some_and(|h| surviving_move_hashes.contains(h)),
                                // Keep unresolved intents so crash recovery stays consistent.
                                Some("intent") => e["id"].as_str().is_some_and(|id| !done_intents.contains(id)),
                                _ => false,
                            }
                        }
                    })
                    .map(|(_, (l, _))| *l)
                    .collect();
                rewrite(&journal, &kept, text.len())?;
            }
            for entry in fs::read_dir(self.data.join("replaced")).into_iter().flatten().flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !surviving_ids.contains(&name) {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        {
            let _log_guard = self.log_file.lock().unwrap();
            let log = self.data.join(LOG_FILE);
            if let Ok(text) = fs::read_to_string(&log) {
                let oldest = timestamp(oldest);
                let kept: String = text
                    .split_inclusive('\n')
                    .filter(|l| *l >= oldest.as_str())
                    .collect();
                rewrite(&log, &kept, text.len())?;
            }
        }
        Ok(())
    }

    /// Moves of photos that are not on Google Photos yet.
    fn pending(&self) -> Vec<Value> {
        let st = self.state();
        st.moves
            .into_iter()
            .filter(|m| {
                let to = Path::new(m["to"].as_str().unwrap_or_default());
                PHOTO.contains(&ext(to).as_str())
                    && !st.rolled.contains(m["id"].as_str().unwrap_or_default())
                    && !st.uploaded.contains(m["hash"].as_str().unwrap_or_default())
                    && to.exists()
            })
            .collect()
    }

    fn connected(&self) -> bool {
        self.data.join(GOOGLE).exists()
    }

    fn touch(&self) {
        self.last_active.fetch_max(unix_now(), Relaxed);
    }
}

/// Write beside it and rename: a crash never leaves half a file.
fn rewrite(file: &Path, kept: &str, old_len: usize) -> io::Result<()> {
    if kept.len() < old_len {
        let mut partial = file.as_os_str().to_owned();
        partial.push(".partial");
        fs::write(&partial, kept)?;
        fs::rename(partial, file)?;
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hash_file(p: &Path) -> io::Result<String> {
    let mut file = fs::File::open(p)?;
    let (mut hasher, mut buf) = (Sha256::new(), vec![0; CHUNK]);
    loop {
        match file.read(&mut buf)? {
            0 => return Ok(hex(&hasher.finalize())),
            n => hasher.update(&buf[..n]),
        }
    }
}

fn sync_dir(dir: Option<&Path>) {
    #[cfg(unix)]
    if let Some(dir) = dir
        && let Ok(f) = fs::File::open(dir)
    {
        let _ = f.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Write a secret file with owner-only permissions (0600 on Unix) via atomic rename.
fn write_private_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut partial = path.as_os_str().to_owned();
    partial.push(".partial");
    let partial = PathBuf::from(partial);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let write_res = (|| -> io::Result<()> {
        let mut f = opts.open(&partial)?;
        f.write_all(data)?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_res {
        let _ = fs::remove_file(&partial);
        return Err(e);
    }
    if let Err(e) = fs::rename(&partial, path) {
        let _ = fs::remove_file(&partial);
        return Err(e);
    }
    sync_dir(path.parent());
    Ok(())
}

/// Copy `from` to `to` in chunks, hashing on the way and preserving mtime; returns (hash, bytes).
fn copy_hashed(from: &Path, to: &Path) -> io::Result<(String, u64)> {
    let mut src = fs::File::open(from)?;
    let mtime = src.metadata().and_then(|m| m.modified()).ok();
    let mut dst = fs::File::create(to)?;
    let (mut hasher, mut buf, mut total) = (Sha256::new(), vec![0; CHUNK], 0u64);
    loop {
        match src.read(&mut buf)? {
            0 => break,
            n => {
                hasher.update(&buf[..n]);
                dst.write_all(&buf[..n])?;
                total += n as u64;
            }
        }
    }
    if let Some(mtime) = mtime {
        let _ = dst.set_modified(mtime);
    }
    dst.sync_all()?;
    Ok((hex(&hasher.finalize()), total))
}

/// Copy, read the copy back and compare, fsync parent dir, and only then delete the original.
fn safe_move(from: &Path, to: &Path) -> io::Result<(String, u64)> {
    // Copy under a temporary name: a half-written file never has its final name.
    let mut partial = to.as_os_str().to_owned();
    partial.push(".partial");
    let partial = PathBuf::from(partial);
    let (hash, bytes) = match copy_hashed(from, &partial) {
        Ok(ok) => ok,
        Err(e) => {
            let _ = fs::remove_file(&partial);
            return Err(e);
        }
    };
    if hash_file(&partial).ok().as_ref() != Some(&hash) {
        let _ = fs::remove_file(&partial);
        return Err(io::Error::other("copy does not match the original"));
    }
    if let Err(e) = fs::rename(&partial, to) {
        let _ = fs::remove_file(&partial);
        return Err(e);
    }
    sync_dir(to.parent());
    fs::remove_file(from)?;
    Ok((hash, bytes))
}

/// "IMG_1.jpg" -> "IMG_1-1.jpg", "IMG_1-2.jpg", ... the first that is free.
fn free_name(p: &Path) -> PathBuf {
    let (dir, name) = (p.parent().unwrap_or(Path::new("")), stem(p));
    let dot = p.extension().map(|e| format!(".{}", e.to_string_lossy()));
    (1..)
        .map(|n| dir.join(format!("{name}-{n}{}", dot.as_deref().unwrap_or_default())))
        .find(|c| !c.exists())
        .unwrap()
}

/// (year, month) of "YYYY:MM:DD HH:MM:SS".
fn exif_month(p: &Path) -> Option<(String, String)> {
    let file = fs::File::open(p).ok()?;
    let exif = exif::Reader::new()
        .read_from_container(&mut BufReader::new(file))
        .ok()?;
    let field = exif.get_field(exif::Tag::DateTimeOriginal, exif::In::PRIMARY)?;
    let exif::Value::Ascii(values) = &field.value else {
        return None;
    };
    let text = std::str::from_utf8(values.first()?).ok()?;
    let (year, month) = (text.get(..4)?, text.get(5..7)?);
    let valid = year.parse::<u32>().is_ok_and(|y| (1900..=2200).contains(&y))
        && month.parse::<u32>().is_ok_and(|m| (1..=12).contains(&m));
    valid.then(|| (year.to_string(), month.to_string()))
}

/// EXIF DateTimeOriginal, else the modification time.
fn capture_month(p: &Path, modified: SystemTime) -> (String, String) {
    exif_month(p).unwrap_or_else(|| {
        let t = timestamp(secs(modified));
        (t[..4].to_string(), t[5..7].to_string())
    })
}

/// Lower the CPU and disk priority of the calling thread, so moving never slows the NAS.
fn be_nice() {
    #[cfg(target_os = "linux")]
    // SAFETY: plain syscalls on the calling thread, no pointers.
    unsafe {
        let tid = libc::syscall(libc::SYS_gettid) as libc::id_t;
        libc::setpriority(libc::PRIO_PROCESS as _, tid, 19);
        // IOPRIO_WHO_PROCESS = 1, who 0 = this thread, class idle = 3 << 13.
        libc::syscall(libc::SYS_ioprio_set, 1, 0, 3 << 13);
    }
}

/// Move one file into the Library. `Ok(Some(dir))`: it is there now (or was already), in `dir`.
/// `dir` is the folder of the photo a sidecar belongs to.
fn file_one(sh: &Shared, path: &Path, dir: Option<PathBuf>, noted: &mut HashSet<PathBuf>) -> io::Result<Option<PathBuf>> {
    let meta = fs::metadata(path)?;
    let dir = match dir {
        Some(dir) => dir,
        None => {
            let (year, month) = capture_month(path, meta.modified()?);
            let root = if VIDEO.contains(&ext(path).as_str()) { &sh.video_library } else { &sh.library };
            root.join(year).join(month)
        }
    };
    fs::create_dir_all(&dir)?;
    let name = path.file_name().unwrap_or_default();
    let mut target = dir.join(name);
    let id = next_id();
    let mut replaced = false;
    if target.exists() {
        if hash_file(path)? == hash_file(&target)? {
            fs::remove_file(path)?;
            sh.log(format!("{}: already in the library, removed", path.display()));
            return Ok(Some(dir));
        }
        match sh.policy() {
            Policy::Skip => {
                if noted.insert(path.to_path_buf()) {
                    sh.log(format!("{}: {} exists with other content, left alone", path.display(), target.display()));
                }
                return Ok(None);
            }
            Policy::Overwrite => replaced = true,
            Policy::Keep => target = free_name(&target),
        }
    }
    // Written first, so a crash between the copy and the "move" line can be finished at start.
    sh.record(json!({"kind": "intent", "id": id, "from": path, "to": target}));
    let stash = sh.data.join("replaced").join(&id);
    let moved = (|| -> io::Result<(String, u64)> {
        if replaced {
            fs::create_dir_all(sh.data.join("replaced"))?;
            safe_move(&target, &stash)?;
        }
        safe_move(path, &target)
    })();
    let (hash, size) = match moved {
        Ok(ok) => ok,
        Err(e) => {
            if !target.exists() {
                if !stash.exists() || safe_move(&stash, &target).is_ok() {
                    sh.record(json!({"kind": "abort", "id": id}));
                }
            } else if replaced && !stash.exists() {
                sh.record(json!({"kind": "abort", "id": id}));
            }
            return Err(e);
        }
    };
    sh.record(json!({
        "kind": "move", "id": id, "from": path, "to": target,
        "hash": hash, "size": size, "replaced": replaced,
    }));
    sh.touch();
    sh.log(format!("{}: moved to {}{}", path.display(), target.display(), if replaced { " (replaced the old file)" } else { "" }));
    Ok(Some(dir))
}

type Seen = HashMap<PathBuf, (u64, SystemTime)>;

/// All regular files under `p`. Symlinks are not followed, hidden and system folders are skipped.
/// Unreadable sub-entries are skipped so one bad folder does not block the rest of the Inbox.
fn walk(p: &Path, out: &mut Vec<(PathBuf, fs::Metadata)>) -> io::Result<()> {
    for entry in fs::read_dir(p)? {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name().to_string_lossy().into_owned();
        // @eaDir and #recycle are Synology's own folders.
        if [".", "@", "#"].iter().any(|c| name.starts_with(c)) || name.ends_with(".partial") {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(entry.path()) else { continue };
        if meta.is_dir() {
            let _ = walk(&entry.path(), out);
        } else if meta.is_file() {
            out.push((entry.path(), meta));
        }
    }
    Ok(())
}

/// Remove folders under `root` that are empty, deepest first. Never follows symlinks or touches system folders.
fn prune_empty(dir: &Path, root: &Path) {
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if [".", "@", "#"].iter().any(|c| name.starts_with(c)) {
            continue;
        }
        if fs::symlink_metadata(entry.path()).is_ok_and(|m| m.is_dir()) {
            prune_empty(&entry.path(), root);
        }
    }
    if dir != root && fs::read_dir(dir).is_ok_and(|mut d| d.next().is_none()) {
        let _ = fs::remove_dir(dir);
    }
}

/// One pass over the Inbox. A file moves once its size and time are the same in two passes.
/// Returns whether anything is new, changing or moved.
fn scan(sh: &Shared, seen: &mut Seen, noted: &mut HashSet<PathBuf>) -> bool {
    let mut files = Vec::new();
    if let Err(e) = walk(&sh.inbox, &mut files) {
        sh.log(format!("cannot read {}: {e}", sh.inbox.display()));
        return false;
    }
    let state = sh.state();
    let (mut active, mut ready) = (false, Vec::new());
    let mut now = Seen::new();
    for (path, meta) in files {
        let kind = ext(&path);
        if ![PHOTO, VIDEO, RAW, SIDECAR].iter().any(|set| set.contains(&kind.as_str())) {
            continue;
        }
        let sig = (meta.len(), meta.modified().unwrap_or(SystemTime::UNIX_EPOCH));
        if seen.get(&path) == Some(&sig) {
            ready.push((path.clone(), meta.len()));
        } else {
            active = true;
        }
        now.insert(path, sig);
    }
    // Photos/RAW first, then videos, then sidecars (so sidecars follow their photo over a Live Photo clip).
    ready.sort_by_key(|(p, _)| {
        let kind = ext(p);
        if SIDECAR.contains(&kind.as_str()) {
            2u8
        } else if VIDEO.contains(&kind.as_str()) {
            1
        } else {
            0
        }
    });
    // Seed sidecar lookup from recent moves too, so a sidecar arriving one scan after its photo is not stranded.
    let mut homes: HashMap<(PathBuf, String), PathBuf> = HashMap::new();
    for m in state.moves.iter().rev() {
        let id = m["id"].as_str().unwrap_or_default();
        if state.rolled.contains(id) {
            continue;
        }
        let from = Path::new(m["from"].as_str().unwrap_or_default());
        let to = Path::new(m["to"].as_str().unwrap_or_default());
        let kind = ext(from);
        if SIDECAR.contains(&kind.as_str()) {
            continue;
        }
        if let Some(dir) = to.parent() {
            let key = (from.parent().unwrap_or(Path::new("")).to_path_buf(), stem(from).to_lowercase());
            if !VIDEO.contains(&kind.as_str()) {
                homes.entry(key).or_insert_with(|| dir.to_path_buf());
            }
        }
    }
    let mut moved = false;
    for (path, size) in ready {
        if STOPPING.load(Relaxed) {
            break;
        }
        let _busy = sh.busy.lock().unwrap();
        let held = state.held.iter().any(|(hash, s)| *s == size && hash_file(&path).is_ok_and(|h| &h == hash));
        if held {
            continue;
        }
        let sidecar = SIDECAR.contains(&ext(&path).as_str());
        let key = (
            path.parent().unwrap_or(Path::new("")).to_path_buf(),
            if sidecar { sidecar_stem(&path) } else { stem(&path).to_lowercase() },
        );
        if sidecar && !homes.contains_key(&key) {
            continue;
        }
        match file_one(sh, &path, homes.get(&key).cloned().filter(|_| sidecar), noted) {
            Ok(Some(dir)) => {
                if !sidecar {
                    // Photos/RAW win over videos with the same stem.
                    if VIDEO.contains(&ext(&path).as_str()) {
                        homes.entry(key).or_insert(dir);
                    } else {
                        homes.insert(key, dir);
                    }
                }
                now.remove(&path);
                moved = true;
            }
            Ok(None) => {}
            Err(e) => sh.log(format!("{}: error: {e}", path.display())),
        }
    }
    if moved {
        prune_empty(&sh.inbox, &sh.inbox);
        active = true;
    }
    *seen = now;
    active
}

impl Shared {
    /// Put a moved file back in the Inbox and the replaced file back in the Library.
    fn rollback(&self, id: &str) -> Result<String, String> {
        let _busy = self.busy.lock().unwrap();
        let state = self.state();
        let m = state.moves.iter().find(|m| m["id"] == id).ok_or("unknown id")?;
        if state.rolled.contains(id) {
            return Err("already rolled back".into());
        }
        let path = |key: &str| PathBuf::from(m[key].as_str().unwrap_or_default());
        let (from, to, hash) = (path("from"), path("to"), m["hash"].as_str().unwrap_or_default());
        if !to.exists() {
            return Err(format!("{} is gone", to.display()));
        }
        if hash_file(&to).map_err(es)? != hash {
            return Err(format!("{} changed since the move", to.display()));
        }
        let mut dest = from;
        if dest.exists() {
            dest = free_name(&dest);
        }
        fs::create_dir_all(dest.parent().unwrap_or(Path::new(""))).map_err(es)?;
        safe_move(&to, &dest).map_err(es)?;
        // Recorded before the rest: the file is back in the Inbox, so the scan must hold it.
        self.record(json!({"kind": "rollback", "id": id, "hash": hash, "size": m["size"], "restored": dest}));
        let line = format!("rolled back {}: restored {}", to.display(), dest.display());
        self.log(line.clone());
        let stash = self.data.join("replaced").join(id);
        if stash.exists() {
            safe_move(&stash, &to).map_err(|e| format!("{line}, but the replaced file stays in {}: {e}", stash.display()))?;
        }
        Ok(line)
    }

    fn invalidate_access_token(&self) {
        *self.access.lock().unwrap() = None;
    }

    fn oauth_post(&self, params: &[(&str, &str)]) -> Result<Value, String> {
        let mut resp = self
            .agent
            .post(TOKEN_URL)
            .send_form(params.iter().copied())
            .map_err(es)?;
        let status = resp.status().as_u16();
        let body = resp.body_mut().read_to_string().map_err(es)?;
        let json: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        if (200..300).contains(&status) {
            Ok(json)
        } else {
            let err = json["error"].as_str();
            let desc = json["error_description"].as_str();
            match (err, desc) {
                (Some(e), Some(d)) => Err(format!("http status: {status} ({e}: {d})")),
                (Some(e), None) => Err(format!("http status: {status} ({e})")),
                _ => Err(format!("http status: {status}")),
            }
        }
    }

    fn access_token(&self) -> Result<String, String> {
        let mut cache = self.access.lock().unwrap();
        // Refresh 5 minutes before expiry so a multi-photo batch is less likely to hit 401 mid-round.
        if let Some((token, expires)) = &*cache
            && *expires > unix_now() + 300
        {
            return Ok(token.clone());
        }
        let res = (|| -> Result<(String, u64), String> {
            let (id, secret) = self.client.as_ref().ok_or("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are not set")?;
            let saved = fs::read_to_string(self.data.join(GOOGLE)).map_err(|_| "Google is not connected")?;
            let saved: Value = serde_json::from_str(&saved).map_err(es)?;
            let refresh = saved["refresh_token"].as_str().ok_or("no refresh token saved")?;
            let reply = self.oauth_post(&[
                ("client_id", id.as_str()),
                ("client_secret", secret.as_str()),
                ("refresh_token", refresh),
                ("grant_type", "refresh_token"),
            ])?;
            let token = reply["access_token"].as_str().ok_or("no access token in the reply")?;
            Ok((token.to_string(), unix_now() + reply["expires_in"].as_u64().unwrap_or(3600)))
        })();
        match res {
            Ok((token, expires)) => {
                *cache = Some((token.clone(), expires));
                *self.google_err.lock().unwrap() = None;
                Ok(token)
            }
            Err(e) => {
                *cache = None;
                *self.google_err.lock().unwrap() = Some(e.clone());
                Err(e)
            }
        }
    }

    /// Trade the pasted redirect URL for a refresh token and save it.
    fn connect(&self, pasted: &str) -> Result<String, String> {
        let (id, secret) = self.client.as_ref().ok_or("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are not set")?;
        let code = auth_code(pasted).ok_or("no code in what you pasted")?;
        let reply = self.oauth_post(&[
            ("code", code.as_str()),
            ("client_id", id.as_str()),
            ("client_secret", secret.as_str()),
            ("redirect_uri", REDIRECT),
            ("grant_type", "authorization_code"),
        ])?;
        let refresh = reply["refresh_token"].as_str().ok_or("Google sent no refresh token")?;
        write_private_atomic(&self.data.join(GOOGLE), json!({"refresh_token": refresh}).to_string().as_bytes()).map_err(es)?;
        self.invalidate_access_token();
        *self.google_err.lock().unwrap() = None;
        self.log("Google connected".into());
        Ok("Google connected.".into())
    }

    /// Remove the saved refresh token so the user can reconnect (e.g., after 7-day Testing expiry).
    fn disconnect(&self) -> Result<String, String> {
        match fs::remove_file(self.data.join(GOOGLE)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(es(e)),
        }
        self.invalidate_access_token();
        *self.google_err.lock().unwrap() = None;
        self.log("Google disconnected".into());
        Ok("Google disconnected. You can approve access again.".into())
    }

    /// Send one Library photo's bytes to Google Photos. Returns the upload token.
    fn upload_bytes(&self, path: &Path, auth: &str) -> Result<String, ApiErr> {
        let mime = match ext(path).as_str() {
            "png" => "image/png",
            "heic" => "image/heic",
            _ => "image/jpeg",
        };
        // shortcut: the photo is read into memory, fine for photos, upgrade for videos.
        let bytes = fs::read(path).map_err(|e| ApiErr::plain(es(e)))?;
        let mut resp = self
            .agent
            .post("https://photoslibrary.googleapis.com/v1/uploads")
            .header("Authorization", auth)
            .header("Content-Type", "application/octet-stream")
            .header("X-Goog-Upload-Content-Type", mime)
            .header("X-Goog-Upload-Protocol", "raw")
            .send(&bytes[..])
            .map_err(|e| ApiErr::plain(es(e)))?;
        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok());
        let body = resp.body_mut().read_to_string().map_err(|e| ApiErr::plain(es(e)))?;
        if (200..300).contains(&status) {
            return Ok(body);
        }
        if status == 401 {
            self.invalidate_access_token();
        }
        Err(ApiErr::status(status, retry_after))
    }

    /// Add uploaded photos (file name, upload token) to the Google Photos library in one call.
    /// `Err`: the call failed as a whole. Otherwise one result per item, in order.
    fn create_items(&self, items: &[(String, String)], auth: &str) -> Result<Vec<Result<(), ApiErr>>, ApiErr> {
        let new_items: Vec<Value> = items
            .iter()
            .map(|(name, token)| json!({"simpleMediaItem": {"uploadToken": token, "fileName": name}}))
            .collect();
        let mut resp = self
            .agent
            .post("https://photoslibrary.googleapis.com/v1/mediaItems:batchCreate")
            .header("Authorization", auth)
            .send_json(json!({ "newMediaItems": new_items }))
            .map_err(|e| ApiErr::plain(es(e)))?;
        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok());
        if !(200..300).contains(&status) {
            if status == 401 {
                self.invalidate_access_token();
            }
            return Err(ApiErr::status(status, retry_after));
        }
        let reply: Value = resp.body_mut().read_json().map_err(|e| ApiErr::plain(es(e)))?;
        Ok(parse_batch_results(&reply, items.len()))
    }

    /// Upload the photos on `workers` threads, then add them all in one call. One outcome per photo, in order.
    /// `known[i]` is an upload token from an earlier round: that photo's bytes are not sent again.
    fn upload_round(&self, due: &[Value], known: &[Option<String>], workers: usize, generation: u64) -> Vec<Outcome> {
        let next = AtomicUsize::new(0);
        let sent: Mutex<Vec<Option<Upload>>> = Mutex::new(vec![None; due.len()]);
        thread::scope(|scope| {
            for _ in 0..workers.min(due.len()) {
                scope.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, Relaxed);
                        let Some(m) = due.get(i) else { break };
                        let up = if STOPPING.load(Relaxed) || !self.awake.load(Relaxed) || self.retry_gen.load(Relaxed) != generation {
                            Upload::Stopped
                        } else if let Some(token) = &known[i] {
                            Upload::Sent(token.clone())
                        } else {
                            match self.access_token() {
                                Ok(tok) => match self.upload_bytes(Path::new(m["to"].as_str().unwrap_or_default()), &format!("Bearer {tok}")) {
                                    Ok(token) => {
                                        self.touch();
                                        Upload::Sent(token)
                                    }
                                    Err(e) => Upload::Failed(e),
                                },
                                Err(e) => Upload::Failed(ApiErr::plain(e)),
                            }
                        };
                        sent.lock().unwrap()[i] = Some(up);
                    }
                });
            }
        });
        let uploads: Vec<Upload> = sent.into_inner().unwrap().into_iter().flatten().collect();
        let items: Vec<(String, String)> = due
            .iter()
            .zip(&uploads)
            .filter_map(|(m, u)| match u {
                Upload::Sent(token) => {
                    let name = Path::new(m["to"].as_str().unwrap_or_default()).file_name().unwrap_or_default();
                    Some((name.to_string_lossy().into_owned(), token.clone()))
                }
                _ => None,
            })
            .collect();
        let created = if items.is_empty() {
            Ok(Vec::new())
        } else {
            match self.access_token() {
                Ok(tok) => self.create_items(&items, &format!("Bearer {tok}")),
                Err(e) => Err(ApiErr::plain(e)),
            }
        };
        join(uploads, created)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ApiErr {
    msg: String,
    overload: bool,
    retry_after: Option<u64>,
}

impl ApiErr {
    fn plain(msg: impl Into<String>) -> Self {
        Self { msg: msg.into(), overload: false, retry_after: None }
    }

    fn status(code: u16, retry_after: Option<u64>) -> Self {
        Self {
            msg: format!("http status: {code}"),
            overload: code == 429 || (500..600).contains(&code),
            retry_after,
        }
    }
}

/// Interpret `mediaItems:batchCreate` per-item statuses.
fn parse_batch_results(reply: &Value, count: usize) -> Vec<Result<(), ApiErr>> {
    (0..count)
        .map(|i| {
            let item = &reply["newMediaItemResults"][i];
            let status = &item["status"];
            let code = status["code"].as_i64();
            let msg = status["message"].as_str();
            let ok = item["mediaItem"]["id"].as_str().is_some()
                || code == Some(0)
                || (code.is_none() && matches!(msg, Some("Success" | "OK")));
            if ok {
                Ok(())
            } else {
                // gRPC codes: 8 = RESOURCE_EXHAUSTED, 13 = INTERNAL, 14 = UNAVAILABLE.
                let overload = matches!(code, Some(8 | 13 | 14));
                let detail = msg.unwrap_or("no status");
                Err(ApiErr {
                    msg: format!("Google refused it: {detail}"),
                    overload,
                    retry_after: None,
                })
            }
        })
        .collect()
}

/// What happened to one photo's bytes.
#[derive(Clone)]
enum Upload {
    /// Google has the bytes; this is the upload token.
    Sent(String),
    Failed(ApiErr),
    /// Not tried: the service went to sleep or /upload/retry was called.
    Stopped,
}

struct Outcome {
    result: Result<(), ApiErr>,
    /// Upload token to try again with, when only adding the photo failed.
    token: Option<String>,
    /// false: not tried, so no backoff.
    tried: bool,
}

/// Match the upload step with the add step. `created` has one result per `Sent` photo, in order.
fn join(uploads: Vec<Upload>, created: Result<Vec<Result<(), ApiErr>>, ApiErr>) -> Vec<Outcome> {
    let mut created = created.map(Vec::into_iter);
    let outcome = |result, token, tried| Outcome { result, token, tried };
    uploads
        .into_iter()
        .map(|u| match u {
            Upload::Stopped => outcome(Err(ApiErr::plain("stopped")), None, false),
            Upload::Failed(e) => outcome(Err(e), None, true),
            Upload::Sent(token) => match &mut created {
                Ok(results) => match results.next() {
                    Some(result) => outcome(result, None, true),
                    None => outcome(Err(ApiErr::plain("no result")), Some(token), true),
                },
                Err(e) => outcome(Err(e.clone()), Some(token), true),
            },
        })
        .collect()
}

/// Sleep up to `secs` seconds, waking early if stopping or `/upload/retry` fires.
fn sleep_interruptible(sh: &Shared, secs: u64, retry_gen: u64) {
    for _ in 0..secs {
        if STOPPING.load(Relaxed) || sh.retry_gen.load(Relaxed) != retry_gen {
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
}

/// Uploads Library photos a few at a time, slowly backing off from failures.
fn upload_loop(sh: Arc<Shared>) {
    // Move id -> (failures, next try in seconds since 1970).
    let mut failed: HashMap<String, (u32, u64)> = HashMap::new();
    // Move id -> (upload token, first created). The bytes are with Google, only adding the photo failed, so a retry
    // skips the upload. Unverified: if the lost add did succeed, Google may refuse the used token, and the
    // retry then uploads the bytes again, which makes a duplicate. Google keeps tokens for a day.
    let mut tokens: HashMap<String, (String, u64)> = HashMap::new();
    let mut retry_gen = 0;
    let mut workers = START_WORKERS;
    let mut auth_fails = 0u32;
    let mut auth_next = 0u64;
    while !STOPPING.load(Relaxed) {
        // One pause per round, not per photo: a backlog goes out without waiting between files.
        sleep_interruptible(&sh, 5, retry_gen);
        if STOPPING.load(Relaxed) {
            break;
        }
        if retry_gen != sh.retry_gen.load(Relaxed) {
            retry_gen = sh.retry_gen.load(Relaxed);
            failed.clear();
            auth_fails = 0;
            auth_next = 0;
        }
        if !sh.awake.load(Relaxed) || !sh.connected() {
            continue;
        }
        // The journal is read once per round, not once per photo.
        let pending = sh.pending();
        let pending_ids: HashSet<&str> = pending.iter().filter_map(|m| m["id"].as_str()).collect();
        failed.retain(|id, _| pending_ids.contains(id.as_str()));
        tokens.retain(|id, (_, when)| pending_ids.contains(id.as_str()) && unix_now() < *when + 20 * 3600);
        let due: Vec<Value> = pending
            .iter()
            .filter(|m| !failed.get(m["id"].as_str().unwrap_or_default()).is_some_and(|(_, next)| *next > unix_now()))
            .take(BATCH)
            .cloned()
            .collect();
        if due.is_empty() {
            continue;
        }
        if auth_next > unix_now() {
            continue;
        }
        // Verify we have a usable access token once before touching per-photo state or tokens.
        if let Err(e) = sh.access_token() {
            auth_fails += 1;
            let wait = (60u64 << auth_fails.min(6)).min(3600);
            sh.log(format!("Google auth failed ({e}), next try in {wait}s"));
            auth_next = unix_now() + wait;
            continue;
        }
        auth_fails = 0;
        auth_next = 0;

        let known: Vec<Option<String>> = due
            .iter()
            .map(|m| tokens.get(m["id"].as_str().unwrap_or_default()))
            .map(|t| t.filter(|(_, when)| unix_now() < when + 20 * 3600).map(|(token, _)| token.clone()))
            .collect();
        let outcomes = sh.upload_round(&due, &known, workers, retry_gen);
        // Google pushes back: halve. A clean round: one more.
        let overloaded = outcomes.iter().any(|o| o.result.as_ref().err().is_some_and(|e| e.overload));
        let retry_after = outcomes
            .iter()
            .filter_map(|o| o.result.as_ref().err().and_then(|e| e.retry_after))
            .max();
        let next = if overloaded {
            (workers / 2).max(1)
        } else if outcomes.iter().all(|o| o.result.is_ok()) {
            (workers + 1).min(MAX_WORKERS)
        } else {
            workers
        };
        if next != workers {
            sh.log(format!("uploading {next} at a time ({})", if overloaded { "Google pushed back" } else { "all went well" }));
            workers = next;
        }
        for (m, o) in due.iter().zip(outcomes) {
            if !o.tried {
                continue;
            }
            let (id, to) = (m["id"].as_str().unwrap_or_default().to_string(), PathBuf::from(m["to"].as_str().unwrap_or_default()));
            match o.token {
                // Keep the original upload-token timestamp so the 20h expiry still fires on repeated failures.
                Some(token) => {
                    tokens.entry(id.clone()).or_insert((token, unix_now()));
                }
                None => {
                    tokens.remove(&id);
                }
            }
            match o.result {
                Ok(()) => {
                    sh.record(json!({"kind": "upload", "id": id, "hash": m["hash"], "to": to}));
                    sh.touch();
                    sh.log(format!("{}: uploaded to Google Photos", to.display()));
                    failed.remove(&id);
                }
                Err(e) => {
                    let tries = failed.get(&id).map_or(1, |(n, _)| n + 1);
                    let wait = (60u64 << tries.min(6)).min(3600);
                    sh.log(format!("{}: upload failed ({}), next try in {wait}s", to.display(), e.msg));
                    failed.insert(id, (tries, unix_now() + wait));
                }
            }
        }
        if overloaded {
            let pause = retry_after.unwrap_or(60).clamp(5, 600);
            sh.log(format!("Google pushed back, pausing uploads for {pause}s"));
            sleep_interruptible(&sh, pause, retry_gen);
        }
    }
}

fn action_btn(action: &str, label: &str) -> String {
    format!("<form class=i method=post action=\"{}\"><button>{}</button></form>", esc(action), esc(label))
}

fn page(sh: &Shared, note: &str) -> String {
    let left = sh.sleep_at.load(Relaxed).saturating_sub(unix_now()).div_ceil(60);
    let state = match (sh.awake.load(Relaxed), sh.sleep_at.load(Relaxed)) {
        (false, _) => "Asleep.".to_string(),
        (true, 0) => "Awake.".to_string(),
        (true, _) => format!("Awake. Sleeps in {left} min if nothing new arrives."),
    };
    let google = if sh.connected() {
        let err = sh
            .google_err
            .lock()
            .unwrap()
            .as_ref()
            .map(|e| format!(" <b>Auth error:</b> {} — reconnect below.", esc(e)))
            .unwrap_or_default();
        format!(
            "Google Photos connected, {} photo(s) waiting for upload ({} {}).{err}",
            sh.pending().len(),
            action_btn("/upload/retry", "retry now"),
            action_btn("/google/disconnect", "Disconnect / reconnect"),
        )
    } else if let Some((id, _)) = &sh.client {
        let url = format!(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline&prompt=consent",
            enc(id), enc(REDIRECT), enc(SCOPE)
        );
        format!(
            "Google Photos not connected. <a href=\"{}\" target=_blank>Approve access</a>, the next page will not load: \
             paste its address here. <form class=i method=post action=/code><input name=url size=60><button>Connect</button></form>",
            esc(&url)
        )
    } else {
        "Google Photos off: set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.".into()
    };
    let st = sh.state();
    let moves: String = st
        .moves
        .iter()
        .rev()
        .take(15)
        .map(|m| {
            let id = m["id"].as_str().unwrap_or_default();
            let undo = if st.rolled.contains(id) {
                "rolled back".into()
            } else {
                action_btn(&format!("/rollback/{id}"), "rollback")
            };
            format!(
                "{} {} {undo}\n",
                esc(m["to"].as_str().unwrap_or_default()),
                if st.uploaded.contains(m["hash"].as_str().unwrap_or_default()) { "(on Google)" } else { "" }
            )
        })
        .collect();
    let log = {
        let _guard = sh.log_file.lock().unwrap();
        fs::read_to_string(sh.data.join(LOG_FILE)).unwrap_or_default()
    };
    let lines: Vec<&str> = log.lines().collect();
    let recent = esc(&lines[lines.len().saturating_sub(20)..].join("\n"));
    let policy = |p: Policy| {
        if sh.policy() == p {
            format!("<b>{}</b>", p.name())
        } else {
            action_btn(&format!("/overwrite/{}", p.name()), p.name())
        }
    };
    format!(
        "<!doctype html><meta name=viewport content='width=device-width'><title>photo-mover</title>\
         <style>form.i{{display:inline}}form.i button{{font:inherit;cursor:pointer}}</style>\
         <h1>photo-mover <small>v{ver}</small></h1>\
         <p>{note}</p><p>{state} Scans every {}s ({} | {} | {}). \
         Name clash with other content: {} | {} | {}.</p>\
         <p>{} | {} | {} | <a href=/>Refresh</a></p>\
         <p>{google}</p><h3>Moves</h3><pre>{moves}</pre><h3>Log</h3><pre>{recent}</pre>",
        sh.interval.load(Relaxed),
        action_btn("/interval/5", "5"),
        action_btn("/interval/30", "30"),
        action_btn("/interval/300", "300"),
        policy(Policy::Skip),
        policy(Policy::Overwrite),
        policy(Policy::Keep),
        action_btn("/start", "Start"),
        action_btn("/stop", "Stop"),
        action_btn("/release", "Release held files"),
        ver = env!("CARGO_PKG_VERSION"),
        note = esc(note),
    )
}

struct HttpRequest {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    body: String,
}

fn read_request(stream: &mut TcpStream) -> io::Result<Option<HttpRequest>> {
    let mut raw = Vec::new();
    let mut chunk = [0; 1024];
    let header_end = loop {
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if raw.len() >= 16 * 1024 {
            return Ok(None);
        }
        match stream.read(&mut chunk)? {
            0 => return Ok(None),
            n => raw.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or_default();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let content_len = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_HTTP_BODY);
    let mut body = raw[header_end..].to_vec();
    while body.len() < content_len {
        let need = (content_len - body.len()).min(chunk.len());
        match stream.read(&mut chunk[..need])? {
            0 => break,
            n => body.extend_from_slice(&chunk[..n]),
        }
    }
    body.truncate(content_len);
    Ok(Some(HttpRequest {
        method,
        target,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }))
}

/// Reject cross-site browser requests based on Fetch Metadata and Origin/Host.
fn is_cross_site(req: &HttpRequest) -> bool {
    if let Some(site) = req.headers.get("sec-fetch-site")
        && !matches!(site.as_str(), "same-origin" | "none")
    {
        return true;
    }
    if let (Some(origin), Some(host)) = (req.headers.get("origin"), req.headers.get("host")) {
        let origin_host = origin
            .strip_prefix("http://")
            .or_else(|| origin.strip_prefix("https://"))
            .unwrap_or(origin)
            .split('/')
            .next()
            .unwrap_or_default();
        if !origin_host.eq_ignore_ascii_case(host) {
            return true;
        }
    }
    false
}

fn form_field(body: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    body.split('&')
        .find_map(|kv| kv.strip_prefix(&prefix))
        .map(unescape)
}

fn send_response(stream: &mut TcpStream, status: &str, extra_headers: &str, content_type: &str, body: &str) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n{extra_headers}\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn is_action_path(path: &str) -> bool {
    matches!(path, "/start" | "/stop" | "/release" | "/upload/retry" | "/google/disconnect" | "/code")
        || path.starts_with("/interval/")
        || path.starts_with("/overwrite/")
        || path.starts_with("/rollback/")
}

/// Answer one request. Only known `POST` actions mutate state or wake a sleeping service.
fn answer(mut stream: TcpStream, sh: &Shared) -> io::Result<()> {
    // A client that says nothing must not block for long.
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let Some(req) = read_request(&mut stream)? else {
        return Ok(());
    };
    let (path, query) = req.target.split_once('?').unwrap_or((&req.target, ""));
    match (req.method.as_str(), path) {
        ("GET" | "HEAD", "/") => {
            let note = sh.note.lock().unwrap().take().unwrap_or_default();
            let html = page(sh, &note);
            let body = if req.method == "HEAD" { "" } else { html.as_str() };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                html.len()
            )
        }
        ("GET" | "HEAD", "/favicon.ico") => send_response(&mut stream, "204 No Content", "", "text/plain", ""),
        ("POST", _) => {
            if is_cross_site(&req) {
                return send_response(&mut stream, "403 Forbidden", "", "text/plain; charset=utf-8", "forbidden\n");
            }
            let mut note = String::new();
            let handled = if path == "/start" {
                sh.wake();
                true
            } else if path == "/stop" {
                sh.awake.store(false, Relaxed);
                true
            } else if let Some(raw) = path.strip_prefix("/interval/") {
                sh.wake();
                if let Some(seconds) = raw.parse::<u64>().ok().filter(|s| *s > 0) {
                    sh.interval.store(seconds, Relaxed);
                    let _ = fs::write(sh.data.join(INTERVAL_FILE), seconds.to_string());
                } else {
                    note = "interval must be a positive number of seconds".into();
                }
                true
            } else if let Some(policy) = path.strip_prefix("/overwrite/").and_then(Policy::parse) {
                sh.wake();
                sh.policy.store(policy as u8, Relaxed);
                sh.log(format!("name clashes: {}", policy.name()));
                true
            } else if let Some(id) = path.strip_prefix("/rollback/") {
                sh.wake();
                note = sh.rollback(id).unwrap_or_else(|e| format!("rollback failed: {e}"));
                true
            } else if path == "/release" {
                sh.wake();
                sh.record(json!({"kind": "release"}));
                note = "Rolled-back files will be moved again.".into();
                true
            } else if path == "/upload/retry" {
                sh.wake();
                sh.retry_gen.fetch_add(1, Relaxed);
                true
            } else if path == "/google/disconnect" {
                sh.wake();
                note = sh.disconnect().unwrap_or_else(|e| format!("disconnect failed: {e}"));
                true
            } else if path == "/code" {
                sh.wake();
                let pasted = form_field(&req.body, "url").or_else(|| form_field(query, "url")).unwrap_or_default();
                note = sh.connect(&pasted).unwrap_or_else(|e| format!("connect failed: {e}"));
                true
            } else {
                false
            };
            if !handled {
                return send_response(&mut stream, "404 Not Found", "", "text/plain; charset=utf-8", "not found\n");
            }
            if !note.is_empty() {
                *sh.note.lock().unwrap() = Some(note.clone());
            }
            let body = if note.is_empty() { "ok\n".to_string() } else { format!("{note}\n") };
            send_response(&mut stream, "303 See Other", "Location: /\r\n", "text/plain; charset=utf-8", &body)
        }
        ("GET", p) if is_action_path(p) => {
            send_response(&mut stream, "405 Method Not Allowed", "Allow: POST\r\n", "text/plain; charset=utf-8", "use POST\n")
        }
        _ => send_response(&mut stream, "404 Not Found", "", "text/plain; charset=utf-8", "not found\n"),
    }
}

#[cfg(target_os = "linux")]
extern "C" fn handle_signal(_: libc::c_int) {
    STOPPING.store(true, Relaxed);
}

fn install_signal_handlers() {
    #[cfg(target_os = "linux")]
    // SAFETY: `handle_signal` only performs an async-signal-safe atomic store.
    unsafe {
        let f = handle_signal as *const () as libc::sighandler_t;
        libc::signal(libc::SIGTERM, f);
        libc::signal(libc::SIGINT, f);
    }
}

struct HttpSlot(Arc<Shared>);

impl Drop for HttpSlot {
    fn drop(&mut self) {
        self.0.active_http.fetch_sub(1, Relaxed);
    }
}

fn main() {
    install_signal_handlers();
    let var = |key: &str| env::var(key).ok().filter(|v| !v.is_empty());
    let number = |key: &str, default: u64| var(key).and_then(|v| v.parse().ok()).unwrap_or(default);
    let data = PathBuf::from(var("LOG_DIR").unwrap_or("/data".into()));
    if let Err(e) = fs::create_dir_all(&data) {
        eprintln!("cannot use {}: {e}", data.display());
        std::process::exit(1);
    }
    let client = var("GOOGLE_CLIENT_ID").zip(var("GOOGLE_CLIENT_SECRET"));
    let library = PathBuf::from(var("LIBRARY").unwrap_or("/library".into()));
    let sh = Arc::new(Shared::new(
        var("INBOX").unwrap_or("/inbox".into()).into(),
        library.clone(),
        var("VIDEO_LIBRARY").map_or(library, PathBuf::from),
        data.clone(),
        var("OVERWRITE").as_deref().and_then(Policy::parse).unwrap_or(Policy::Skip),
        client,
    ));
    sh.recover();
    // At least 1: a pause of 0 would scan without a break. A value set from the page wins.
    let saved = fs::read_to_string(data.join(INTERVAL_FILE)).ok().and_then(|s| s.trim().parse().ok());
    sh.interval.store(saved.unwrap_or(number("INTERVAL", 30)).max(1), Relaxed);
    let log_days = number("LOG_DAYS", 60);
    let port = u16::try_from(number("PORT", 8768)).unwrap_or(8768);
    let idle_minutes = number("IDLE_MINUTES", 60);
    sh.log(format!(
        "watching {} -> {} (videos: {}) every {}s, name clashes: {}, Google Photos {}",
        sh.inbox.display(),
        sh.library.display(),
        sh.video_library.display(),
        sh.interval.load(Relaxed),
        sh.default_policy.name(),
        if sh.client.is_some() { "on" } else { "off" },
    ));

    let listening = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(listener) => {
            let sh = sh.clone();
            thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    if STOPPING.load(Relaxed) {
                        break;
                    }
                    if sh.active_http.fetch_add(1, Relaxed) >= MAX_HTTP_CLIENTS {
                        sh.active_http.fetch_sub(1, Relaxed);
                        let mut s = stream;
                        let _ = send_response(&mut s, "503 Service Unavailable", "", "text/plain", "busy\n");
                        continue;
                    }
                    let slot = HttpSlot(sh.clone());
                    thread::spawn(move || {
                        let _slot = slot;
                        let _ = answer(stream, &_slot.0);
                    });
                }
            });
            true
        }
        Err(e) => {
            sh.log(format!("cannot listen on port {port} ({e}), so it never sleeps"));
            false
        }
    };
    // Without the page nothing could wake it again.
    let idle = if listening { idle_minutes.saturating_mul(60) } else { 0 };
    sh.idle_secs.store(idle, Relaxed);
    if idle > 0 {
        sh.sleep_at.store(unix_now().saturating_add(idle), Relaxed);
    }
    let uploader = {
        let sh = sh.clone();
        thread::spawn(move || upload_loop(sh))
    };
    be_nice();

    // shortcut: a manual copy that stalls longer than INTERVAL looks finished,
    // raise INTERVAL if a hand-copied photo ever arrives cut short.
    let (mut seen, mut noted) = (Seen::new(), HashSet::new());
    let (mut pruned_day, mut was_awake) = (String::new(), false);
    while !STOPPING.load(Relaxed) {
        // Once a day is enough.
        let today = timestamp(unix_now())[..10].to_string();
        if today != pruned_day {
            if let Err(e) = sh.prune(unix_now().saturating_sub(log_days.saturating_mul(86400))) {
                sh.log(format!("cannot trim the log: {e}"));
            }
            pruned_day = today;
        }

        let awake = sh.awake.load(Relaxed);
        if awake != was_awake {
            was_awake = awake;
            // After a sleep every file has to prove again that it is finished.
            seen.clear();
            noted.clear();
            sh.log(if awake { "awake" } else { "asleep" }.into());
        }
        if !awake {
            thread::sleep(Duration::from_secs(1));
            continue;
        }

        if scan(&sh, &mut seen, &mut noted) {
            sh.touch();
        }
        if idle > 0 {
            let sleep_at = sh.last_active.load(Relaxed).saturating_add(idle);
            sh.sleep_at.store(sleep_at, Relaxed);
            if unix_now() >= sleep_at {
                sh.log(format!("nothing new for {idle_minutes} min"));
                sh.awake.store(false, Relaxed);
                continue;
            }
        }
        // In steps of a second, so a start, stop, or interval change is noticed at once.
        let mut waited = 0;
        while waited < sh.interval.load(Relaxed) && sh.awake.load(Relaxed) && !STOPPING.load(Relaxed) {
            thread::sleep(Duration::from_secs(1));
            waited += 1;
        }
    }
    sh.log("stopping".into());
    let _ = uploader.join();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(name: &str, policy: Policy) -> (Shared, PathBuf) {
        let root = env::temp_dir().join(format!("photo-mover-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for d in ["inbox", "library", "videos", "data"] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        let sh = Shared::new(root.join("inbox"), root.join("library"), root.join("videos"), root.join("data"), policy, None);
        (sh, root)
    }

    /// Two passes: the first sees the files, the second moves them.
    fn run(sh: &Shared, noted: &mut HashSet<PathBuf>) {
        let mut seen = Seen::new();
        scan(sh, &mut seen, noted);
        scan(sh, &mut seen, noted);
    }

    fn put(root: &Path, name: &str, body: &str) -> PathBuf {
        let p = root.join("inbox").join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, body).unwrap();
        p
    }

    fn month_dir(root: &Path, file: &Path) -> PathBuf {
        let t = timestamp(secs(fs::metadata(file).unwrap().modified().unwrap()));
        root.join("library").join(&t[..4]).join(&t[5..7])
    }

    #[test]
    fn moves_with_sidecar_and_leaves_the_rest() {
        let (sh, root) = setup("move", Policy::Skip);
        let photo = put(&root, "trip/IMG_1.jpg", "photo");
        put(&root, "trip/IMG_1.xmp", "meta");
        put(&root, "trip/notes.txt", "text");
        let dir = month_dir(&root, &photo);
        run(&sh, &mut HashSet::new());
        assert_eq!(fs::read_to_string(dir.join("IMG_1.jpg")).unwrap(), "photo");
        assert!(dir.join("IMG_1.xmp").exists());
        assert!(root.join("inbox/trip/notes.txt").exists());
        assert!(!root.join("inbox/trip/IMG_1.jpg").exists());
        assert_eq!(sh.state().moves.len(), 2);
        assert_eq!(sh.pending().len(), 1, "only the photo goes to Google");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn videos_go_to_their_own_library() {
        let (sh, root) = setup("video", Policy::Skip);
        let clip = put(&root, "a.mp4", "clip");
        run(&sh, &mut HashSet::new());
        let found = |lib: &str| {
            let mut files = Vec::new();
            walk(&root.join(lib), &mut files).unwrap();
            files.len()
        };
        assert!(!clip.exists());
        assert_eq!((found("videos"), found("library")), (1, 0));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn join_matches_each_photo_with_its_own_result() {
        let uploads = || {
            vec![
                Upload::Sent("a".into()),
                Upload::Failed(ApiErr::plain("x")),
                Upload::Sent("b".into()),
                Upload::Stopped,
                Upload::Sent("c".into()),
            ]
        };
        let out = join(uploads(), Ok(vec![Ok(()), Err(ApiErr::plain("refused")), Ok(())]));
        assert!(out[0].result.is_ok() && out[4].result.is_ok());
        assert_eq!(out[1].result, Err(ApiErr::plain("x")));
        assert_eq!((out[2].result.clone(), out[2].token.clone()), (Err(ApiErr::plain("refused")), None));
        assert!(!out[3].tried);
        // The add call failed as a whole: the photos that were sent keep their token.
        let out = join(uploads(), Err(ApiErr::plain("timeout")));
        let kept: Vec<_> = out.iter().map(|o| o.token.clone()).collect();
        assert_eq!(kept, [Some("a".to_string()), None, Some("b".to_string()), None, Some("c".to_string())]);
    }

    #[test]
    fn name_clash_follows_the_policy() {
        for (policy, expect) in [(Policy::Skip, "old"), (Policy::Overwrite, "new"), (Policy::Keep, "old")] {
            let (mut sh, root) = setup("clash", policy);
            sh.default_policy = policy;
            let first = put(&root, "a.jpg", "old");
            let dir = month_dir(&root, &first);
            run(&sh, &mut HashSet::new());
            let again = put(&root, "a.jpg", "new");
            run(&sh, &mut HashSet::new());
            assert_eq!(fs::read_to_string(dir.join("a.jpg")).unwrap(), expect, "{policy:?}");
            assert_eq!(again.exists(), policy == Policy::Skip, "{policy:?}");
            assert_eq!(dir.join("a-1.jpg").exists(), policy == Policy::Keep, "{policy:?}");
            // Same content again: removed from the Inbox whatever the policy.
            let same = put(&root, "a.jpg", expect);
            run(&sh, &mut HashSet::new());
            assert!(!same.exists(), "{policy:?}");
            fs::remove_dir_all(&root).unwrap();
        }
    }

    #[test]
    fn rollback_restores_and_holds() {
        let (sh, root) = setup("rollback", Policy::Overwrite);
        let first = put(&root, "a.jpg", "old");
        let dir = month_dir(&root, &first);
        run(&sh, &mut HashSet::new());
        put(&root, "a.jpg", "new");
        run(&sh, &mut HashSet::new());
        let id = sh.state().moves[1]["id"].as_str().unwrap().to_string();
        assert_eq!(fs::read_to_string(dir.join("a.jpg")).unwrap(), "new");

        sh.rollback(&id).unwrap();
        assert_eq!(fs::read_to_string(root.join("inbox/a.jpg")).unwrap(), "new");
        assert_eq!(fs::read_to_string(dir.join("a.jpg")).unwrap(), "old", "replaced file is back");
        assert!(sh.rollback(&id).is_err(), "only once");

        // The scan leaves a rolled-back file alone until it is released.
        run(&sh, &mut HashSet::new());
        assert!(root.join("inbox/a.jpg").exists());
        sh.record(json!({"kind": "release"}));
        run(&sh, &mut HashSet::new());
        assert!(!root.join("inbox/a.jpg").exists());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn reads_the_capture_date_and_codes() {
        let (_, root) = setup("date", Policy::Skip);
        let p = root.join("none.jpg");
        fs::write(&p, "not a jpeg").unwrap();
        let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_709_164_800);
        assert_eq!(capture_month(&p, mtime), ("2024".into(), "02".into()));

        assert_eq!(unescape("a%2Fb+c"), "a/b c");
        let url = "http://127.0.0.1/?state=x&code=4%2F0AbC&scope=y";
        assert_eq!(auth_code(url).unwrap(), "4/0AbC");
        assert_eq!(auth_code("4/0AbC").unwrap(), "4/0AbC");
        assert_eq!(auth_code("http://127.0.0.1/?error=access_denied"), None);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn prunes_old_transactions() {
        let (sh, root) = setup("prune", Policy::Skip);
        let journal = root.join("data").join(JOURNAL);
        fs::write(&journal, "{\"kind\":\"move\",\"id\":\"old\",\"t\":10}\n{\"kind\":\"move\",\"id\":\"new\",\"t\":5000}\n").unwrap();
        sh.prune(100).unwrap();
        let moves = sh.state().moves;
        assert_eq!(moves.len(), 1);
        assert_eq!(moves[0]["id"], "new");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn page_wakes_on_post_actions_and_blocks_cross_site_and_unknown_gets() {
        let (sh, root) = setup("page", Policy::Skip);
        let sh = Arc::new(sh);
        sh.idle_secs.store(3600, Relaxed);
        sh.awake.store(false, Relaxed);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let served = sh.clone();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = answer(stream, &served);
            }
        });
        let req = |raw: &str| {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write_all(raw.as_bytes()).unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).unwrap();
            reply
        };
        let get = |path: &str| req(&format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"));
        let post = |path: &str, body: &str| {
            req(&format!(
                "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ))
        };

        assert!(get("/").contains("Asleep.") && !sh.awake.load(Relaxed));
        assert!(get("/favicon.ico").starts_with("HTTP/1.1 204") && !sh.awake.load(Relaxed));
        assert!(get("/robots.txt").starts_with("HTTP/1.1 404") && !sh.awake.load(Relaxed));
        assert!(get("/stop").starts_with("HTTP/1.1 405") && !sh.awake.load(Relaxed));
        assert!(post("/unknown", "").starts_with("HTTP/1.1 404") && !sh.awake.load(Relaxed));

        // Cross-site POST is rejected with 403 and does not wake.
        let csrf = req("POST /overwrite/overwrite HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: cross-site\r\n\r\n");
        assert!(csrf.starts_with("HTTP/1.1 403") && !sh.awake.load(Relaxed) && sh.policy() == Policy::Skip);

        // POST actions wake and redirect (PRG).
        assert!(post("/interval/7", "").starts_with("HTTP/1.1 303") && sh.awake.load(Relaxed));
        assert_eq!(sh.interval.load(Relaxed), 7);
        assert!(sh.sleep_at.load(Relaxed) > unix_now());
        assert!(get("/").contains("Awake."));

        assert!(post("/stop", "").starts_with("HTTP/1.1 303") && !sh.awake.load(Relaxed));
        // Waking via /overwrite/keep sets Keep and keeps it after wake.
        assert!(post("/overwrite/keep", "").starts_with("HTTP/1.1 303"));
        assert!(sh.awake.load(Relaxed) && sh.policy() == Policy::Keep);

        // /interval/0 is rejected and preserves current interval.
        post("/interval/0", "");
        assert_eq!(sh.interval.load(Relaxed), 7);

        // Disconnect removes google.json so reconnect UI appears.
        write_private_atomic(&sh.data.join(GOOGLE), br#"{"refresh_token":"tok"}"#).unwrap();
        assert!(sh.connected());
        assert!(post("/google/disconnect", "").starts_with("HTTP/1.1 303"));
        assert!(!sh.connected());

        // POST /code reads form body cleanly (does not stall on body).
        let code_resp = post("/code", "url=http%3A%2F%2F127.0.0.1%2F%3Fcode%3Dabc");
        assert!(code_resp.starts_with("HTTP/1.1 303"));
        assert!(get("/").contains("GOOGLE_CLIENT_ID"));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn finishes_a_move_cut_short_by_a_crash() {
        let (sh, root) = setup("crash", Policy::Skip);
        // Copy landed, original not yet deleted, no "move" line.
        let from = put(&root, "a.jpg", "photo");
        let to = root.join("library/2024/02/a.jpg");
        fs::create_dir_all(to.parent().unwrap()).unwrap();
        fs::write(&to, "photo").unwrap();
        sh.record(json!({"kind": "intent", "id": "1", "from": from, "to": to}));
        // Old file set aside, new one never placed.
        let lost = root.join("library/2024/02/b.jpg");
        fs::create_dir_all(sh.data.join("replaced")).unwrap();
        fs::write(sh.data.join("replaced/2"), "old").unwrap();
        sh.record(json!({"kind": "intent", "id": "2", "from": root.join("inbox/b.jpg"), "to": lost}));

        sh.recover();
        assert!(!from.exists());
        assert_eq!(sh.state().moves.len(), 1);
        assert_eq!(sh.pending().len(), 1, "the photo still goes to Google");
        assert_eq!(fs::read_to_string(&lost).unwrap(), "old");
        sh.recover();
        assert_eq!(sh.state().moves.len(), 1, "a second start changes nothing");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rollback_is_recorded_when_the_old_file_cannot_come_back() {
        let (sh, root) = setup("half", Policy::Overwrite);
        put(&root, "a.jpg", "old");
        run(&sh, &mut HashSet::new());
        put(&root, "a.jpg", "new");
        run(&sh, &mut HashSet::new());
        let id = sh.state().moves[1]["id"].as_str().unwrap().to_string();
        // A folder in place of the stashed file makes the restore fail.
        let stash = sh.data.join("replaced").join(&id);
        fs::remove_file(&stash).unwrap();
        fs::create_dir(&stash).unwrap();
        assert!(sh.rollback(&id).unwrap_err().contains("replaced file stays"));
        assert!(sh.state().rolled.contains(&id), "the scan holds the file");
        run(&sh, &mut HashSet::new());
        assert!(root.join("inbox/a.jpg").exists());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn failed_overwrite_aborts_intent_and_preserves_target() {
        let (sh, root) = setup("abort", Policy::Overwrite);
        let first = put(&root, "a.jpg", "old");
        let dir = month_dir(&root, &first);
        run(&sh, &mut HashSet::new());
        // Block `data/replaced` by placing a regular file where the directory must be created.
        fs::write(sh.data.join("replaced"), "blocker").unwrap();
        let second = put(&root, "a.jpg", "new");
        let err = file_one(&sh, &second, None, &mut HashSet::new());
        assert!(err.is_err());
        // Original library file stays intact and the failed intent is aborted so recover() won't replay it.
        assert_eq!(fs::read_to_string(dir.join("a.jpg")).unwrap(), "old");
        assert!(sh.events().iter().any(|e| e["kind"] == "abort"));
        let count_before = sh.state().moves.len();
        sh.recover();
        assert_eq!(sh.state().moves.len(), count_before);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn safe_move_preserves_mtime_and_cleans_partial_on_error() {
        let (_, root) = setup("mtime", Policy::Skip);
        let src = put(&root, "old.jpg", "hello");
        let old_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        fs::OpenOptions::new().write(true).open(&src).unwrap().set_modified(old_time).unwrap();
        let dst = root.join("library/old.jpg");
        let (_, bytes) = safe_move(&src, &dst).unwrap();
        assert_eq!(bytes, 5);
        assert_eq!(secs(fs::metadata(&dst).unwrap().modified().unwrap()), 1_600_000_000);

        // Moving a missing source leaves no .partial behind.
        let missing_dst = root.join("library/missing.jpg");
        assert!(safe_move(&root.join("inbox/nope.jpg"), &missing_dst).is_err());
        assert!(!root.join("library/missing.jpg.partial").exists());
        fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn prune_empty_skips_symlinks_and_system_dirs() {
        use std::os::unix::fs::symlink;
        let (_, root) = setup("symlink", Policy::Skip);
        let outside = root.join("outside");
        let outside_empty = outside.join("empty");
        fs::create_dir_all(&outside_empty).unwrap();
        fs::create_dir_all(root.join("inbox/@eaDir")).unwrap();
        fs::create_dir_all(root.join("inbox/normal_empty")).unwrap();
        symlink(&outside, root.join("inbox/link")).unwrap();

        prune_empty(&root.join("inbox"), &root.join("inbox"));
        assert!(outside_empty.exists(), "must not delete empty dirs through symlink");
        assert!(root.join("inbox/@eaDir").exists(), "must not touch Synology system dirs");
        assert!(!root.join("inbox/normal_empty").exists());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn prune_keeps_active_holds_and_referenced_uploads() {
        let (sh, root) = setup("prune_keep", Policy::Skip);
        let journal = root.join("data").join(JOURNAL);
        fs::write(
            &journal,
            concat!(
                "{\"kind\":\"upload\",\"id\":\"old_u\",\"hash\":\"h_shared\",\"t\":10}\n",
                "{\"kind\":\"rollback\",\"id\":\"old_r\",\"hash\":\"h_held\",\"size\":42,\"t\":20}\n",
                "{\"kind\":\"move\",\"id\":\"new_m\",\"hash\":\"h_shared\",\"t\":5000}\n",
            ),
        )
        .unwrap();
        fs::create_dir_all(sh.data.join("replaced")).unwrap();
        fs::write(sh.data.join("replaced/new_m"), "keep_me").unwrap();
        fs::write(sh.data.join("replaced/stale_id"), "drop_me").unwrap();

        sh.prune(100).unwrap();
        let st = sh.state();
        assert_eq!(st.moves.len(), 1);
        assert!(st.uploaded.contains("h_shared"), "upload record kept for surviving move");
        assert_eq!(st.held, vec![("h_held".into(), 42)], "unreleased rollback hold kept");
        assert!(sh.data.join("replaced/new_m").exists());
        assert!(!sh.data.join("replaced/stale_id").exists());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn sidecars_handle_double_ext_late_arrival_and_live_photo() {
        let (sh, root) = setup("sidecar", Policy::Skip);
        let photo = put(&root, "trip/IMG_2.JPG", "photo");
        put(&root, "trip/IMG_2.MOV", "live");
        put(&root, "trip/IMG_2.JPG.xmp", "meta");
        let dir = month_dir(&root, &photo);
        run(&sh, &mut HashSet::new());
        assert!(dir.join("IMG_2.JPG").exists());
        assert!(dir.join("IMG_2.JPG.xmp").exists(), "double-ext sidecar goes with photo, not video");
        // Late-arriving sidecar in a subsequent scan finds its photo's library folder via journal.
        put(&root, "trip/IMG_2.aae", "edits");
        run(&sh, &mut HashSet::new());
        assert!(dir.join("IMG_2.aae").exists());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn batch_results_and_auth_code_fragments() {
        let reply = json!({
            "newMediaItemResults": [
                {"mediaItem": {"id": "m1"}, "status": {}},
                {"status": {"code": 0}},
                {"status": {"code": 8, "message": "Quota exceeded"}},
                {"status": {"code": 3, "message": "Invalid"}},
            ]
        });
        let res = parse_batch_results(&reply, 4);
        assert!(res[0].is_ok() && res[1].is_ok());
        assert!(res[2].as_ref().unwrap_err().overload);
        assert!(!res[3].as_ref().unwrap_err().overload);
        assert_eq!(auth_code("http://127.0.0.1/?code=4%2F0AbC#frag").unwrap(), "4/0AbC");
    }
}
