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

fn es(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('"', "&quot;")
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
        return Some(pasted.to_string()).filter(|c| !c.is_empty() && !c.contains('='));
    };
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
    /// Seconds since 1970 when the service falls asleep; 0 is never.
    sleep_at: AtomicU64,
    interval: AtomicU64,
    /// Last Move or Upload, so the idle timer sees the upload worker too.
    last_active: AtomicU64,
    /// Counts /upload/retry calls; the upload worker drops its backoff when it changes.
    retry_gen: AtomicU64,
    /// Held while a file is moved or rolled back.
    busy: Mutex<()>,
    /// Held while the journal is read or written.
    file: Mutex<()>,
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
            sleep_at: AtomicU64::new(0),
            interval: AtomicU64::new(30),
            last_active: AtomicU64::new(unix_now()),
            retry_gen: AtomicU64::new(0),
            busy: Mutex::new(()),
            file: Mutex::new(()),
            access: Mutex::new(None),
            client,
            // Uploads of large photos take longer than a page request.
            agent: ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(300)))
                .build()
                .into(),
        }
    }

    fn policy(&self) -> Policy {
        [Policy::Skip, Policy::Overwrite, Policy::Keep][self.policy.load(Relaxed) as usize]
    }

    /// To stdout (the container log) and to the log file.
    fn log(&self, line: String) {
        println!("{line}");
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
    fn prune(&self, oldest: u64) -> io::Result<()> {
        let _guard = self.file.lock().unwrap();
        let journal = self.data.join(JOURNAL);
        if let Ok(text) = fs::read_to_string(&journal) {
            let kept: String = text
                .split_inclusive('\n')
                .filter(|l| {
                    let t = serde_json::from_str::<Value>(l).ok().and_then(|e| e["t"].as_u64());
                    t.is_none_or(|t| t >= oldest)
                })
                .collect();
            rewrite(&journal, &kept, text.len())?;
        }
        let log = self.data.join(LOG_FILE);
        if let Ok(text) = fs::read_to_string(&log) {
            let oldest = timestamp(oldest);
            let kept: String = text
                .split_inclusive('\n')
                .filter(|l| *l >= oldest.as_str())
                .collect();
            rewrite(&log, &kept, text.len())?;
        }
        for entry in fs::read_dir(self.data.join("replaced")).into_iter().flatten().flatten() {
            let old = entry.metadata().and_then(|m| m.modified()).map(secs);
            if old.is_ok_and(|t| t < oldest) {
                let _ = fs::remove_file(entry.path());
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

/// Copy `from` to `to` in chunks, hashing on the way; returns the hash of what was read.
fn copy_hashed(from: &Path, to: &Path) -> io::Result<String> {
    let (mut src, mut dst) = (fs::File::open(from)?, fs::File::create(to)?);
    let (mut hasher, mut buf) = (Sha256::new(), vec![0; CHUNK]);
    loop {
        match src.read(&mut buf)? {
            0 => break,
            n => {
                hasher.update(&buf[..n]);
                dst.write_all(&buf[..n])?;
            }
        }
    }
    dst.sync_all()?;
    Ok(hex(&hasher.finalize()))
}

/// Copy, read the copy back and compare, and only then delete the original.
fn safe_move(from: &Path, to: &Path) -> io::Result<String> {
    // Copy under a temporary name: a half-written file never has its final name.
    let mut partial = to.as_os_str().to_owned();
    partial.push(".partial");
    let partial = PathBuf::from(partial);
    let hash = copy_hashed(from, &partial)?;
    if hash_file(&partial)? != hash {
        let _ = fs::remove_file(&partial);
        return Err(io::Error::other("copy does not match the original"));
    }
    fs::rename(&partial, to)?;
    fs::remove_file(from)?;
    Ok(hash)
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
    let id = format!("{:x}", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_nanos());
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
    if replaced {
        let stash = sh.data.join("replaced");
        fs::create_dir_all(&stash)?;
        safe_move(&target, &stash.join(&id))?;
    }
    let hash = safe_move(path, &target)?;
    sh.record(json!({
        "kind": "move", "id": id, "from": path, "to": target,
        "hash": hash, "size": meta.len(), "replaced": replaced,
    }));
    sh.touch();
    sh.log(format!("{}: moved to {}{}", path.display(), target.display(), if replaced { " (replaced the old file)" } else { "" }));
    Ok(Some(dir))
}

type Seen = HashMap<PathBuf, (u64, SystemTime)>;

/// All regular files under `p`. Symlinks are not followed, hidden and system folders are skipped.
fn walk(p: &Path, out: &mut Vec<(PathBuf, fs::Metadata)>) -> io::Result<()> {
    for entry in fs::read_dir(p)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        // @eaDir and #recycle are Synology's own folders.
        if [".", "@", "#"].iter().any(|c| name.starts_with(c)) || name.ends_with(".partial") {
            continue;
        }
        let meta = fs::symlink_metadata(entry.path())?;
        if meta.is_dir() {
            walk(&entry.path(), out)?;
        } else if meta.is_file() {
            out.push((entry.path(), meta));
        }
    }
    Ok(())
}

/// Remove folders under `root` that are empty, deepest first.
fn prune_empty(dir: &Path, root: &Path) {
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        if entry.path().is_dir() {
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
    // Sidecars last: they go where their photo went.
    ready.sort_by_key(|(p, _)| SIDECAR.contains(&ext(p).as_str()));
    let mut homes: HashMap<(PathBuf, String), PathBuf> = HashMap::new();
    let mut moved = false;
    for (path, size) in ready {
        let _busy = sh.busy.lock().unwrap();
        let held = state.held.iter().any(|(hash, s)| *s == size && hash_file(&path).is_ok_and(|h| &h == hash));
        if held {
            continue;
        }
        let key = (path.parent().unwrap_or(Path::new("")).to_path_buf(), stem(&path).to_lowercase());
        let sidecar = SIDECAR.contains(&ext(&path).as_str());
        if sidecar && !homes.contains_key(&key) {
            continue;
        }
        match file_one(sh, &path, homes.get(&key).cloned().filter(|_| sidecar), noted) {
            Ok(Some(dir)) => {
                homes.insert(key, dir);
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

    fn access_token(&self) -> Result<String, String> {
        let mut cache = self.access.lock().unwrap();
        if let Some((token, expires)) = &*cache
            && *expires > unix_now() + 60
        {
            return Ok(token.clone());
        }
        let (id, secret) = self.client.as_ref().ok_or("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are not set")?;
        let saved = fs::read_to_string(self.data.join(GOOGLE)).map_err(|_| "Google is not connected")?;
        let saved: Value = serde_json::from_str(&saved).map_err(es)?;
        let refresh = saved["refresh_token"].as_str().ok_or("no refresh token saved")?;
        let reply: Value = self
            .agent
            .post(TOKEN_URL)
            .send_form([
                ("client_id", id.as_str()),
                ("client_secret", secret.as_str()),
                ("refresh_token", refresh),
                ("grant_type", "refresh_token"),
            ])
            .map_err(es)?
            .body_mut()
            .read_json()
            .map_err(es)?;
        let token = reply["access_token"].as_str().ok_or("no access token in the reply")?;
        *cache = Some((token.to_string(), unix_now() + reply["expires_in"].as_u64().unwrap_or(3600)));
        Ok(token.to_string())
    }

    /// Trade the pasted redirect URL for a refresh token and save it.
    fn connect(&self, pasted: &str) -> Result<String, String> {
        let (id, secret) = self.client.as_ref().ok_or("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are not set")?;
        let code = auth_code(pasted).ok_or("no code in what you pasted")?;
        let reply: Value = self
            .agent
            .post(TOKEN_URL)
            .send_form([
                ("code", code.as_str()),
                ("client_id", id.as_str()),
                ("client_secret", secret.as_str()),
                ("redirect_uri", REDIRECT),
                ("grant_type", "authorization_code"),
            ])
            .map_err(es)?
            .body_mut()
            .read_json()
            .map_err(es)?;
        let refresh = reply["refresh_token"].as_str().ok_or("Google sent no refresh token")?;
        fs::write(self.data.join(GOOGLE), json!({"refresh_token": refresh}).to_string()).map_err(es)?;
        *self.access.lock().unwrap() = None;
        self.log("Google connected".into());
        Ok("Google connected.".into())
    }

    /// Send one Library photo's bytes to Google Photos. Returns the upload token.
    fn upload_bytes(&self, path: &Path, auth: &str) -> Result<String, String> {
        let mime = match ext(path).as_str() {
            "png" => "image/png",
            "heic" => "image/heic",
            _ => "image/jpeg",
        };
        // shortcut: the photo is read into memory, fine for photos, upgrade for videos.
        let bytes = fs::read(path).map_err(es)?;
        self.agent
            .post("https://photoslibrary.googleapis.com/v1/uploads")
            .header("Authorization", auth)
            .header("Content-Type", "application/octet-stream")
            .header("X-Goog-Upload-Content-Type", mime)
            .header("X-Goog-Upload-Protocol", "raw")
            .send(&bytes[..])
            .map_err(es)?
            .body_mut()
            .read_to_string()
            .map_err(es)
    }

    /// Add uploaded photos (file name, upload token) to the Google Photos library in one call.
    /// `Err`: the call failed as a whole. Otherwise one result per item, in order.
    fn create_items(&self, items: &[(String, String)], auth: &str) -> Result<Vec<Result<(), String>>, String> {
        let new_items: Vec<Value> = items
            .iter()
            .map(|(name, token)| json!({"simpleMediaItem": {"uploadToken": token, "fileName": name}}))
            .collect();
        let reply: Value = self
            .agent
            .post("https://photoslibrary.googleapis.com/v1/mediaItems:batchCreate")
            .header("Authorization", auth)
            .send_json(json!({ "newMediaItems": new_items }))
            .map_err(es)?
            .body_mut()
            .read_json()
            .map_err(es)?;
        Ok((0..items.len())
            .map(|i| match reply["newMediaItemResults"][i]["status"]["message"].as_str() {
                Some("Success" | "OK") => Ok(()),
                other => Err(format!("Google refused it: {}", other.unwrap_or("no status"))),
            })
            .collect())
    }

    /// Upload the photos on `workers` threads, then add them all in one call. One outcome per photo, in order.
    /// `known[i]` is an upload token from an earlier round: that photo's bytes are not sent again.
    fn upload_round(&self, due: &[Value], known: &[Option<String>], auth: &str, workers: usize, generation: u64) -> Vec<Outcome> {
        let next = AtomicUsize::new(0);
        let sent: Mutex<Vec<Option<Upload>>> = Mutex::new(vec![None; due.len()]);
        thread::scope(|scope| {
            for _ in 0..workers.min(due.len()) {
                scope.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, Relaxed);
                        let Some(m) = due.get(i) else { break };
                        let up = if !self.awake.load(Relaxed) || self.retry_gen.load(Relaxed) != generation {
                            Upload::Stopped
                        } else if let Some(token) = &known[i] {
                            Upload::Sent(token.clone())
                        } else {
                            match self.upload_bytes(Path::new(m["to"].as_str().unwrap_or_default()), auth) {
                                Ok(token) => Upload::Sent(token),
                                Err(e) => Upload::Failed(e),
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
        let created = if items.is_empty() { Ok(Vec::new()) } else { self.create_items(&items, auth) };
        join(uploads, created)
    }
}

/// What happened to one photo's bytes.
#[derive(Clone)]
enum Upload {
    /// Google has the bytes; this is the upload token.
    Sent(String),
    Failed(String),
    /// Not tried: the service went to sleep or /upload/retry was called.
    Stopped,
}

struct Outcome {
    result: Result<(), String>,
    /// Upload token to try again with, when only adding the photo failed.
    token: Option<String>,
    /// false: not tried, so no backoff.
    tried: bool,
}

/// Match the upload step with the add step. `created` has one result per `Sent` photo, in order.
fn join(uploads: Vec<Upload>, created: Result<Vec<Result<(), String>>, String>) -> Vec<Outcome> {
    let mut created = created.map(Vec::into_iter);
    let outcome = |result, token, tried| Outcome { result, token, tried };
    uploads
        .into_iter()
        .map(|u| match u {
            Upload::Stopped => outcome(Err("stopped".into()), None, false),
            Upload::Failed(e) => outcome(Err(e), None, true),
            Upload::Sent(token) => match &mut created {
                Ok(results) => match results.next() {
                    Some(result) => outcome(result, None, true),
                    None => outcome(Err("no result".into()), Some(token), true),
                },
                Err(e) => outcome(Err(e.clone()), Some(token), true),
            },
        })
        .collect()
}

/// Google asks to slow down, or has a problem of its own.
fn overload(e: &str) -> bool {
    e.contains("http status: 429") || e.contains("http status: 5")
}

/// Uploads Library photos a few at a time, slowly backing off from failures.
fn upload_loop(sh: Arc<Shared>) {
    // Move id -> (failures, next try in seconds since 1970).
    let mut failed: HashMap<String, (u32, u64)> = HashMap::new();
    // Move id -> (upload token, when). The bytes are with Google, only adding the photo failed, so a retry
    // skips the upload. Unverified: if the lost add did succeed, Google may refuse the used token, and the
    // retry then uploads the bytes again, which makes a duplicate. Google keeps tokens for a day.
    let mut tokens: HashMap<String, (String, u64)> = HashMap::new();
    let mut retry_gen = 0;
    let mut workers = START_WORKERS;
    loop {
        // One pause per round, not per photo: a backlog goes out without waiting between files.
        thread::sleep(Duration::from_secs(5));
        if retry_gen != sh.retry_gen.load(Relaxed) {
            retry_gen = sh.retry_gen.load(Relaxed);
            failed.clear();
        }
        if !sh.awake.load(Relaxed) || !sh.connected() {
            continue;
        }
        // The journal is read once per round, not once per photo.
        let due: Vec<Value> = sh
            .pending()
            .into_iter()
            .filter(|m| !failed.get(m["id"].as_str().unwrap_or_default()).is_some_and(|(_, next)| *next > unix_now()))
            .take(BATCH)
            .collect();
        if due.is_empty() {
            continue;
        }
        let known: Vec<Option<String>> = due
            .iter()
            .map(|m| tokens.get(m["id"].as_str().unwrap_or_default()))
            .map(|t| t.filter(|(_, when)| unix_now() < when + 20 * 3600).map(|(token, _)| token.clone()))
            .collect();
        let outcomes = match sh.access_token() {
            Ok(token) => sh.upload_round(&due, &known, &format!("Bearer {token}"), workers, retry_gen),
            Err(e) => due.iter().map(|_| Outcome { result: Err(e.clone()), token: None, tried: true }).collect(),
        };
        // Google pushes back: halve. A clean round: one more.
        let overloaded = outcomes.iter().any(|o| o.result.as_ref().err().is_some_and(|e| overload(e)));
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
                Some(token) => tokens.insert(id.clone(), (token, unix_now())),
                None => tokens.remove(&id),
            };
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
                    sh.log(format!("{}: upload failed ({e}), next try in {wait}s", to.display()));
                    failed.insert(id, (tries, unix_now() + wait));
                }
            }
        }
        if overloaded {
            sh.log("Google pushed back, pausing uploads for 60s".into());
            thread::sleep(Duration::from_secs(60));
        }
    }
}

fn page(sh: &Shared, note: &str) -> String {
    let left = sh.sleep_at.load(Relaxed).saturating_sub(unix_now()).div_ceil(60);
    let state = match (sh.awake.load(Relaxed), sh.sleep_at.load(Relaxed)) {
        (false, _) => "Asleep.".to_string(),
        (true, 0) => "Awake.".to_string(),
        (true, _) => format!("Awake. Sleeps in {left} min if nothing new arrives."),
    };
    let google = if sh.connected() {
        format!("Google Photos connected, {} photo(s) waiting for upload (<a href=/upload/retry>retry now</a>).", sh.pending().len())
    } else if let Some((id, _)) = &sh.client {
        let url = format!(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline&prompt=consent",
            enc(id), enc(REDIRECT), enc(SCOPE)
        );
        format!(
            "Google Photos not connected. <a href=\"{}\" target=_blank>Approve access</a>, the next page will not load: \
             paste its address here. <form action=/code><input name=url size=60><button>Connect</button></form>",
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
            let undo = if st.rolled.contains(id) { "rolled back".into() } else { format!("<a href=/rollback/{id}>rollback</a>") };
            format!("{} {} {undo}\n", esc(m["to"].as_str().unwrap_or_default()), if st.uploaded.contains(m["hash"].as_str().unwrap_or_default()) { "(on Google)" } else { "" })
        })
        .collect();
    let log = fs::read_to_string(sh.data.join(LOG_FILE)).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    let recent = esc(&lines[lines.len().saturating_sub(20)..].join("\n"));
    let policy = |p: Policy| if sh.policy() == p { format!("<b>{}</b>", p.name()) } else { format!("<a href=/overwrite/{0}>{0}</a>", p.name()) };
    format!(
        "<!doctype html><meta name=viewport content='width=device-width'><title>photo-mover</title><h1>photo-mover</h1>\
         <p>{note}</p><p>{state} Scans every {}s (<a href=/interval/5>5</a> | <a href=/interval/30>30</a> | <a href=/interval/300>300</a>). \
         Name clash with other content: {} | {} | {}.</p>\
         <p><a href=/start>Start</a> | <a href=/stop>Stop</a> | <a href=/release>Release held files</a> | <a href=/>Refresh</a></p>\
         <p>{google}</p><h3>Moves</h3><pre>{moves}</pre><h3>Log</h3><pre>{recent}</pre>",
        sh.interval.load(Relaxed),
        policy(Policy::Skip),
        policy(Policy::Overwrite),
        policy(Policy::Keep),
        note = esc(note),
    )
}

/// Answer one request. Every path but / and /favicon.ico also wakes a sleeping service.
fn answer(mut stream: TcpStream, sh: &Shared) -> io::Result<()> {
    // A client that says nothing must not block the next one for long.
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    // Read the whole header: closing with unread data would reset the connection.
    let mut request = Vec::new();
    let mut chunk = [0; 1024];
    while !request.ends_with(b"\r\n\r\n") && request.len() < 16 * 1024 {
        match stream.read(&mut chunk)? {
            0 => break,
            read => request.extend_from_slice(&chunk[..read]),
        }
    }
    let request = String::from_utf8_lossy(&request);
    let path = request.split_whitespace().nth(1).unwrap_or("/");
    if path != "/" && path != "/favicon.ico" && !sh.awake.load(Relaxed) {
        sh.awake.store(true, Relaxed);
    }
    let mut note = String::new();
    if path == "/stop" {
        sh.awake.store(false, Relaxed);
    } else if let Some(seconds) = path.strip_prefix("/interval/").and_then(|s| s.parse::<u64>().ok()).filter(|s| *s > 0) {
        sh.interval.store(seconds, Relaxed);
        let _ = fs::write(sh.data.join(INTERVAL_FILE), seconds.to_string());
    } else if let Some(policy) = path.strip_prefix("/overwrite/").and_then(Policy::parse) {
        sh.policy.store(policy as u8, Relaxed);
        sh.log(format!("name clashes: {}", policy.name()));
    } else if let Some(id) = path.strip_prefix("/rollback/") {
        note = sh.rollback(id).unwrap_or_else(|e| format!("rollback failed: {e}"));
    } else if path == "/release" {
        sh.record(json!({"kind": "release"}));
        note = "Rolled-back files will be moved again.".into();
    } else if path == "/upload/retry" {
        sh.retry_gen.fetch_add(1, Relaxed);
    } else if let Some(pasted) = path.strip_prefix("/code?url=") {
        note = sh.connect(&unescape(pasted)).unwrap_or_else(|e| format!("connect failed: {e}"));
    }
    let page = page(sh, &note);
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{page}",
        page.len()
    )
}

fn main() {
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
    let (log_days, port) = (number("LOG_DAYS", 60), number("PORT", 8768) as u16);
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
                    let _ = answer(stream, &sh);
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
    {
        let sh = sh.clone();
        thread::spawn(move || upload_loop(sh));
    }
    be_nice();

    // shortcut: a manual copy that stalls longer than INTERVAL looks finished,
    // raise INTERVAL if a hand-copied photo ever arrives cut short.
    let (mut seen, mut noted) = (Seen::new(), HashSet::new());
    let (mut pruned_day, mut was_awake) = (String::new(), false);
    loop {
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
            sh.touch();
            sh.last_active.store(unix_now(), Relaxed);
            // After a sleep every file has to prove again that it is finished.
            seen.clear();
            noted.clear();
            if awake {
                sh.policy.store(sh.default_policy as u8, Relaxed);
            }
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
        // In steps of a second, so a start or stop is noticed at once.
        for _ in 0..sh.interval.load(Relaxed) {
            if !sh.awake.load(Relaxed) {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
    }
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
        let uploads = || vec![Upload::Sent("a".into()), Upload::Failed("x".into()), Upload::Sent("b".into()), Upload::Stopped, Upload::Sent("c".into())];
        let out = join(uploads(), Ok(vec![Ok(()), Err("refused".into()), Ok(())]));
        assert!(out[0].result.is_ok() && out[4].result.is_ok());
        assert_eq!(out[1].result, Err("x".to_string()));
        assert_eq!((out[2].result.clone(), out[2].token.clone()), (Err("refused".to_string()), None));
        assert!(!out[3].tried);
        // The add call failed as a whole: the photos that were sent keep their token.
        let out = join(uploads(), Err("timeout".into()));
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
    fn page_wakes_on_calls_but_not_on_the_front_page() {
        let (sh, root) = setup("page", Policy::Skip);
        let sh = Arc::new(sh);
        sh.awake.store(false, Relaxed);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let served = sh.clone();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = answer(stream, &served);
            }
        });
        let get = |path: &str| {
            let mut stream = TcpStream::connect(address).unwrap();
            write!(stream, "GET {path} HTTP/1.1\r\n\r\n").unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).unwrap();
            reply
        };
        assert!(get("/").contains("Asleep.") && !sh.awake.load(Relaxed));
        assert!(get("/favicon.ico").contains("Asleep."));
        assert!(get("/interval/7").contains("Awake.") && sh.awake.load(Relaxed));
        assert!(get("/stop").contains("Asleep."));
        get("/overwrite/keep");
        assert_eq!(sh.policy(), Policy::Keep);
        get("/interval/0");
        assert_eq!(sh.interval.load(Relaxed), 7);
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
}
