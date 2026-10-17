# photo-mover

Watches an inbox folder and moves each photo into a library by capture date, then uploads photos to Google Photos. Videos go to their own library (`VIDEO_LIBRARY`) with the same layout.

- Library path: `<year>/<month>/<filename>`. The date is EXIF `DateTimeOriginal`, else the file's modification time.
- Moved: `jpg jpeg png heic`, `cr2 cr3 nef arw dng orf rw2 raf`, `mp4 mov m4v avi mkv 3gp`, and `xmp aae` sidecars (next to their photo). Other files stay in the inbox.
- A move copies, reads the copy back, compares SHA-256, and only then deletes the original. It runs at lowest CPU and disk priority, one file at a time.
- Same name, same content: the inbox copy is removed. Same name, other content follows the clash setting: `skip` (leave it, default), `overwrite` (old file is kept for rollback), `keep` (`name-1.jpg`).
- Only `jpg jpeg png heic` go to Google Photos, from the library copy after the move. An upload never deletes anything. Uploads run in parallel batches of up to 50 photos: 4 at a time at first, one more after a clean round (up to 8), half as many when Google answers 429 or 5xx.
- Every move, upload and rollback is a line in `transactions.jsonl`. `/rollback/<id>` puts the file back in the inbox and restores a replaced file. A rolled-back file is ignored by the watcher until `/release`. Google Photos keeps the photo.
- The service sleeps after `IDLE_MINUTES` without activity. Any call except `/` and `/favicon.ico` wakes it.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `INBOX` | `/inbox` | Folder to watch (subfolders too) |
| `LIBRARY` | `/library` | Photo library |
| `VIDEO_LIBRARY` | same as `LIBRARY` | Where videos go, same `YYYY/MM` layout |
| `INTERVAL` | `30` | Seconds between scans. A value set with `/interval/<s>` wins after that |
| `IDLE_MINUTES` | `60` | Fall asleep after this long with nothing new. `0`: never |
| `OVERWRITE` | `skip` | Clash setting at each wake: `skip`, `overwrite`, `keep` |
| `PORT` | `8768` | Port of the control page |
| `LOG_DIR` | `/data` | Log, transactions, replaced files, Google token |
| `LOG_DAYS` | `60` | Days a log line, transaction or replaced file is kept. Rollback works this long |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | empty | OAuth client. Empty: no uploads |

## Calls

`/start`, `/stop`, `/interval/30`, `/overwrite/keep`, `/rollback/<id>`, `/release`, `/upload/retry`. The page has no password: do not expose it to the internet.

## Google Photos

1. Cloud console: enable the Photos Library API, create an OAuth client of type **Desktop app**, and set the consent screen to **In production** (in Testing, refresh tokens expire after 7 days).
2. Put the ID and secret in `compose.yaml`.
3. Open the page, click *Approve access*, accept the "not verified" warning. The next page will not load: paste its address into the box. This is done once.
