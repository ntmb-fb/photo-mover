# Photo Mover

Ingests photos from a source into an organized library and mirrors them to Google Photos. Runs in Docker on a NAS, driven from a web interface.

## Language

**Inbox**:
The watched folder photos arrive in. Replaces the idea of a user-picked Source.
_Avoid_: Source, input, watch folder

**Library**:
The organized photo tree on the NAS, laid out as `YYYY/MM/<filename>` by capture date.
_Avoid_: Archive, destination

**Session**:
The awake period between a wake call and the next Sleep. Carries its own Overwrite policy.
_Avoid_: Job, run, batch

**Overwrite policy**:
A per-Session setting for a file whose name exists in the Library with different content: `skip` (leave it in the Inbox, default), `overwrite` (replace, stashing the old file), or `keep` (store both, with a suffix). Identical content is always skipped and removed from the Inbox.
_Avoid_: Conflict mode

**Capture date**:
When the photo was taken: EXIF `DateTimeOriginal`, else file modification time.
_Avoid_: Photo date, timestamp

**Move**:
Copy to the Library, verify, then delete from the Inbox.
_Avoid_: Transfer, rename

**Upload**:
Sending a Library photo to Google Photos after its Move succeeded. Never deletes anything.
_Avoid_: Sync, backup

**Transaction**:
One logged Move or Upload of a single file, with enough detail to be rolled back.
_Avoid_: Operation, event

**Rollback**:
Undoing a Move by restoring the file from the Library to its original Inbox path (suffixed if taken), and restoring any Replaced file. Possible only within the log retention window.
_Avoid_: Undo, revert

**Sleep**:
Idle state after a timeout with no activity, where the Inbox is not scanned until woken by a call.
_Avoid_: Pause, stop

**Replaced file**:
A Library file displaced by the `overwrite` policy, stashed so Rollback can restore it.
_Avoid_: Backup, trash
