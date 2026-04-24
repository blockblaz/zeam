# liblmdb upstream snapshot

These files are vendored verbatim from the OpenLDAP `mdb.master` branch of
LMDB (maintained by Howard Chu / Symas) via the GitHub mirror.

* Source: https://github.com/LMDB/lmdb/tree/mdb.master/libraries/liblmdb
* Pinned commit: `40d3741b7d40ba4c75cb91dd9987ce692d376d71` (2026-01-13)
* License: OpenLDAP Public License v2.8 — see `LICENSE`

## What is vendored

| File     | Purpose |
| -------- | ------- |
| `lmdb.h` | Public C API header. |
| `midl.h` | Internal ID-list header used by `mdb.c`. |
| `mdb.c`  | The database engine. |
| `midl.c` | ID-list helpers used by `mdb.c`. |

## Updating

1. Re-clone upstream: `git clone --depth=1 --branch mdb.master https://github.com/LMDB/lmdb.git`
2. Overwrite the four files above with the new revisions.
3. Update the pinned commit hash at the top of this file.
4. Run `zig build test --summary all` to make sure nothing regressed.

## Local modifications

None. The files are committed verbatim; do not patch them in place. If a
change is needed for zeam, open an issue upstream and either pin a fork or
apply the change via `build.zig` CFLAGS / `-D` defines rather than editing
the vendored C.
