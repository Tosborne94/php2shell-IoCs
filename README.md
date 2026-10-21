# PHP2Shell IoCs — CVE-2026-109618 / CVE-2026-109619

**Status:** Detection leads, not vendor-confirmed IoCs. No confirmed in-the-wild activity or official advisory at time of writing. Don't rely on the `PHP_SESSION_UPLOAD_PROGRESS` field name alone (suspected multipart-parser path). Re-baseline when the patch/advisory lands.

## Logs (host) — verified by lab repro, highest confidence
- `Allowed memory size of <N> bytes exhausted (tried to allocate <N> bytes) in Unknown on line 0` — match **any** byte count
- LiteSpeed: same line in `/usr/local/lsws/logs/error.log` as `[STDERR] PHP Fatal error: ...`, request returns **HTTP 500**
- Multipart limit warnings (alert on several together, field-independent): `Multipart body parts limit exceeded`, `Maximum number of allowable file uploads has been exceeded`, `Input variables exceeded`, `POST Content-Length ... exceeds the limit`, `File Upload Mime headers garbled`
- Worker crashes after multipart POSTs: `Segmentation fault`, `zend_mm_heap corrupted`

## Host artifacts
- `sess_*` files containing `upload_progress_` immediately followed by `<?php` / `<?=` / `<script language="php">` (session poisoning)
- Leftover `upload_progress_*|a:5:{` session entries (cleanup normally removes these)
- Burst of `phpXXXXXX` temp files created/unlinked in `upload_tmp_dir` (`/tmp`) during these POSTs

## Process creation — post-exploitation
- PHP worker (`php-fpm`, `php-cgi`, `apache2`, `httpd`, `lsphp`, `frankenphp`) spawning `sh` / `bash` / `python` / `perl` / `curl` / `wget` / `nc`
- `execve` by `euid=33` (www-data)
- Command lines containing `/dev/tcp/`, `fsockopen`, `mkfifo`; recon `id`, `whoami`, `uname -a`

## Network — request shape (field-name-independent; baseline before alerting)
- Multipart POST with high part count / ≥20 file parts / repeated `name="x[]"` fields
- Oversized `Content-Disposition` filenames (~256 KB)
- `PHP_SESSION_UPLOAD_PROGRESS` field whose **value** contains `<?php` / `<?=` (poisoning — malicious)
- Mid-stream stall (slow body) within one connection

## PoC literals — high fidelity, trivially changed
- User-Agent `php2shell-109618` / `php2shell-109619`
- Multipart boundary `B7kQpoc618` / `B7kQpoc619`
- `JACKALPOC` or `uid=` in a **response** body = command ran
