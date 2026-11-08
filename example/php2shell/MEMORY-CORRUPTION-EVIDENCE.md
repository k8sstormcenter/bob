<!-- Maintainer: Constanze Roedig <constanze.roedig@gmail.com> ; SPDX-License-Identifier: Apache-2.0 -->
# PHP2Shell — proof the RCE is a real session.upload_progress memory corruption

**Question:** is the php2shell exploit genuinely corrupting PHP's heap and gaining code
execution, or is the "RCE" an artifact / a staged path?

**Answer: it is a genuine use-after-free in PHP's `session.upload_progress` handler
(CVE-2026-109618 / CVE-2026-109619).** Proven four independent ways below: a gdb
backtrace catching PHP's own heap-corruption detector in the vulnerable code path;
reproducible code execution on the unpatched build; and two controls (the advisory's
config mitigation, and the real patched release) that each kill the exploit at its first
memory-disclosure primitive. All runs are on a real k3s (build-VM, 64 GB, no in-docker
nesting); each target is a fresh pod with the memory limit raised to 3 Gi so nothing is
groom-starved.

## 0. The advisory (external)
- CVE-2026-109618 / CVE-2026-109619: pre-RINIT **use-after-free** in `session.upload_progress`,
  remote memory disclosure → pre-auth RCE, CVSS 9.2.
- Fixed 2026-10-21 in **PHP 8.4.27 / 8.5.12 / 8.3.36 / 8.2.35**. Interim mitigation:
  `session.upload_progress.enabled=0`.
- Sources: https://sansec.io/research/php2shell · https://www.upwind.io/feed/initial-assessment-php2shell-two-critical-unpatched-php-rces-cve-2026-109618-cve-2026-109619 · https://github.com/RemiPelloux/php-session-upload-progress-uaf

## 1. The target app has no exec path
`example/php2shell/app/{index.php,upload.php,healthz.php}` contain **no** `system`/`exec`/
`shell_exec`/`passthru`/`popen`/`proc_open`/`eval`/backticks. The uploader only stores a file.
So any shell spawned by the apache worker can only come from PHP core, not the application.

## 2. Vulnerable build (php:8.4.26-apache) — gdb SMOKING GUN
gdb attached to the apache worker (pod given `SYS_PTRACE`), break on `system`, catch signals,
then the sealed PoC was driven at the pod. PHP's Zend memory manager detected a corrupted heap
and aborted **inside the upload_progress callback**:

```
Program received signal SIGABRT, Aborted.
#3  zend_mm_panic.constprop ()            from libphp.so   ← Zend heap-corruption detector
#4  _efree.cold ()                        from libphp.so   ← freeing corrupted chunk
#5  php_rshutdown_session_globals ()      from libphp.so
#6  php_session_rfc1867_callback ()       from libphp.so   ← session.upload_progress (the CVE)
#7  rfc1867_post_handler ()               from libphp.so
#8  sapi_handle_post ()
#9  php_default_treat_data ()
#13 php_request_startup ()
#14 php_handler ()                        ← reached pre-RINIT, from a multipart POST
```
`zend_mm_panic` is PHP's internal "heap metadata is corrupt" abort. It fires in
`php_session_rfc1867_callback` → `_efree` — exactly the pre-RINIT UAF the advisory describes.
This is PHP itself reporting its own memory is corrupted; it cannot come from application code.

## 3. Vulnerable build — reproducible code execution
Fresh pod, `/tmp/p2s` removed first. The PoC's leaks succeed (ASLR defeated) and the planted
command runs as the apache worker:
```
stage 1: heap leak … OK
stage 2: libphp leak … OK
stage 3: HTDATA=0x76b2bd6690d8  ZIF=0x76b2bf610370     (live leaked Zend addresses)
# kubectl exec … cat /tmp/p2s  →
uid=33(www-data) gid=33(www-data) groups=33(www-data)   (the planted `id` ran in-container)
```
Reproduced on every run. Note the PoC prints `NOT CONFIRMED / no execution proof` because the
driver is invoked with `--proof-file ''`, which disables the PoC's *own* read-back check — the
command still executes; `/tmp/p2s` is the independent proof.

## 3b. Second, independent PoC — identical corruption
A different public exploit by a different author (`github.com/vitalelele/CVE-2026-109618-PoC`,
pure-stdlib, raw-socket HTTP, unrelated to the sealed driver) was run under gdb against the
same vulnerable pod. It trips the **same** abort at the **same** call site:
```
Program received signal SIGABRT, Aborted.
#3  zend_mm_panic.constprop ()        from libphp.so
#4  _efree.cold ()                    from libphp.so
#5  php_rshutdown_session_globals ()  from libphp.so
#6  php_session_rfc1867_callback ()   from libphp.so   ← same session.upload_progress UAF
#7  rfc1867_post_handler ()           from libphp.so
```
Two independent exploits converging on the identical `zend_mm_panic` in
`php_session_rfc1867_callback` rules out a quirk of any one PoC.

## 4. Control A — advisory mitigation (same 8.4.26, `upload_progress.enabled=Off`)
Identical image and config, only the vulnerable surface disabled:
```
session.upload_progress.enabled => Off
stage 1: heap leak … MISSED (×3)      ← the memory-disclosure primitive is gone
RESULT: NOT CONFIRMED ; /tmp/p2s: <none>
```
The exploit dies at its first primitive the moment the upload_progress surface is removed.

## 5. Control B — the real patch (php:8.4.27-apache, verified `php -v` = 8.4.27)
Same image recipe, base bumped to the fixed release (digest-pinned FROM corrected, `php -v`
gated to 8.4.27 before the run), `SYS_PTRACE` + gdb attached:
```
server reports PHP 8.4.27
stage 1: heap leak … MISSED (×3)
gdb: no SIGABRT, no zend_mm_panic, no system() — worker never corrupted
RESULT: NOT CONFIRMED ; /tmp/p2s: <none>
```
On the patched release the same exploit cannot even leak; no corruption, no abort, no RCE.

## Conclusion
| build / config | heap leak | zend_mm_panic (gdb) | code exec `/tmp/p2s` |
| --- | --- | --- | --- |
| 8.4.26, upload_progress **On** (vulnerable) | **OK** | **yes — in `php_session_rfc1867_callback`** | **`uid=33`** |
| 8.4.26, upload_progress **Off** (mitigated) | missed | — | none |
| 8.4.27 (patched) | missed | none | none |

The RCE is a genuine use-after-free in `session.upload_progress` (CVE-2026-109618/109619):
PHP's own heap-corruption detector fires in that callback on the vulnerable build, the planted
command executes in-container, and both removing the surface and applying the real patch stop
it at the first memory read. It is not a backdoor, a staged path, or a test artifact.
