# SENTINEL analyzer execution boundary

## What is enforced

The Node server does not parse PDFs, DOCX packages, or PE files inside the Express process. Python analyzers are launched as named, repository-owned scripts in a separate process. The launcher:

- resolves the analyzer directory relative to its own module rather than the caller's working directory;
- permits only `analyze_pdf.py`, `analyze_docx.py`, and `analyze_exe.py`;
- uses argument arrays with `shell: false`;
- supplies a deliberately small environment rather than forwarding application secrets;
- requires Linux `prlimit` by default and applies `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE`, and `RLIMIT_CORE`;
- starts a separate process group on POSIX and kills that group on wall-time or stdout-limit violations;
- bounds stdout and stderr and accepts exactly one JSON document, rather than extracting a JSON-looking substring from arbitrary logs;
- maps timeout, process failure, oversized output, invalid JSON, and unavailable resource limiting to analyzer failure. The orchestration layer must keep those states review-required.

Default Python analyzer limits are 1.5 GiB address space, CPU time no greater than the configured wall timeout (up to 60 seconds), 16 MiB maximum file size per generated file, 64 open descriptors, 2 MiB stdout, and a bounded stderr tail. Individual analyzer timeouts are still configured by the calling service.

ClamAV is also launched as a bounded process. On Linux it requires a trusted `clamscan` path and `prlimit`, applies a 3 GiB address-space cap, a 120-second CPU cap, a 16 MiB generated-file cap, 128 file descriptors, a 120-second wall timeout, and a 64 KiB stdout cap. Missing tools, timeouts, abnormal exits, and output overflow do not become clean results.

## ZIP archive armor and bounded recursive inspection

`inspectZipArchive` validates EOCD and central-directory bounds, entry counts, ZIP64/multi-disk limitations, local-header signatures and bounds, local/central filename and CRC/size agreement, portable entry paths, duplicate names, encryption, symlink entries, alternate Unicode path metadata, compression-ratio metadata, and aggregate declared expansion size.

The recursive worker streams each supported member into a uniquely named file in SENTINEL's RAM vault; it never uses an archive-provided path as a filesystem destination. It supports stored and DEFLATE entries, enforces both declared and actual per-entry/aggregate expansion budgets, verifies decoded byte counts and CRC-32, runs ClamAV on extracted members, dispatches PDF and PE files to the existing structural analyzers, dispatches DOCX/DOCM packages to the existing OOXML analyzer, and recursively inspects nested ZIPs. Each member produces an individual coverage result, including failures and unsupported entries.

Limits are currently depth 3, 2,000 members across the recursive traversal, 10 MiB decoded per member, 50 MiB decoded across the traversal, a 10:1 compression-ratio ceiling, 10,000 entries in a single central directory, and a 16 MiB central-directory inspection cap. ZIP64, multi-disk archives, encrypted members, unsupported compression methods, malformed headers, CRC mismatches, and exhausted budgets remain explicit findings or coverage gaps. A recursive archive scan is not considered complete if any member could not be inspected.

The worker does not extract to user-controlled paths and does not execute archived files. It does not claim to inspect every file format: members other than ZIP, PDF, PE, and DOCX/DOCM receive the ClamAV pass only. Full XML/OOXML subpart semantics, ELF internals, RAR/7z support, and PDF embedded-file extraction remain separate work.

## Important boundary and limitations

`prlimit` enforces process resource limits; it is not a complete sandbox. It does not create a separate mount/network namespace, block network access, or prevent access to every file readable by the service account. For production use with hostile inputs, run SENTINEL under a dedicated unprivileged account and add an OS/container sandbox (for example, bubblewrap with a read-only runtime and only the required input/output mounts, or an equivalent hardened worker service). Do not describe this stage as full isolation or as proof of zero disk writes.

On non-Linux platforms, resource limits are not silently substituted. Analyzer execution is unavailable by default unless `SENTINEL_ALLOW_UNSANDBOXED_ANALYZERS=1` is explicitly set for a development environment. This override accepts weaker process containment and must not be used for hostile uploads in production.

## Tests

The server test suite includes process-boundary tests for valid JSON, mixed output, timeout termination, output overflow, missing resource-limit refusal, and script allowlisting; ZIP fixtures cover a valid archive, path traversal, compression-ratio/aggregate expansion metadata, encrypted entries, symlink entries, truncated EOCD, and malformed local headers. These tests validate the implemented metadata and process-boundary behaviors; they are not a fuzz campaign and do not replace testing inside a real OS sandbox.
