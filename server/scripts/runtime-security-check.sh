#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
FAILURES=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1" >&2; FAILURES=$((FAILURES + 1)); }
need() { command -v "$1" >/dev/null 2>&1; }

printf 'SENTINEL runtime security calibration\n'
printf 'Server directory: %s\n\n' "$ROOT"

if [[ "$(uname -s)" != Linux ]]; then fail 'Linux host required for strict worker isolation'; else pass 'Linux host'; fi
if need findmnt && [[ "$(findmnt -n -o FSTYPE --target /dev/shm 2>/dev/null || true)" == tmpfs ]]; then pass '/dev/shm is mounted as tmpfs'; else fail '/dev/shm is not confirmed tmpfs'; fi
if need prlimit; then pass 'prlimit available'; else fail 'prlimit missing'; fi
if need bwrap; then pass 'bubblewrap executable available'; else fail 'bubblewrap missing; strict archive worker must not be used'; fi
if need clamscan; then pass 'ClamAV clamscan available'; else fail 'ClamAV clamscan missing'; fi

if need bwrap && need node; then
  host_net="$(stat -Lc '%i' /proc/self/ns/net 2>/dev/null || true)"
  args=(--die-with-parent --new-session --unshare-all --ro-bind / / --proc /proc --dev /dev --tmpfs /tmp -- node -e 'process.stdout.write(require("node:fs").statSync("/proc/self/ns/net").ino.toString())')
  if child_net="$(bwrap "${args[@]}" 2>/dev/null)" && [[ -n "$host_net" && -n "$child_net" && "$host_net" != "$child_net" ]]; then
    pass 'bubblewrap creates a distinct network namespace'
  else
    fail 'bubblewrap namespace probe failed (kernel/user namespace policy may prohibit it)'
  fi
fi

if need clamscan; then
  if [[ "${SENTINEL_UPDATE_CLAMAV_DB:-0}" == 1 ]]; then
    if need freshclam; then
      if freshclam; then pass 'freshclam signature database update'; else fail 'freshclam update failed'; fi
    else
      fail 'SENTINEL_UPDATE_CLAMAV_DB=1 but freshclam is unavailable'
    fi
  fi

  vault="/dev/shm/sentinel-runtime-calibration-$$"
  if mkdir -m 700 "$vault" 2>/dev/null; then
    trap 'rm -rf -- "$vault"' EXIT
    printf 'SENTINEL clean calibration fixture\n' > "$vault/clean.txt"
    printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$vault/eicar.com"
    set +e
    clean_output="$(clamscan --no-summary --stdout "$vault/clean.txt" 2>&1)"
    clean_code=$?
    eicar_output="$(clamscan --no-summary --stdout "$vault/eicar.com" 2>&1)"
    eicar_code=$?
    set -e
    if [[ $clean_code -eq 0 && "$clean_output" == *'OK'* ]]; then pass 'ClamAV clean fixture'; else fail "ClamAV clean fixture failed (exit=$clean_code): ${clean_output:0:240}"; fi
    if [[ $eicar_code -eq 1 && "$eicar_output" == *'Eicar-Test-Signature'* && "$eicar_output" == *'FOUND'* ]]; then pass 'ClamAV EICAR signature detection'; else fail "ClamAV did not produce expected EICAR detection (exit=$eicar_code): ${eicar_output:0:240}"; fi
    rm -rf -- "$vault"
    trap - EXIT
  else
    fail 'Cannot create private calibration directory under /dev/shm'
  fi
fi

if [[ $FAILURES -eq 0 ]]; then
  printf '\nRunning strict-mode application tests (development fallback disabled)...\n'
  (cd "$ROOT" && SENTINEL_ALLOW_UNSANDBOXED_ARCHIVE_WORKER=0 npm test && npm run build) || fail 'Strict-mode test/build suite failed'
else
  printf '\nRuntime prerequisites failed; strict-mode integration suite was not run.\n' >&2
fi

if [[ $FAILURES -ne 0 ]]; then printf '\nCalibration FAILED: %s check(s) failed.\n' "$FAILURES" >&2; exit 1; fi
printf '\nCalibration PASSED. This result applies only to this host and current ClamAV database.\n'
