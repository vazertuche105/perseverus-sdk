#!/usr/bin/env python3
"""Fail if library code prints outside `debug_log!`.

On a phone, stderr/stdout end up in the system log, where crash reporters
and other apps can read them. Diagnostics must go through
`perseverus_client_native::debug_log!` (off unless PERSEVERUS_DEBUG=1) and
must never include txids, vouts, tags, real block heights, pack ids,
nullifiers or token indices. Test modules (after `#[cfg(test)]`) are exempt.
"""
import pathlib, re, sys

ROOTS = ["core/src", "circuits/src", "client-native/src", "sdk/src"]
EXEMPT = {"client-native/src/debug.rs"}
PAT = re.compile(r"\b(e?println!|dbg!|e?print!)\s*\(")

bad = []
for root in ROOTS:
    for f in sorted(pathlib.Path(root).rglob("*.rs")):
        rel = f.as_posix()
        if rel in EXEMPT or "/bin/" in rel:
            continue
        code = f.read_text().split("#[cfg(test)]", 1)[0]
        for n, line in enumerate(code.splitlines(), 1):
            if line.lstrip().startswith("//"):
                continue
            if PAT.search(line):
                bad.append(f"{rel}:{n}: {line.strip()}")
if bad:
    print("Use debug_log! instead of printing directly (see client-native/src/debug.rs):")
    print("\n".join(bad))
    sys.exit(1)
print("ok: no direct printing in library code")
