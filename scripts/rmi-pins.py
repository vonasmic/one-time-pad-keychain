#!/usr/bin/env python3
"""Fill the spkiSha384 RMI pins of the lab SAE directory (JAVA_APPS/env/sae-nodes.json).

For every entry, the pin is taken from the node leaf certs/{name}.pem (PQC_CERTS_DIR if set):
lowercase hex SHA-384 over the DER SubjectPublicKeyInfo of the first certificate in the PEM,
the value fel.cvut.node.interNodeCommunication.KnownPeers compares. Only the spkiSha384 values
change; the other fields, their order and the layout stay as they are. The file is replaced
atomically, only when a pin changed, and kept at mode 0644 or stricter.

Usage: rmi-pins.py [--java-dir DIR] [--nodes PATH] [--certs-dir DIR] [--print]
"""
import argparse
import base64
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

DEFAULT_NODES = "env/sae-nodes.json"
PIN_FIELD = "spkiSha384"


def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def warn(msg):
    print(f"warning: {msg}", file=sys.stderr)


def first_pem_cert(path):
    m = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
                  path.read_text(encoding="ascii"), re.S)
    if not m:
        raise ValueError(f"no CERTIFICATE block in {path}")
    return base64.b64decode("".join(m.group(1).split()))


def tlv(buf, i):
    """(tag, content_start, end) of the DER element at offset i."""
    tag = buf[i]
    length = buf[i + 1]
    j = i + 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[j:j + n], "big")
        j += n
    return tag, j, j + length


def spki_der(cert):
    tag, c, _ = tlv(cert, 0)                 # Certificate
    if tag != 0x30:
        raise ValueError("certificate is not a SEQUENCE")
    tag, i, _ = tlv(cert, c)                 # tbsCertificate
    if tag != 0x30:
        raise ValueError("tbsCertificate is not a SEQUENCE")
    if cert[i] == 0xA0:                      # [0] version
        i = tlv(cert, i)[2]
    for _ in range(5):                       # serial, signature, issuer, validity, subject
        i = tlv(cert, i)[2]
    tag, _, end = tlv(cert, i)               # subjectPublicKeyInfo
    if tag != 0x30:
        raise ValueError("subjectPublicKeyInfo is not a SEQUENCE")
    return cert[i:end]


def entry_spans(text):
    """[(obj, start, end)] of the top-level array's elements, with their exact text spans."""
    dec = json.JSONDecoder()
    ws = re.compile(r"\s*")
    i = ws.match(text, 0).end()
    if i >= len(text) or text[i] != "[":
        raise ValueError("not a JSON array")
    i = ws.match(text, i + 1).end()
    out = []
    if i < len(text) and text[i] == "]":
        return out
    while True:
        obj, end = dec.raw_decode(text, i)
        if not isinstance(obj, dict):
            raise ValueError(f"element {len(out)} is not an object")
        out.append((obj, i, end))
        i = ws.match(text, end).end()
        if i < len(text) and text[i] == ",":
            i = ws.match(text, i + 1).end()
            continue
        if i < len(text) and text[i] == "]":
            break
        raise ValueError(f"unexpected character at offset {i}")
    if text[i + 1:].strip():
        raise ValueError("trailing data after the array")
    return out


def set_pin(span, fp):
    """span is one object's text; set or add its spkiSha384 member."""
    pat = re.compile(r'("' + PIN_FIELD + r'"\s*:\s*)"(?:[^"\\]|\\.)*"')
    if pat.search(span):
        return pat.sub(lambda m: m.group(1) + '"' + fp + '"', span, count=1)
    close = span.rstrip().rfind("}")
    body = span[:close].rstrip()
    sep = ", " if not body.endswith("{") else " "
    return body + sep + f'"{PIN_FIELD}": "{fp}"' + span[len(body):]


def main():
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--java-dir", type=Path, default=here.parent / "JAVA_APPS")
    ap.add_argument("--nodes", default=DEFAULT_NODES, help=f"relative to --java-dir (default {DEFAULT_NODES})")
    ap.add_argument("--certs-dir", default=os.environ.get("PQC_CERTS_DIR", "").strip() or "certs",
                    help="relative to --java-dir (default PQC_CERTS_DIR or certs)")
    ap.add_argument("--print", action="store_true", help="also print the file")
    args = ap.parse_args()
    java = args.java_dir.resolve()
    nodes = Path(args.nodes)
    nodes = (nodes if nodes.is_absolute() else java / nodes).resolve()   # follow a symlink to its target
    certs = Path(args.certs_dir)
    certs = certs if certs.is_absolute() else java / certs

    if not nodes.is_file():
        die(f"{nodes} missing; create it with one entry per SAE (saeId, name, location, hostname, port, {PIN_FIELD})")
    text = nodes.read_text(encoding="utf-8")
    try:
        spans = entry_spans(text)
    except ValueError as ex:
        die(f"{nodes}: {ex}")

    out, pos, seen, pinned = [], 0, {}, 0
    for obj, start, end in spans:
        sae, name = str(obj.get("saeId", "")).strip(), str(obj.get("name", "")).strip()
        span = text[start:end]
        if not sae or not name:
            die(f"{nodes}: entry {span!r} needs saeId and name")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
            die(f"{nodes}: {sae}: name {name!r} is not a plain file name")
        pem = certs / f"{name}.pem"
        if not pem.is_file():
            warn(f"{sae}: {pem} missing; {PIN_FIELD} left as is")
        else:
            fp = hashlib.sha384(spki_der(first_pem_cert(pem))).hexdigest()
            if fp in seen:
                die(f"{sae} and {seen[fp]} share one leaf key ({fp}); the SAE directory rejects duplicates")
            seen[fp] = sae
            span = set_pin(span, fp)
            pinned += 1
        out.append(text[pos:start])
        out.append(span)
        pos = end
    out.append(text[pos:])
    new = "".join(out)
    if not pinned:
        die("no SAE could be pinned")
    check = json.loads(new)
    strip = lambda o: {k: v for k, v in o.items() if k != PIN_FIELD}
    if len(check) != len(spans) or any(strip(a) != strip(b) for a, (b, _, _) in zip(check, spans)):
        die("internal error: rewrite changed more than the pins")

    mode = stat.S_IMODE(nodes.stat().st_mode) & 0o644
    if new != text:
        fd, tmp = tempfile.mkstemp(dir=nodes.parent, prefix=".sae-nodes.")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new)
        os.chmod(tmp, mode)
        os.replace(tmp, nodes)
        print(f"==> RMI pins written: {nodes} ({pinned} SAE)")
    else:
        if stat.S_IMODE(nodes.stat().st_mode) != mode:
            os.chmod(nodes, mode)
            print(f"==> {nodes}: mode set to {mode:o}")
        print(f"==> RMI pins up to date: {nodes} ({pinned} SAE)")
    if args.print:
        sys.stdout.write(new)


if __name__ == "__main__":
    main()
