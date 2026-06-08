#!/usr/bin/env python3
"""
Scan a HashiCorp Vault Enterprise cluster (tested target: 1.19.8) for KV
secrets that contain at least one data field key matching the pattern
"m" followed by any 5 digits (0-9).

Matches (field-key NAMES, same as vault_svc_scan.py):
    m12345          -> yes
    m98765          -> yes  (any 5 digits, not just 12345)
    m00000          -> yes
    m123456         -> yes  (extra characters after the 5 digits are allowed)
    m12345-prod     -> yes
    svc-m12345      -> no   (must START with m)
    m1234           -> no   (needs at least 5 digits after the m)
    mabcde          -> no   (the 5 chars after m must be digits)
Override the default with --pattern if you need different rules.

It walks EVERY namespace (recursively, including nested children), discovers
every KV engine (v1 and v2) in each namespace, recursively lists all secret
paths, reads each secret, and reports the path when any field key matches.

Output: CSV with columns
    namespace, kv_path, matched_keys
(`matched_keys` is the m12345* field name(s) found at that path.)

Auth: standard Vault CLI env vars
    VAULT_ADDR   e.g. https://vault.example.com:8200
    VAULT_TOKEN  a token with read/list on the namespaces + KV engines

Usage:
    export VAULT_ADDR=https://vault.example.com:8200
    export VAULT_TOKEN=s.xxxxxxxx
    python3 vault_m12345_scan.py                      # writes m12345_kv_paths.csv
    python3 vault_m12345_scan.py -o out.csv           # custom output file
    python3 vault_m12345_scan.py --pattern '^m9\d+'   # change the match regex
    python3 vault_m12345_scan.py --insecure           # skip TLS verification (lab only)
    python3 vault_m12345_scan.py --ns team-a/         # start at a sub-namespace
"""

import argparse
import csv
import json
import os
import re
import ssl
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

VAULT_ADDR = os.environ.get("VAULT_ADDR", "").rstrip("/")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "")

# Default regex: a field key that STARTS with "m" followed by ANY 5 digits
# (0-9) -- e.g. m12345, m98765, m00000. \d{5} means exactly five digits; the
# match is a PREFIX match (re.search anchored with ^), so anything after the
# 5 digits is still allowed (more digits, "-prod", "_password", etc.).
# Pass --pattern r'^m\d{5}$' if you want EXACTLY m + 5 digits and nothing else,
# or r'^m\d{5}\d*$' for "m + 5-or-more digits, nothing else".
DEFAULT_PATTERN = r"^m\d{5}"

# How many seconds to wait on each API call.
TIMEOUT = 30


def log(msg):
    """Write a progress line to stderr and flush immediately (no buffering)."""
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


def die(msg):
    sys.stderr.write("ERROR: %s\n" % msg)
    sys.exit(1)


def api(path, namespace="", list_op=False, ssl_ctx=None):
    """
    Make a GET against the Vault API.

    path       : API path WITHOUT leading /v1/ (e.g. "sys/mounts")
    namespace  : value for the X-Vault-Namespace header ("" == root)
    list_op    : append ?list=true and treat 404 as "empty list"

    Returns the parsed JSON dict, or None for a 404 (not found / empty).
    """
    # Secret names can legally contain spaces and other characters that are
    # illegal in a raw URL (e.g. "connections/ m12345"). Percent-encode the
    # path while keeping "/" as a separator so the request is well-formed.
    safe_path = urllib.parse.quote(path, safe="/")
    url = "%s/v1/%s" % (VAULT_ADDR, safe_path)
    if list_op:
        url += "?list=true"

    req = urllib.request.Request(url, method="GET")
    req.add_header("X-Vault-Token", VAULT_TOKEN)
    if namespace:
        # Vault wants the namespace path WITHOUT a leading slash.
        req.add_header("X-Vault-Namespace", namespace.lstrip("/"))

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ssl_ctx) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None  # empty list or no such path
        if e.code == 403:
            # Permission denied — log and keep going so one bad ACL
            # doesn't abort the whole sweep.
            sys.stderr.write("  [403] denied: ns=%r %s\n" % (namespace, path))
            return None
        body = e.read().decode("utf-8", "replace")
        sys.stderr.write("  [%d] %s ns=%r %s\n" % (e.code, path, namespace, body[:200]))
        return None
    except urllib.error.URLError as e:
        sys.stderr.write("  [conn] %s ns=%r %s\n" % (path, namespace, e))
        return None
    except Exception as e:
        # Never let one malformed path/secret kill the whole multi-namespace
        # sweep — log it and move on.
        sys.stderr.write("  [skip] %s ns=%r %s\n" % (path, namespace, e))
        return None


def list_namespaces(ssl_ctx, workers, start_ns=""):
    """
    Return every namespace path reachable from start_ns, INCLUDING start_ns
    itself. Namespace paths carry a trailing slash, except the root namespace
    which is the empty string "".

    Parallel breadth-first search: at each depth, list the children of every
    namespace in the current frontier concurrently. On a wide, shallow tree
    (hundreds of namespaces under root) this is dramatically faster than the
    one-call-at-a-time walk.
    """
    all_ns = [start_ns]
    seen = {start_ns}
    frontier = [start_ns]

    def children_of(ns):
        data = api("sys/namespaces", namespace=ns, list_op=True, ssl_ctx=ssl_ctx)
        keys = (data.get("data") or {}).get("keys", []) if data else []
        return ns, (keys or [])

    with ThreadPoolExecutor(max_workers=workers) as ex:
        while frontier:
            next_frontier = []
            for parent, keys in ex.map(children_of, frontier):
                for child in keys:
                    # child is relative to parent, e.g. "team-a/"
                    full = (parent + child) if parent else child
                    if full not in seen:
                        seen.add(full)
                        all_ns.append(full)
                        next_frontier.append(full)
            log("  ...%d namespaces discovered so far" % len(all_ns))
            frontier = next_frontier  # descend to the next depth level
    return all_ns


def list_kv_mounts(namespace, ssl_ctx):
    """
    Return a list of (mount_path, kv_version) for every KV engine mounted in
    `namespace`. mount_path keeps its trailing slash, e.g. "secret/".
    """
    data = api("sys/mounts", namespace=namespace, ssl_ctx=ssl_ctx)
    if not data:
        return []
    # In newer Vault the mounts live under data{}, older versions put them at
    # the top level — handle both.
    mounts = data.get("data", data)
    result = []
    for mount_path, info in mounts.items():
        if not isinstance(info, dict):
            continue
        if info.get("type") != "kv":
            continue
        # "options" is often null (KV v1 / non-KV mounts), so coerce with `or {}`
        # before indexing — a missing default won't catch a present-but-null value.
        version = str((info.get("options") or {}).get("version", "1") or "1")
        result.append((mount_path, version))
    return result


def list_dir(mount, version, namespace, rel, ssl_ctx):
    """
    List a single KV folder. Returns (subfolders, leaf_secrets) as two lists of
    mount-relative paths. Used as the unit of work for parallel tree walking.
    """
    list_prefix = mount + ("metadata/" if version == "2" else "")
    data = api(list_prefix + rel, namespace=namespace, list_op=True, ssl_ctx=ssl_ctx)
    folders, leaves = [], []
    if data:
        for key in data.get("data", {}).get("keys", []) or []:
            child = rel + key
            (folders if key.endswith("/") else leaves).append(child)
    return folders, leaves


def read_secret(mount, version, rel_path, namespace, ssl_ctx):
    """Return the dict of data fields for a secret, or {} on failure."""
    read_path = mount + ("data/" if version == "2" else "") + rel_path
    data = api(read_path, namespace=namespace, ssl_ctx=ssl_ctx)
    if not data:
        return {}
    if version == "2":
        # v2 nests fields under data.data; either level can be null.
        return (data.get("data") or {}).get("data") or {}
    return data.get("data") or {}


def main():
    ap = argparse.ArgumentParser(description="Find KV secrets with m12345* field keys across all Vault namespaces.")
    ap.add_argument("-o", "--output", default="m12345_kv_paths.csv", help="CSV output file (default: m12345_kv_paths.csv)")
    ap.add_argument("--pattern", default=DEFAULT_PATTERN,
                    help=r"regex the field-key name must match (default: %s)" % DEFAULT_PATTERN)
    ap.add_argument("--ignore-case", action="store_true",
                    help="match the pattern case-insensitively (e.g. also M12345)")
    ap.add_argument("--match", choices=["key", "name", "both"], default="both",
                    help="match the secret's leaf NAME, its field KEYs, or BOTH "
                         "(default: both). 'name' is for secrets literally named m12345*.")
    ap.add_argument("--show-all", action="store_true",
                    help="debug: log every secret path and its field-key names, "
                         "whether or not it matches. Use to see what's actually there.")
    ap.add_argument("--ns", default="", help="starting namespace (default: root)")
    ap.add_argument("--workers", type=int, default=16, help="concurrent API workers (default: 16)")
    ap.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    args = ap.parse_args()

    if not VAULT_ADDR:
        die("VAULT_ADDR is not set")
    if not VAULT_TOKEN:
        die("VAULT_TOKEN is not set")

    try:
        flags = re.IGNORECASE if args.ignore_case else 0
        key_re = re.compile(args.pattern, flags)
    except re.error as e:
        die("invalid --pattern regex %r: %s" % (args.pattern, e))

    ssl_ctx = None
    if args.insecure:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    log("Matching %s against regex: %s%s"
        % ({"key": "field keys", "name": "secret names", "both": "secret names + field keys"}[args.match],
           args.pattern, " (case-insensitive)" if args.ignore_case else ""))

    # --- Phase 1: enumerate namespaces (parallel BFS, one call per ns) -------
    log("Phase 1: enumerating namespaces (parallel BFS, %d workers)..." % args.workers)
    namespaces = list_namespaces(ssl_ctx, args.workers, start_ns=args.ns)
    log("Phase 1 done: %d namespace(s)" % len(namespaces))

    # --- Phase 2: discover KV engines in every namespace, in parallel --------
    # Each entry is (namespace, mount_path, kv_version).
    log("Phase 2: discovering KV engines across %d namespaces..." % len(namespaces))
    ns_mounts = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for ns, mounts in zip(namespaces, ex.map(lambda n: list_kv_mounts(n, ssl_ctx), namespaces)):
            ns_label = ns if ns else "root"
            if mounts:
                log("namespace %s : %d KV engine(s)" % (ns_label, len(mounts)))
            for mount, version in mounts:
                ns_mounts.append((ns, mount, version))
    log("Phase 2 done: %d KV engine(s) total" % len(ns_mounts))

    # --- Phase 3: parallel tree-walk + secret reads --------------------------
    # A single thread pool drives two kinds of task:
    #   "list" -> list one folder, queue child folders + leaf reads
    #   "read" -> read one secret, record a row if a field key matches
    # The main thread owns `fmap` (future -> task descriptor); workers only
    # touch the shared rows list / counter under their locks.
    rows = []
    rows_lock = threading.Lock()
    counter = {"secrets": 0}
    counter_lock = threading.Lock()

    def do_list(ns, mount, version, rel):
        return list_dir(mount, version, ns, rel, ssl_ctx)

    def do_read(ns, mount, version, rel):
        # Does the secret's own leaf name match? (e.g. a secret named "m12345")
        leaf = rel.rstrip("/").rsplit("/", 1)[-1]
        name_hit = key_re.search(leaf) if args.match in ("name", "both") else None

        # Only read the secret body when we actually need to inspect field keys.
        matched_keys = []
        if args.match in ("key", "both") or args.show_all:
            fields = read_secret(mount, version, rel, ns, ssl_ctx)
            with counter_lock:
                counter["secrets"] += 1
            matched_keys = sorted(k for k in fields if key_re.search(k))
            if args.show_all:
                ns_label = ns if ns else "root"
                log("  SEEN %s -> %s%s  leaf=%r  keys=%r"
                    % (ns_label, mount, rel, leaf, sorted(fields.keys())))
        else:
            # name-only mode: we already have the leaf from the listing, no read.
            with counter_lock:
                counter["secrets"] += 1
            if args.show_all:
                ns_label = ns if ns else "root"
                log("  SEEN %s -> %s%s  leaf=%r" % (ns_label, mount, rel, leaf))

        if name_hit or matched_keys:
            ns_label = ns if ns else "root"
            full_path = mount + rel  # e.g. "app1/kv/m12345"
            matched_name = leaf if name_hit else ""
            with rows_lock:
                rows.append((ns_label, full_path, matched_name, ";".join(matched_keys)))
            log("  MATCH %s -> %s  name=%s keys=%s"
                % (ns_label, full_path, matched_name or "-", ",".join(matched_keys) or "-"))

    log("Phase 3: walking trees + reading secrets with %d workers..." % args.workers)
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        fmap = {}

        def submit(kind, ns, mount, version, rel):
            fn = do_list if kind == "list" else do_read
            fmap[ex.submit(fn, ns, mount, version, rel)] = (kind, ns, mount, version, rel)

        for ns, mount, version in ns_mounts:
            submit("list", ns, mount, version, "")  # "" == mount root

        last_report = 0
        while fmap:
            done, _ = wait(list(fmap), return_when=FIRST_COMPLETED)
            for fut in done:
                kind, ns, mount, version, rel = fmap.pop(fut)
                if kind != "list":
                    continue  # read task: side effects already done
                folders, leaves = fut.result()
                for f in folders:
                    submit("list", ns, mount, version, f)
                for lf in leaves:
                    submit("read", ns, mount, version, lf)
            # Throttled heartbeat so a long scan visibly progresses.
            read_so_far = counter["secrets"]
            if read_so_far - last_report >= 50:
                last_report = read_so_far
                log("  progress: %d secrets read, %d task(s) in flight, %d match(es)"
                    % (read_so_far, len(fmap), len(rows)))

    secrets_read = counter["secrets"]

    with open(args.output, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["namespace", "kv_path", "matched_name", "matched_keys"])
        w.writerows(rows)

    sys.stderr.write(
        "\nDone. Read %d secrets, %d match(es). Wrote %s\n"
        % (secrets_read, len(rows), args.output)
    )


if __name__ == "__main__":
    main()
