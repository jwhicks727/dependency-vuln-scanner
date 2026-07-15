#!/usr/bin/env python3
"""
lockfile_to_deps.py - Convert an npm package-lock.json into dependencies.csv
for sca_scan.py.

Why the lockfile and not package.json:
package.json lists version RANGES ("^4.17.4" - "this or anything compatible").
OSV.dev needs the EXACT installed version to check. package-lock.json is the
file npm writes after actually resolving those ranges, so it's the only
place the real, installed version numbers live.

Handles both lockfile shapes you'll encounter in the wild:
  - lockfileVersion 1  (older npm): nested "dependencies" object, one level
    per package, with nested sub-dependencies inside each entry.
  - lockfileVersion 2/3 (npm 7+):   flat "packages" object, keyed by path
    like "node_modules/lodash", each entry carrying its own "version".

Also captures each package's dependency_type ("prod" or "dev"), read from
npm's own "dev" flag in the lockfile. A package is "dev" if it's strictly
part of the devDependencies tree - build tools, test runners, bundlers -
code that never ships to production or runs in front of a real user. This
matters for triage: a vulnerability in a devDependency is a supply-chain/
build-environment risk, not a live production attack surface, and the two
should usually be prioritized differently.

Usage:
    python lockfile_to_deps.py package-lock.json dependencies.csv
"""
import csv
import json
import sys
from pathlib import Path


def from_v1(data):
    """Walk the nested 'dependencies' tree of a v1 lockfile.

    Returns {name: (version, dependency_type)}.
    """
    seen = {}

    def walk(deps):
        if not deps:
            return
        for name, info in deps.items():
            version = info.get("version", "")
            dep_type = "dev" if info.get("dev") else "prod"
            if name and version:
                # Keep the first version we see for a given name; a package
                # can appear multiple times nested at different depths.
                # If already recorded as "prod" (shipped code), keep that -
                # a package used both ways is still shipped.
                if name not in seen or seen[name][1] == "dev":
                    seen[name] = (version, dep_type)
            walk(info.get("dependencies"))

    walk(data.get("dependencies"))
    return seen


def from_v2_or_v3(data):
    """Walk the flat 'packages' map of a v2/v3 lockfile.

    Returns {name: (version, dependency_type)}.
    """
    seen = {}
    for path, info in data.get("packages", {}).items():
        if not path:  # "" is the root project itself, not a dependency
            continue
        name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
        version = info.get("version", "")
        dep_type = "dev" if info.get("dev") else "prod"
        if name and version:
            if name not in seen or seen[name][1] == "dev":
                seen[name] = (version, dep_type)
    return seen


def main():
    if len(sys.argv) != 3:
        sys.exit("Usage: python lockfile_to_deps.py <package-lock.json> <output.csv>")

    lock_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    if not lock_path.exists():
        sys.exit(f"Lockfile not found: {lock_path.resolve()}")

    data = json.loads(lock_path.read_text(encoding="utf-8"))
    version = data.get("lockfileVersion", 1)

    if version == 1:
        packages = from_v1(data)
    else:
        packages = from_v2_or_v3(data)
        if not packages:
            # Some v2 lockfiles keep the old nested shape too; fall back.
            packages = from_v1(data)

    if not packages:
        sys.exit("No packages found - is this a valid package-lock.json?")

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["name", "ecosystem", "version", "dependency_type"])
        for name, (ver, dep_type) in sorted(packages.items()):
            writer.writerow([name, "npm", ver, dep_type])

    prod_count = sum(1 for _, dt in packages.values() if dt == "prod")
    dev_count = len(packages) - prod_count

    print(f"Lockfile version detected: {version}")
    print(f"Wrote {len(packages)} packages to {out_path.resolve()}")
    print(f"  prod: {prod_count}  |  dev: {dev_count}")


if __name__ == "__main__":
    main()