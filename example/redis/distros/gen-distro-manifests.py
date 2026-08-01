#!/usr/bin/env python3
"""Generate one deployment manifest per redis-protocol distro, from ONE template.

The question these support is "does contrast testing distinguish valkey from
redis?". That only has a meaningful answer if the distros are the ONLY variable,
so the pod spec is generated rather than hand-written: identical namespace shape,
identical Service name (`redis`) and container name (`redis`), identical
securityContext and identical host mounts. Each distro lands in its own namespace
so a single attack suite can be pointed at any of them with `--namespace`.

What legitimately differs per distro, and why:
  * image           — the point of the exercise
  * server argv     — redis-server / valkey-server / keydb-server / dragonfly
                      are different binaries; dragonfly is not a redis fork at
                      all and takes its own flags
  * config mount    — redis/valkey/keydb read a redis.conf; dragonfly does not,
                      so it gets flags instead

Anything else differing between two of these files is a bug in this generator.

    ./gen-distro-manifests.py            # write all four
    ./gen-distro-manifests.py --check    # verify on-disk files match (CI-safe)
"""
import argparse
import difflib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Versions resolved from each project's own latest release, 2026-07-31.
# There is no "redis 18" or "valkey 15" — both are far lower.
DISTROS = [
    {
        "name": "redis-oss", "ns": "redis-oss",
        "image": "redis:8.10.0",
        "version": "8.10.0",
        "cmd": ["redis-server", "/etc/redis/redis.conf"],
        "conf": True,
    },
    {
        "name": "valkey", "ns": "valkey",
        "image": "valkey/valkey:9.1.1",
        "version": "9.1.1",
        "cmd": ["valkey-server", "/etc/redis/redis.conf"],
        "conf": True,
    },
    {
        "name": "keydb", "ns": "keydb",
        "image": "eqalpha/keydb:x86_64_v6.3.4",
        "version": "6.3.4",
        "cmd": ["keydb-server", "/etc/redis/redis.conf"],
        "conf": True,
    },
    {
        "name": "dragonfly", "ns": "dragonfly",
        "image": "ghcr.io/dragonflydb/dragonfly:v1.39.0",
        "version": "1.39.0",
        # Dragonfly is a reimplementation, not a fork: no redis.conf, and it
        # needs an explicit bind + admin port to behave like the others here.
        "cmd": ["dragonfly", "--bind", "0.0.0.0", "--port", "6379",
                "--requirepass=", "--dbfilename", "dump"],
        "conf": False,
    },
]

TEMPLATE = """apiVersion: v1
kind: Namespace
metadata:
  name: {ns}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: redis-config
  namespace: {ns}
data:
  redis.conf: |
    bind 0.0.0.0
    protected-mode no
    port 6379
    dir /data
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: {ns}
  labels:
    app.kubernetes.io/name: redis
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: redis
  template:
    metadata:
      labels:
        app.kubernetes.io/name: redis
        app.kubernetes.io/version: "{version}"
        bob.k8sstormcenter.io/distro: {name}
    spec:
      containers:
        - name: redis
          image: {image}
          command: {cmd}
          ports:
            - containerPort: 6379
              name: redis
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              add: ["SYS_PTRACE"]
              drop: ["NET_RAW"]
          volumeMounts:
{conf_mount}            - name: data
              mountPath: /data
            - name: host-etc
              mountPath: /host-etc
              readOnly: true
            - name: host-tmp
              mountPath: /host-tmp
      volumes:
{conf_vol}        - name: data
          emptyDir: {{}}
        - name: host-etc
          hostPath:
            path: /etc
            type: Directory
        - name: host-tmp
          hostPath:
            path: /tmp
            type: Directory
---
apiVersion: v1
kind: Service
metadata:
  name: redis
  namespace: {ns}
spec:
  selector:
    app.kubernetes.io/name: redis
  ports:
    - name: redis
      port: 6379
      targetPort: 6379
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis-client
  namespace: {ns}
  labels:
    app.kubernetes.io/name: redis-client
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: redis-client
  template:
    metadata:
      labels:
        app.kubernetes.io/name: redis-client
    spec:
      containers:
        - name: client
          image: redis:8.10.0-alpine
          command: ["sleep", "infinity"]
---
apiVersion: v1
kind: Service
metadata:
  name: redis-client
  namespace: {ns}
spec:
  selector:
    app.kubernetes.io/name: redis-client
  ports:
    - name: client
      port: 6379
      targetPort: 6379
"""

CONF_MOUNT = "            - name: config\n              mountPath: /etc/redis\n"
CONF_VOL = "        - name: config\n          configMap:\n            name: redis-config\n"


def render(d):
    return TEMPLATE.format(
        ns=d["ns"], name=d["name"], image=d["image"], version=d["version"],
        cmd="[" + ", ".join(f'"{c}"' for c in d["cmd"]) + "]",
        conf_mount=CONF_MOUNT if d["conf"] else "",
        conf_vol=CONF_VOL if d["conf"] else "",
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="fail if on-disk manifests differ from the template")
    args = ap.parse_args()

    rc = 0
    for d in DISTROS:
        out = HERE / f"{d['name']}.yaml"
        want = render(d)
        if args.check:
            have = out.read_text() if out.is_file() else ""
            if have != want:
                rc = 1
                print(f"DRIFT: {out.name}", file=sys.stderr)
                for line in difflib.unified_diff(have.splitlines(), want.splitlines(),
                                                 "on-disk", "template", lineterm="", n=1):
                    print("  " + line, file=sys.stderr)
            else:
                print(f"ok    {out.name}")
        else:
            out.write_text(want)
            print(f"wrote {out.name}  ({d['image']})")
    return rc


if __name__ == "__main__":
    sys.exit(main())
