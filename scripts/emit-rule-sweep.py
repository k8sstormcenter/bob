#!/usr/bin/env python3
"""Emit the standard rule-family attack block for a contrast leg.

Every app leg should reach the same detection families, but the primitives that
actually LAND differ per image, and the differences are not guessable — they have
to be probed on the running container first:

  * which shell/interpreter exists (perl gives memfd + raw sockets; a busybox
    image has neither, so R1005 is unreachable and egress goes through nc)
  * which directory is WRITABLE (/tmp is read-only in several images)
  * which directory is a real MOUNT (R1004 only fires from a volume mount, and
    an exec from /dev/shm scores as R1000 on this node-agent build)
  * what is already in the learned baseline (a binary in `execs` cannot fire
    R0001 — assert the path-side rule instead)

So this emits the block; it does not decide what is true for your image. Probe
first, pass what you found, then dogfood the tune and demote whatever misses to
an `expectedDetections: []` probe WITH the reason.

Usage:
  emit-rule-sweep.py --container client --stage /dev/shm --mount /var/lib/mysql \
      --rules R0005,R1000,R1004 [--no-perl] >> example/<app>-attacks.yaml
"""
import argparse
import sys

# path-independent pieces, keyed by rule id
def blocks(c, stage, mount, perl, drift_src, mount_src):
    b = {}
    b["R0005"] = f'''  - name: dns-anomaly-lookup
    type: cmdinject
    exec: {{ command: ["sh", "-c", "getent hosts scanner.evil-c2.example.com >/dev/null 2>&1 && echo dns_resolved || echo dns_attempted"] }}
    successIndicators: [{{ responseContains: "dns_" }}]
    expectedDetections:
      - {{ ruleID: R0005, ruleName: DNS Anomalies in container, containerName: {c} }}
'''
    b["R1008"] = f'''  - name: crypto-mining-dns
    type: cmdinject
    exec: {{ command: ["sh", "-c", "getent hosts xmr.pool.minergate.com >/dev/null 2>&1 && echo miner_dns_ok || echo miner_dns_attempted"] }}
    successIndicators: [{{ responseContains: "miner_dns_" }}]
    expectedDetections:
      - {{ ruleID: R1008, ruleName: Crypto Mining Domain Communication, containerName: {c} }}
'''
    b["R0008"] = f'''  - name: exec-proc-environ
    type: cmdinject
    exec: {{ command: ["cat", "/proc/1/environ"] }}
    successIndicators: [{{ responseContains: "PATH" }}]
    expectedDetections:
      - {{ ruleID: R0008, ruleName: Read Environment Variables from procfs, containerName: {c}, command: cat }}
'''
    b["R0010"] = f'''  - name: exec-etc-shadow
    type: cmdinject
    exec: {{ command: ["cat", "/etc/shadow"] }}
    expectedDetections:
      - {{ ruleID: R0010, ruleName: Unexpected Sensitive File Access, containerName: {c}, command: cat }}
'''
    b["R0006"] = f'''  - name: sa-token-read
    type: cmdinject
    exec: {{ command: ["sh", "-c", "cat /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null 2>&1 && echo sa_token_read_done || echo sa_token_absent"] }}
    successIndicators: [{{ responseContains: "sa_token_read_done" }}]
    expectedDetections:
      - {{ ruleID: R0006, ruleName: Unexpected service account token access, containerName: {c}, command: cat }}
'''
    b["R1010"] = f'''  - name: symlink-shadow
    type: cmdinject
    exec: {{ command: ["ln", "-sf", "/etc/shadow", "{stage}/softlink_probe"] }}
    successIndicators: [{{ responseContains: "" }}]
    expectedDetections:
      - {{ ruleID: R1010, ruleName: Soft link created over sensitive file, containerName: {c}, command: ln }}
'''
    b["R1012"] = f'''  - name: hardlink-shadow
    type: cmdinject
    exec: {{ command: ["sh", "-c", "ln /etc/shadow {stage}/hl_probe >/dev/null 2>&1 && echo hardlink_done; rm -f {stage}/hl_probe"] }}
    successIndicators: [{{ responseContains: "hardlink_done" }}]
    expectedDetections:
      - {{ ruleID: R1012, ruleName: Hard link created over sensitive file, containerName: {c}, command: ln }}
'''
    b["R1000"] = f'''  - name: drifted-binary-exec
    type: cmdinject
    exec: {{ command: ["sh", "-c", "cp {drift_src} {stage}/drifted_bob && printf '\\\\n#bob-drift' >> {stage}/drifted_bob && chmod +x {stage}/drifted_bob && {stage}/drifted_bob {'true' if 'busybox' in drift_src else '/'} >/dev/null 2>&1 && echo drift_exec_done; rm -f {stage}/drifted_bob"] }}
    successIndicators: [{{ responseContains: "drift_exec_done" }}]
    expectedDetections:
      - {{ ruleID: R1000, ruleName: Process executed from malicious source, containerName: {c} }}
'''
    b["R1004"] = f'''  - name: exec-from-volume-mount
    type: cmdinject
    exec: {{ command: ["sh", "-c", "cp {mount_src} {mount}/mnt_payload && chmod +x {mount}/mnt_payload && {mount}/mnt_payload mount_exec_done; rm -f {mount}/mnt_payload"] }}
    successIndicators: [{{ responseContains: "mount_exec_done" }}]
    expectedDetections:
      - {{ ruleID: R1004, ruleName: Process executed from mount, containerName: {c} }}
'''
    if perl:
        b["R0007"] = f'''  - name: k8s-api-unexpected-call
    type: cmdinject
    exec: {{ command: ["perl", "-e", "use Socket; socket(my $s,PF_INET,SOCK_STREAM,getprotobyname('tcp')); connect($s,sockaddr_in(443,inet_aton('10.43.0.1'))); close($s); print qq{{k8s_api_probe_done}}"] }}
    successIndicators: [{{ responseContains: "k8s_api_probe_done" }}]
    expectedDetections:
      - {{ ruleID: R0007, ruleName: Workload uses Kubernetes API unexpectedly, containerName: {c} }}
'''
        b["R0011"] = f'''  - name: egress-external-c2
    type: cmdinject
    exec: {{ command: ["perl", "-e", "use Socket; socket(my $s,PF_INET,SOCK_STREAM,getprotobyname('tcp')); connect($s,sockaddr_in(80,inet_aton('1.1.1.1'))); close($s); print qq{{egress_attempted}}"] }}
    successIndicators: [{{ responseContains: "egress_attempted" }}]
    expectedDetections:
      - {{ ruleID: R0011, ruleName: Unexpected Egress Network Traffic, containerName: {c} }}
'''
        b["R1005"] = f'''  - name: fileless-memfd-exec
    type: fileless
    exec: {{ command: ["perl", "-e", "my $n=\\"bobfl\\\\0\\"; my $fd=syscall(319,$n,0); die if $fd<0; open(my $m,'>&='.$fd) or die; open(my $s,'<','/bin/echo') or die; binmode $s; binmode $m; local $/; my $d=<$s>; print $m $d; exec(\\"/proc/$$/fd/$fd\\",\\"memfd_exec_done\\");"] }}
    successIndicators: [{{ responseContains: "memfd_exec_done" }}]
    expectedDetections:
      - {{ ruleID: R1005, ruleName: Fileless execution detected, containerName: {c} }}
'''
    else:
        b["R0007"] = f'''  - name: k8s-api-unexpected-call
    type: cmdinject
    exec: {{ command: ["sh", "-c", "nc -w 2 10.43.0.1 443 </dev/null >/dev/null 2>&1; echo k8s_api_probe_done"] }}
    successIndicators: [{{ responseContains: "k8s_api_probe_done" }}]
    expectedDetections:
      - {{ ruleID: R0007, ruleName: Workload uses Kubernetes API unexpectedly, containerName: {c} }}
'''
        b["R0011"] = f'''  - name: egress-external-c2
    type: cmdinject
    exec: {{ command: ["sh", "-c", "nc -w 2 1.1.1.1 80 </dev/null >/dev/null 2>&1; echo egress_attempted"] }}
    successIndicators: [{{ responseContains: "egress_attempted" }}]
    expectedDetections:
      - {{ ruleID: R0011, ruleName: Unexpected Egress Network Traffic, containerName: {c} }}
'''
    return b


def main():
    ap = argparse.ArgumentParser(description="Emit the standard rule-family attack block")
    ap.add_argument("--container", required=True, help="k8s container name the execs land in")
    ap.add_argument("--stage", default="/dev/shm", help="writable dir for staged binaries/links")
    ap.add_argument("--mount", default="/dev/shm", help="a REAL volume mount, for R1004")
    ap.add_argument("--rules", required=True, help="comma-separated rule ids to emit")
    ap.add_argument("--no-perl", action="store_true", help="image has no perl (busybox/alpine)")
    ap.add_argument("--drift-src", default="/bin/ls", help="binary to copy for the R1000 drift exec")
    ap.add_argument("--mount-src", default="/bin/echo", help="binary to copy for the R1004 mount exec")
    args = ap.parse_args()

    b = blocks(args.container, args.stage, args.mount, not args.no_perl,
               args.drift_src, args.mount_src)
    want = [r.strip() for r in args.rules.split(",") if r.strip()]
    unknown = [r for r in want if r not in b]
    if unknown:
        print(f"no template for: {', '.join(unknown)}", file=sys.stderr)
        return 2

    print("\n  # ── Full rule-family sweep (scripts/emit-rule-sweep.py) ─────────────────────")
    print("  # Primitives probed on the live container: staging dir, real mount, interpreter.")
    print("  # Anything that misses on the dogfood run must be demoted to a probe WITH a reason.")
    for r in want:
        print(b[r], end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
