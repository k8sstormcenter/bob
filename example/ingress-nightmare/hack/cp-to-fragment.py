import json, sys, yaml

# Accepts either `kubectl get -o json` or an authored YAML profile, so the same
# converter serves a fresh recording and the checked-in SBoB.
raw = sys.stdin.read()
try:
    doc = json.loads(raw)
except ValueError:
    doc = yaml.safe_load(raw)
s = doc["spec"]
# ingress/egress/rulePolicies were missing here, so a profile that declared its
# network peers or a rule policy lost both on the way to the signature — the
# signed object then differed from the profile that was validated, and the R0006
# comm allowlist that makes the controller quiet was silently discarded.
keep = ["architectures", "matchLabels", "capabilities", "execs", "opens", "syscalls",
        "endpoints", "rulePolicies", "ingress", "egress", "imageID", "imageTag"]
frag = {
    "apiVersion": "spdx.softwarecomposition.kubescape.io/v1beta1",
    "kind": "ContainerProfile",
    "metadata": {"name": "ingress-base", "namespace": "ingress-nginx", "labels": {"kubescape.io/managed-by": "user"}},
    "spec": {k: s[k] for k in keep if s.get(k) is not None},
}
yaml.safe_dump(frag, sys.stdout, sort_keys=False)
