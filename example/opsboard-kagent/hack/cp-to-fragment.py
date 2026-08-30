import json, sys, yaml
s = json.load(sys.stdin)["spec"]
keep = ["architectures", "capabilities", "execs", "opens", "syscalls", "endpoints", "egress", "ingress", "imageID", "imageTag"]
frag = {
    "apiVersion": "spdx.softwarecomposition.kubescape.io/v1beta1",
    "kind": "ContainerProfile",
    "metadata": {"name": "opsboard-base", "namespace": "shop", "labels": {"kubescape.io/managed-by": "user"}},
    "spec": {k: s[k] for k in keep if s.get(k) is not None},
}
yaml.safe_dump(frag, sys.stdout, sort_keys=False)
