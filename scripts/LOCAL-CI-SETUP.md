# Local CI Setup — arm64 Image Build Instructions

When running `local-ci.sh` on an arm64 VM, the `ghcr.io/k8sstormcenter/{node-agent,storage}` images
may not have arm64 manifests. Build them locally from source and import into k3s.

## Prerequisites

```bash
# Core tools (Ubuntu 24.04)
sudo apt-get install -y make jq git

# Go 1.25+ (match go.mod)
curl -fsSL "https://go.dev/dl/go1.25.3.linux-arm64.tar.gz" -o /tmp/go.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tar.gz
export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH

# kubectl, helm, yq
curl -fsSL "https://dl.k8s.io/release/$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/arm64/kubectl" \
  -o /tmp/kubectl && sudo install /tmp/kubectl /usr/local/bin/kubectl
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
curl -fsSL "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_arm64" \
  -o /tmp/yq && sudo install /tmp/yq /usr/local/bin/yq

# k3s
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--write-kubeconfig-mode 644" sh -
mkdir -p ~/.kube && sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config && sudo chown $(id -u):$(id -g) ~/.kube/config

# Docker (required for ig image build)
curl -fsSL https://get.docker.com | sh
sudo systemctl start docker

# inspektor-gadget CLI (match VERSION in node-agent/Makefile)
IG_VERSION=v0.48.1
curl -fsSL "https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${IG_VERSION}/ig-linux-arm64-${IG_VERSION}.tar.gz" \
  -o /tmp/ig.tar.gz && sudo tar -C /usr/local/bin -xzf /tmp/ig.tar.gz ig

# buildkit (for building OCI images without docker buildx)
curl -fsSL "https://github.com/moby/buildkit/releases/download/v0.21.1/buildkit-v0.21.1.linux-arm64.tar.gz" \
  -o /tmp/buildkit.tar.gz && sudo tar -C /usr/local -xzf /tmp/buildkit.tar.gz
sudo buildkitd &  # start daemon in background
```

## Clone Repos

```bash
cd ~
# storage — use the branch matching the image tag in kubescape/values.yaml
git clone --branch feature/collapse-config-crd https://github.com/k8sstormcenter/storage.git

# node-agent — same branch
git clone https://github.com/k8sstormcenter/node-agent.git
cd node-agent && git checkout feature/collapse-config-crd
```

## Build storage image

```bash
cd ~/storage
IMAGE_TAG=dev-$(git rev-parse --short HEAD)  # e.g. dev-e64d59a

sudo buildctl build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=./build \
  --opt platform=linux/arm64 \
  --output type=oci,name=ghcr.io/k8sstormcenter/storage:${IMAGE_TAG} \
  | sudo k3s ctr images import -
```

## Build node-agent image

### 1. Fix go.sum (if needed)

```bash
cd ~/node-agent
go mod tidy
```

### 2. Build eBPF gadgets (tracers.tar)

The node-agent Dockerfile COPYs `tracers.tar` which contains all eBPF gadgets.

```bash
cd ~/node-agent

# Build custom kubescape gadgets
KUBESCAPE_GADGETS="bpf exit fork hardlink http iouring_new iouring_old kmod network ptrace randomx ssh symlink unshare"
for g in $KUBESCAPE_GADGETS; do
  sudo ig image build -t ${g}:latest ./pkg/ebpf/gadgets/${g}/
done

# Pull upstream inspektor-gadget gadgets (match VERSION in Makefile)
IG_VERSION=v0.48.1
GADGETS="advise_seccomp trace_capabilities trace_dns trace_exec trace_open"
for g in $GADGETS; do
  sudo ig image pull ghcr.io/inspektor-gadget/gadget/${g}:${IG_VERSION}
done

# Export all to tracers.tar
sudo ig image export \
  $(for g in $GADGETS; do echo "ghcr.io/inspektor-gadget/gadget/${g}:${IG_VERSION}"; done) \
  $(for g in $KUBESCAPE_GADGETS; do echo "${g}:latest"; done) \
  tracers.tar
```

### 3. Build the image

```bash
cd ~/node-agent
IMAGE_TAG=dev-$(cd ~/storage && git rev-parse --short HEAD)  # tag matches storage

sudo buildctl build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=./build \
  --opt platform=linux/arm64 \
  --output type=oci,name=ghcr.io/k8sstormcenter/node-agent:${IMAGE_TAG} \
  | sudo k3s ctr images import -
```

## Verify

```bash
sudo k3s ctr images ls | grep k8sstormcenter
# Should show both images with linux/arm64 platform
```

## Then run local-ci.sh

```bash
cd ~/bob
export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH
export KUBECONFIG=~/.kube/config
./scripts/local-ci.sh --app webapp
```

If kubescape was already installed but pods were in ImagePullBackOff, delete and let them restart:
```bash
kubectl delete pod -n honey -l app=node-agent
kubectl delete pod -n honey -l app=storage
```

## Notes

- The image tag in `kubescape/values.yaml` must match what you built (e.g. `dev-e64d59a`)
- `imagePullPolicy` should be `IfNotPresent` (default) so k3s uses the locally imported image
- Only `ghcr.io/k8sstormcenter` images are tested — never substitute upstream kubescape images
