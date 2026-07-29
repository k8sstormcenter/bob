NAME := bobctl
VERSION ?= 0.1.0
BUILD_DIR := bin

GO ?= go
GO_VERSION ?= 1.24
KUBESCAPE_CHART_VER ?= 1.40.3

OUTPUT_PATH := $(BUILD_DIR)/$(NAME)
HELM := $(shell which helm)

#CURRENT_CONTEXT := $(shell kubectl config current-context)
OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH := $(shell uname -m | sed 's/x86_64/amd64/')

GO_LDFLAGS := -s -w -X main.version=$(VERSION)
REPO_ROOT := $(shell git rev-parse --show-toplevel)


.PHONY: all
all: build

.PHONY: build
build: $(OUTPUT_PATH)

$(OUTPUT_PATH): $(GO_FILES)
	@echo "Building $(NAME) for $(OS)/$(ARCH)..."
	@mkdir -p $(dir $(OUTPUT_PATH))
	cd pkg && CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(GO_LDFLAGS)" -o ../$(OUTPUT_PATH) ./main.go
	@echo "Build complete: $(OUTPUT_PATH)"

.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete."

.PHONY: docker-build
docker-build:
	@echo "Running docker build $(NAME)..."
	docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/k8sstormcenter/$(NAME):latest -f Dockerfile .

.PHONY: run
run: build
	@echo "Running $(NAME)..."
	@$(OUTPUT_PATH)

.PHONY: mac-prep
mac-prep:
	docker buildx create --name mybuilder --driver docker-container --use

.PHONY: tetragon
tetragon:
	-$(HELM) repo add cilium https://helm.cilium.io
	-$(HELM) repo update
	-$(HELM) upgrade --install tetragon cilium/tetragon -n bob --create-namespace --values honeycluster/honeystack/tetragon/values.yaml
	-kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=tetragon -n bob --timeout=5m 

# ── Unified deploy targets (used by CI and local-ci.sh) ─────────────────────
# Usage: make deploy-<app>
# Each target handles its own deploy method (manifest, helm, operator) and waits
# for readiness. Adding a new app = adding a new deploy-<app> target here.

.PHONY: deploy-webapp
deploy-webapp:
	@echo "=== Deploying webapp (manifest) ==="
	kubectl apply -f example/webapp-manifest.yaml
	kubectl wait --for=condition=available --timeout=120s deployment/webapp-mywebapp -n webapp

.PHONY: deploy-redis
deploy-redis:
	@echo "=== Deploying redis (manifest) ==="
	kubectl apply -f example/redis-vulnerable.yaml
	kubectl wait --for=condition=available --timeout=120s deployment/redis -n redis

.PHONY: deploy-mariadb
deploy-mariadb:
	@echo "=== Deploying mariadb (manifest, intentionally insecure) ==="
	kubectl apply -f example/mariadb-vulnerable.yaml
	kubectl wait --for=condition=available --timeout=180s deployment/mariadb -n mariadb
	kubectl wait --for=condition=available --timeout=120s deployment/mariadb-client -n mariadb
	@echo "=== Pods in mariadb ==="
	kubectl get pods -n mariadb

# deploy-misp and deploy-elk removed: misp + elk are archived to the inner repo
# under pkg/nonmigrated/ and are no longer part of the contrast-tuning matrix.

# Argo CD — FULL upstream install (all subcomponents) + vulnerable overlay.
# ARGOCD_VERSION pins the CVE-carrying release (see example/argocd-vulnerable.yaml).
ARGOCD_VERSION ?= v2.9.3
.PHONY: deploy-argocd
deploy-argocd:
	@echo "=== Deploying Argo CD $(ARGOCD_VERSION) (full install: all subcomponents) ==="
	kubectl create namespace argocd 2>/dev/null || true
	# Full install.yaml (NOT core-install): server + repo-server + app-controller
	# + applicationset + notifications + dex + redis. Pinned + CVE-carrying.
	kubectl apply -n argocd -f \
		https://raw.githubusercontent.com/argoproj/argo-cd/$(ARGOCD_VERSION)/manifests/install.yaml
	@echo "=== Vulnerable overlay (permissive AppProject + exec-render surface) ==="
	kubectl apply -f example/argocd-vulnerable.yaml
	@echo "=== Wait for all Argo CD subcomponents ==="
	-kubectl rollout status -n argocd deploy/argocd-server                    --timeout=300s
	-kubectl rollout status -n argocd deploy/argocd-repo-server               --timeout=300s
	-kubectl rollout status -n argocd deploy/argocd-applicationset-controller --timeout=300s
	-kubectl rollout status -n argocd deploy/argocd-notifications-controller  --timeout=300s
	-kubectl rollout status -n argocd deploy/argocd-dex-server                --timeout=300s
	-kubectl rollout status -n argocd deploy/argocd-redis                     --timeout=300s
	-kubectl rollout status -n argocd statefulset/argocd-application-controller --timeout=300s
	@echo "=== Argo CD subcomponents ==="
	kubectl get pods -n argocd

.PHONY: deploy-postgres
deploy-postgres:
	@echo "=== Deploying postgres (CloudNativePG) ==="
	helm repo add cnpg https://cloudnative-pg.github.io/charts 2>/dev/null || true
	helm upgrade --install cnpg cnpg/cloudnative-pg \
		-n cnpg-system --create-namespace --wait --timeout 5m
	@# pg-client Service is declared headless (clusterIP: None) in
	@# postgres/cluster.yaml. Pre-existing clusterIP-typed Services from
	@# earlier deploys cannot be mutated in-place (K8s spec.clusterIP is
	@# immutable once set), so delete it before apply.
	-kubectl delete svc pg-client -n postgres --ignore-not-found
	kubectl apply -f postgres/cluster.yaml
	@echo "Waiting for CNPG cluster to be ready..."
	@TIMEOUT=300; ELAPSED=0; \
	while [ $$ELAPSED -lt $$TIMEOUT ]; do \
		PHASE=$$(kubectl get cluster pg -n postgres -o jsonpath='{.status.phase}' 2>/dev/null || echo ""); \
		echo "  Cluster phase: $$PHASE ($$ELAPSED/$${TIMEOUT}s)"; \
		if [ "$$PHASE" = "Cluster in healthy state" ]; then break; fi; \
		sleep 10; ELAPSED=$$((ELAPSED + 10)); \
	done
	@echo "Waiting for pg-client pod..."
	-kubectl wait --for=condition=ready pod -l app=pg-client -n postgres --timeout=120s
	kubectl get pods -n postgres

.PHONY: build-postgres-vuln
build-postgres-vuln:
	@echo "=== Building postgres-vuln image ==="
	@DOCKER_HOST=$${DOCKER_HOST:-unix:///var/run/docker.sock}; export DOCKER_HOST; \
	docker build -t postgres-vuln:latest postgres-vuln/

.PHONY: deploy-postgres-vuln
deploy-postgres-vuln: build-postgres-vuln
	@echo "=== Deploying postgres-vuln (CVE-2019-9193 superuser misconfiguration) ==="
	@# Load image into cluster (Kind, k3d, or k3s). The portability job's
	@# differential cluster B is k3d — without a k3d branch the locally-built
	@# postgres-vuln:latest never reaches its containerd, so imagePullPolicy:
	@# IfNotPresent falls back to pulling docker.io/postgres-vuln (nonexistent)
	@# → ImagePullBackOff → the deployment wait times out.
	@DOCKER_CMD="docker"; [ -S /var/run/docker.sock ] && DOCKER_CMD="env DOCKER_HOST=unix:///var/run/docker.sock docker"; \
	if command -v kind >/dev/null 2>&1 && kind get clusters 2>/dev/null | grep -q .; then \
		echo "Loading image into Kind..."; \
		env DOCKER_HOST=unix:///var/run/docker.sock kind load docker-image postgres-vuln:latest --name $$(kind get clusters | head -1) 2>/dev/null \
		  || kind load docker-image postgres-vuln:latest --name $$(kind get clusters | head -1); \
	elif command -v k3d >/dev/null 2>&1 && k3d cluster list 2>/dev/null | tail -n +2 | grep -q .; then \
		CLU=$$(k3d cluster list 2>/dev/null | awk 'NR>1{print $$1; exit}'); \
		echo "Importing image into k3d cluster $$CLU..."; \
		k3d image import postgres-vuln:latest -c $$CLU; \
	elif command -v k3s >/dev/null 2>&1; then \
		echo "Importing image into k3s..."; \
		$$DOCKER_CMD save postgres-vuln:latest | sudo k3s ctr images import -; \
	fi
	kubectl apply -f postgres-vuln/cluster.yaml
	@# pg-vuln Deployment uses imagePullPolicy: IfNotPresent and pg-vuln-client
	@# is a raw Pod with restartPolicy: Never. Without an explicit rollout +
	@# pod recreation, repeated runs silently use the previously-loaded image
	@# (rabbit on PR 119, Makefile:170). Force fresh containers here.
	@echo "Forcing rollout of pg-vuln after image reload..."
	-kubectl rollout restart deployment/pg-vuln -n postgres-vuln 2>/dev/null
	@echo "Recreating pg-vuln-client (raw Pod won't pick up new image otherwise)..."
	-kubectl delete pod pg-vuln-client -n postgres-vuln --ignore-not-found --grace-period=0 --force 2>/dev/null
	kubectl apply -f postgres-vuln/cluster.yaml
	@echo "Waiting for pg-vuln deployment..."
	kubectl wait --for=condition=available deployment/pg-vuln -n postgres-vuln --timeout=180s
	@echo "Waiting for pg-vuln-client pod..."
	-kubectl wait --for=condition=ready pod -l app=pg-vuln-client -n postgres-vuln --timeout=120s
	@echo "Verifying postgres accepts connections..."
	@TIMEOUT=60; ELAPSED=0; READY=0; \
	while [ $$ELAPSED -lt $$TIMEOUT ]; do \
		if kubectl exec pg-vuln-client -n postgres-vuln -- pg_isready -h pg-vuln -U postgres 2>/dev/null; then READY=1; break; fi; \
		sleep 5; ELAPSED=$$((ELAPSED + 5)); \
	done; \
	if [ $$READY -eq 0 ]; then echo "ERROR: postgres-vuln did not become ready within $${TIMEOUT}s"; exit 1; fi
	kubectl get pods -n postgres-vuln

# ── Legacy targets (kept for backward compat) ───────────────────────────────

.PHONY: helm-install-no-bob
helm-install-no-bob: 
	@echo "Installing webapp without BoB configuration..."
	helm pull oci://ghcr.io/k8sstormcenter/mywebapp 
	helm upgrade --install webapp oci://ghcr.io/k8sstormcenter/mywebapp --version 0.1.0 --namespace webapp --create-namespace --set bob.create=false
	rm -rf mywebapp-0.1.0.tgz
	-kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=mywebapp -n webapp

.PHONY: helm-install
helm-install: 
	@echo "Installing webapp with BoB configuration ..."
	helm upgrade --install webapp example/mywebapp-chart --namespace webapp --create-namespace --values example/mywebapp-chart/values.yaml --set bob.create=false
	-kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=mywebapp -n webapp


.PHONY: helm-redis
helm-redis: 
	@echo "Installing redis..."
	helm dependency update example/myredis-umbrella-chart/redis-bob/
	helm upgrade --install bob -n bob --create-namespace ./example/myredis-umbrella-chart/redis-bob --values ./example/myredis-umbrella-chart/redis-bob/values.yaml
	-kubectl wait --for=condition=ready pod -n bob -l app.kubernetes.io/instance=bob


.PHONY: helm-redis-compromise #TODO this is a bit whimsical , come up with something better
helm-redis-compromise: 	
	@echo "Installing a compromised redis with original bob"
	#kubectl delete -n bob applicationprofile statefulset-bob-redis-master-$$(kubectl get statefulset -n bob -o jsonpath='{.items[0].status.currentRevision}'|cut -f4 -d '-')
	helm upgrade --install bob -n bob --create-namespace ./example/myredis-umbrella-chart/redis-bob --values ./example/myredis-umbrella-chart/redis-bob/values_compromised.yaml
	-kubectl wait --for=condition=ready pod -n bob -l app.kubernetes.io/instance=bob


.PHONY: helm-redis-test
helm-redis-test:
	-helm test bob -n bob

.PHONY: helm-test
helm-test:
	kubectl wait --for=condition=available --timeout=120s deployment/webapp-mywebapp -n webapp
	@echo "Deployment is ready. Running Helm tests..."
	helm test webapp -n webapp

.PHONY: helm-uninstall
helm-uninstall:
	helm uninstall webapp -n webapp

.PHONY: fwd
fwd:
	-sudo kill -9 $$(sudo lsof -t -i :8080)
	kubectl --namespace webapp port-forward $$(kubectl get pods --namespace webapp -l "app.kubernetes.io/name=mywebapp,app.kubernetes.io/instance=webapp" -o jsonpath="{.items[0].metadata.name}") 8080:80 &

.PHONY: fileopenattack
fileopenattack:
	kubectl exec -n webapp $(WEBAPP_POD) -- cat /etc/apache2/apache2.conf
	kubectl exec -n webapp $(WEBAPP_POD) -- touch /tmp/pwned
	kubectl exec -n webapp $(WEBAPP_POD) -- echo hi > /tmp/pwned
	kubectl exec -n webapp $(WEBAPP_POD) -- cat /tmp/pwned
	kubectl exec -n webapp $(WEBAPP_POD) -- rm /tmp/pwned




.PHONY: attack # this is only for the webapp
attack:
	curl 127.0.0.1:8080/ping.php?ip=1.1.1.1\;ls
	curl  127.0.0.1:8080/ping.php?ip=1.1.1.1%3Bcat%20/proc/self/mounts
	curl "127.0.0.1:8080/ping.php?ip=1.1.1.1%3Bcat%20index.html"
	curl "127.0.0.1:8080/ping.php?ip=1.1.1.1%3Bcurl%20github.com"
	curl "127.0.0.1:8080/ping.php?ip=1.1.1.1%3Bcat%20/run/secrets/kubernetes.io/serviceaccount/token"
	sleep 10

.PHONY: kubescape-orig
kubescape-orig:
	-$(HELM) repo add kubescape https://kubescape.github.io/helm-charts/
	-$(HELM) repo update
	-$(HELM) upgrade --install kubescape kubescape/kubescape-operator --version $(KUBESCAPE_CHART_VER)  -n honey --create-namespace --values kubescape/deprecated/values_orig.yaml
	-kubectl apply  -f kubescape/default-rules.yaml
	sleep 5
	-kubectl rollout restart -n honey ds node-agent


.PHONY: kubescape
kubescape: 
	helm repo add kubescape https://kubescape.github.io/helm-charts/
	helm repo update
	helm upgrade --install kubescape kubescape/kubescape-operator --version $(KUBESCAPE_CHART_VER) -n honey --create-namespace --values kubescape/values.yaml
	@echo "Ensuring CRDs are up-to-date (helm upgrade skips CRDs)..."
	-helm show crds kubescape/kubescape-operator --version $(KUBESCAPE_CHART_VER) | kubectl apply --server-side --force-conflicts -f - 2>/dev/null || true
	-kubectl apply  -f kubescape/default-rules.yaml
	sleep 5
	-kubectl rollout status -n honey deploy/kubevuln --timeout=120s
	$(MAKE) enable-streaming

# enable-streaming forces networkStreamingEnabled=true in the node-agent
# configmap and rolls the DaemonSet. The chart gates the flag behind
# cloud-submit (rendered = submit AND enable; submit = non-empty .Values.server)
# so on an on-prem stack with no server it renders FALSE regardless of
# capabilities.networkEventsStreaming. This target is idempotent and MUST be
# re-run after EVERY helm upgrade — kubescape/alertmanager/kubescape-vendor all
# call it — so the setting never drifts. See docs/portability-spec.md D7a.
.PHONY: enable-streaming
enable-streaming:
	@echo "Forcing node-agent networkStreamingEnabled=true (chart renders FALSE without cloud-submit)..."
	@PATCH=$$(kubectl -n honey get configmap node-agent -o jsonpath='{.data.config\.json}' | python3 -c 'import json,sys; cfg=json.load(sys.stdin); cfg["networkStreamingEnabled"]=True; print(json.dumps({"data":{"config.json":json.dumps(cfg)}}))'); \
		kubectl -n honey patch configmap node-agent --type merge -p "$$PATCH"
	-kubectl rollout restart -n honey ds node-agent
	-kubectl rollout status -n honey ds node-agent --timeout=180s
	$(MAKE) verify-streaming

# Fail loud if node-agent network streaming is not actually live. Without it
# the profile's inline network shape (ingress/egress) is inert and R0005 (DNS) /
# R0011 (egress) silently never fire — which reads as "clean" when it is really
# "blind".
.PHONY: verify-streaming
verify-streaming:
	@echo "Verifying node-agent networkStreamingEnabled is live..."
	@kubectl -n honey get configmap node-agent -o jsonpath='{.data.config\.json}' \
		| python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("networkStreamingEnabled") is True else 1)' \
		&& echo "OK: networkStreamingEnabled=true (R0005/R0011 can fire)" \
		|| { echo "ERROR: node-agent networkStreamingEnabled != true — the profile's inline network is inert; R0005 (DNS) and R0011 (egress) will silently never fire. Re-run 'make kubescape' or see docs/portability-spec.md D7a."; exit 1; }

.PHONY: alertmanager
alertmanager:
	@echo "Deploying alertmanager in honey namespace..."
	kubectl create namespace honey --dry-run=client -o yaml | kubectl apply -f -
	kubectl apply -n honey -f kubescape/alertmanager.yaml
	kubectl wait --for=condition=ready pod -l app=alertmanager -n honey --timeout=120s
	@echo "Reconciling node-agent config (exporter is in values.yaml; re-assert streaming)..."
	# upgrade --install (not bare upgrade): idempotent, and does not require the
	# kubescape release to pre-exist — so `make alertmanager` works on a fresh
	# cluster / standalone, same as `make kubescape`.
	$(HELM) upgrade --install kubescape kubescape/kubescape-operator --version $(KUBESCAPE_CHART_VER) -n honey --create-namespace --values kubescape/values.yaml
	$(MAKE) enable-streaming
	@echo "Alertmanager ready. Forward with: kubectl -n honey port-forward svc/alertmanager 9093:9093"

.PHONY: fwd-autotune
fwd-autotune:
	-sudo kill -9 $$(sudo lsof -t -i :8081) 2>/dev/null
	-sudo kill -9 $$(sudo lsof -t -i :9093) 2>/dev/null
	kubectl --namespace webapp port-forward svc/webapp-mywebapp 8081:80 &
	kubectl -n honey port-forward svc/alertmanager 9093:9093 &
	@sleep 2
	@echo "Port-forwards active: webapp=localhost:8081 alertmanager=localhost:9093"

.PHONY: kubescape-vendor
kubescape-vendor: 
	-$(HELM) repo add kubescape https://kubescape.github.io/helm-charts/
	-$(HELM) repo update
	$(HELM) upgrade --install kubescape kubescape/kubescape-operator --version $(KUBESCAPE_CHART_VER) -n honey --create-namespace --values kubescape/deprecated/values_vendor.yaml
	-kubectl apply  -f kubescape/runtimerules.yaml
	sleep 5
	-kubectl rollout status -n honey deploy/kubevuln --timeout=120s
	$(MAKE) enable-streaming



.PHONY: wipe
wipe:
	-sudo kill -9 $$(sudo lsof -t -i :8080)
	-$(HELM) uninstall -n honey kubescape
	-$(HELM) uninstall -n webapp webapp
	-$(HELM) uninstall -n bob bob
	-kubectl delete namespace bob 
	-$(HELM) uninstall webapp -n webapp

.PHONY: helm
helm: ## Download helm if required
	curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 \
		&& chmod +x get_helm.sh &&./get_helm.sh
HELM = $(shell which helm)


.PHONY: sample-app
sample-app:
	$(MAKE) --makefile=example/myharbor/Makefile install-helm install-harbor
	@kubectl wait --for=condition=ready pod -l app=harbor -n harbor --timeout=600s

.PHONY: nothing
nothing:
# for when we know the hash upfront:
#helm upgrade --install bob -n bob --create-namespace --set bob.create=true ./myredis-umbrella-chart/redis-bob
	#helm upgrade --install bob -n bob --create-namespace ./myredis-umbrella-chart/redis-bob --values ./myredis-umbrella-chart/redis-bob/values.yaml
	#kubectl annotate applicationprofile statefulset-bob-redis-master-668c4559b4  -n bob meta.helm.sh/release-name- 
	#kubectl annotate applicationprofile statefulset-bob-redis-master-668c4559b4  -n bob meta.helm.sh/release-namespace-
	#kubectl annotate --overwrite applicationprofile statefulset-bob-redis-master-668c4559b4  -n bob kubescape.io/status='completed'
    #helm repo update 
	#helm upgrade --install bob -n bob --create-namespace --set bob.create=false --set bob.ignore=true ./myredis-umbrella-chart/redis-bob
	#helm upgrade --install bob -n bob --create-namespace --set bob.create=true --set bob.ignore=false --set bob.templateHash=$$(kubectl get statefulset -n bob -o jsonpath='{.items[0].status.currentRevision}'|cut -f4 -d '-') ./myredis-umbrella-chart/redis-bob
	#helm dependency update myredis-umbrella-chart/redis-bob/
	#helm upgrade --install bob -n bob --create-namespace --set bob.create=false --set bob.ignore=true ./myredis-umbrella-chart/redis-bob --values ./myredis-umbrella-chart/redis-bob/values_compromised.yaml
	#helm upgrade --install bob -n bob --create-namespace --set bob.create=true --set bob.ignore=false  --set bob.templateHash=$$(kubectl get statefulset -n bob -o jsonpath='{.items[0].status.currentRevision}'|cut -f4 -d '-')  ./myredis-umbrella-chart/redis-bob --values ./myredis-umbrella-chart/redis-bob/values_compromised.yaml
