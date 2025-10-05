NAMESPACE := harbor
HELM_REPO := https://helm.goharbor.io
HELM_CHART := harbor/harbor
HELM_RELEASE := harbor
VALUES_FILE := ./example/myharbor/values.yaml
VALUES_BOB_FILE := ./example/myharbor/values_bob.yaml
.EXPORT_ALL_VARIABLES:

.PHONY: all install-helm install-harbor clean

all:  install-helm  install-harbor

install-helm:
	@helm repo add harbor $(HELM_REPO)
	@helm repo update

install-harbor:
	@helm upgrade --install $(HELM_RELEASE) $(HELM_CHART) --namespace $(NAMESPACE) -f $(VALUES_FILE) --create-namespace --timeout 3m
	
install-harbor-bob:
	@helm upgrade --install $(HELM_RELEASE) $(HELM_CHART) --namespace $(NAMESPACE) -f $(VALUES_BOB_FILE) --create-namespace --timeout 3m
	
clean:
	@helm uninstall $(HELM_RELEASE) --namespace $(NAMESPACE) || true
	@kubectl delete namespace $(NAMESPACE) || true
