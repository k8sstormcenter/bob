my# Define variables
NAMESPACE := harbor
HELM_REPO := https://helm.goharbor.io
HELM_CHART := harbor/harbor
HELM_RELEASE := harbor
VALUES_FILE := ./cncf/harbor/values.yaml
.EXPORT_ALL_VARIABLES:

.PHONY: all install-helm install-harbor clean

all:  install-helm  install-harbor

install-helm:
	@helm repo add harbor $(HELM_REPO)
	@helm repo update

install-harbor:
	@helm upgrade --install $(HELM_RELEASE) $(HELM_CHART) --namespace $(NAMESPACE) -f $(VALUES_FILE) --create-namespace
	kubectl wait --for=condition=ready pod -l app=harbor -n harbor --timeout=600s

clean:
	@helm uninstall $(HELM_RELEASE) --namespace $(NAMESPACE) || true
	@kubectl delete namespace $(NAMESPACE) || true