# ───────────────────────────────────────────────────────────────────────────
# Attack × noise-profile matrix runner for the bob demo chains.
#
# Fire any chain's attack, overlaid on a chosen benign noise profile, with the
# learn-before-fire ordering and the three hard-won robustness fixes baked in
# (new-ReplicaSet identity for a clean re-learn, nginx restart for the cached
# backend IP, node-agent restart for the laptop learning-race).
#
#   make cell CHAIN=log4shell SCENARIO=A PROFILE=bursty
#   make sweep CHAIN=log4shell                 # all profiles, all scenarios of one chain
#   make matrix                                # print the full grid
#   make teardown CHAIN=log4shell
#
# Axes:
#   CHAIN     log4shell | react2shell | argo | dapr
#   SCENARIO  A=vulnerable  B=contained  C=patched   (log4shell A/B/C; argo A only
#             until app-b/c.yaml land; react2shell/dapr single -> use A)
#   PROFILE   realistic | flat | bursty | diurnal    (the noise overlay)
# ───────────────────────────────────────────────────────────────────────────
SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

CHAIN    ?= log4shell
SCENARIO ?= A
PROFILE  ?= realistic
# KSNS: kubescape namespace; LEARN_WAIT: max secs to wait for AP completion;
# WINDOW: node-agent alert lookback for collect. (No inline comments below —
# Make would fold the trailing spaces into the value.)
KSNS ?= honey
LEARN_WAIT ?= 420
WINDOW ?= 6m
# SETTLE: secs to wait after firing before scraping alerts. The attack "completes"
# when the probe is SENT, but the workload-side chain + node-agent's alerts land
# later — and slower chains need more: argo waits on the controller reconcile +
# repo-server render; dapr on the daprd->k8s-API secret path. Per-chain, CLI-overridable.
SETTLE_log4shell := 25
SETTLE_dapr := 75
SETTLE_argo := 90
SETTLE_react2shell := 25
SETTLE := $(or $(SETTLE_$(CHAIN)),30)

# ── per-chain configuration (resolved via X_$(CHAIN) indirection) ────────────
DIR_log4shell := log4j-chain
NS_log4shell  := log4j-poc
LGNS_log4shell := log4j-loadgen
LGDEP_log4shell := log4j-loadgen
TARGET_log4shell := chain-backend
SEL_log4shell := app=chain-backend
FRONTEND_log4shell := chain-frontend
TEARDOWN_NS_log4shell := log4j-poc attacker-ns log4j-loadgen
EXPECT_log4shell := A:R0001,R0010,R0011  B:R0011,R1100  C:none

DIR_dapr := dapr-shop
NS_dapr  := shop
LGNS_dapr := shop-loadgen
LGDEP_dapr := shop-loadgen
TARGET_dapr := frontend
SEL_dapr := app=frontend
FRONTEND_dapr :=
TEARDOWN_NS_dapr := shop shop-loadgen dapr-system
EXPECT_dapr := A:R0006,R0007(secret-sweep);lateral+exfil-blend

DIR_argo := argocd
NS_argo  := argocd
LGNS_argo := argocd-loadgen
LGDEP_argo := argocd-loadgen
TARGET_argo := argocd-repo-server
SEL_argo := app.kubernetes.io/name=argocd-repo-server
FRONTEND_argo :=
TEARDOWN_NS_argo := argocd adv gitops argocd-loadgen
EXPECT_argo := A:R0001,R0010,R0011  B:R0011,R1100  C:none

DIR_react2shell := react2shell
NS_react2shell  := react
LGNS_react2shell := react-loadgen
LGDEP_react2shell := react-loadgen
TARGET_react2shell := react
SEL_react2shell := app=react
FRONTEND_react2shell :=
TEARDOWN_NS_react2shell := react react-loadgen gitops
EXPECT_react2shell := A:R0001,R0010 (RSC RCE)

# resolve for the selected CHAIN
DIR      := $(DIR_$(CHAIN))
NS       := $(NS_$(CHAIN))
LGNS     := $(LGNS_$(CHAIN))
LGDEP    := $(LGDEP_$(CHAIN))
TARGET   := $(TARGET_$(CHAIN))
SEL      := $(SEL_$(CHAIN))
FRONTEND := $(FRONTEND_$(CHAIN))
TEARDOWN_NS := $(TEARDOWN_NS_$(CHAIN))

CHAINS := log4shell react2shell argo dapr
PROFILES := realistic flat bursty diurnal

# guard: unknown chain
ifeq ($(DIR),)
  ifneq ($(filter $(CHAIN),$(CHAINS)),$(CHAIN))
    $(error CHAIN='$(CHAIN)' is unknown. Use one of: $(CHAINS))
  endif
endif

TAG = [$(CHAIN)/$(SCENARIO)/$(PROFILE)]

# ── chain-specific deploy recipes ────────────────────────────────────────────
define deploy_log4shell
kubectl apply -f $(DIR)/log4j-chain.yaml
case "$(SCENARIO)" in
  B) test -f $(DIR)/backend-b.yaml && kubectl apply -f $(DIR)/backend-b.yaml ;;
  C) test -f $(DIR)/backend-c.yaml && kubectl apply -f $(DIR)/backend-c.yaml ;;
esac
for d in chain-postgres chain-backend chain-frontend; do kubectl -n $(NS) rollout status deploy/$$d --timeout=180s; done
endef

define deploy_dapr
helm status dapr -n dapr-system >/dev/null 2>&1 || \
  helm install dapr dapr/dapr -n dapr-system --create-namespace --set global.ha.enabled=false --wait --timeout 5m
kubectl apply -f $(DIR)/deploy.yaml
for d in redis nats frontend orders payments admin; do kubectl -n $(NS) rollout status deploy/$$d --timeout=180s; done
endef

define deploy_argo
case "$(SCENARIO)" in
  B|C) test -f $(DIR)/app-$$(echo $(SCENARIO)|tr A-Z a-z).yaml || { echo "ERROR: argo scenario $(SCENARIO) needs $(DIR)/app-$$(echo $(SCENARIO)|tr A-Z a-z).yaml (not present yet)"; exit 1; } ;;
esac
kubectl get ns argocd >/dev/null 2>&1 || kubectl create ns argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/v2.9.3/manifests/core-install.yaml
kubectl apply -f $(DIR)/argocd.yaml
case "$(SCENARIO)" in B) kubectl apply -f $(DIR)/app-b.yaml ;; C) kubectl apply -f $(DIR)/app-c.yaml ;; esac
kubectl apply -f $(DIR)/gitserver.yaml
kubectl apply -f $(DIR)/benign-apps.yaml
kubectl -n argocd rollout status deploy/argocd-repo-server --timeout=180s
kubectl -n gitops rollout status deploy/gitserver --timeout=120s || true
endef

define deploy_react2shell
echo "ERROR: react2shell is GitOps-deployed by the argo demo (no standalone manifest)."
echo "       Wire its argo Application first; deploy not yet automated in this Makefile."
exit 1
endef

# ── chain-specific fire recipes (attack overlaid on the running loadgen) ─────
define fire_log4shell
a=$$(echo $(SCENARIO) | tr A-Z a-z)
kubectl -n $(NS) delete pod attack-$$a --ignore-not-found --wait=true
sed "s/attack-PLACEHOLDER/attack-$$a/" $(DIR)/attack-pod.yaml | kubectl apply -f -
kubectl -n $(NS) wait --for=jsonpath='{.status.phase}'=Succeeded pod/attack-$$a --timeout=90s || true
endef

define fire_dapr
kubectl -n $(NS) delete job dapr-shop-trigger --ignore-not-found --wait=true
kubectl apply -f $(DIR)/attack-trigger.yaml
kubectl -n $(NS) wait --for=condition=complete job/dapr-shop-trigger --timeout=90s || true
endef

define fire_argo
kubectl apply -f $(DIR)/attack-pod.yaml
echo "  probe-app applied; controller reconcile -> repo-server render"; sleep 25
endef

define fire_react2shell
echo "ERROR: react2shell attack not yet automated (blind; rides POST /api/rsc)."
exit 1
endef

# ─────────────────────────────────── targets ────────────────────────────────
.PHONY: help matrix show deploy noise learn fire collect cell sweep teardown

help:
	@echo "Attack × noise-profile matrix runner"
	@echo "  make cell  CHAIN=<c> SCENARIO=<A|B|C> PROFILE=<p>   one matrix cell, end to end"
	@echo "  make sweep CHAIN=<c>                                all scenarios×profiles of a chain"
	@echo "  make matrix                                         print the grid"
	@echo "  make show  CHAIN=<c>                                resolved config for a chain"
	@echo "  make teardown CHAIN=<c>                             delete the chain's namespaces"
	@echo "  CHAINS=$(CHAINS)  PROFILES=$(PROFILES)"

show:
	@echo "$(TAG)"
	@echo "  dir=$(DIR) ns=$(NS) target=$(TARGET) sel='$(SEL)' frontend='$(FRONTEND)'"
	@echo "  loadgen=$(LGDEP)/$(LGNS)  teardown-ns='$(TEARDOWN_NS)'"
	@echo "  expected signature: $(EXPECT_$(CHAIN))"

matrix:
	@printf "Attack × noise matrix (cell = chain/scenario/profile)\n\n"
	@printf "  %-12s %-18s %-10s %s\n" CHAIN SCENARIOS DEPLOY "PROFILES (overlay)"
	@printf "  %-12s %-18s %-10s %s\n" log4shell  "A,B,C"  "ready"     "$(PROFILES)"
	@printf "  %-12s %-18s %-10s %s\n" argo       "A (B/C TODO)" "ready" "$(PROFILES)"
	@printf "  %-12s %-18s %-10s %s\n" dapr       "single(A)"  "ready(helm)" "$(PROFILES)"
	@printf "  %-12s %-18s %-10s %s\n" react2shell "A"        "TODO(gitops)" "$(PROFILES)"
	@printf "\n  runnable cells now: log4shell 3×4=12, argo 1×4=4, dapr 1×4=4  (+ react2shell once wired)\n"

deploy:
	@echo ">> $(TAG) deploy"
	$(deploy_$(CHAIN))

noise:
	@echo ">> $(TAG) noise overlay (PROFILE=$(PROFILE))"
	kubectl apply -f $(DIR)/loadgen.yaml
	kubectl -n $(LGNS) set env deploy/$(LGDEP) PROFILE=$(PROFILE)
	kubectl -n $(LGNS) rollout status deploy/$(LGDEP) --timeout=120s

# clean-learn the baseline under the current noise: new RS identity (dodge the
# AP-name tombstone) + frontend restart (dodge cached backend IP) + node-agent
# restart (laptop learning-race) + wait for completion.
learn:
	@echo ">> $(TAG) learn baseline"
	kubectl -n $(NS) rollout restart deploy/$(TARGET)
	[ -n "$(FRONTEND)" ] && kubectl -n $(NS) rollout restart deploy/$(FRONTEND) || true
	kubectl -n $(NS) rollout status deploy/$(TARGET) --timeout=180s
	[ -n "$(FRONTEND)" ] && kubectl -n $(NS) rollout status deploy/$(FRONTEND) --timeout=120s || true
	sleep 8
	kubectl -n $(KSNS) rollout restart ds/node-agent
	kubectl -n $(KSNS) rollout status ds/node-agent --timeout=120s
	RS=$$(kubectl -n $(NS) get rs -l '$(SEL)' --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1].metadata.name}')
	AP=replicaset-$$RS
	echo "  waiting for AP $$AP to complete (<= $(LEARN_WAIT)s)"
	for i in $$(seq 1 $$(( $(LEARN_WAIT) / 20 ))); do
	  st=$$(kubectl -n $(NS) get applicationprofile $$AP -o jsonpath='{.metadata.annotations.kubescape\.io/status}' 2>/dev/null || true)
	  [ "$$st" = "completed" ] && { echo "  AP $$AP completed"; break; }
	  sleep 20
	done
	[ "$$st" = "completed" ] || { echo "WARN: AP not completed (status=$$st)"; }

fire:
	@echo ">> $(TAG) FIRE attack into live noise"
	$(fire_$(CHAIN))

collect:
	@echo ">> $(TAG) collect — settling $(SETTLE)s for the attack chain + alerts to land"
	@sleep $(SETTLE)
	@echo ">> $(TAG) collect — distinct node-agent rules on ns=$(NS) (last $(WINDOW))"
	@kubectl -n $(KSNS) logs ds/node-agent --since=$(WINDOW) 2>/dev/null \
	  | grep -E '"RuleID"' \
	  | jq -r 'select(.RuntimeK8sDetails.namespace=="$(NS)") | .RuleID+" "+(.RuntimeK8sDetails.containerName//"?")' 2>/dev/null \
	  | sort | uniq -c | sort -rn | sed 's/^/    /' || echo "    (none / jq unavailable)"
	@echo "    expected: $(EXPECT_$(CHAIN))"

cell: deploy noise learn fire collect
	@echo "== $(TAG) cell complete =="

# all scenarios × profiles for one chain (log4shell=A,B,C; others=A)
SCENS_log4shell := A B C
SCENS_argo := A
SCENS_dapr := A
SCENS_react2shell := A
sweep:
	@for s in $(SCENS_$(CHAIN)); do for p in $(PROFILES); do \
	  echo "############ sweep: $(CHAIN)/$$s/$$p ############"; \
	  $(MAKE) --no-print-directory cell CHAIN=$(CHAIN) SCENARIO=$$s PROFILE=$$p || echo "cell $(CHAIN)/$$s/$$p FAILED"; \
	  $(MAKE) --no-print-directory teardown CHAIN=$(CHAIN); \
	done; done

# chain-specific teardown hooks (empty for most; dapr must uninstall its helm release)
define teardown_dapr
helm uninstall dapr -n dapr-system 2>/dev/null || true
endef

teardown:
	@echo ">> $(TAG) teardown ($(TEARDOWN_NS))"
	$(teardown_$(CHAIN))
	kubectl delete ns $(TEARDOWN_NS) --ignore-not-found --wait=false
	@echo "  df:"; df -h / | tail -1
