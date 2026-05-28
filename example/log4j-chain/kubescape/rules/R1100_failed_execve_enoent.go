// Drop into kubescape/node-agent/pkg/ruleengine/v1/ and register in
// rule_creator.go (R1100 alongside the existing R0001..R0011).
//
// Rationale:
//   Default Kubescape rules trigger on ApplicationProfile deviations
//   (positive signals: "this pod did X which is not in its profile").
//   The log4j PoC needs the complementary signal — a *failed* exec attempt
//   under a process that already loaded an payload class. The fact that
//   execve() returned -ENOENT is itself the diagnostic: the JVM tried to
//   shell out and the container image refused. Without this rule, the
//   evaluator can only commit on a K-second timeout of silence, which is
//   slower and less defensible forensically.

package ruleenginev1

import (
	"fmt"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	R1100ID   = "R1100"
	R1100Name = "Failed execve (ENOENT) under JVM"
)

var R1100FailedExecveEnoentRuleDescriptor = RuleDescriptor{
	ID:          R1100ID,
	Name:        R1100Name,
	Description: "Container's JVM attempted execve() and got ENOENT — diagnostic for distroless-contained RCE.",
	Tags:        []string{"log4j-poc", "containment-diagnostic"},
	Priority:    RulePriorityCritical,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{utils.ExecveEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1100FailedExecveEnoent()
	},
}

type R1100FailedExecveEnoent struct {
	BaseRule
}

func CreateRuleR1100FailedExecveEnoent() *R1100FailedExecveEnoent {
	return &R1100FailedExecveEnoent{}
}

func (rule *R1100FailedExecveEnoent) Name() string { return R1100Name }
func (rule *R1100FailedExecveEnoent) ID() string   { return R1100ID }
func (rule *R1100FailedExecveEnoent) DeleteRule()  {}

func (rule *R1100FailedExecveEnoent) ProcessEvent(
	eventType utils.EventType,
	event utils.K8sEvent,
	objectCache objectcache.ObjectCache,
) ruleengine.RuleFailure {
	if eventType != utils.ExecveEventType {
		return nil
	}
	execEvent, ok := event.(*tracerexectype.Event)
	if !ok {
		return nil
	}

	// ENOENT = -2 in linux errno. IG's exec tracer exposes the syscall
	// return value verbatim in Retval (negative = failure).
	if execEvent.Retval != -2 {
		return nil
	}

	// Only interesting when the offending caller is a JVM thread —
	// "java" is the standard comm string for openjdk + temurin.
	if execEvent.Comm != "java" {
		return nil
	}

	// Scope to the backend container so we don't fire on unrelated JVMs
	// elsewhere in the cluster. Adjust the substring for prod use.
	if !strings.Contains(execEvent.GetContainer(), "backend") {
		return nil
	}

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:      rule.Name(),
			InfectedPID:    execEvent.Pid,
			FixSuggestions: "Confirm: distroless image is doing its job. Persist the alert; do not auto-mute — this is the smoking gun for contained Log4Shell.",
			Severity:       R1100FailedExecveEnoentRuleDescriptor.Priority,
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm: execEvent.Comm,
				PID:  execEvent.Pid,
				PPID: execEvent.Ppid,
				Uid:  &execEvent.Uid,
				Gid:  &execEvent.Gid,
			},
			ContainerID: execEvent.Runtime.ContainerID,
		},
		TriggerEvent: execEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf(
				"JVM in container %q attempted execve(%q) and got ENOENT — RCE landed in JVM but cannot escape to a process.",
				execEvent.GetContainer(), execEvent.Args,
			),
		},
		RuleID: rule.ID(),
	}
}

func (rule *R1100FailedExecveEnoent) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: []utils.EventType{utils.ExecveEventType},
	}
}
