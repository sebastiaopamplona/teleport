/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"regexp"
	"strings"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
	"github.com/vulcand/predicate"
)

// SessionAccessEvaluator takes a set of policies
// and uses rules to evaluate them to determine when a session may start
// and if a user can join a session.
//
// The current implementation is very simple and uses a brute-force algorithm.
// More efficient implementations that run in non O(n^2)-ish time are possible but require complex code
// that is harder to debug in the case of misconfigured policies or other error and are harder to intuitively follow.
// In the real world, the number of roles and session are small enough that this doesn't have a meaningful impact.
type SessionAccessEvaluator struct {
	kind       types.SessionKind
	policySets []*types.SessionTrackerPolicySet
}

// NewSessionAccessEvaluator creates a new session access evaluator for a given session kind
// and a set of roles attached to the host user.
func NewSessionAccessEvaluator(policySets []*types.SessionTrackerPolicySet, kind types.SessionKind) SessionAccessEvaluator {
	return SessionAccessEvaluator{
		kind,
		policySets,
	}
}

func getAllowPolicies(participant SessionAccessContext) []*types.SessionJoinPolicy {
	var policies []*types.SessionJoinPolicy

	for _, role := range participant.Roles {
		policies = append(policies, role.GetSessionJoinPolicies()...)
	}

	return policies
}

func containsKind(s []string, e types.SessionKind) bool {
	for _, a := range s {
		if types.SessionKind(a) == e {
			return true
		}
	}

	return false
}

// SessionAccessContext is the context that must be provided per participant in the session.
type SessionAccessContext struct {
	Username string
	Roles    []types.Role
}

// GetIdentifier is used by the `predicate` library to evaluate variable expressions when
// evaluating policy filters. It deals with evaluating strings like `participant.name` to the appropriate value.
func (ctx *SessionAccessContext) GetIdentifier(fields []string) (interface{}, error) {
	if fields[0] == "participant" {
		if len(fields) == 2 || len(fields) == 3 {
			switch fields[1] {
			case "name":
				return ctx.Username, nil
			case "roles":
				var roles []string
				for _, role := range ctx.Roles {
					roles = append(roles, role.GetName())
				}

				return roles, nil
			}
		}
	}

	return nil, trace.NotFound("%v is not defined", strings.Join(fields, "."))
}

func (ctx *SessionAccessContext) GetResource() (types.Resource, error) {
	return nil, trace.BadParameter("resource unsupported")
}

func (e *SessionAccessEvaluator) matchesPredicate(ctx *SessionAccessContext, require *types.SessionRequirePolicy, allow *types.SessionJoinPolicy) (bool, error) {
	if !e.matchesKind(require.Kinds) || !e.matchesKind(allow.Kinds) {
		return false, nil
	}

	parser, err := services.NewWhereParser(ctx)
	if err != nil {
		return false, trace.Wrap(err)
	}

	ifn, err := parser.Parse(require.Filter)
	if err != nil {
		return false, trace.Wrap(err)
	}

	fn, ok := ifn.(predicate.BoolPredicate)
	if !ok {
		return false, trace.BadParameter("unsupported type: %T", ifn)
	}

	return fn(), nil
}

func (e *SessionAccessEvaluator) matchesJoin(allow *types.SessionJoinPolicy) bool {
	if !e.matchesKind(allow.Kinds) {
		return false
	}

	for _, policySet := range e.policySets {
		for _, allowRole := range allow.Roles {
			expr := utils.GlobToRegexp(policySet.Name)
			// GlobToRegexp makes sure this is always a valid regexp.
			matched, _ := regexp.MatchString(expr, allowRole)

			if matched {
				return true
			}
		}
	}

	return false
}

func (e *SessionAccessEvaluator) matchesKind(allow []string) bool {
	if containsKind(allow, e.kind) || containsKind(allow, "*") {
		return true
	}

	return false
}

// CanJoin returns the modes a user has access to join a session with.
// If the list is empty, the user doesn't have access to join the session at all.
func (e *SessionAccessEvaluator) CanJoin(user SessionAccessContext) ([]types.SessionParticipantMode, error) {
	supported, err := e.supportsSessionAccessControls()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// If we don't support session access controls, return the default mode set that was supported prior to Moderated Sessions.
	if !supported {
		return preAccessControlsModes(e.kind), nil
	}

	var modes []types.SessionParticipantMode

	// Loop over every allow policy attached the participant and check it's applicability.
	// This code serves to merge the permissions of all applicable join policies.
	for _, allowPolicy := range getAllowPolicies(user) {
		// If the policy is applicable and allows joining the session, add the allowed modes to the list of modes.
		if e.matchesJoin(allowPolicy) {
			for _, modeString := range allowPolicy.Modes {
				mode := types.SessionParticipantMode(modeString)
				if !SliceContainsMode(modes, mode) {
					modes = append(modes, mode)
				}
			}
		}
	}

	return modes, nil
}

func SliceContainsMode(s []types.SessionParticipantMode, e types.SessionParticipantMode) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// PolicyOptions is a set of settings for the session determined by the matched require policy.
type PolicyOptions struct {
	TerminateOnLeave bool
}

// FulfilledFor checks if a given session may run with a list of participants.
func (e *SessionAccessEvaluator) FulfilledFor(participants []SessionAccessContext) (bool, PolicyOptions, error) {
	supported, err := e.supportsSessionAccessControls()
	if err != nil {
		return false, PolicyOptions{}, trace.Wrap(err)
	}

	// If advanced access controls are supported or no require policies are defined, we allow by default.
	if len(e.policySets) == 0 || !supported {
		return true, PolicyOptions{TerminateOnLeave: true}, nil
	}

	options := PolicyOptions{TerminateOnLeave: true}

	// Check every policy set to check if it's fulfilled.
	// We need every policy set to match to allow the session.
policySetLoop:
	for _, policySet := range e.policySets {
		// Check every require policy to see if it's fulfilled.
		// Only one needs to be checked to pass the policyset.
		for _, requirePolicy := range policySet.RequireSessionJoin {
			// Count of how many additional participant matches we need to fulfill the policy.
			left := requirePolicy.Count

			// Check every participant against the policy.
			for _, participant := range participants {
				// Check the allow polices attached to the participant against the session.
				allowPolicies := getAllowPolicies(participant)
				for _, allowPolicy := range allowPolicies {
					// Evaluate the filter in the require policy against the participant and allow policy.
					matchesPredicate, err := e.matchesPredicate(&participant, requirePolicy, allowPolicy)
					if err != nil {
						return false, PolicyOptions{}, trace.Wrap(err)
					}

					// If the the filter matches the participant and the allow policy matches the session
					// we conclude that the participant matches against the require policy.
					if matchesPredicate && e.matchesJoin(allowPolicy) {
						left--
						break
					}
				}

				// If we've matched enough participants against the require policy, we can allow the session.
				if left <= 0 {
					switch requirePolicy.OnLeave {
					case types.OnSessionLeaveTerminate:
					case types.OnSessionLeavePause:
						options.TerminateOnLeave = false
					default:
						return false, PolicyOptions{}, trace.BadParameter("unsupported on_leave policy: %v", requirePolicy.OnLeave)
					}

					// We matched at least one require policy within the set. Continue ahead.
					continue policySetLoop
				}
			}
		}

		// We failed to match against any require policy and thus the set.
		// Thus, we can't allow the session.
		return false, PolicyOptions{}, nil
	}

	// All policy sets matched, we can allow the session.
	return true, options, nil
}

// supportsSessionAccessControls checks if moderated sessions-style access controls can be applied to the session.
// If a set only has v4 or earlier roles, we don't want to apply the access checks to SSH sessions.
//
// This only applies to SSH sessions since they previously had no access control for joining sessions.
// We don't need this fallback behaviour for multiparty kubernetes since it's a new feature.
func (e *SessionAccessEvaluator) supportsSessionAccessControls() (bool, error) {
	if e.kind == types.SSHSessionKind {
		for _, policySet := range e.policySets {
			switch policySet.Version {
			case types.V1, types.V2, types.V3, types.V4:
				return false, nil
			case types.V5:
				return true, nil
			default:
				return false, trace.BadParameter("unsupported role version: %v", policySet.Version)
			}
		}
	}

	return false, nil
}

func preAccessControlsModes(kind types.SessionKind) []types.SessionParticipantMode {
	switch kind {
	case types.SSHSessionKind:
		return []types.SessionParticipantMode{types.SessionPeerMode}
	default:
		return nil
	}
}
