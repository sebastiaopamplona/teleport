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
	"strings"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
	"github.com/vulcand/predicate"
)

// SessionAccessEvaluator takes a set of policies
// and uses rules to evaluate them to determine when a session may start
// and if a user can join a session.
//
// The current implementation is very simple and uses a brute-force algorithm.
// More efficient implementations that run in non O(n^2)-ish time a possible but require significant complexity.
// In the real world, the number of roles and session are small enough that this doesn't have a meaningful impact.
type SessionAccessEvaluator struct {
	kind     types.SessionKind
	requires []*types.SessionRequirePolicy
	roles    []types.Role
}

// NewSessionAccessEvaluator creates a new session access evaluator for a given session kind
// and a set of roles attached to the host user.
func NewSessionAccessEvaluator(roles []types.Role, kind types.SessionKind) SessionAccessEvaluator {
	requires := getRequirePolicies(roles)

	return SessionAccessEvaluator{
		kind,
		requires,
		roles,
	}
}

func getRequirePolicies(participant []types.Role) []*types.SessionRequirePolicy {
	var policies []*types.SessionRequirePolicy

	for _, role := range participant {
		policiesFromRole := role.GetSessionRequirePolicies()
		if len(policiesFromRole) == 0 {
			continue
		}

		policies = append(policies, policiesFromRole...)
	}

	return policies
}

func getAllowPolicies(participant SessionAccessContext) []*types.SessionJoinPolicy {
	var policies []*types.SessionJoinPolicy

	for _, role := range participant.Roles {
		policies = append(policies, role.GetSessionJoinPolicies()...)
	}

	return policies
}

func contains(s []string, e types.SessionKind) bool {
	for _, a := range s {
		if types.SessionKind(a) == e {
			return true
		}
	}

	return false
}

// SessionAccessContext is the context that must be provided per participant in the session.
type SessionAccessContext struct {
	Roles []types.Role
}

func (ctx *SessionAccessContext) GetIdentifier(fields []string) (interface{}, error) {
	if fields[0] == "user" {
		if len(fields) == 2 {
			switch fields[1] {
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
	if !contains(require.Kinds, e.kind) || !contains(allow.Kinds, e.kind) {
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
	if !contains(allow.Kinds, e.kind) {
		return false
	}

	for _, requireRole := range e.roles {
		for _, allowRole := range allow.Roles {
			if requireRole.GetName() == allowRole {
				return true
			}
		}
	}

	return false
}

// CanJoin checks if a given user is eligible to join a session.
func (e *SessionAccessEvaluator) CanJoin(user SessionAccessContext) []types.SessionParticipantMode {
	var modes []types.SessionParticipantMode

	for _, allowPolicy := range getAllowPolicies(user) {
		if e.matchesJoin(allowPolicy) {
			for _, modeString := range allowPolicy.Modes {
				mode := types.SessionParticipantMode(modeString)
				if !SliceContainsMode(modes, mode) {
					modes = append(modes, mode)
				}
			}
		}
	}

	return modes
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
	if len(e.requires) == 0 {
		return true, PolicyOptions{}, nil
	}

	for _, requirePolicy := range e.requires {
		left := requirePolicy.Count

		for _, participant := range participants {
			allowPolicies := getAllowPolicies(participant)
			for _, allowPolicy := range allowPolicies {
				matchesPredicate, err := e.matchesPredicate(&participant, requirePolicy, allowPolicy)
				if err != nil {
					return false, PolicyOptions{}, trace.Wrap(err)
				}

				if matchesPredicate && e.matchesJoin(allowPolicy) {
					left--
					break
				}
			}

			if left <= 0 {
				options := PolicyOptions{}

				switch requirePolicy.OnLeave {
				case types.OnSessionLeaveTerminate:
					options.TerminateOnLeave = true
				case types.OnSessionLeavePause:
					options.TerminateOnLeave = false
				default:
					return false, PolicyOptions{}, trace.BadParameter("unsupported on_leave policy: %v", requirePolicy.OnLeave)
				}

				return true, options, nil
			}
		}
	}

	return false, PolicyOptions{}, nil
}
