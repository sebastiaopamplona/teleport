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

type SessionAccessEvaluator struct {
	kind     types.SessionKind
	requires []*types.SessionRequirePolicy
}

func NewSessionAccessEvaluator(initiator []types.Role, kind types.SessionKind) SessionAccessEvaluator {
	requires := getRequirePolicies(initiator)

	return SessionAccessEvaluator{
		kind,
		requires,
	}
}

func getRequirePolicies(participant []types.Role) []*types.SessionRequirePolicy {
	var policies []*types.SessionRequirePolicy

	for _, role := range participant {
		policiesFromRole := role.GetSessionRequirePolicies(types.Allow)
		if len(policiesFromRole) == 0 {
			return nil
		}

		policies = append(policies, policiesFromRole...)
	}

	return policies
}

func getAllowPolicies(participant SessionAccessContext) []*types.SessionJoinPolicy {
	var policies []*types.SessionJoinPolicy

	for _, role := range participant.roles {
		policies = append(policies, role.GetSessionJoinPolicies(types.Allow)...)
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

type SessionAccessContext struct {
	user  types.User
	roles []types.Role
}

func (ctx *SessionAccessContext) GetIdentifier(fields []string) (interface{}, error) {
	if fields[0] == "user" {
		if len(fields) == 2 {
			switch fields[1] {
			case "roles":
				return ctx.user.GetRoles(), nil
			case "traits":
				return ctx.user.GetTraits(), nil
			}
		}
	}

	return nil, trace.NotFound("%v is not defined", strings.Join(fields, "."))
}

func (ctx *SessionAccessContext) GetResource() (types.Resource, error) {
	return nil, trace.BadParameter("resource unsupported")
}

func (e *SessionAccessEvaluator) matchesPolicy(ctx *SessionAccessContext, require *types.SessionRequirePolicy, allow *types.SessionJoinPolicy) (bool, error) {
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

func (e *SessionAccessEvaluator) FulfilledFor(participants []SessionAccessContext) (bool, error) {
	if len(e.requires) == 0 {
		return true, nil
	}

	for _, requirePolicy := range e.requires {
		left := requirePolicy.Count

		for _, participant := range participants {
			allowPolicies := getAllowPolicies(participant)
			for _, allowPolicy := range allowPolicies {
				matches, err := e.matchesPolicy(&participant, requirePolicy, allowPolicy)
				if err != nil {
					return false, trace.Wrap(err)
				}

				if matches {
					left--
					break
				}
			}

			if left <= 0 {
				return true, nil
			}
		}
	}

	return false, nil
}
