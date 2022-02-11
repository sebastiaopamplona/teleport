/*
Copyright 2022 Gravitational, Inc.

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
	"context"
	"fmt"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
)

// tokenJoinMethod returns the join method of the token with the given tokenName
func (a *Server) tokenJoinMethod(ctx context.Context, tokenName string) types.JoinMethod {
	provisionToken, err := a.GetToken(ctx, tokenName)
	if err != nil {
		// could not find dynamic token, assume static token. If it does not
		// exist this will be caught later.
		return types.JoinMethodToken
	}
	return provisionToken.GetJoinMethod()
}

// checkTokenJoinRequestCommon checks all token join rules that are common to
// all join methods, including token existence, token TTL, and allowed roles.
func (a *Server) checkTokenJoinRequestCommon(ctx context.Context, req *types.RegisterUsingTokenRequest) error {
	// make sure the token is valid
	roles, _, err := a.ValidateToken(ctx, req.Token)
	if err != nil {
		log.Warningf("%q [%v] can not join the cluster with role %s, token error: %v", req.NodeName, req.HostID, req.Role, err)
		return trace.AccessDenied(fmt.Sprintf("%q [%v] can not join the cluster with role %s, the token is not valid", req.NodeName, req.HostID, req.Role))
	}

	// make sure the caller is requesting a role allowed by the token
	if !roles.Include(req.Role) {
		msg := fmt.Sprintf("node %q [%v] can not join the cluster, the token does not allow %q role", req.NodeName, req.HostID, req.Role)
		log.Warn(msg)
		return trace.BadParameter(msg)
	}

	return nil
}

// RegisterUsingToken returns credentials for a new node to join the Teleport
// cluster using a previously issued token.
//
// A node must also request a specific role (and the role must match one of the roles
// the token was generated for.)
//
// If a token was generated with a TTL, it gets enforced (can't register new
// nodes after TTL expires.)
//
// If the token includes a specific join method, the rules for that join method
// will be checked.
func (a *Server) RegisterUsingToken(ctx context.Context, req *types.RegisterUsingTokenRequest) (*proto.Certs, error) {
	log.Infof("Node %q [%v] is trying to join with role: %v.", req.NodeName, req.HostID, req.Role)
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	switch a.tokenJoinMethod(ctx, req.Token) {
	case types.JoinMethodEC2:
		if err := a.checkEC2JoinRequest(ctx, req); err != nil {
			return nil, trace.Wrap(err)
		}
	case types.JoinMethodIAM:
		// IAM join method must use the gRPC RegisterUsingIAMMethod
		return nil, trace.AccessDenied("this token is only valid for the IAM " +
			"join method but the node has connected to the wrong endpoint, make " +
			"sure your node is configured to use the IAM join method")
	case types.JoinMethodToken:
		// carry on to common token checking logic
	default:
		// this is a logic error, all valid join methods should be captured
		// above (empty join method will be set to JoinMethodToken by
		// CheckAndSetDefaults)
		return nil, trace.BadParameter("unrecognized token join method")
	}

	// perform common token checks
	if err := a.checkTokenJoinRequestCommon(ctx, req); err != nil {
		return nil, trace.Wrap(err)
	}

	// generate and return host certificate and keys
	certs, err := a.GenerateHostCerts(ctx,
		&proto.HostCertsRequest{
			HostID:               req.HostID,
			NodeName:             req.NodeName,
			Role:                 req.Role,
			AdditionalPrincipals: req.AdditionalPrincipals,
			PublicTLSKey:         req.PublicTLSKey,
			PublicSSHKey:         req.PublicSSHKey,
			RemoteAddr:           req.RemoteAddr,
			DNSNames:             req.DNSNames,
		})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	log.Infof("Node %q [%v] has joined the cluster.", req.NodeName, req.HostID)
	return certs, nil
}

func (a *Server) RegisterNewAuthServer(ctx context.Context, token string) error {
	tok, err := a.GetToken(ctx, token)
	if err != nil {
		return trace.Wrap(err)
	}
	if !tok.GetRoles().Include(types.RoleAuth) {
		return trace.AccessDenied("role does not match")
	}
	if err := a.DeleteToken(ctx, token); err != nil {
		return trace.Wrap(err)
	}
	return nil
}
