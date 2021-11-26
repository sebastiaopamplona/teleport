// Copyright 2022 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package databases

import (
	"context"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/config"
)

// BootstrapFlags flags provided by users to configure and define how the
// configurators will work.
type BootstrapFlags struct {
	// ConfigPath database agent configuration path.
	ConfigPath string
	// Manual boolean indicating if the configurator will perform the
	// instructions or if it will be the user.
	Manual bool
	// PolicyName name of the generated policy.
	PolicyName string
	// AttachToUser user that the generated policies will be attached to.
	AttachToUser string
	// AttachToRole role that the generated policies will be attached to.
	AttachToRole string
	// IncludeRedshiftWildcard indicates if Redshift permissions must be
	// included using a wildcard.
	IncludeRedshiftWildcard bool
	// ForceRDSPermissions forces the presence of RDS permissions.
	ForceRDSPermissions bool
	// ForceAuroraPermissions forces the presence of Redshift permissions.
	ForceRedshiftPermissions bool
}

// Instruction instruction that should be performed by users or the
// configurator. It contains a human-readable description and optional details
// about it.
type Instruction struct {
	// Description instruction description.
	Description string
	// Details instruction details.
	Details string
}

// ExecutionResult execution step result.
type ExecutionResult struct {
	// Step description of the current step.
	Description string
	// Err error returned by the step.
	Err error
}

// Configurator
type Configurator interface {
	// Execute executes the configurator returning a list of steps results. Each
	// result has a description similar to the ones produced by `Instructions` and
	// an error attribute to indicate if the step failed or not.
	//
	// When a step fails, the execution stops and returns the results until the one
	// that failed.
	Execute(ctx context.Context) []ExecutionResult
	// Instructions return the list of instructions performed by the users (when in
	// manual mode) or by the configurator itself.
	Instructions() []Instruction
	// Name returns the configurator name.
	Name() string
	// Empty defines if the configurator will have to perform any action.
	Empty() bool
}

// BuildConfigurators reads the configuration and returns a list of
// configurators. Configurators that are "empty" are not returned.
func BuildConfigurators(flags BootstrapFlags) ([]Configurator, error) {
	fileConfig, err := config.ReadFromFile(flags.ConfigPath)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	aws, err := NewAWSConfigurator(flags, fileConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var configurators []Configurator
	if !aws.Empty() {
		configurators = append(configurators, aws)
	}

	return configurators, nil
}
