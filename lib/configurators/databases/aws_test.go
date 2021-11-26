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
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	awslib "github.com/gravitational/teleport/lib/cloud/aws"
	"github.com/gravitational/teleport/lib/config"
)

func TestAWSConfiguratorBuild(t *testing.T) {
	t.Run("ManualMode", func(t *testing.T) {
		configurator := &awsConfigurator{
			flags: BootstrapFlags{
				PolicyName: "test",
				Manual:     true,
			},
			fileConfig: &config.FileConfig{},
			// Set STS to return error, as it shouldn't make any difference when
			// running in manual mode.
			awsSTSClient: &STSMock{callerIdentityErr: errors.New("sts error")},
		}

		err := configurator.build()
		require.NoError(t, err)
	})

	t.Run("PolicyDocuments", func(t *testing.T) {
		tests := map[string]struct {
			empty                    bool
			manual                   bool
			forceRedshiftPermissions bool
			forceRDSPermissions      bool
			attachToUser             string
			attachToRole             string
			fileConfig               *config.FileConfig
			awsSTSClient             stsiface.STSAPI
			policyStatements         []*awslib.Statement
			policyBoundaryStatements []*awslib.Statement
		}{
			"RDSAutoDiscoveryUserManual": {
				attachToUser: "user",
				manual:       true,
				fileConfig: &config.FileConfig{
					// Enable RDS/Aurora auto-discovery.
					Databases: config.Databases{
						AWSMatchers: []config.AWSMatcher{
							{Types: []string{types.DatabaseTypeRDS}, Regions: []string{"us-west-2"}},
						},
					},
				},
				policyStatements: []*awslib.Statement{
					{
						Effect:    "Allow",
						Resources: []string{"*"},
						Actions: []string{
							"rds:DescribeDBInstances",
							"rds:ModifyDBInstance",
							"rds:DescribeDBClusters",
							"rds:ModifyDBCluster",
							"iam:GetUserPolicy",
							"iam:PutUserPolicy",
							"iam:DeleteUserPolicy",
						},
					},
				},
				policyBoundaryStatements: []*awslib.Statement{
					{
						Effect:    "Allow",
						Resources: []string{"*"},
						Actions: []string{
							"rds:DescribeDBInstances",
							"rds:ModifyDBInstance",
							"rds:DescribeDBClusters",
							"rds:ModifyDBCluster",
							"iam:GetUserPolicy",
							"iam:PutUserPolicy",
							"iam:DeleteUserPolicy",
							"rds-db:connect",
						},
					},
				},
			},
			"RedshiftAutoDiscoveryUserManual": {
				attachToUser: "user",
				manual:       true,
				fileConfig: &config.FileConfig{
					// Enable RDS/Aurora auto-discovery.
					Databases: config.Databases{
						AWSMatchers: []config.AWSMatcher{
							{Types: []string{types.DatabaseTypeRedshift}, Regions: []string{"us-west-2"}},
						},
					},
				},
				policyStatements: []*awslib.Statement{
					{
						Effect:    "Allow",
						Resources: []string{"*"},
						Actions: []string{
							"redshift:DescribeClusters",
							"iam:GetUserPolicy",
							"iam:PutUserPolicy",
							"iam:DeleteUserPolicy",
						},
					},
				},
				policyBoundaryStatements: []*awslib.Statement{
					{
						Effect:    "Allow",
						Resources: []string{"*"},
						Actions: []string{
							"redshift:DescribeClusters",
							"iam:GetUserPolicy",
							"iam:PutUserPolicy",
							"iam:DeleteUserPolicy",
							"redshift:GetClusterCredentials",
						},
					},
				},
			},
			"RedshiftAutoDiscoveryRoleManual": {
				attachToRole: "role",
				manual:       true,
				fileConfig: &config.FileConfig{
					// Enable RDS/Aurora auto-discovery.
					Databases: config.Databases{
						AWSMatchers: []config.AWSMatcher{
							{Types: []string{types.DatabaseTypeRedshift}, Regions: []string{"us-west-2"}},
						},
					},
				},
				policyStatements: []*awslib.Statement{
					{
						Effect:    "Allow",
						Resources: []string{"*"},
						Actions: []string{
							"redshift:DescribeClusters",
							"iam:GetRolePolicy",
							"iam:PutRolePolicy",
							"iam:DeleteRolePolicy",
						},
					},
				},
				policyBoundaryStatements: []*awslib.Statement{
					{
						Effect:    "Allow",
						Resources: []string{"*"},
						Actions: []string{
							"redshift:DescribeClusters",
							"iam:GetRolePolicy",
							"iam:PutRolePolicy",
							"iam:DeleteRolePolicy",
							"redshift:GetClusterCredentials",
						},
					},
				},
			},
			"RedshiftAutoDiscoveryRoleForcedManual": {
				attachToRole:             "role",
				manual:                   true,
				forceRedshiftPermissions: true,
				fileConfig:               &config.FileConfig{},
				policyStatements: []*awslib.Statement{
					{
						Effect:    "Allow",
						Resources: []string{"*"},
						Actions: []string{
							"redshift:DescribeClusters",
							"iam:GetRolePolicy",
							"iam:PutRolePolicy",
							"iam:DeleteRolePolicy",
						},
					},
				},
				policyBoundaryStatements: []*awslib.Statement{
					{
						Effect:    "Allow",
						Resources: []string{"*"},
						Actions: []string{
							"redshift:DescribeClusters",
							"iam:GetRolePolicy",
							"iam:PutRolePolicy",
							"iam:DeleteRolePolicy",
							"redshift:GetClusterCredentials",
						},
					},
				},
			},
			"RedshiftInstances": {
				attachToUser: "user",
				awsSTSClient: &STSMock{ARN: "arn:aws:iam::123456789012:user/test"},
				fileConfig: &config.FileConfig{
					// Enable Redshift auto-discovery.
					Databases: config.Databases{
						Databases: []*config.Database{
							{
								Name: "redshift-cluster-1",
								URI:  "redshift-cluster-1.abcdefghijkl.us-west-2.redshift.amazonaws.com:5439",
							},
						},
					},
				},
				policyStatements: []*awslib.Statement{
					{
						Effect:  "Allow",
						Actions: []string{"redshift:GetClusterCredentials"},
						Resources: []string{
							"arn:aws:redshift:us-west-2:123456789012:dbuser:redshift-cluster-1/*",
							"arn:aws:redshift:us-west-2:123456789012:dbname:redshift-cluster-1/*",
							"arn:aws:redshift:us-west-2:123456789012:dbgroup:redshift-cluster-1/*",
						},
					},
					{
						Effect:    "Allow",
						Actions:   []string{"redshift:DescribeClusters"},
						Resources: []string{"*"},
					},
				},
				policyBoundaryStatements: []*awslib.Statement{
					{
						Effect:  "Allow",
						Actions: []string{"redshift:GetClusterCredentials"},
						Resources: []string{
							"arn:aws:redshift:us-west-2:123456789012:dbuser:redshift-cluster-1/*",
							"arn:aws:redshift:us-west-2:123456789012:dbname:redshift-cluster-1/*",
							"arn:aws:redshift:us-west-2:123456789012:dbgroup:redshift-cluster-1/*",
						},
					},
					{
						Effect:    "Allow",
						Actions:   []string{"redshift:DescribeClusters"},
						Resources: []string{"*"},
					},
				},
			},
			"RedshiftInstancesManual": {
				attachToUser: "user",
				manual:       true,
				fileConfig: &config.FileConfig{
					// Enable Redshift auto-discovery.
					Databases: config.Databases{
						Databases: []*config.Database{
							{
								Name: "redshift-cluster-1",
								URI:  "redshift-cluster-1.abcdefghijkl.us-west-2.redshift.amazonaws.com:5439",
							},
						},
					},
				},
				policyStatements: []*awslib.Statement{
					{
						Effect:  "Allow",
						Actions: []string{"redshift:GetClusterCredentials"},
						Resources: []string{
							"arn:aws:redshift:us-west-2:*:dbuser:redshift-cluster-1/*",
							"arn:aws:redshift:us-west-2:*:dbname:redshift-cluster-1/*",
							"arn:aws:redshift:us-west-2:*:dbgroup:redshift-cluster-1/*",
						},
					},
					{
						Effect:    "Allow",
						Actions:   []string{"redshift:DescribeClusters"},
						Resources: []string{"*"},
					},
				},
				policyBoundaryStatements: []*awslib.Statement{
					{
						Effect:  "Allow",
						Actions: []string{"redshift:GetClusterCredentials"},
						Resources: []string{
							"arn:aws:redshift:us-west-2:*:dbuser:redshift-cluster-1/*",
							"arn:aws:redshift:us-west-2:*:dbname:redshift-cluster-1/*",
							"arn:aws:redshift:us-west-2:*:dbgroup:redshift-cluster-1/*",
						},
					},
					{
						Effect:    "Allow",
						Actions:   []string{"redshift:DescribeClusters"},
						Resources: []string{"*"},
					},
				},
			},
		}

		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				configurator := &awsConfigurator{
					flags: BootstrapFlags{
						Manual:                   test.manual,
						AttachToUser:             test.attachToUser,
						AttachToRole:             test.attachToRole,
						ForceRedshiftPermissions: test.forceRedshiftPermissions,
						ForceRDSPermissions:      test.forceRDSPermissions,
					},
					fileConfig:   test.fileConfig,
					awsSTSClient: test.awsSTSClient,
				}

				err := configurator.build()
				require.NoError(t, err)

				if test.empty {
					require.Empty(t, configurator.policyDocument.Statements)
					require.Empty(t, configurator.policyBoundaryDocument.Statements)
					return
				}

				sortStringsTrans := cmp.Transformer("SortStrings", func(in []string) []string {
					out := append([]string(nil), in...) // Copy input to avoid mutating it
					sort.Strings(out)
					return out
				})
				require.Empty(t, cmp.Diff(test.policyStatements, configurator.policyDocument.Statements, sortStringsTrans))
				require.Empty(t, cmp.Diff(test.policyBoundaryStatements, configurator.policyBoundaryDocument.Statements, sortStringsTrans))
			})
		}
	})
}

func TestAWSConfiguratorExecute(t *testing.T) {
	now := time.Now()

	testCases := map[string]struct {
		flags                  BootstrapFlags
		fileConfig             *config.FileConfig
		policy                 *iam.Policy
		policyVersions         []*iam.PolicyVersion
		expectedDeletedVersion string
		numberOfExecutedSteps  int
		executionFails         bool
	}{
		"NewPolicyAttachToUser": {
			flags: BootstrapFlags{
				ForceRDSPermissions: true,
				PolicyName:          "test",
				AttachToUser:        "user",
			},
			fileConfig:            &config.FileConfig{},
			numberOfExecutedSteps: 3,
		},
		"NewPolicyAttachToRole": {
			flags: BootstrapFlags{
				ForceRDSPermissions: true,
				PolicyName:          "test",
				AttachToRole:        "role",
			},
			fileConfig:            &config.FileConfig{},
			numberOfExecutedSteps: 3,
		},
		"UpdatePolicyWithoutTag": {
			flags: BootstrapFlags{
				ForceRDSPermissions: true,
				PolicyName:          "test",
				AttachToUser:        "user",
			},
			fileConfig:            &config.FileConfig{},
			policy:                &iam.Policy{},
			numberOfExecutedSteps: 1,
			executionFails:        true,
		},
		"UpdatePolicyAttachToUser": {
			flags: BootstrapFlags{
				ForceRDSPermissions: true,
				PolicyName:          "test",
				AttachToUser:        "user",
			},
			fileConfig: &config.FileConfig{},
			policy: &iam.Policy{
				Tags: []*iam.Tag{
					{Key: aws.String(policyTeleportTagKey), Value: aws.String(policyTeleportTagValue)},
				},
			},
			numberOfExecutedSteps: 3,
			policyVersions: []*iam.PolicyVersion{
				{
					VersionId:        aws.String("v1"),
					CreateDate:       aws.Time(now.Add(time.Minute)),
					IsDefaultVersion: aws.Bool(true),
				},
			},
		},
		"UpdatePolicyDeletingVersion": {
			flags: BootstrapFlags{
				ForceRDSPermissions: true,
				PolicyName:          "test",
				AttachToUser:        "user",
			},
			fileConfig: &config.FileConfig{},
			policy: &iam.Policy{
				Tags: []*iam.Tag{
					{Key: aws.String(policyTeleportTagKey), Value: aws.String(policyTeleportTagValue)},
				},
			},
			numberOfExecutedSteps: 3,
			policyVersions: []*iam.PolicyVersion{
				{
					VersionId:        aws.String("v1"),
					CreateDate:       aws.Time(now.Add(2 * time.Minute)),
					IsDefaultVersion: aws.Bool(false),
				},
				{
					VersionId:        aws.String("v2"),
					CreateDate:       aws.Time(now.Add(time.Minute)),
					IsDefaultVersion: aws.Bool(false),
				},
				{
					VersionId:        aws.String("v3"),
					CreateDate:       aws.Time(now.Add(3 * time.Minute)),
					IsDefaultVersion: aws.Bool(false),
				},
				{
					VersionId:        aws.String("v4"),
					CreateDate:       aws.Time(now.Add(4 * time.Minute)),
					IsDefaultVersion: aws.Bool(false),
				},
				{
					VersionId:        aws.String("v5"),
					CreateDate:       aws.Time(now.Add(5 * time.Minute)),
					IsDefaultVersion: aws.Bool(true),
				},
			},
			// Should delete the oldest non-default version.
			expectedDeletedVersion: "v2",
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			expectedPolicyArn := "arn:aws:iam::123456789012:policy/test"
			expectedBoundaryArn := "arn:aws:iam::123456789012:policy/testBoundary"

			configurator := &awsConfigurator{
				flags:        test.flags,
				fileConfig:   test.fileConfig,
				awsSTSClient: &STSMock{ARN: "arn:aws:iam::123456789012:user/test"},
				awsIAMClient: &IAMMock{
					PolicyArn:                      expectedPolicyArn,
					BoundaryArn:                    expectedBoundaryArn,
					AttachToUser:                   test.flags.AttachToUser,
					AttachToRole:                   test.flags.AttachToRole,
					Policy:                         test.policy,
					PolicyVersions:                 test.policyVersions,
					ExpectedDeletedPolicyVersionID: test.expectedDeletedVersion,
				},
			}

			err := configurator.build()
			require.NoError(t, err)

			instructions := configurator.Instructions()
			require.Len(t, instructions, 3)

			results := configurator.Execute(ctx)
			require.Len(t, results, test.numberOfExecutedSteps)

			if test.executionFails {
				require.Error(t, results[len(results)-1].Err)
				return
			}

			for _, result := range results {
				require.NoErrorf(t, result.Err, "Execution %q failed", result.Description)
			}
		})
	}
}

type STSMock struct {
	stsiface.STSAPI
	ARN               string
	callerIdentityErr error
}

func (m *STSMock) GetCallerIdentityWithContext(aws.Context, *sts.GetCallerIdentityInput, ...request.Option) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{
		Arn: aws.String(m.ARN),
	}, m.callerIdentityErr
}

type IAMMock struct {
	iamiface.IAMAPI

	PolicyArn    string
	BoundaryArn  string
	AttachToUser string
	AttachToRole string

	CreatePolicyError              error
	Policy                         *iam.Policy
	PolicyVersions                 []*iam.PolicyVersion
	ExpectedDeletedPolicyVersionID string
}

func (m *IAMMock) CreatePolicyWithContext(_ aws.Context, input *iam.CreatePolicyInput, _ ...request.Option) (*iam.CreatePolicyOutput, error) {
	arn := m.PolicyArn
	if strings.HasSuffix(*input.PolicyName, boundarySuffix) {
		arn = m.BoundaryArn
	}

	return &iam.CreatePolicyOutput{
		Policy: &iam.Policy{
			Arn: aws.String(arn),
		},
	}, m.CreatePolicyError
}

func (m *IAMMock) GetPolicy(_ *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
	if m.Policy == nil {
		return nil, awserr.NewRequestFailure(awserr.New(iam.ErrCodeNoSuchEntityException, "not found", nil), 404, "")
	}

	return &iam.GetPolicyOutput{Policy: m.Policy}, nil
}

func (m *IAMMock) AttachUserPolicy(_ *iam.AttachUserPolicyInput) (*iam.AttachUserPolicyOutput, error) {
	if m.AttachToUser == "" {
		return nil, awserr.New("501", "not implemented", nil)
	}

	return &iam.AttachUserPolicyOutput{}, nil
}

func (m *IAMMock) PutUserPermissionsBoundary(_ *iam.PutUserPermissionsBoundaryInput) (*iam.PutUserPermissionsBoundaryOutput, error) {
	if m.AttachToUser == "" {
		return nil, awserr.New("501", "not implemented", nil)
	}

	return &iam.PutUserPermissionsBoundaryOutput{}, nil
}

func (m *IAMMock) AttachRolePolicy(_ *iam.AttachRolePolicyInput) (*iam.AttachRolePolicyOutput, error) {
	if m.AttachToRole == "" {
		return nil, awserr.New("501", "not implemented", nil)
	}

	return &iam.AttachRolePolicyOutput{}, nil
}

func (m *IAMMock) PutRolePermissionsBoundary(_ *iam.PutRolePermissionsBoundaryInput) (*iam.PutRolePermissionsBoundaryOutput, error) {
	if m.AttachToRole == "" {
		return nil, awserr.New("501", "not implemented", nil)
	}

	return &iam.PutRolePermissionsBoundaryOutput{}, nil
}

func (m *IAMMock) CreatePolicyVersion(_ *iam.CreatePolicyVersionInput) (*iam.CreatePolicyVersionOutput, error) {
	if m.Policy == nil {
		return nil, awserr.NewRequestFailure(awserr.New(iam.ErrCodeNoSuchEntityException, "not found", nil), 404, "")
	}

	return &iam.CreatePolicyVersionOutput{}, nil
}

func (m *IAMMock) ListPolicyVersions(_ *iam.ListPolicyVersionsInput) (*iam.ListPolicyVersionsOutput, error) {
	if len(m.PolicyVersions) == 0 {
		return nil, awserr.NewRequestFailure(awserr.New(iam.ErrCodeNoSuchEntityException, "not found", nil), 404, "")
	}

	return &iam.ListPolicyVersionsOutput{Versions: m.PolicyVersions}, nil
}

func (m *IAMMock) DeletePolicyVersion(input *iam.DeletePolicyVersionInput) (*iam.DeletePolicyVersionOutput, error) {
	fmt.Println(input)
	if *input.VersionId != m.ExpectedDeletedPolicyVersionID {
		return nil, awserr.NewRequestFailure(awserr.New(iam.ErrCodeNoSuchEntityException, "not found", nil), 404, "")
	}

	return &iam.DeletePolicyVersionOutput{}, nil
}
