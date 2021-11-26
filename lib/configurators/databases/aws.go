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
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/gravitational/teleport/api/types"
	apiutils "github.com/gravitational/teleport/api/utils"
	awslib "github.com/gravitational/teleport/lib/cloud/aws"
	"github.com/gravitational/teleport/lib/config"
	"github.com/gravitational/trace"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
)

const (
	// DefaultPolicyName default policy name.
	DefaultPolicyName = "DatabaseAccess"
	// policyDescription description used on the policy created.
	policyDescription = "Used by Teleport database agents for discovering AWS-hosted databases."
	// boundarySuffix boundary policies will have this suffix.
	boundarySuffix = "Boundary"
	// policyTeleportTagKey key of the tag added to the policies created.
	policyTeleportTagKey = "teleport"
	// policyTeleportTagValue value of the tag added to the policies created.
	policyTeleportTagValue = ""
)

var (
	// userBaseActions list of actions used when target is an user.
	userBaseActions = []string{"iam:GetUserPolicy", "iam:PutUserPolicy", "iam:DeleteUserPolicy"}
	// roleBaseActions list of actions used when target is a role.
	roleBaseActions = []string{"iam:GetRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy"}
	// rdsActions list of actions used when giving RDS permissions.
	rdsActions = []string{"rds:DescribeDBInstances", "rds:ModifyDBInstance"}
	// auroraActions list of acions used when giving RDS Aurora permissions.
	auroraActions = []string{"rds:DescribeDBClusters", "rds:ModifyDBCluster"}
	// redshiftActions list of actions used when giving Redshift auto-discovery
	// permissions.
	redshiftActions = []string{"redshift:DescribeClusters"}
	// redshiftActions list of resources used when giving Redshift permissions.
	redshiftResources = []string{"dbuser", "dbname", "dbgroup"}
	// boundaryRDSAuroraActions aditional actions added to the policy boundary
	// when policy has RDS auto-discovery.
	boundaryRDSAuroraActions = []string{"rds-db:connect"}
	// boundaryRedshiftActions aditional actions added to the policy boundary
	// when policy has Redshift auto-discovery.
	boundaryRedshiftActions = []string{"redshift:GetClusterCredentials"}
)

// awsConfigurator defines the AWS database configurator.
type awsConfigurator struct {
	// flags user-provided flags to configure/execute the configurator.
	flags BootstrapFlags
	// fileConfig Teleport database agent config.
	fileConfig *config.FileConfig

	policyName                      string
	policyBoundaryName              string
	policyDocument                  *awslib.PolicyDocument
	policyBoundaryDocument          *awslib.PolicyDocument
	formattedPolicyDocument         string
	formattedPolicyBoundaryDocument string

	targetType targetType
	target     string

	// awsIdentity current identity fetched using STS.
	awsIdentity awslib.Identity
	// awsSession current AWS session.
	awsSession *awssession.Session

	awsIAMClient iamiface.IAMAPI
	awsSTSClient stsiface.STSAPI
}

// NewAWSConfigurator creates an instance of awsConfigurator struct and executes
// the `build` function.
func NewAWSConfigurator(flags BootstrapFlags, fileConfig *config.FileConfig) (Configurator, error) {
	configurator := &awsConfigurator{
		flags:                  flags,
		fileConfig:             fileConfig,
		policyName:             flags.PolicyName,
		policyBoundaryName:     fmt.Sprintf("%s%s", flags.PolicyName, boundarySuffix),
		policyDocument:         awslib.NewPolicyDocument(),
		policyBoundaryDocument: awslib.NewPolicyDocument(),
	}

	err := configurator.build()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return configurator, nil
}

func (a *awsConfigurator) Empty() bool {
	return len(a.policyDocument.Statements) == 0
}

func (a *awsConfigurator) Name() string {
	return "AWS"
}

func (a *awsConfigurator) Instructions() []Instruction {
	return []Instruction{
		{Description: fmt.Sprintf("1. Create IAM policy %q:", a.policyName), Details: a.formattedPolicyDocument},
		{Description: fmt.Sprintf("2. Create IAM boundary policy %q:", a.policyBoundaryName), Details: a.formattedPolicyBoundaryDocument},
		{Description: fmt.Sprintf("3. Attach policies to %s %q.", a.targetType.String(), a.target)},
	}
}

func (a *awsConfigurator) Execute(ctx context.Context) []ExecutionResult {
	// Re-use instructions as step descriptions.
	descriptions := a.Instructions()
	var results []ExecutionResult

	// Create/Update policy document.
	policyArn, err := a.upsertPolicyDocument(a.policyName, policyDescription, a.policyDocument)
	results = append(results, ExecutionResult{Description: descriptions[0].Description, Err: err})
	if err != nil {
		return results
	}

	// Create/Update policy boundary document.
	policyBoundaryArn, err := a.upsertPolicyDocument(a.policyBoundaryName, policyDescription, a.policyBoundaryDocument)
	results = append(results, ExecutionResult{Description: descriptions[1].Description, Err: err})
	if err != nil {
		return results
	}

	// Attach policies to the target.
	err = a.attachPolicies(policyArn, policyBoundaryArn)
	results = append(results, ExecutionResult{Description: descriptions[2].Description, Err: err})
	if err != nil {
		return results
	}

	return results
}

// build generates the policy documents and store them into the
// `awsConfigurator` struct.
func (a *awsConfigurator) build() error {
	var err error

	// When running the command in manual mode, we want to have zero dependency
	// with AWS configurations (like awscli or environment variables), so that
	// the user can run this command and generate the instructions without any
	// pre-requisite.
	if !a.flags.Manual {
		stsClient, err := a.getAWSSTSClient()
		if err != nil {
			return trace.Wrap(err)
		}

		a.awsIdentity, err = awslib.GetIdentityWithClient(context.Background(), stsClient)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	// Define the target and target type.
	a.target, a.targetType, err = policiesTarget(a.flags, a.awsIdentity)
	if err != nil {
		return trace.Wrap(err)
	}

	// Generate policies.
	a.policyDocument, a.policyBoundaryDocument, err = buildPolicyDocuments(
		a.targetType,
		a.flags,
		a.fileConfig,
		a.awsIdentity,
	)
	if err != nil {
		return trace.Wrap(err)
	}

	// Generate formatted policies.
	a.formattedPolicyDocument, err = formatPolicyDocument(a.policyDocument)
	if err != nil {
		return trace.Wrap(err)
	}

	a.formattedPolicyBoundaryDocument, err = formatPolicyDocument(a.policyBoundaryDocument)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// retrieveCurrentPolicy returns information from AWS about a policy. If the
// policy doesn't have `teleport` tag and error will be returned.
func (a *awsConfigurator) retrieveCurrentPolicy(policyName string) (string, []*iam.PolicyVersion, error) {
	if a.awsIdentity == nil {
		return "", nil, trace.NotFound("AWS identity not provided, unable to determine policy account ID")
	}

	policyArn := fmt.Sprintf("arn:aws:iam::%s:policy/%s", a.awsIdentity.GetAccountID(), policyName)
	client, err := a.getAWSIAMClient()
	if err != nil {
		return "", nil, trace.Wrap(err)
	}

	getPolicyResp, err := client.GetPolicy(&iam.GetPolicyInput{PolicyArn: aws.String(policyArn)})
	if err != nil {
		return policyArn, nil, wrapAWSError(err)
	}

	// Check if the policy has Teleport tag.
	if !hasTeleportTag(getPolicyResp.Policy.Tags) {
		return policyArn, nil, trace.BadParameter("Policy %q already exists and was not created by Teleport configurator.", policyName)
	}

	resp, err := client.ListPolicyVersions(&iam.ListPolicyVersionsInput{PolicyArn: aws.String(policyArn)})
	if err != nil {
		return policyArn, nil, wrapAWSError(err)
	}

	return policyArn, resp.Versions, nil
}

// upsertPolicyDocument creates a new Policy or creates a Policy version if a
// policy with the same name already exists.
//
// Since policies can hold only five versions, we need to delete a policy
// version (if the limit is reached) and create a new version.
// Ref: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-versioning.html#version-limits
func (a *awsConfigurator) upsertPolicyDocument(documentName, documentDescription string, document *awslib.PolicyDocument) (string, error) {
	encodedPolicyDocument, err := encodePolicyDocument(document)
	if err != nil {
		return "", trace.Wrap(err)
	}

	iamClient, err := a.getAWSIAMClient()
	if err != nil {
		return "", trace.Wrap(err)
	}

	//
	policyArn, versions, err := a.retrieveCurrentPolicy(documentName)
	if err != nil && !trace.IsNotFound(err) {
		return "", trace.Wrap(err)
	}

	// If no versions were found, we need to create a new policy.
	if trace.IsNotFound(err) {
		resp, err := iamClient.CreatePolicyWithContext(context.Background(), &iam.CreatePolicyInput{
			Description:    aws.String(documentDescription),
			PolicyDocument: aws.String(encodedPolicyDocument),
			PolicyName:     aws.String(documentName),
			Tags: []*iam.Tag{
				{Key: aws.String(policyTeleportTagKey), Value: aws.String(policyTeleportTagValue)},
			},
		})
		if err != nil {
			return "", wrapAWSError(err)
		}

		return *resp.Policy.Arn, nil
	}

	// Check number of policy versions and delete one if necessary.
	if len(versions) == 5 {
		// Sort versions based on create date.
		sort.Slice(versions, func(i, j int) bool {
			return versions[i].CreateDate.Before(*versions[j].CreateDate)
		})

		// Find the first version that is not default.
		var policyVersionID string
		for _, policyVersion := range versions {
			if !*policyVersion.IsDefaultVersion {
				policyVersionID = *policyVersion.VersionId
				break
			}
		}

		// Delete first non-default version.
		_, err := iamClient.DeletePolicyVersion(&iam.DeletePolicyVersionInput{
			PolicyArn: aws.String(policyArn),
			VersionId: aws.String(policyVersionID),
		})
		if err != nil {
			return "", wrapAWSError(err)
		}
	}

	// Create new policy version.
	_, err = iamClient.CreatePolicyVersion(&iam.CreatePolicyVersionInput{
		PolicyArn:      aws.String(policyArn),
		PolicyDocument: aws.String(encodedPolicyDocument),
		SetAsDefault:   aws.Bool(true),
	})
	if err != nil {
		return "", wrapAWSError(err)
	}

	return policyArn, nil
}

// attachPolicies attach policies to the target (user or role).
func (a *awsConfigurator) attachPolicies(policyArn, policyBoundaryArn string) error {
	iamClient, err := a.getAWSIAMClient()
	if err != nil {
		return trace.Wrap(err)
	}

	switch a.targetType {
	case targetTypeUser:
		_, err := iamClient.AttachUserPolicy(&iam.AttachUserPolicyInput{
			PolicyArn: aws.String(policyArn),
			UserName:  aws.String(a.target),
		})
		if err != nil {
			return wrapAWSError(err)
		}

		_, err = iamClient.PutUserPermissionsBoundary(&iam.PutUserPermissionsBoundaryInput{
			PermissionsBoundary: aws.String(policyBoundaryArn),
			UserName:            aws.String(a.target),
		})
		if err != nil {
			return wrapAWSError(err)
		}
	case targetTypeRole:
		_, err := iamClient.AttachRolePolicy(&iam.AttachRolePolicyInput{
			PolicyArn: aws.String(policyArn),
			RoleName:  aws.String(a.target),
		})
		if err != nil {
			return trace.Wrap(err)
		}

		_, err = iamClient.PutRolePermissionsBoundary(&iam.PutRolePermissionsBoundaryInput{
			PermissionsBoundary: aws.String(policyBoundaryArn),
			RoleName:            aws.String(a.target),
		})
		if err != nil {
			return wrapAWSError(err)
		}
	default:
		return trace.Errorf("invalid target type %q", a.targetType.String())
	}

	return nil
}

// getAWSIAMClient returns the struct `awsIAMClient` if initialized, otherwise
// creates a new IAM client.
func (a *awsConfigurator) getAWSIAMClient() (iamiface.IAMAPI, error) {
	if a.awsIAMClient != nil {
		return a.awsIAMClient, nil
	}

	session, err := a.getAWSSession()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	a.awsIAMClient = iam.New(session)
	return a.awsIAMClient, nil
}

// getAWSSTSClient returns the struct `awsSTSClient` if initialized, otherwise
// creates a new STS client.
func (a *awsConfigurator) getAWSSTSClient() (stsiface.STSAPI, error) {
	if a.awsSTSClient != nil {
		return a.awsSTSClient, nil
	}

	session, err := a.getAWSSession()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	a.awsSTSClient = sts.New(session)
	return a.awsSTSClient, nil
}

// getAWSSession returns the struct `awsSession` if initialized, otherwise
// creates a new Session.
func (a *awsConfigurator) getAWSSession() (*awssession.Session, error) {
	if a.awsSession != nil {
		return a.awsSession, nil
	}

	var err error
	a.awsSession, err = awssession.NewSessionWithOptions(awssession.Options{
		// TODO: remove this, only used to test locally
		// Config: aws.Config{
		// 	Endpoint: aws.String("http://localhost:4566"),
		// },
		SharedConfigState: awssession.SharedConfigEnable,
	})

	return a.awsSession, err
}

// policiesTarget defines which target and its type the policies will be
// attached to.
func policiesTarget(flags BootstrapFlags, awsIdentity awslib.Identity) (string, targetType, error) {
	if flags.AttachToUser != "" {
		return flags.AttachToUser, targetTypeUser, nil
	}

	if flags.AttachToRole != "" {
		return flags.AttachToRole, targetTypeRole, nil
	}

	if awsIdentity == nil {
		return defaultAttachTarget, defaultAttachTargetType, nil
	}

	// If either role or user are not provided, try to get the current one (using
	// Security token service).
	target := awsIdentity.GetName()
	var targetType targetType

	switch awsIdentity.(type) {
	case awslib.User:
		targetType = targetTypeUser
	case awslib.Role:
		targetType = targetTypeRole
	default:
		return "", targetTypeUnknown, trace.BadParameter("not able to identify the target type")
	}

	return target, targetType, nil
}

// buildPolicyDocuments generates policy and policy boundary document based on
// flags and fileConfig.
func buildPolicyDocuments(targetType targetType, flags BootstrapFlags, fileConfig *config.FileConfig, identity awslib.Identity) (*awslib.PolicyDocument, *awslib.PolicyDocument, error) {
	policyDocument := awslib.NewPolicyDocument()
	boundaryDocument := awslib.NewPolicyDocument()

	var autoDiscoveryDatabaseTypes []string
	for _, matcher := range fileConfig.Databases.AWSMatchers {
		autoDiscoveryDatabaseTypes = append(autoDiscoveryDatabaseTypes, matcher.Types...)
	}

	// Force RDS auto-discovery permissions.
	if flags.ForceRDSPermissions {
		autoDiscoveryDatabaseTypes = append(autoDiscoveryDatabaseTypes, types.DatabaseTypeRDS)
	}

	// Force Redshift auto-discovery permissions.
	if flags.ForceRedshiftPermissions {
		autoDiscoveryDatabaseTypes = append(autoDiscoveryDatabaseTypes, types.DatabaseTypeRedshift)
	}

	// Deduplicate entries.
	autoDiscoveryDatabaseTypes = apiutils.Deduplicate(autoDiscoveryDatabaseTypes)

	// Generates policy statements for auto-discovery AWS databases.
	autoDiscoveryStatement, autoDiscoveryBoundaryStatement := buildAutoDiscoveryStatements(targetType, autoDiscoveryDatabaseTypes)
	if autoDiscoveryStatement != nil && autoDiscoveryBoundaryStatement != nil {
		policyDocument.Statements = append(
			policyDocument.Statements,
			autoDiscoveryStatement,
		)

		boundaryDocument.Statements = append(
			boundaryDocument.Statements,
			autoDiscoveryBoundaryStatement,
		)
	}

	// Add Redshift permissions for the databases.
	redshiftStatements, err := buildRedshiftStatements(fileConfig, identity)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	policyDocument.Statements = append(
		policyDocument.Statements,
		redshiftStatements...,
	)

	boundaryDocument.Statements = append(
		boundaryDocument.Statements,
		redshiftStatements...,
	)

	return policyDocument, boundaryDocument, nil
}

// buildAutoDiscoveryPermissions generates policy and boundary statements for
// auto-discovery.
func buildAutoDiscoveryStatements(targetType targetType, databaseTypes []string) (*awslib.Statement, *awslib.Statement) {
	var actions []string
	var boundaryActions []string

	for _, databaseType := range databaseTypes {
		switch databaseType {
		case types.DatabaseTypeRDS:
			actions = append(actions, auroraActions...)
			actions = append(actions, rdsActions...)
			boundaryActions = append(boundaryActions, boundaryRDSAuroraActions...)
		case types.DatabaseTypeRedshift:
			actions = append(actions, redshiftActions...)
			boundaryActions = append(boundaryActions, boundaryRedshiftActions...)
		}
	}

	// If auto-discovery only has "unsupported" databases, return empty
	// statements.
	if len(actions) == 0 {
		return nil, nil
	}

	switch targetType {
	case targetTypeUser:
		actions = append(actions, userBaseActions...)
	case targetTypeRole:
		actions = append(actions, roleBaseActions...)
	}

	policyStatement := &awslib.Statement{Effect: awslib.EffectAllow, Actions: actions, Resources: []string{"*"}}
	boundaryStatement := &awslib.Statement{Effect: awslib.EffectAllow, Actions: append(actions, boundaryActions...), Resources: []string{"*"}}
	return policyStatement, boundaryStatement
}

// buildRedshiftStatements generates policy Statements for Redshift databases.
func buildRedshiftStatements(fileConfig *config.FileConfig, identity awslib.Identity) ([]*awslib.Statement, error) {
	accountID := "*"
	if identity != nil {
		accountID = identity.GetAccountID()
	}

	var resources []string
	for _, database := range fileConfig.Databases.Databases {
		if strings.Contains(database.URI, types.RedshiftEndpointSuffix) {
			clusterID, region, err := types.ParseRedshiftEndpoint(database.URI)
			if err != nil {
				return nil, trace.Wrap(err)
			}

			for _, resource := range redshiftResources {
				resources = append(resources, fmt.Sprintf(
					"arn:aws:redshift:%s:%s:%s:%s/*",
					region,
					accountID,
					resource,
					clusterID,
				))
			}
		}
	}

	if len(resources) == 0 {
		return []*awslib.Statement{}, nil
	}

	return []*awslib.Statement{
		{Effect: awslib.EffectAllow, Actions: []string{"redshift:GetClusterCredentials"}, Resources: resources},
		{Effect: awslib.EffectAllow, Actions: []string{"redshift:DescribeClusters"}, Resources: []string{"*"}},
	}, nil
}

// formatPolicyDocument formats the PolicyDocument in a "friendly" format, which
// can be presented to end users.
func formatPolicyDocument(policy *awslib.PolicyDocument) (string, error) {
	b, err := json.MarshalIndent(policy, "", "    ")
	if err != nil {
		return "", trace.Wrap(err)
	}

	return string(b), nil
}

// encodePolicyDocument encode PolicyDocument into JSON.
func encodePolicyDocument(policy *awslib.PolicyDocument) (string, error) {
	b, err := json.Marshal(policy)
	if err != nil {
		return "", trace.Wrap(err)
	}

	return string(b), nil
}

// hasTeleportTag check if list of tag contains the Teleport tag.
func hasTeleportTag(tags []*iam.Tag) bool {
	for _, tag := range tags {
		if *tag.Key == policyTeleportTagKey {
			return true
		}
	}

	return false
}

// wrapAWSError wraps an AWS error accordingly.
func wrapAWSError(err error) error {
	switch e := err.(type) {
	case awserr.RequestFailure:
		return awslib.ConvertAWSRequestFailureError(e)
	default:
		return trace.Wrap(err)
	}
}

// targetType represents types that will have the policies attached to.
type targetType int

const (
	// targetTypeUser attach policies to Users.
	targetTypeUser targetType = iota
	// targetTypeRole attach policies to Roles.
	targetTypeRole
	//
	targetTypeUnknown
)

// Default values for target.
const (
	defaultAttachTarget                = "username"
	defaultAttachTargetType targetType = targetTypeUser
)

func (t targetType) String() string {
	switch t {
	case targetTypeUser:
		return "user"
	case targetTypeRole:
		return "role"
	default:
		return "unknown"
	}
}
